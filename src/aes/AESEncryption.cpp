#include "AESEncryption.h"
#include <rand/Rand.h>
#include <cstring>
#include <bit> // Provides bit rotation
#include <iostream>
#include <assert.h>
#include <thread>

#define RAND_128 (((uint128_t)rand->NextInt() << 96) & ((uint128_t)0xffffffff << 96)) \
| (((uint128_t)rand->NextInt() << 64) & ((uint128_t)0xffffffff << 64)) \
| (((uint128_t)rand->NextInt() << 32) & ((uint128_t)0xffffffff << 32)) \
| (uint128_t)(rand->NextInt() & 0xffffffff)

Rand* AESEncryption::rand = nullptr;

std::vector<uint8_t> AESEncryption::AES128(std::vector<uint8_t> data, std::vector<uint8_t> key) {
	ProcessKey128(key, rand); // Generate a random key using the CSPRNG from the given key - This function seeds the CSPRNG

	// Generate the round keys
	std::vector<RoundKey> roundKeys = GenRoundKeys128(key, rand);
	// Using the counter mode of operation, so we need a counter - This needs to be 128 bits, the size of an AES block, so I use a convenient uint128_t library: https://github.com/calccrypto/uint128_t
	uint128_t counter = RAND_128;

	// Size of data should be a multiple of 16, so it can be split into blocks
	size_t dataSizeOrig = data.size();
	if(data.size() % 16 != 0) {
		uint8_t numBytesAway = 16 - data.size() % 16;
		data.resize(data.size() + numBytesAway);
	}

	std::vector<uint128_t> blocks;// = (uint128_t*)data.data();
	blocks.resize(data.size() / 16); // This should always, thanks to the above bit of code, be exact. data.size() should always be a multiple of 16
	memcpy(blocks.data(), data.data(), data.size()); // Copy data into blocks

	// We only want to go multithreaded when there's quite a lot of data. Max of uint16_t is like 0.05 of a megabyte (I actually have got so confused about the definition of a megabyte, along with all the others like mebibyte and everything)
	bool multithreaded = data.size() > std::numeric_limits<uint16_t>().max();
	if(multithreaded) {
		// Don't necessarily need locks or mutexes or semaphores or whatnot if I simply have it so there's no chance of threads trying to access blocks other threads are accessing
		// Set the number of threads to be the number of cores the machine has. std::thread::hardware_concurrency() can return 0 if it can't detect, so in that case just use 8
#define NUM_THREADS std::thread::hardware_concurrency() == 0 ? 8 : std::thread::hardware_concurrency()
		// Container to store all the threads
		std::vector<std::thread> threads;

		// Start all of the threads
		for(uint8_t i = 0; i < NUM_THREADS; i++) {
			threads.push_back(std::thread([i, &blocks, &counter, &roundKeys]() {
				for(size_t j = i; j < blocks.size(); j += NUM_THREADS) {
					uint128_t& dblock = blocks[i];
					uint128_t counterCpy = counter;
					Block<128> cblock = &counterCpy;
					EncryptBlock128(cblock, roundKeys);
					dblock ^= counterCpy;
					counter++;
				}
			}));
		}

		// Wait for all the threads to finish
		for(uint8_t i = 0; i < threads.size(); i++) {
			threads.at(i).join();
		}
	} else { // We do it serially otherwise
		for(size_t i = 0; i < blocks.size(); i++) {
			uint128_t& dblock = blocks[i];
			uint128_t counterCpy = counter;
			Block<128> cblock = &counterCpy;
			EncryptBlock128(cblock, roundKeys);
			dblock ^= counterCpy;
			counter++;
		}
	}

	memcpy(data.data(), blocks.data(), data.size());

	data.resize(dataSizeOrig); // Resize back to what it was before. Cut the crap

	delete rand;
	rand = nullptr;

	return data;
}

void AESEncryption::ProcessKey128(std::vector<uint8_t>& key, Rand*& rand) {
	// Copy the key into a buffer to be used as the CSPRNG seed
	std::vector<uint32_t> randSeed;
	randSeed.resize(RANDSIZ);
	uint32_t seedBytes = RANDSIZ * sizeof(uint32_t);
	size_t copyAmt = key.size() > seedBytes ? seedBytes : key.size(); // Make sure that what's copied doesn't go over the limit the size of the seed (in bytes) - don't want any segfaults
	memcpy(&randSeed.front(), &key.front(), copyAmt);
	rand = new Rand(randSeed);

	key.resize(16);

	// Write random numbers into the key array
	for(uint8_t i = 0; i < key.size(); i += sizeof(uint32_t)) {
		uint32_t n = rand->NextInt();
		key[i] = n & 0xff;
		key[i + 1] = (n >> 8) & 0xff;
		key[i + 2] = (n >> 16) & 0xff;
		key[i + 3] = (n >> 24) & 0xff;
	}
}

std::vector<RoundKey> AESEncryption::GenRoundKeys128(const std::vector<uint8_t>& key, Rand* rand) { // TODO Should probably remove rand
	std::vector<RoundKey> roundKeys;
	roundKeys.resize(11);

	// Copy bytes into the first round key - This is the value of it
	memcpy((uint8_t*)&roundKeys.front(), &key.front(), key.size());

	// Calculate all the round keys
	// Each round key contains words w0, w1, w2, w3
	// Each of the round keys from 1 to 10 (0 is initialised to the value of the key):
	//   w0 is the sum of: w0 from previous round key, w3 from previous round key rotated right by 8, and a value from a special table called Rcon
	//   w1, w2, w3 are the sum of the corresponding word in the previous round key and the preceding word in the current round key
	// Note that this is using Finite Field Arithmetic, so addition is actually XOR (^)
	// This method: https://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Appendixes/Appendix+A.+Overview+of+the+AES+Block+Cipher/Steps+in+the+AES+Encryption+Process/
	// Finite Field Arithmetic: https://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Appendixes/Appendix+A.+Overview+of+the+AES+Block+Cipher/Finite+Field+Arithmetic/
	for(uint8_t i = 1; i < roundKeys.size(); i++) {
		roundKeys.at(i).w0 = roundKeys.at(i - 1).w0 ^ std::rotr(roundKeys.at(i - 1).w3, 8) ^ c_Rcon128[i];
		roundKeys.at(i).w1 = roundKeys.at(i - 1).w1 ^ roundKeys.at(i).w0;
		roundKeys.at(i).w2 = roundKeys.at(i - 1).w2 ^ roundKeys.at(i).w1;
		roundKeys.at(i).w3 = roundKeys.at(i - 1).w3 ^ roundKeys.at(i).w2;
	}

	return roundKeys;
}

void AESEncryption::EncryptBlock128(Block<128>& block, const std::vector<RoundKey>& roundKeys) {
	assert(roundKeys.size() == 11);

	// Whether we're using the AES-NI instruction extension (it's actually only called AES-NI for x86/x86_64) or using software implementation
	bool aesni = true;

	// We only support hardware-accelerated AES on x86/x86_64 compiled with GCC - For now at least
#if defined __GNUC__ && (defined __i386__ || defined __amd64__)
	// Using GCC intrinsics to check if we've got all the necessary instructions (https://gcc.gnu.org/onlinedocs/gcc/x86-Built-in-Functions.html#x86-Built-in-Functions)
	bool sse = __builtin_cpu_supports("sse"); // SSE1 for xorps
	bool sse2 = __builtin_cpu_supports("sse2"); // SSE2 for movdqa
	bool aes = __builtin_cpu_supports("aes"); // AES for AES instructions
	bool gotInstructions = sse && sse2 && aes; // If we've got access to all the necessary instructions
	if(gotInstructions) {
		// Intel's AES encryption: Page 17: https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

		uint128_t& b = *(uint128_t*)block.m_BlockStart;

		// I should probably do all this using intrinsics... But honestly I understand this assembly much better so maybe not.
		// I'll look into the intrinsics at some point probably
		asm (
			// Load the block into XMM1
			"movdqa %0, %%xmm1;"
			// Move the first key into XMM0
			"movdqa %1, %%xmm0;"
			// Encrypt the block with each of the round keys
			"xorps %%xmm0, %%xmm1;"
			"aesenc %2, %%xmm1;"
			"aesenc %3, %%xmm1;"
			"aesenc %4, %%xmm1;"
			"aesenc %5, %%xmm1;"
			"aesenc %6, %%xmm1;"
			"aesenc %7, %%xmm1;"
			"aesenc %8, %%xmm1;"
			"aesenc %9, %%xmm1;"
			"aesenc %10, %%xmm1;"
			"aesenclast %11, %%xmm1;"
			// Finally move the result back into the block
			"movdqa %%xmm1, %0;"
			: "=m"(b)
			: "m"(roundKeys.at(0)), "m"(roundKeys.at(1)), "m"(roundKeys.at(2)), "m"(roundKeys.at(3)), "m"(roundKeys.at(4)), "m"(roundKeys.at(5)),
			  "m"(roundKeys.at(6)), "m"(roundKeys.at(7)), "m"(roundKeys.at(8)), "m"(roundKeys.at(9)), "m"(roundKeys.at(10))
			: "%xmm0", // The register to store the first round key
			  "%xmm1" // The register to hold the block
		);
	}
#else
	aesni = false;
#warning Hardware accelerated AES is only implemented for GCC on x86 and x86_64 - Compiling using non-accelerated AES
#endif

	if(!aesni) {
		// TODO Test AES
		for(uint8_t i = 0; i < roundKeys.size(); i++) {
			if(i == 0) {
				// XOR
				AddRoundKey128(block, roundKeys.at(i));
			} else if(i == roundKeys.size() - 1) {
				// AESENCLAST
				SubBytes128(block, roundKeys.at(i));
				ShiftRows128(block, roundKeys.at(i));
				AddRoundKey128(block, roundKeys.at(i));
			} else {
				// AESENC
				SubBytes128(block, roundKeys.at(i));
				ShiftRows128(block, roundKeys.at(i));
				MixColumns128(block, roundKeys.at(i));
				AddRoundKey128(block, roundKeys.at(i));
			}
		}
	}
}

void AESEncryption::SubBytes128(Block<128>& data, const RoundKey& roundKey) {
	// Rijndael substitution box. Apparently memory access patters to this array can make the implementation vulnerable to side-channel attacks
	static uint8_t sbox[] = { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
	// Loop through all bytes in data
	for(uint8_t i = 0; i < data.c_BlockDims; i++) {
		for(uint8_t j = 0; j < data.c_BlockDims; j++) {
			data.At(i, j) = sbox[data.At(i, j)]; // Replace each byte with the corresponding byte in the substitution box
		}
	}
}

inline void Swap(uint8_t& num1, uint8_t& num2) {
	uint8_t tmp = num1;
	num1 = num2;
	num2 = tmp;
}

inline void ShiftLeft(uint8_t& b0, uint8_t& b1, uint8_t& b2, uint8_t& b3, uint8_t places) {
	switch(places) {
		case 0:
			return;

		case 1:
			Swap(b3, b0);
			Swap(b0, b1);
			Swap(b1, b2);
			return;

		case 2:
			Swap(b0, b2);
			Swap(b1, b3);
			return;

		case 3:
			Swap(b0, b1);
			Swap(b0, b2);
			Swap(b0, b3);
			return;

		case 4:
			return;

		default:
			assert(false);
			return;
	}
}

void AESEncryption::ShiftRows128(Block<128>& data, const RoundKey& roundKey) {
	for(uint8_t y = 0; y < data.c_BlockDims; y++) {
		uint8_t shift = y;
		if(shift > 0) {
			ShiftLeft(data.At(0, y), data.At(1, y), data.At(2, y), data.At(3, y), shift);
		}
	}
}

/// Finite Field Arithmetic namespace. These functions do all their operations inside the Galois Field GF(2^8)
/// See <a href="https://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Appendixes/Appendix+A.+Overview+of+the+AES+Block+Cipher/Finite+Field+Arithmetic/">This website for an overview</a>
namespace FFA {
	/// Addition is just XOR
	uint8_t Add(uint8_t n1, uint8_t n2) {
		return n1 ^ n2;
	};

	/// Subtraction is just XOR - Same as addition
	uint8_t Sub(uint8_t n1, uint8_t n2) {
		return n1 ^ n2;
	}

	uint16_t Mult(uint8_t n1, uint8_t n2) {
		uint8_t res = 0;
		for(int8_t i = 7; i >= 0; i--) { // Go from MSB (index 7) to LSB (index 0)
			// If the MSB of res is 1, that means it's going to overflow
			if((res >> 7) & 0x1) {
				res <<= 1;
				res ^= 0b00011011; // XOR with Galois Field bounding irreducible polynomial for GF(2^8). This is actually 100011011 but the MSB of that is out of range so is unused in the calculation
			} else {
				res <<= 1;
			}
			// If bit at index i is 1
			if((n2 >> i) & 0x1) {
				res ^= n1;
			}
		}
		return res;
	}
}

inline void MixColumn(uint8_t& b0, uint8_t& b1, uint8_t& b2, uint8_t& b3) {
	static uint8_t block[] = { 2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2 };
	static Block<128> matrix = Block<128>((uint128_t*)block);

	using namespace FFA;
	b0 = Mult(b0, matrix(0, 0)) ^ Mult(b1, matrix(1, 0)) ^ Mult(b2, matrix(2, 0)) ^ Mult(b3, matrix(3, 0));
	b1 = Mult(b0, matrix(0, 1)) ^ Mult(b1, matrix(1, 1)) ^ Mult(b2, matrix(2, 1)) ^ Mult(b3, matrix(3, 1));
	b2 = Mult(b0, matrix(0, 2)) ^ Mult(b1, matrix(1, 2)) ^ Mult(b2, matrix(2, 2)) ^ Mult(b3, matrix(3, 2));
	b3 = Mult(b0, matrix(0, 3)) ^ Mult(b1, matrix(1, 3)) ^ Mult(b2, matrix(2, 3)) ^ Mult(b3, matrix(3, 3));
}

void AESEncryption::MixColumns128(Block<128>& data, const RoundKey& roundKey) {
	for(uint8_t col = 0; col < data.c_BlockDims; col++) {
		MixColumn(data(col, 0), data(col, 1), data(col, 2), data(col, 3));
	}
}

void AESEncryption::AddRoundKey128(Block<128>& data, const RoundKey& roundKey) {
	*(uint128_t*)data.m_BlockStart ^= *(uint128_t*)&roundKey;
}
