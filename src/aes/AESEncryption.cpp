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
#error Hardware accelerated AES is only implemented for GCC on x86 and x86_64 - Compiling using non-accelerated AES
#endif

	if(!aesni) {
		// TODO Implement AES. I'll do that at some point
		assert(false);
	}
}
