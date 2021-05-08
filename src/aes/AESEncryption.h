#ifndef AESENCRYPTION_H
#define AESENCRYPTION_H

#include <cstdint>
#include <vector>
#include "uint128/uint128_t.h"

class Rand;

struct RoundKey {
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;

	RoundKey() : w0(0), w1(0), w2(0), w3(0) {}
	RoundKey(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3) : w0(w0), w1(w1), w2(w2), w3(w3) {}
	uint128_t ToUInt128() const {
		// Should they be the other way around? Idk and it's too past 2am for me to care rn
		return (((uint128_t)w0 << 96) & ((uint128_t)0xffffffff << 96)) \
		| (((uint128_t)w1 << 64) & ((uint128_t)0xffffffff << 64)) \
		| (((uint128_t)w2 << 32) & ((uint128_t)0xffffffff << 32)) \
		| (uint128_t)(w3 & 0xffffffff);
	}
};

template <uint8_t bits>
struct Block {
};

/// Blocks are assumed to be square
template <>
struct Block<128> {
	uint8_t* m_BlockStart;
	/// The width and height of the block if it were a 2D array
	static constexpr uint8_t c_BlockDims = 4;

	Block(uint128_t* b) : m_BlockStart((uint8_t*)b) {
	}

	uint8_t& At(uint8_t col, uint8_t row) const {
		return m_BlockStart[row + col * c_BlockDims];
	}

	uint128_t ToUInt128() {
		return *(uint128_t*)m_BlockStart;
	}
};

/// All my AES implementations use the Counter mode of operation: <a href="https://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Part+II+The+Design+of+Wi-Fi+Security/Chapter+12.+AES+CCMP/AES+Overview/">AES Overview</a>
class AESEncryption {
public:
	/// Encrypts/Decrypts data using AES - The key does not have to be 128 bits as it will be converted to 128-bit (using my own method, but it should be pretty good)
	static std::vector<uint8_t> AES128(std::vector<uint8_t> data, std::vector<uint8_t> key);

private:
	virtual ~AESEncryption() = 0;
	static Rand* rand;
	/// From: <a href="https://etutorials.org/Networking/802.11+security.+wi-fi+protected+access+and+802.11i/Appendixes/Appendix+A.+Overview+of+the+AES+Block+Cipher/Steps+in+the+AES+Encryption+Process/">AES Steps</a><br>
	/// Rcon[0] is unused
	static constexpr uint8_t c_Rcon128[11] = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108 };

	/// Creates a 128-bit key from the key supplied. This is not using any official method, just using a CSPRNG (Cryptographically Secure PseudoRandom Number Generator)
	static void ProcessKey128(std::vector<uint8_t>& key, Rand*& rand);
	/// Generates the round keys
	static std::vector<RoundKey> GenRoundKeys128(const std::vector<uint8_t>& key, Rand* rand);

	static void EncryptBlock128(Block<128>& block, const std::vector<RoundKey>& roundKeys);

	// The round operations
	static void SubBytes128(std::vector<uint8_t>& data, const RoundKey& roundKey);
	static void ShiftRows128(std::vector<uint8_t>& data, const RoundKey& roundKey);
	static void MixColumns128(std::vector<uint8_t>& data, const RoundKey& roundKey);
	static void XorRoundKey128(std::vector<uint8_t>& data, const RoundKey& roundKey);
};

#endif // AESENCRYPTION_H
