#ifndef RAND_H
#define RAND_H

#include <cstdint>
#include <vector>

// This has all been adapted from the C and C# implementations of ISAAC from https://www.burtleburtle.net/bob/rand

#define RANDSIZL   (8)
#define RANDSIZ    (1 << RANDSIZL)

struct RandContext
{
	uint32_t randcnt;			// Count through the results in randrsl[]
	uint32_t randrsl[RANDSIZ];	// Results - Randomness
	uint32_t randmem[RANDSIZ];	// Memory - The internal state
	uint32_t randa;				// Accumulator
	uint32_t randb;				// Last result
	uint32_t randc;				// Counter, guarantees cycle is at least 2^^40
};

/// Implementation of ISAAC (Indirection, Shift, Accumulate, Add, and Count) CSPRNG (Cryptographically Secure PseudoRandom Number Generator)
class Rand {
private:
	RandContext ctx;

	void Init(bool flag);
	void Isaac();

public:
	Rand();
	Rand(const std::vector<uint32_t>& seed);
	~Rand();

	void SeedRand(const std::vector<uint32_t>& seed);
	uint32_t NextInt();
};

#endif // RAND_H
