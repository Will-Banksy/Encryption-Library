#include "Rand.h"
#include <cstring>

#define ind(mm,x)  (*(uint32_t *)((uint8_t *)(mm) + ((x) & ((RANDSIZ-1)<<2))))
#define rngstep(mix,a,b,mm,m,m2,r,x) \
{ \
	x = *m;  \
	a = (a^(mix)) + *(m2++); \
	*(m++) = y = ind(mm,x) + a + b; \
	*(r++) = b = ind(mm,y>>RANDSIZL) + x; \
}

#define mix(a,b,c,d,e,f,g,h) \
{ \
	a^=b<<11; d+=a; b+=c; \
	b^=c>>2;  e+=b; c+=d; \
	c^=d<<8;  f+=c; d+=e; \
	d^=e>>16; g+=d; e+=f; \
	e^=f<<10; h+=e; f+=g; \
	f^=g>>4;  a+=f; g+=h; \
	g^=h<<8;  b+=g; h+=a; \
	h^=a>>9;  c+=h; a+=b; \
}

Rand::Rand() {
	ctx = RandContext();
	Init(false);
}

Rand::Rand(const std::vector<uint32_t>& seed) {
	ctx = RandContext();
	SeedRand(seed);
}

void Rand::SeedRand(const std::vector<uint32_t>& seed) {
	uint32_t amtData = seed.size() > 256u ? 256u : seed.size();
	memcpy(ctx.randrsl, &seed.front(), amtData);
	Init(true);
}

uint32_t Rand::NextInt() {
	if(ctx.randcnt-- == 0) {
		Isaac();
		ctx.randcnt = RANDSIZ - 1;
	}
	return ctx.randrsl[ctx.randcnt];
}

Rand::~Rand() {
}

void Rand::Init(bool flag) {
	int i;
	uint32_t a,b,c,d,e,f,g,h;
	uint32_t *m,*r;
	ctx.randa = ctx.randb = ctx.randc = 0;
	m=ctx.randmem;
	r=ctx.randrsl;
	a=b=c=d=e=f=g=h=0x9e3779b9;  /* the golden ratio */

	for (i=0; i<4; ++i)          /* scramble it */
	{
		mix(a,b,c,d,e,f,g,h);
	}

	if (flag)
	{
		/* initialize using the contents of r[] as the seed */
		for (i=0; i<RANDSIZ; i+=8)
		{
			a+=r[i  ]; b+=r[i+1]; c+=r[i+2]; d+=r[i+3];
			e+=r[i+4]; f+=r[i+5]; g+=r[i+6]; h+=r[i+7];
			mix(a,b,c,d,e,f,g,h);
			m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
			m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
		}
		/* do a second pass to make all of the seed affect all of m */
		for (i=0; i<RANDSIZ; i+=8)
		{
			a+=m[i  ]; b+=m[i+1]; c+=m[i+2]; d+=m[i+3];
			e+=m[i+4]; f+=m[i+5]; g+=m[i+6]; h+=m[i+7];
			mix(a,b,c,d,e,f,g,h);
			m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
			m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
		}
	}
	else
	{
		/* fill in m[] with messy stuff */
		for (i=0; i<RANDSIZ; i+=8)
		{
			mix(a,b,c,d,e,f,g,h);
			m[i  ]=a; m[i+1]=b; m[i+2]=c; m[i+3]=d;
			m[i+4]=e; m[i+5]=f; m[i+6]=g; m[i+7]=h;
		}
	}

	Isaac();            /* fill in the first set of results */
	ctx.randcnt=RANDSIZ;  /* prepare to use the first set of results */
}

void Rand::Isaac() {
	uint32_t a,b,x,y,*m,*mm,*m2,*r,*mend;
	mm=ctx.randmem; r=ctx.randrsl;
	a = ctx.randa; b = ctx.randb + (++ctx.randc);
	for (m = mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
	{
		rngstep( a<<13, a, b, mm, m, m2, r, x);
		rngstep( a>>6 , a, b, mm, m, m2, r, x);
		rngstep( a<<2 , a, b, mm, m, m2, r, x);
		rngstep( a>>16, a, b, mm, m, m2, r, x);
	}
	for (m2 = mm; m2<mend; )
	{
		rngstep( a<<13, a, b, mm, m, m2, r, x);
		rngstep( a>>6 , a, b, mm, m, m2, r, x);
		rngstep( a<<2 , a, b, mm, m, m2, r, x);
		rngstep( a>>16, a, b, mm, m, m2, r, x);
	}
	ctx.randb = b; ctx.randa = a;
}
