#include "sha256.h"
#include <string.h>

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t r(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void transform(sha256_ctx *s) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    const unsigned char *p = s->block + 4 * i;
    w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
  }
  for (int i = 16; i < 64; ++i)
    w[i] = w[i-16] + (r(w[i-15],7) ^ r(w[i-15],18) ^ (w[i-15] >> 3)) +
           w[i-7] + (r(w[i-2],17) ^ r(w[i-2],19) ^ (w[i-2] >> 10));
  uint32_t a=s->h[0], b=s->h[1], c=s->h[2], d=s->h[3];
  uint32_t e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
  for (int i=0; i<64; ++i) {
    uint32_t t1=h+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+k[i]+w[i];
    uint32_t t2=(r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  uint32_t v[8]={a,b,c,d,e,f,g,h};
  for (int i=0; i<8; ++i) s->h[i]+=v[i];
}
void sha256_init(sha256_ctx *s) {
  static const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  memset(s,0,sizeof(*s)); memcpy(s->h,initial,sizeof(initial));
}
void sha256_update(sha256_ctx *s, const void *data, size_t len) {
  const unsigned char *p=data;
  s->bits += (uint64_t)len * 8;
  while (len) {
    size_t n=64-s->used; if(n>len)n=len;
    memcpy(s->block+s->used,p,n); s->used+=n; p+=n; len-=n;
    if(s->used==64){ transform(s); s->used=0; }
  }
}
void sha256_final(sha256_ctx *s, unsigned char out[32]) {
  uint64_t bits=s->bits;
  s->block[s->used++]=0x80;
  if(s->used>56){ memset(s->block+s->used,0,64-s->used); transform(s); s->used=0; }
  memset(s->block+s->used,0,56-s->used);
  for(int i=0;i<8;++i)s->block[56+i]=(unsigned char)(bits>>(56-8*i));
  transform(s);
  for(int i=0;i<8;++i)for(int j=0;j<4;++j)out[4*i+j]=(unsigned char)(s->h[i]>>(24-8*j));
}
