#ifndef LS_SHA256_H
#define LS_SHA256_H
#include <stddef.h>
#include <stdint.h>
typedef struct {
  uint32_t h[8];
  uint64_t bits;
  unsigned char block[64];
  size_t used;
} sha256_ctx;
void sha256_init(sha256_ctx *s);
void sha256_update(sha256_ctx *s, const void *data, size_t len);
void sha256_final(sha256_ctx *s, unsigned char out[32]);
#endif
