#pragma once

#include <inttypes.h>
#include <sys/types.h>

struct siphash {
  uint64_t v0;
  uint64_t v1;
  uint64_t v2;
  uint64_t v3;
  uint64_t padding;
  size_t inlen;
};

void siphash24_init(struct siphash *state, const uint8_t k[16]);
void siphash24_compress(const void *in, size_t inlen, struct siphash *state);
void siphash24_finalize(uint8_t out[8], struct siphash *state);

void siphash24(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
