#pragma once

#include <inttypes.h>
#include <sys/types.h>

void siphash24(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
