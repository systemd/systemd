/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

struct sha256_ctx {
        uint32_t H[8];

        union {
                uint64_t total64;
#define TOTAL64_low (1 - (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define TOTAL64_high (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                uint32_t total[2];
        };

        uint32_t buflen;

        union {
                uint8_t  buffer[128]; /* NB: always correctly aligned for UINT32.  */
                uint32_t buffer32[32];
                uint64_t buffer64[16];
        };
};

void sha256_init_ctx(struct sha256_ctx *ctx);
uint8_t *sha256_finish_ctx(struct sha256_ctx *ctx, uint8_t resbuf[static SHA256_DIGEST_SIZE]);
void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx);

uint8_t* sha256_direct(const void *buffer, size_t sz, uint8_t result[static SHA256_DIGEST_SIZE]);

#define SHA256_DIRECT(buffer, sz) sha256_direct(buffer, sz, (uint8_t[SHA256_DIGEST_SIZE]) {})
