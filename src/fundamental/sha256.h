/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef SD_BOOT
#include <efi.h>
#include <efilib.h>
#endif

#include "type.h"

struct sha256_ctx {
        sd_uint32_t H[8];

        union {
                sd_uint64_t total64;
#define TOTAL64_low (1 - (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define TOTAL64_high (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                sd_uint32_t total[2];
        };

        sd_uint32_t buflen;

        union {
                sd_uint8_t  buffer[128]; /* NB: always correctly aligned for UINT32.  */
                sd_uint32_t buffer32[32];
                sd_uint64_t buffer64[16];
        };
};

void sha256_init_ctx(struct sha256_ctx *ctx);
void *sha256_finish_ctx(struct sha256_ctx *ctx, sd_void *resbuf);
void sha256_process_bytes(const void *buffer, sd_size_t len, struct sha256_ctx *ctx);
