/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <efi.h>
#include <efilib.h>

struct sha256_ctx {
        UINT32 H[8];

        union {
                UINT64 total64;
#define TOTAL64_low (1 - (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define TOTAL64_high (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                UINT32 total[2];
        };

        UINT32 buflen;

        union {
                UINT8 buffer[128]; /* NB: always correctly aligned for UINT32.  */
                UINT32 buffer32[32];
                UINT64 buffer64[16];
        };
};

void sha256_init_ctx(struct sha256_ctx *ctx);
void *sha256_finish_ctx(struct sha256_ctx *ctx, VOID *resbuf);
void sha256_process_bytes(const void *buffer, UINTN len, struct sha256_ctx *ctx);
