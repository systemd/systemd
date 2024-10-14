/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Stolen from glibc and converted to our style. In glibc it comes with the following copyright blurb: */

/* Functions to compute SHA256 message digest of files or memory blocks.
   according to the definition of SHA256 in FIPS 180-2.
   Copyright (C) 2007-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include "macro-fundamental.h"
#include "memory-util-fundamental.h"
#include "sha256-fundamental.h"
#include "unaligned-fundamental.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define SWAP(n)                                                        \
        __builtin_bswap32(n)
# define SWAP64(n)                              \
        __builtin_bswap64(n)
#else
# define SWAP(n) (n)
# define SWAP64(n) (n)
#endif

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.1)  */
static const uint8_t fillbuf[64] = {
        0x80, 0 /* , 0, 0, ...  */
};

/* Constants for SHA256 from FIPS 180-2:4.2.2.  */
static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_process_block(const void *, size_t, struct sha256_ctx *);

/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
void sha256_init_ctx(struct sha256_ctx *ctx) {
        assert(ctx);

        ctx->H[0] = 0x6a09e667;
        ctx->H[1] = 0xbb67ae85;
        ctx->H[2] = 0x3c6ef372;
        ctx->H[3] = 0xa54ff53a;
        ctx->H[4] = 0x510e527f;
        ctx->H[5] = 0x9b05688c;
        ctx->H[6] = 0x1f83d9ab;
        ctx->H[7] = 0x5be0cd19;

        ctx->total64 = 0;
        ctx->buflen = 0;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF. */
uint8_t *sha256_finish_ctx(struct sha256_ctx *ctx, uint8_t resbuf[static SHA256_DIGEST_SIZE]) {
        /* Take yet unprocessed bytes into account.  */
        uint32_t bytes = ctx->buflen;
        size_t pad;

        assert(ctx);
        assert(resbuf);

        /* Now count remaining bytes.  */
        ctx->total64 += bytes;

        pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
        memcpy(&ctx->buffer[bytes], fillbuf, pad);

        /* Put the 64-bit file length in *bits* at the end of the buffer.  */
        ctx->buffer32[(bytes + pad + 4) / 4] = SWAP(ctx->total[TOTAL64_low] << 3);
        ctx->buffer32[(bytes + pad) / 4] = SWAP((ctx->total[TOTAL64_high] << 3)
                                                | (ctx->total[TOTAL64_low] >> 29));

        /* Process last bytes.  */
        sha256_process_block(ctx->buffer, bytes + pad + 8, ctx);

        /* Put result from CTX in first 32 bytes following RESBUF.  */
        for (size_t i = 0; i < 8; ++i)
                unaligned_write_ne32(resbuf + i * sizeof(uint32_t), SWAP(ctx->H[i]));
        return resbuf;
}

void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx) {
        assert(buffer);
        assert(ctx);

        /* When we already have some bits in our internal buffer concatenate
           both inputs first.  */

        if (ctx->buflen != 0) {
                size_t left_over = ctx->buflen;
                size_t add = 128 - left_over > len ? len : 128 - left_over;

                memcpy(&ctx->buffer[left_over], buffer, add);
                ctx->buflen += add;

                if (ctx->buflen > 64) {
                        sha256_process_block(ctx->buffer, ctx->buflen & ~63, ctx);

                        ctx->buflen &= 63;
                        /* The regions in the following copy operation cannot overlap.  */
                        memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
                                ctx->buflen);
                }

                buffer = (const char *) buffer + add;
                len -= add;
        }

        /* Process available complete blocks.  */
        if (len >= 64) {
                if (IS_ALIGNED32(buffer)) {
                        sha256_process_block(buffer, len & ~63, ctx);
                        buffer = (const char *) buffer + (len & ~63);
                        len &= 63;
                } else
                        while (len > 64) {
                                memcpy(ctx->buffer, buffer, 64);
                                sha256_process_block(ctx->buffer, 64, ctx);
                                buffer = (const char *) buffer + 64;
                                len -= 64;
                        }
        }

        /* Move remaining bytes into internal buffer.  */
        if (len > 0) {
                size_t left_over = ctx->buflen;

                memcpy(&ctx->buffer[left_over], buffer, len);
                left_over += len;
                if (left_over >= 64) {
                        sha256_process_block(ctx->buffer, 64, ctx);
                        left_over -= 64;
                        memcpy(ctx->buffer, &ctx->buffer[64], left_over);
                }
                ctx->buflen = left_over;
        }
}

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void sha256_process_block(const void *buffer, size_t len, struct sha256_ctx *ctx) {
        const uint32_t *words = ASSERT_PTR(buffer);
        size_t nwords = len / sizeof(uint32_t);

        assert(ctx);

        uint32_t a = ctx->H[0];
        uint32_t b = ctx->H[1];
        uint32_t c = ctx->H[2];
        uint32_t d = ctx->H[3];
        uint32_t e = ctx->H[4];
        uint32_t f = ctx->H[5];
        uint32_t g = ctx->H[6];
        uint32_t h = ctx->H[7];

        /* First increment the byte count.  FIPS 180-2 specifies the possible
           length of the file up to 2^64 bits.  Here we only compute the
           number of bytes.  */
        ctx->total64 += len;

        /* Process all bytes in the buffer with 64 bytes in each round of
           the loop.  */
        while (nwords > 0) {
                uint32_t W[64];
                uint32_t a_save = a;
                uint32_t b_save = b;
                uint32_t c_save = c;
                uint32_t d_save = d;
                uint32_t e_save = e;
                uint32_t f_save = f;
                uint32_t g_save = g;
                uint32_t h_save = h;

                /* Operators defined in FIPS 180-2:4.1.2.  */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 2) ^ CYCLIC (x, 13) ^ CYCLIC (x, 22))
#define S1(x) (CYCLIC (x, 6) ^ CYCLIC (x, 11) ^ CYCLIC (x, 25))
#define R0(x) (CYCLIC (x, 7) ^ CYCLIC (x, 18) ^ (x >> 3))
#define R1(x) (CYCLIC (x, 17) ^ CYCLIC (x, 19) ^ (x >> 10))

                /* It is unfortunate that C does not provide an operator for
                   cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))

                /* Compute the message schedule according to FIPS 180-2:6.2.2 step 2.  */
                for (size_t t = 0; t < 16; ++t) {
                        W[t] = SWAP (*words);
                        ++words;
                }
                for (size_t t = 16; t < 64; ++t)
                        W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

                /* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
                for (size_t t = 0; t < 64; ++t) {
                        uint32_t T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
                        uint32_t T2 = S0 (a) + Maj (a, b, c);
                        h = g;
                        g = f;
                        f = e;
                        e = d + T1;
                        d = c;
                        c = b;
                        b = a;
                        a = T1 + T2;
                }

                /* Add the starting values of the context according to FIPS 180-2:6.2.2
                   step 4.  */
                a += a_save;
                b += b_save;
                c += c_save;
                d += d_save;
                e += e_save;
                f += f_save;
                g += g_save;
                h += h_save;

                /* Prepare for the next round.  */
                nwords -= 16;
        }

        /* Put checksum in context given as argument.  */
        ctx->H[0] = a;
        ctx->H[1] = b;
        ctx->H[2] = c;
        ctx->H[3] = d;
        ctx->H[4] = e;
        ctx->H[5] = f;
        ctx->H[6] = g;
        ctx->H[7] = h;
}

uint8_t* sha256_direct(const void *buffer, size_t sz, uint8_t result[static SHA256_DIGEST_SIZE]) {
        struct sha256_ctx ctx;
        sha256_init_ctx(&ctx);
        sha256_process_bytes(buffer, sz, &ctx);
        return sha256_finish_ctx(&ctx, result);
}
