/* Stolen from glibc and converted to UEFI style. In glibc it comes with the following copyright blurb: */

/* Functions to compute SHA256 message digest of files or memory blocks.
   according to the definition of SHA256 in FIPS 180-2.
   Copyright (C) 2007-2019 Free Software Foundation, Inc.
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
   <http://www.gnu.org/licenses/>.  */

/* Written by Ulrich Drepper <drepper@redhat.com>, 2007.  */

#include "sha256.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define SWAP(n)                                                        \
        (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
# define SWAP64(n)                              \
        (((n) << 56)                            \
         | (((n) & 0xff00) << 40)               \
         | (((n) & 0xff0000) << 24)             \
         | (((n) & 0xff000000) << 8)            \
         | (((n) >> 8) & 0xff000000)            \
         | (((n) >> 24) & 0xff0000)             \
         | (((n) >> 40) & 0xff00)               \
         | ((n) >> 56))
#else
# define SWAP(n) (n)
# define SWAP64(n) (n)
#endif

/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  (FIPS 180-2:5.1.1)  */
static const UINT8 fillbuf[64] = {
        0x80, 0 /* , 0, 0, ...  */
};

/* Constants for SHA256 from FIPS 180-2:4.2.2.  */
static const UINT32 K[64] = {
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

static void sha256_process_block(const void *, UINTN, struct sha256_ctx *);

/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
void sha256_init_ctx(struct sha256_ctx *ctx) {
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
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
void *sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf) {
        /* Take yet unprocessed bytes into account.  */
        UINT32 bytes = ctx->buflen;
        UINTN pad, i;

        /* Now count remaining bytes.  */
        ctx->total64 += bytes;

        pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
        CopyMem (&ctx->buffer[bytes], fillbuf, pad);

        /* Put the 64-bit file length in *bits* at the end of the buffer.  */
        ctx->buffer32[(bytes + pad + 4) / 4] = SWAP (ctx->total[TOTAL64_low] << 3);
        ctx->buffer32[(bytes + pad) / 4] = SWAP ((ctx->total[TOTAL64_high] << 3)
                                                 | (ctx->total[TOTAL64_low] >> 29));

        /* Process last bytes.  */
        sha256_process_block (ctx->buffer, bytes + pad + 8, ctx);

        /* Put result from CTX in first 32 bytes following RESBUF.  */
        for (i = 0; i < 8; ++i)
                ((UINT32 *) resbuf)[i] = SWAP (ctx->H[i]);

        return resbuf;
}

void sha256_process_bytes(const void *buffer, UINTN len, struct sha256_ctx *ctx) {
        /* When we already have some bits in our internal buffer concatenate
           both inputs first.  */

        if (ctx->buflen != 0) {
                UINTN left_over = ctx->buflen;
                UINTN add = 128 - left_over > len ? len : 128 - left_over;

                CopyMem (&ctx->buffer[left_over], buffer, add);
                ctx->buflen += add;

                if (ctx->buflen > 64) {
                        sha256_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

                        ctx->buflen &= 63;
                        /* The regions in the following copy operation cannot overlap.  */
                        CopyMem (ctx->buffer, &ctx->buffer[(left_over + add) & ~63],
                                ctx->buflen);
                }

                buffer = (const char *) buffer + add;
                len -= add;
        }

        /* Process available complete blocks.  */
        if (len >= 64) {
#if !_STRING_ARCH_unaligned
/* To check alignment gcc has an appropriate operator.  Other
   compilers don't.  */
# if __GNUC__ >= 2
#  define UNALIGNED_P(p) (((UINTN) p) % __alignof__ (UINT32) != 0)
# else
#  define UNALIGNED_P(p) (((UINTN) p) % sizeof (UINT32) != 0)
# endif
                if (UNALIGNED_P (buffer))
                        while (len > 64) {
                                CopyMem (ctx->buffer, buffer, 64);
                                sha256_process_block (ctx->buffer, 64, ctx);
                                buffer = (const char *) buffer + 64;
                                len -= 64;
                        }
                else
#endif
                {
                        sha256_process_block (buffer, len & ~63, ctx);
                        buffer = (const char *) buffer + (len & ~63);
                        len &= 63;
                }
        }

        /* Move remaining bytes into internal buffer.  */
        if (len > 0) {
                UINTN left_over = ctx->buflen;

                CopyMem (&ctx->buffer[left_over], buffer, len);
                left_over += len;
                if (left_over >= 64) {
                        sha256_process_block (ctx->buffer, 64, ctx);
                        left_over -= 64;
                        CopyMem (ctx->buffer, &ctx->buffer[64], left_over);
                }
                ctx->buflen = left_over;
        }
}


/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.  */
static void sha256_process_block(const void *buffer, UINTN len, struct sha256_ctx *ctx) {
        const UINT32 *words = buffer;
        UINTN nwords = len / sizeof (UINT32);
        UINT32 a = ctx->H[0];
        UINT32 b = ctx->H[1];
        UINT32 c = ctx->H[2];
        UINT32 d = ctx->H[3];
        UINT32 e = ctx->H[4];
        UINT32 f = ctx->H[5];
        UINT32 g = ctx->H[6];
        UINT32 h = ctx->H[7];

        /* First increment the byte count.  FIPS 180-2 specifies the possible
           length of the file up to 2^64 bits.  Here we only compute the
           number of bytes.  */
        ctx->total64 += len;

        /* Process all bytes in the buffer with 64 bytes in each round of
           the loop.  */
        while (nwords > 0) {
                UINT32 W[64];
                UINT32 a_save = a;
                UINT32 b_save = b;
                UINT32 c_save = c;
                UINT32 d_save = d;
                UINT32 e_save = e;
                UINT32 f_save = f;
                UINT32 g_save = g;
                UINT32 h_save = h;
                UINTN t;

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
                for (t = 0; t < 16; ++t) {
                        W[t] = SWAP (*words);
                        ++words;
                }
                for (t = 16; t < 64; ++t)
                        W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

                /* The actual computation according to FIPS 180-2:6.2.2 step 3.  */
                for (t = 0; t < 64; ++t) {
                        UINT32 T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
                        UINT32 T2 = S0 (a) + Maj (a, b, c);
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
