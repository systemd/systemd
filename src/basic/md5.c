/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "md5.h"
#include "memory-util.h"
#include "unaligned.h"

/* Per-round shift amounts (RFC 1321, section 3.4). */
static const uint8_t S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

/* T[i] = floor(2^32 * abs(sin(i + 1))) (RFC 1321, section 3.4). */
static const uint32_t T[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static uint32_t rotl32(uint32_t x, unsigned n) {
        return (x << n) | (x >> (32 - n));
}

static void md5_process_block(struct md5_ctx *ctx, const uint8_t block[static MD5_BLOCK_SIZE]) {
        uint32_t X[16];
        CLEANUP_ERASE(X); /* may carry secret input, e.g. HMAC key material */

        for (size_t i = 0; i < ELEMENTSOF(X); i++)
                X[i] = unaligned_read_le32(block + i * 4);

        uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];

        for (unsigned i = 0; i < 64; i++) {
                uint32_t f;
                unsigned k;

                switch (i / 16) {
                case 0:
                        f = (b & c) | (~b & d);
                        k = i;
                        break;
                case 1:
                        f = (b & d) | (c & ~d);
                        k = (5 * i + 1) % 16;
                        break;
                case 2:
                        f = b ^ c ^ d;
                        k = (3 * i + 5) % 16;
                        break;
                default:
                        f = c ^ (b | ~d);
                        k = (7 * i) % 16;
                }

                uint32_t tmp = d;
                d = c;
                c = b;
                b += rotl32(a + f + T[i] + X[k], S[i]);
                a = tmp;
        }

        ctx->state[0] += a;
        ctx->state[1] += b;
        ctx->state[2] += c;
        ctx->state[3] += d;
}

void md5_init_ctx(struct md5_ctx *ctx) {
        assert(ctx);

        *ctx = (struct md5_ctx) {
                .state = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 },
        };
}

void md5_process_bytes(const void *buffer, size_t len, struct md5_ctx *ctx) {
        const uint8_t *p = buffer;

        assert(buffer || len == 0);
        assert(ctx);

        size_t used = ctx->size % MD5_BLOCK_SIZE;
        ctx->size += len;

        if (used > 0) {
                size_t n = MIN(len, MD5_BLOCK_SIZE - used);

                memcpy(ctx->buffer + used, p, n);
                p += n;
                len -= n;

                if (used + n < MD5_BLOCK_SIZE)
                        return;

                md5_process_block(ctx, ctx->buffer);
        }

        for (; len >= MD5_BLOCK_SIZE; p += MD5_BLOCK_SIZE, len -= MD5_BLOCK_SIZE)
                md5_process_block(ctx, p);

        memcpy_safe(ctx->buffer, p, len);
}

uint8_t* md5_finish_ctx(struct md5_ctx *ctx, uint8_t result[static MD5_DIGEST_SIZE]) {
        static const uint8_t padding[MD5_BLOCK_SIZE] = { 0x80 };
        uint8_t length[8];

        assert(ctx);
        assert(result);

        /* Append a single 1 bit and zeros up to 56 mod 64 bytes, then the message length in bits as a 64-bit
         * little-endian value (RFC 1321, sections 3.1 and 3.2). */
        unaligned_write_le64(length, ctx->size * 8);

        size_t used = ctx->size % MD5_BLOCK_SIZE;
        md5_process_bytes(padding, used < 56 ? 56 - used : MD5_BLOCK_SIZE + 56 - used, ctx);
        md5_process_bytes(length, sizeof(length), ctx);
        assert(ctx->size % MD5_BLOCK_SIZE == 0);

        for (size_t i = 0; i < ELEMENTSOF(ctx->state); i++)
                unaligned_write_le32(result + i * 4, ctx->state[i]);

        explicit_bzero_safe(ctx, sizeof(*ctx));
        return result;
}

uint8_t* md5_direct(const void *buffer, size_t sz, uint8_t result[static MD5_DIGEST_SIZE]) {
        struct md5_ctx ctx;

        md5_init_ctx(&ctx);
        md5_process_bytes(buffer, sz, &ctx);
        return md5_finish_ctx(&ctx, result);
}
