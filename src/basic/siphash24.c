/* SPDX-License-Identifier: CC0-1.0 */

/*
   SipHash reference C implementation

   Written in 2012 by
   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.

   (Minimal changes made by Lennart Poettering, to make clean for inclusion in systemd)
   (Refactored by Tom Gundersen to split up in several functions and follow systemd
    coding style)
*/

#include <stdio.h>

#include "siphash24.h"
#include "string-util.h"
#include "unaligned.h"

static uint64_t rotate_left(uint64_t x, uint8_t b) {
        assert(b < 64);

        return (x << b) | (x >> (64 - b));
}

static void sipround(struct siphash *state) {
        assert(state);

        state->v0 += state->v1;
        state->v1 = rotate_left(state->v1, 13);
        state->v1 ^= state->v0;
        state->v0 = rotate_left(state->v0, 32);
        state->v2 += state->v3;
        state->v3 = rotate_left(state->v3, 16);
        state->v3 ^= state->v2;
        state->v0 += state->v3;
        state->v3 = rotate_left(state->v3, 21);
        state->v3 ^= state->v0;
        state->v2 += state->v1;
        state->v1 = rotate_left(state->v1, 17);
        state->v1 ^= state->v2;
        state->v2 = rotate_left(state->v2, 32);
}

void siphash24_init(struct siphash *state, const uint8_t k[static 16]) {
        uint64_t k0, k1;

        assert(state);
        assert(k);

        k0 = unaligned_read_le64(k);
        k1 = unaligned_read_le64(k + 8);

        *state = (struct siphash) {
                /* "somepseudorandomlygeneratedbytes" */
                .v0 = 0x736f6d6570736575ULL ^ k0,
                .v1 = 0x646f72616e646f6dULL ^ k1,
                .v2 = 0x6c7967656e657261ULL ^ k0,
                .v3 = 0x7465646279746573ULL ^ k1,
                .padding = 0,
                .inlen = 0,
        };
}

void siphash24_compress(const void *_in, size_t inlen, struct siphash *state) {

        const uint8_t *in = ASSERT_PTR(_in);
        const uint8_t *end = in + inlen;
        size_t left = state->inlen & 7;
        uint64_t m;

        assert(state);

        /* Update total length */
        state->inlen += inlen;

        /* If padding exists, fill it out */
        if (left > 0) {
                for ( ; in < end && left < 8; in ++, left ++)
                        state->padding |= ((uint64_t) *in) << (left * 8);

                if (in == end && left < 8)
                        /* We did not have enough input to fill out the padding completely */
                        return;

#if ENABLE_DEBUG_SIPHASH
                printf("(%3zu) v0 %08x %08x\n", state->inlen, (uint32_t) (state->v0 >> 32), (uint32_t) state->v0);
                printf("(%3zu) v1 %08x %08x\n", state->inlen, (uint32_t) (state->v1 >> 32), (uint32_t) state->v1);
                printf("(%3zu) v2 %08x %08x\n", state->inlen, (uint32_t) (state->v2 >> 32), (uint32_t) state->v2);
                printf("(%3zu) v3 %08x %08x\n", state->inlen, (uint32_t) (state->v3 >> 32), (uint32_t) state->v3);
                printf("(%3zu) compress padding %08x %08x\n", state->inlen, (uint32_t) (state->padding >> 32), (uint32_t)state->padding);
#endif

                state->v3 ^= state->padding;
                sipround(state);
                sipround(state);
                state->v0 ^= state->padding;

                state->padding = 0;
        }

        end -= (state->inlen % sizeof(uint64_t));

        for ( ; in < end; in += 8) {
                m = unaligned_read_le64(in);
#if ENABLE_DEBUG_SIPHASH
                printf("(%3zu) v0 %08x %08x\n", state->inlen, (uint32_t) (state->v0 >> 32), (uint32_t) state->v0);
                printf("(%3zu) v1 %08x %08x\n", state->inlen, (uint32_t) (state->v1 >> 32), (uint32_t) state->v1);
                printf("(%3zu) v2 %08x %08x\n", state->inlen, (uint32_t) (state->v2 >> 32), (uint32_t) state->v2);
                printf("(%3zu) v3 %08x %08x\n", state->inlen, (uint32_t) (state->v3 >> 32), (uint32_t) state->v3);
                printf("(%3zu) compress %08x %08x\n", state->inlen, (uint32_t) (m >> 32), (uint32_t) m);
#endif
                state->v3 ^= m;
                sipround(state);
                sipround(state);
                state->v0 ^= m;
        }

        left = state->inlen & 7;
        switch (left) {
                case 7:
                        state->padding |= ((uint64_t) in[6]) << 48;
                        _fallthrough_;
                case 6:
                        state->padding |= ((uint64_t) in[5]) << 40;
                        _fallthrough_;
                case 5:
                        state->padding |= ((uint64_t) in[4]) << 32;
                        _fallthrough_;
                case 4:
                        state->padding |= ((uint64_t) in[3]) << 24;
                        _fallthrough_;
                case 3:
                        state->padding |= ((uint64_t) in[2]) << 16;
                        _fallthrough_;
                case 2:
                        state->padding |= ((uint64_t) in[1]) <<  8;
                        _fallthrough_;
                case 1:
                        state->padding |= ((uint64_t) in[0]);
                        _fallthrough_;
                case 0:
                        break;
        }
}

void siphash24_compress_string(const char *in, struct siphash *state) {
        siphash24_compress_safe(in, strlen_ptr(in), state);
}

uint64_t siphash24_finalize(struct siphash *state) {
        uint64_t b;

        assert(state);

        b = state->padding | (((uint64_t) state->inlen) << 56);

#if ENABLE_DEBUG_SIPHASH
        printf("(%3zu) v0 %08x %08x\n", state->inlen, (uint32_t) (state->v0 >> 32), (uint32_t) state->v0);
        printf("(%3zu) v1 %08x %08x\n", state->inlen, (uint32_t) (state->v1 >> 32), (uint32_t) state->v1);
        printf("(%3zu) v2 %08x %08x\n", state->inlen, (uint32_t) (state->v2 >> 32), (uint32_t) state->v2);
        printf("(%3zu) v3 %08x %08x\n", state->inlen, (uint32_t) (state->v3 >> 32), (uint32_t) state->v3);
        printf("(%3zu) padding   %08x %08x\n", state->inlen, (uint32_t) (state->padding >> 32), (uint32_t) state->padding);
#endif

        state->v3 ^= b;
        sipround(state);
        sipround(state);
        state->v0 ^= b;

#if ENABLE_DEBUG_SIPHASH
        printf("(%3zu) v0 %08x %08x\n", state->inlen, (uint32_t) (state->v0 >> 32), (uint32_t) state->v0);
        printf("(%3zu) v1 %08x %08x\n", state->inlen, (uint32_t) (state->v1 >> 32), (uint32_t) state->v1);
        printf("(%3zu) v2 %08x %08x\n", state->inlen, (uint32_t) (state->v2 >> 32), (uint32_t) state->v2);
        printf("(%3zu) v3 %08x %08x\n", state->inlen, (uint32_t) (state->v3 >> 32), (uint32_t) state->v3);
#endif
        state->v2 ^= 0xff;

        sipround(state);
        sipround(state);
        sipround(state);
        sipround(state);

        return state->v0 ^ state->v1 ^ state->v2  ^ state->v3;
}

uint64_t siphash24(const void *in, size_t inlen, const uint8_t k[static 16]) {
        struct siphash state;

        assert(in);
        assert(k);

        siphash24_init(&state, k);
        siphash24_compress(in, inlen, &state);

        return siphash24_finalize(&state);
}

uint64_t siphash24_string(const char *s, const uint8_t k[static 16]) {
        return siphash24(s, strlen(s) + 1, k);
}
