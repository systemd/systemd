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

#include "iovec-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "unaligned.h"

/* The round operates on the four state words as local variables of the caller, rather than through a
 * pointer to struct siphash. That matters: as a function taking a struct siphash* gcc declines to inline
 * this, and every one of the ten call sites then pays a call/ret plus a reload and store of the state. Most
 * of our hashes are short (hashmap keys, unit names, paths, journal field names), so that overhead
 * dominates: making the state local is worth up to 4.8x for inputs of 8 to 64 bytes. clang inlines the
 * round either way; this brings gcc builds in line with it. */

#define SIPHASH_ROTL(x, b) ((uint64_t) (((x) << (b)) | ((x) >> (64 - (b)))))

#define SIPROUND(v0, v1, v2, v3)                        \
        do {                                            \
                v0 += v1;                               \
                v1 = SIPHASH_ROTL(v1, 13);              \
                v1 ^= v0;                               \
                v0 = SIPHASH_ROTL(v0, 32);              \
                v2 += v3;                               \
                v3 = SIPHASH_ROTL(v3, 16);              \
                v3 ^= v2;                               \
                v0 += v3;                               \
                v3 = SIPHASH_ROTL(v3, 21);              \
                v3 ^= v0;                               \
                v2 += v1;                               \
                v1 = SIPHASH_ROTL(v1, 17);              \
                v1 ^= v2;                               \
                v2 = SIPHASH_ROTL(v2, 32);              \
        } while (false)

#if ENABLE_DEBUG_SIPHASH
#  define DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3)                                                            \
        do {                                                                                                    \
                printf("(%3zu) v0 %08x %08x\n", (state)->inlen, (uint32_t) ((v0) >> 32), (uint32_t) (v0));       \
                printf("(%3zu) v1 %08x %08x\n", (state)->inlen, (uint32_t) ((v1) >> 32), (uint32_t) (v1));       \
                printf("(%3zu) v2 %08x %08x\n", (state)->inlen, (uint32_t) ((v2) >> 32), (uint32_t) (v2));       \
                printf("(%3zu) v3 %08x %08x\n", (state)->inlen, (uint32_t) ((v3) >> 32), (uint32_t) (v3));       \
        } while (false)
#  define DEBUG_SIPHASH_WORD(state, label, m)                                                                   \
        printf("(%3zu) " label " %08x %08x\n", (state)->inlen, (uint32_t) ((m) >> 32), (uint32_t) (m))
#else
#  define DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3) do {} while (false)
#  define DEBUG_SIPHASH_WORD(state, label, m) do {} while (false)
#endif

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
        size_t left;
        uint64_t v0, v1, v2, v3, padding;

        assert(state);

        left = state->inlen & 7;
        padding = state->padding;

        /* Update total length */
        state->inlen += inlen;

        v0 = state->v0;
        v1 = state->v1;
        v2 = state->v2;
        v3 = state->v3;

        /* If padding exists, fill it out */
        if (left > 0) {
                for ( ; in < end && left < 8; in ++, left ++)
                        padding |= ((uint64_t) *in) << (left * 8);

                if (in == end && left < 8) {
                        /* We did not have enough input to fill out the padding completely */
                        state->padding = padding;
                        return;
                }

                DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3);
                DEBUG_SIPHASH_WORD(state, "compress padding", padding);

                v3 ^= padding;
                SIPROUND(v0, v1, v2, v3);
                SIPROUND(v0, v1, v2, v3);
                v0 ^= padding;

                padding = 0;
        }

        end -= (state->inlen % sizeof(uint64_t));

        for ( ; in < end; in += 8) {
                uint64_t m = unaligned_read_le64(in);

                DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3);
                DEBUG_SIPHASH_WORD(state, "compress", m);

                v3 ^= m;
                SIPROUND(v0, v1, v2, v3);
                SIPROUND(v0, v1, v2, v3);
                v0 ^= m;
        }

        state->v0 = v0;
        state->v1 = v1;
        state->v2 = v2;
        state->v3 = v3;

        left = state->inlen & 7;
        switch (left) {
                case 7:
                        padding |= ((uint64_t) in[6]) << 48;
                        _fallthrough_;
                case 6:
                        padding |= ((uint64_t) in[5]) << 40;
                        _fallthrough_;
                case 5:
                        padding |= ((uint64_t) in[4]) << 32;
                        _fallthrough_;
                case 4:
                        padding |= ((uint64_t) in[3]) << 24;
                        _fallthrough_;
                case 3:
                        padding |= ((uint64_t) in[2]) << 16;
                        _fallthrough_;
                case 2:
                        padding |= ((uint64_t) in[1]) <<  8;
                        _fallthrough_;
                case 1:
                        padding |= ((uint64_t) in[0]);
                        _fallthrough_;
                case 0:
                        break;
        }

        state->padding = padding;
}

void siphash24_compress_string(const char *in, struct siphash *state) {
        siphash24_compress_safe(in, strlen_ptr(in), state);
}

void siphash24_compress_iovec(const struct iovec *iov, struct siphash *state) {
        assert(iovec_is_valid(iov));
        assert(state);

        if (!iovec_is_set(iov))
                return;

        siphash24_compress(iov->iov_base, iov->iov_len, state);
}

uint64_t siphash24_finalize(struct siphash *state) {
        uint64_t v0, v1, v2, v3, b;

        assert(state);

        v0 = state->v0;
        v1 = state->v1;
        v2 = state->v2;
        v3 = state->v3;

        b = state->padding | (((uint64_t) state->inlen) << 56);

        DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3);
        DEBUG_SIPHASH_WORD(state, "padding  ", state->padding);

        v3 ^= b;
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        v0 ^= b;

        DEBUG_SIPHASH_STATE(state, v0, v1, v2, v3);

        v2 ^= 0xff;

        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);
        SIPROUND(v0, v1, v2, v3);

        state->v0 = v0;
        state->v1 = v1;
        state->v2 = v2;
        state->v3 = v3;

        return v0 ^ v1 ^ v2 ^ v3;
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
