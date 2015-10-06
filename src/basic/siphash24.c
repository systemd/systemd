/*
   SipHash reference C implementation

   Written in 2012 by
   Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
   Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

   (Minimal changes made by Lennart Poettering, to make clean for inclusion in systemd)
   (Refactored by Tom Gundersen to split up in several functions and follow systemd
    coding style)
*/

#include "sparse-endian.h"

#include "siphash24.h"
#include "util.h"

static inline uint64_t rotate_left(uint64_t x, uint8_t b) {
        assert(b < 64);

        return (x << b) | (x >> (64 - b));
}

static inline void sipround(struct siphash *state) {
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

void siphash24_init(struct siphash *state, const uint8_t k[16]) {
        uint64_t k0, k1;

        assert(state);
        assert(k);

        k0 = le64toh(*(le64_t*) k);
        k1 = le64toh(*(le64_t*) (k + 8));

        /* "somepseudorandomlygeneratedbytes" */
        state->v0 = 0x736f6d6570736575ULL ^ k0;
        state->v1 = 0x646f72616e646f6dULL ^ k1;
        state->v2 = 0x6c7967656e657261ULL ^ k0;
        state->v3 = 0x7465646279746573ULL ^ k1;
        state->padding = 0;
        state->inlen = 0;
}

void siphash24_compress(const void *_in, size_t inlen, struct siphash *state) {
        uint64_t m;
        const uint8_t *in = _in;
        const uint8_t *end = in + inlen;
        unsigned left = state->inlen & 7;

        assert(in);
        assert(state);

        /* update total length */
        state->inlen += inlen;

        /* if padding exists, fill it out */
        if (left > 0) {
                for ( ; in < end && left < 8; in ++, left ++ )
                        state->padding |= ( ( uint64_t )*in ) << (left * 8);

                if (in == end && left < 8)
                        /* we did not have enough input to fill out the padding completely */
                        return;

#ifdef DEBUG
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

        end -= ( state->inlen % sizeof (uint64_t) );

        for ( ; in < end; in += 8 ) {
                m = le64toh(*(le64_t*) in);
#ifdef DEBUG
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

        switch(left)
        {
                case 7: state->padding |= ((uint64_t) in[6]) << 48;

                case 6: state->padding |= ((uint64_t) in[5]) << 40;

                case 5: state->padding |= ((uint64_t) in[4]) << 32;

                case 4: state->padding |= ((uint64_t) in[3]) << 24;

                case 3: state->padding |= ((uint64_t) in[2]) << 16;

                case 2: state->padding |= ((uint64_t) in[1]) <<  8;

                case 1: state->padding |= ((uint64_t) in[0]); break;

                case 0: break;
        }
}

void siphash24_finalize(uint8_t out[8], struct siphash *state) {
        uint64_t b;

        b = state->padding | (( ( uint64_t )state->inlen ) << 56);
#ifdef DEBUG
        printf("(%3zu) v0 %08x %08x\n", state->inlen, (uint32_t) (state->v0 >> 32), (uint32_t)state->v0);
        printf("(%3zu) v1 %08x %08x\n", state->inlen, (uint32_t) (state->v1 >> 32), (uint32_t)state->v1);
        printf("(%3zu) v2 %08x %08x\n", state->inlen, (uint32_t) (state->v2 >> 32), (uint32_t)state->v2);
        printf("(%3zu) v3 %08x %08x\n", state->inlen, (uint32_t) (state->v3 >> 32), (uint32_t)state->v3);
        printf("(%3zu) padding   %08x %08x\n", state->inlen, (uint32_t) (state->padding >> 32), (uint32_t) state->padding);
#endif
        state->v3 ^= b;
        sipround(state);
        sipround(state);
        state->v0 ^= b;

#ifdef DEBUG
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

        *(le64_t*)out = htole64(state->v0 ^ state->v1 ^ state->v2  ^ state->v3);
}

/* SipHash-2-4 */
void siphash24(uint8_t out[8], const void *_in, size_t inlen, const uint8_t k[16]) {
        struct siphash state;

        siphash24_init(&state, k);
        siphash24_compress(_in, inlen, &state);
        siphash24_finalize(out, &state);
}
