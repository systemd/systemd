/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "siphash24.h"
#include "bus-bloom.h"

static inline void set_bit(uint64_t filter[], unsigned b) {
        filter[b >> 6] |= 1ULL << (b & 63);
}

#define HASH_KEY1 SD_ID128_MAKE(b9,66,0b,f0,46,70,47,c1,88,75,c4,9c,54,b9,bd,15)
#define HASH_KEY2 SD_ID128_MAKE(aa,a1,54,a2,e0,71,4b,39,bf,e1,dd,2e,9f,c5,4a,3b)

static void bloom_add_data(uint64_t filter[BLOOM_SIZE/8], const void *data, size_t n) {
        uint8_t a[8], b[8];
        unsigned k = 0;

        /*
         * Our bloom filter has the following parameters:
         *
         * m=512   (bits in the filter)
         * k=8     (hash functions)
         *
         * We calculate a two 64bit SipHash values (for two fixed but
         * randomly generated hash keys) of which we use 8 parts of 9 bits
         * as individual hash functions.
         *
         */

        siphash24(a, data, n, HASH_KEY1.bytes);
        siphash24(b, data, n, HASH_KEY2.bytes);

        assert_cc(BLOOM_SIZE*8 == 512);

        for (k = 0; k < 8; k++)
                set_bit(filter, ((uint16_t) a[k] << 1) ^ (uint16_t) b[k]);

        /* log_debug("bloom: adding <%.*s>", (int) n, (char*) data); */
}

void bloom_add_pair(uint64_t filter[BLOOM_SIZE/8], const char *a, const char *b) {
        size_t n;
        char *c;

        assert(filter);
        assert(a);
        assert(b);

        n = strlen(a) + 1 + strlen(b);
        c = alloca(n + 1);
        strcpy(stpcpy(stpcpy(c, a), ":"), b);

        bloom_add_data(filter, c, n);
}

void bloom_add_prefixes(uint64_t filter[BLOOM_SIZE/8], const char *a, const char *b, char sep) {
        size_t n;
        char *c, *p;

        assert(filter);
        assert(a);
        assert(b);

        n = strlen(a) + 1 + strlen(b);
        c = alloca(n + 1);

        p = stpcpy(stpcpy(c, a), ":");
        strcpy(p, b);

        for (;;) {
                char *e;

                e = strrchr(p, sep);
                if (!e || e == p)
                        break;

                *e = 0;
                bloom_add_data(filter, c, e - c);
        }
}
