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

static inline void set_bit(uint64_t filter[], unsigned long b) {
        filter[b >> 6] |= 1ULL << (b & 63);
}

static const sd_id128_t hash_keys[] = {
        SD_ID128_ARRAY(b9,66,0b,f0,46,70,47,c1,88,75,c4,9c,54,b9,bd,15),
        SD_ID128_ARRAY(aa,a1,54,a2,e0,71,4b,39,bf,e1,dd,2e,9f,c5,4a,3b),
        SD_ID128_ARRAY(63,fd,ae,be,cd,82,48,12,a1,6e,41,26,cb,fa,a0,c8),
        SD_ID128_ARRAY(23,be,45,29,32,d2,46,2d,82,03,52,28,fe,37,17,f5),
        SD_ID128_ARRAY(56,3b,bf,ee,5a,4f,43,39,af,aa,94,08,df,f0,fc,10),
        SD_ID128_ARRAY(31,80,c8,73,c7,ea,46,d3,aa,25,75,0f,9e,4c,09,29),
        SD_ID128_ARRAY(7d,f7,18,4b,7b,a4,44,d5,85,3c,06,e0,65,53,96,6d),
        SD_ID128_ARRAY(f2,77,e9,6f,93,b5,4e,71,9a,0c,34,88,39,25,bf,35),
};

static void bloom_add_data(
                uint64_t filter[],     /* The filter bits */
                size_t size,           /* Size of the filter in bytes */
                unsigned k,            /* Number of hash functions */
                const void *data,      /* Data to hash */
                size_t n) {            /* Size of data to hash in bytes */

        uint8_t h[8];
        uint64_t m;
        unsigned w, i, c = 0;
        unsigned hash_index;

        assert(size > 0);
        assert(k > 0);

        /* Determine bits in filter */
        m = size * 8;

        /* Determine how many bytes we need to generate a bit index 0..m for this filter */
        w = (u64log2(m) + 7) / 8;

        assert(w <= sizeof(uint64_t));

        /* Make sure we have enough hash keys to generate m * k bits
         * of hash value. Note that SipHash24 generates 64 bits of
         * hash value for each 128 bits of hash key. */
        assert(k * w <= ELEMENTSOF(hash_keys) * 8);

        for (i = 0, hash_index = 0; i < k; i++) {
                uint64_t p = 0;
                unsigned d;

                for (d = 0; d < w; d++) {
                        if (c <= 0) {
                                siphash24(h, data, n, hash_keys[hash_index++].bytes);
                                c += 8;
                        }

                        p = (p << 8ULL) | (uint64_t) h[8 - c];
                        c--;
                }

                p &= m - 1;
                set_bit(filter, p);
        }

        /* log_debug("bloom: adding <%.*s>", (int) n, (char*) data); */
}

void bloom_add_pair(uint64_t filter[], size_t size, unsigned k, const char *a, const char *b) {
        size_t n;
        char *c;

        assert(filter);
        assert(a);
        assert(b);

        n = strlen(a) + 1 + strlen(b);
        c = alloca(n + 1);
        strcpy(stpcpy(stpcpy(c, a), ":"), b);

        bloom_add_data(filter, size, k, c, n);
}

void bloom_add_prefixes(uint64_t filter[], size_t size, unsigned k, const char *a, const char *b, char sep) {
        size_t n;
        char *c, *p;

        assert(filter);
        assert(a);
        assert(b);

        n = strlen(a) + 1 + strlen(b);
        c = alloca(n + 1);

        p = stpcpy(stpcpy(c, a), ":");
        strcpy(p, b);

        bloom_add_data(filter, size, k, c, n);

        for (;;) {
                char *e;

                e = strrchr(p, sep);
                if (!e)
                        break;

                *(e + 1) = 0;
                bloom_add_data(filter, size, k, c, e - c + 1);

                if (e == p)
                        break;

                *e = 0;
                bloom_add_data(filter, size, k, c, e - c);
        }
}

bool bloom_validate_parameters(size_t size, unsigned k) {
        uint64_t m;
        unsigned w;

        if (size <= 0)
                return false;

        if (k <= 0)
                return false;

        m = size * 8;
        w = (u64log2(m) + 7) / 8;
        if (w > sizeof(uint64_t))
                return false;

        if (k * w > ELEMENTSOF(hash_keys) * 8)
                return false;

        return true;
}
