/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 Michal Schmidt

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

#include "hash-funcs.h"

void string_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, strlen(p) + 1, state);
}

int string_compare_func(const void *a, const void *b) {
        return strcmp(a, b);
}

const struct hash_ops string_hash_ops = {
        .hash = string_hash_func,
        .compare = string_compare_func
};

void trivial_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(&p, sizeof(p), state);
}

int trivial_compare_func(const void *a, const void *b) {
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops trivial_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func
};

void uint64_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(uint64_t), state);
}

int uint64_compare_func(const void *_a, const void *_b) {
        uint64_t a, b;
        a = *(const uint64_t*) _a;
        b = *(const uint64_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops uint64_hash_ops = {
        .hash = uint64_hash_func,
        .compare = uint64_compare_func
};

#if SIZEOF_DEV_T != 8
void devt_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(p, sizeof(dev_t), state);
}

int devt_compare_func(const void *_a, const void *_b) {
        dev_t a, b;
        a = *(const dev_t*) _a;
        b = *(const dev_t*) _b;
        return a < b ? -1 : (a > b ? 1 : 0);
}

const struct hash_ops devt_hash_ops = {
        .hash = devt_hash_func,
        .compare = devt_compare_func
};
#endif
