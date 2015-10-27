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

#include <stdlib.h>

#include "alloc-util.h"
#include "prioq.h"
#include "set.h"
#include "siphash24.h"
#include "util.h"

#define SET_SIZE 1024*4

static int unsigned_compare(const void *a, const void *b) {
        const unsigned *x = a, *y = b;

        if (*x < *y)
                return -1;

        if (*x > *y)
                return 1;

        return 0;
}

static void test_unsigned(void) {
        unsigned buffer[SET_SIZE], i;
        Prioq *q;

        srand(0);

        q = prioq_new(trivial_compare_func);
        assert_se(q);

        for (i = 0; i < ELEMENTSOF(buffer); i++) {
                unsigned u;

                u = (unsigned) rand();
                buffer[i] = u;
                assert_se(prioq_put(q, UINT_TO_PTR(u), NULL) >= 0);
        }

        qsort(buffer, ELEMENTSOF(buffer), sizeof(buffer[0]), unsigned_compare);

        for (i = 0; i < ELEMENTSOF(buffer); i++) {
                unsigned u;

                assert_se(prioq_size(q) == ELEMENTSOF(buffer) - i);

                u = PTR_TO_UINT(prioq_pop(q));
                assert_se(buffer[i] == u);
        }

        assert_se(prioq_isempty(q));
        prioq_free(q);
}

struct test {
        unsigned value;
        unsigned idx;
};

static int test_compare(const void *a, const void *b) {
        const struct test *x = a, *y = b;

        if (x->value < y->value)
                return -1;

        if (x->value > y->value)
                return 1;

        return 0;
}

static void test_hash(const void *a, struct siphash *state) {
        const struct test *x = a;

        siphash24_compress(&x->value, sizeof(x->value), state);
}

static const struct hash_ops test_hash_ops = {
        .hash = test_hash,
        .compare = test_compare
};

static void test_struct(void) {
        Prioq *q;
        Set *s;
        unsigned previous = 0, i;
        int r;

        srand(0);

        q = prioq_new(test_compare);
        assert_se(q);

        s = set_new(&test_hash_ops);
        assert_se(s);

        for (i = 0; i < SET_SIZE; i++) {
                struct test *t;

                t = new0(struct test, 1);
                assert_se(t);
                t->value = (unsigned) rand();

                r = prioq_put(q, t, &t->idx);
                assert_se(r >= 0);

                if (i % 4 == 0) {
                        r = set_consume(s, t);
                        assert_se(r >= 0);
                }
        }

        for (;;) {
                struct test *t;

                t = set_steal_first(s);
                if (!t)
                        break;

                r = prioq_remove(q, t, &t->idx);
                assert_se(r > 0);

                free(t);
        }

        for (i = 0; i < SET_SIZE * 3 / 4; i++) {
                struct test *t;

                assert_se(prioq_size(q) == (SET_SIZE * 3 / 4) - i);

                t = prioq_pop(q);
                assert_se(t);

                assert_se(previous <= t->value);
                previous = t->value;
                free(t);
        }

        assert_se(prioq_isempty(q));
        prioq_free(q);

        assert_se(set_isempty(s));
        set_free(s);
}

int main(int argc, char* argv[]) {

        test_unsigned();
        test_struct();

        return 0;
}
