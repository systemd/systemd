/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdint.h>

#include "alloc-util.h"
#include "macro.h"
#include "util.h"

static void test_alloca(void) {
        static const uint8_t zero[997] = { };
        char *t;

        t = alloca_align(17, 512);
        assert_se(!((uintptr_t)t & 0xff));
        memzero(t, 17);

        t = alloca0_align(997, 1024);
        assert_se(!((uintptr_t)t & 0x1ff));
        assert_se(!memcmp(t, zero, 997));
}

static void test_memdup_multiply_and_greedy_realloc(void) {
        int org[] = {1, 2, 3};
        _cleanup_free_ int *dup;
        int *p;
        size_t i, allocated = 3;

        dup = (int*) memdup_suffix0_multiply(org, sizeof(int), 3);
        assert_se(dup);
        assert_se(dup[0] == 1);
        assert_se(dup[1] == 2);
        assert_se(dup[2] == 3);
        assert_se(*(uint8_t*) (dup + 3) == (uint8_t) 0);
        free(dup);

        dup = (int*) memdup_multiply(org, sizeof(int), 3);
        assert_se(dup);
        assert_se(dup[0] == 1);
        assert_se(dup[1] == 2);
        assert_se(dup[2] == 3);

        p = dup;
        assert_se(greedy_realloc0((void**) &dup, &allocated, 2, sizeof(int)) == p);

        p = (int *) greedy_realloc0((void**) &dup, &allocated, 10, sizeof(int));
        assert_se(p == dup);
        assert_se(allocated >= 10);
        assert_se(p[0] == 1);
        assert_se(p[1] == 2);
        assert_se(p[2] == 3);
        for (i = 3; i < allocated; i++)
                assert_se(p[i] == 0);
}

int main(int argc, char *argv[]) {
        test_alloca();
        test_memdup_multiply_and_greedy_realloc();

        return 0;
}
