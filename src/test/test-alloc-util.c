/* SPDX-License-Identifier: LGPL-2.1+ */

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

static void test_bool_assign(void) {
        bool b, c, *cp = &c, d, e, f, g, h;

        b = 123;
        *cp = -11;
        d = 0xF & 0xFF;
        e = b & d;
        f = 0x0;
        g = cp;    /* cast from pointer */
        h = NULL;  /* cast from pointer */

        assert(b);
        assert(c);
        assert(d);
        assert(e);
        assert(!f);
        assert(g);
        assert(!h);
}

int main(int argc, char *argv[]) {
        test_alloca();
        test_memdup_multiply_and_greedy_realloc();
        test_bool_assign();

        return 0;
}
