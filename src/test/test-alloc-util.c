/* SPDX-License-Identifier: LGPL-2.1+ */

#include <malloc.h>
#include <stdint.h>

#include "alloc-util.h"
#include "macro.h"
#include "memory-util.h"
#include "random-util.h"
#include "tests.h"

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

static void test_GREEDY_REALLOC(void) {
        _cleanup_free_ int *a = NULL, *b = NULL;
        size_t n_allocated = 0, i, j;

        /* Give valgrind a chance to verify our realloc() operations */

        for (i = 0; i < 20480; i++) {
                assert_se(GREEDY_REALLOC(a, n_allocated, i + 1));
                assert_se(n_allocated >= i + 1);
                assert_se(malloc_usable_size(a) >= (i + 1) * sizeof(int));
                a[i] = (int) i;
                assert_se(GREEDY_REALLOC(a, n_allocated, i / 2));
                assert_se(n_allocated >= i / 2);
                assert_se(malloc_usable_size(a) >= (i / 2) * sizeof(int));
        }

        for (j = 0; j < i / 2; j++)
                assert_se(a[j] == (int) j);

        for (i = 30, n_allocated = 0; i < 20480; i += 7) {
                assert_se(GREEDY_REALLOC(b, n_allocated, i + 1));
                assert_se(n_allocated >= i + 1);
                assert_se(malloc_usable_size(b) >= (i + 1) * sizeof(int));
                b[i] = (int) i;
                assert_se(GREEDY_REALLOC(b, n_allocated, i / 2));
                assert_se(n_allocated >= i / 2);
                assert_se(malloc_usable_size(b) >= (i / 2) * sizeof(int));
        }

        for (j = 30; j < i / 2; j += 7)
                assert_se(b[j] == (int) j);
}

static void test_memdup_multiply_and_greedy_realloc(void) {
        static const int org[] = { 1, 2, 3 };
        _cleanup_free_ int *dup;
        int *p;
        size_t i, allocated = 3;

        dup = memdup_suffix0_multiply(org, sizeof(int), 3);
        assert_se(dup);
        assert_se(dup[0] == 1);
        assert_se(dup[1] == 2);
        assert_se(dup[2] == 3);
        assert_se(((uint8_t*) dup)[sizeof(int) * 3] == 0);
        free(dup);

        dup = memdup_multiply(org, sizeof(int), 3);
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

static int cleanup_counter = 0;

static void cleanup1(void *a) {
        log_info("%s(%p)", __func__, a);
        assert_se(++cleanup_counter == *(int*) a);
}
static void cleanup2(void *a) {
        log_info("%s(%p)", __func__, a);
        assert_se(++cleanup_counter == *(int*) a);
}
static void cleanup3(void *a) {
        log_info("%s(%p)", __func__, a);
        assert_se(++cleanup_counter == *(int*) a);
}

static void test_cleanup_order(void) {
        _cleanup_(cleanup1) int x1 = 4, x2 = 3;
        _cleanup_(cleanup3) int z = 2;
        _cleanup_(cleanup2) int y = 1;
        log_debug("x1: %p", &x1);
        log_debug("x2: %p", &x2);
        log_debug("y: %p", &y);
        log_debug("z: %p", &z);
}

static void test_auto_erase_memory(void) {
        _cleanup_(erase_and_freep) uint8_t *p1, *p2;

        assert_se(p1 = new(uint8_t, 1024));
        assert_se(p2 = new(uint8_t, 1024));

        assert_se(genuine_random_bytes(p1, 1024, RANDOM_BLOCK) == 0);

        /* before we exit the scope, do something with this data, so that the compiler won't optimize this away */
        memcpy(p2, p1, 1024);
        for (size_t i = 0; i < 1024; i++)
                assert_se(p1[i] == p2[i]);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_alloca();
        test_GREEDY_REALLOC();
        test_memdup_multiply_and_greedy_realloc();
        test_bool_assign();
        test_cleanup_order();
        test_auto_erase_memory();

        return 0;
}
