/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>
#include <stdint.h>

#include "alloc-util.h"
#include "macro.h"
#include "memory-util.h"
#include "random-util.h"
#include "tests.h"

TEST(alloca) {
        static const uint8_t zero[997] = { };
        char *t;

        t = alloca_align(17, 512);
        assert_se(!((uintptr_t)t & 0xff));
        memzero(t, 17);

        t = alloca0_align(997, 1024);
        assert_se(!((uintptr_t)t & 0x1ff));
        assert_se(!memcmp(t, zero, 997));
}

TEST(GREEDY_REALLOC) {
        _cleanup_free_ int *a = NULL, *b = NULL;
        size_t i, j;

        /* Give valgrind a chance to verify our realloc() operations */

        for (i = 0; i < 20480; i++) {
                assert_se(GREEDY_REALLOC(a, i + 1));
                assert_se(MALLOC_ELEMENTSOF(a) >= i + 1);
                assert_se(MALLOC_SIZEOF_SAFE(a) >= (i + 1) * sizeof(int));
                a[i] = (int) i;
                assert_se(GREEDY_REALLOC(a, i / 2));
                assert_se(MALLOC_ELEMENTSOF(a) >= i / 2);
                assert_se(MALLOC_SIZEOF_SAFE(a) >= (i / 2) * sizeof(int));
        }

        for (j = 0; j < i / 2; j++)
                assert_se(a[j] == (int) j);

        for (i = 30; i < 20480; i += 7) {
                assert_se(GREEDY_REALLOC(b, i + 1));
                assert_se(MALLOC_ELEMENTSOF(b) >= i + 1);
                assert_se(MALLOC_SIZEOF_SAFE(b) >= (i + 1) * sizeof(int));
                b[i] = (int) i;
                assert_se(GREEDY_REALLOC(b, i / 2));
                assert_se(MALLOC_ELEMENTSOF(b) >= i / 2);
                assert_se(MALLOC_SIZEOF_SAFE(b) >= (i / 2) * sizeof(int));
        }

        for (j = 30; j < i / 2; j += 7)
                assert_se(b[j] == (int) j);
}

TEST(memdup_multiply_and_greedy_realloc) {
        static const int org[] = { 1, 2, 3 };
        _cleanup_free_ int *dup;
        size_t i;
        int *p;

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

        memzero(dup + 3, malloc_usable_size(dup) - sizeof(int) * 3);

        p = dup;
        assert_se(GREEDY_REALLOC0(dup, 2) == p);

        p = GREEDY_REALLOC0(dup, 10);
        assert_se(p == dup);
        assert_se(MALLOC_ELEMENTSOF(p) >= 10);
        assert_se(p[0] == 1);
        assert_se(p[1] == 2);
        assert_se(p[2] == 3);
        for (i = 3; i < MALLOC_ELEMENTSOF(p); i++)
                assert_se(p[i] == 0);
}

TEST(bool_assign) {
        bool b, c, *cp = &c, d, e, f, g, h;

        b = 123;
        *cp = -11;
        d = 0xF & 0xFF;
        e = b & d;
        f = 0x0;
        g = cp;    /* cast from pointer */
        h = NULL;  /* cast from pointer */

        assert_se(b);
        assert_se(c);
        assert_se(d);
        assert_se(e);
        assert_se(!f);
        assert_se(g);
        assert_se(!h);
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

TEST(cleanup_order) {
        _cleanup_(cleanup1) int x1 = 4, x2 = 3;
        _cleanup_(cleanup3) int z = 2;
        _cleanup_(cleanup2) int y = 1;
        log_debug("x1: %p", &x1);
        log_debug("x2: %p", &x2);
        log_debug("y: %p", &y);
        log_debug("z: %p", &z);
}

TEST(auto_erase_memory) {
        _cleanup_(erase_and_freep) uint8_t *p1, *p2;

        /* print address of p2, else e.g. clang-11 will optimize it out */
        log_debug("p1: %p p2: %p", &p1, &p2);

        assert_se(p1 = new(uint8_t, 4703)); /* use prime size, to ensure that there will be free space at the
                                             * end of the allocation, since malloc() enforces alignment */
        assert_se(p2 = new(uint8_t, 4703));

        assert_se(genuine_random_bytes(p1, 4703, RANDOM_BLOCK) == 0);

        /* before we exit the scope, do something with this data, so that the compiler won't optimize this away */
        memcpy(p2, p1, 4703);
        for (size_t i = 0; i < 4703; i++)
                assert_se(p1[i] == p2[i]);
}

#define TEST_SIZES(f, n)                                                \
        do {                                                            \
                log_debug("requested=%zu vs. malloc_size=%zu vs. gcc_size=%zu", \
                          n * sizeof(*f),                               \
                          malloc_usable_size(f),                        \
                          __builtin_object_size(f, 0));                 \
                assert_se(MALLOC_ELEMENTSOF(f) >= n);                   \
                assert_se(MALLOC_SIZEOF_SAFE(f) >= sizeof(*f) * n);     \
                assert_se(malloc_usable_size(f) >= sizeof(*f) * n);     \
                assert_se(__builtin_object_size(f, 0) >= sizeof(*f) * n); \
        } while (false)

TEST(malloc_size_safe) {
        _cleanup_free_ uint32_t *f = NULL;
        size_t n = 4711;

        /* Let's check the macros and built-ins work on NULL and return the expected values */
        assert_se(MALLOC_ELEMENTSOF((float*) NULL) == 0);
        assert_se(MALLOC_SIZEOF_SAFE((float*) NULL) == 0);
        assert_se(malloc_usable_size(NULL) == 0); /* as per man page, this is safe and defined */
        assert_se(__builtin_object_size(NULL, 0) == SIZE_MAX); /* as per docs SIZE_MAX is returned for pointers where the size isn't known */

        /* Then, let's try these macros once with constant size values, so that __builtin_object_size()
         * definitely can work (as long as -O2 is used when compiling) */
        assert_se(f = new(uint32_t, n));
        TEST_SIZES(f, n);

        /* Finally, let's use some dynamically sized allocations, to make sure this doesn't deteriorate */
        for (unsigned i = 0; i < 50; i++) {
                _cleanup_free_ uint64_t *g = NULL;
                size_t m;

                m = random_u64_range(16*1024);
                assert_se(g = new(uint64_t, m));
                TEST_SIZES(g, m);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
