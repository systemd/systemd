/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>

#include "alloc-util.h"
#include "memory-util.h"
#include "random-util.h"
#include "tests.h"

TEST(alloca) {
        static const uint8_t zero[997] = { };
        char *t;

        t = alloca_align(17, 512);
        ASSERT_FALSE((uintptr_t)t & 0xff);
        memzero(t, 17);

        t = alloca0_align(997, 1024);
        ASSERT_FALSE((uintptr_t)t & 0x1ff);
        ASSERT_EQ(memcmp(t, zero, 997), 0);
}

TEST(GREEDY_REALLOC) {
        _cleanup_free_ int *a = NULL, *b = NULL, *c = NULL;
        size_t i, j, n_c = 0;

        /* Give valgrind a chance to verify our realloc() operations */

        for (i = 0; i < 20480; i++) {
                ASSERT_NOT_NULL(GREEDY_REALLOC(a, i + 1));
                ASSERT_GE(MALLOC_ELEMENTSOF(a), i + 1);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(a), (i + 1) * sizeof(int));
                a[i] = (int) i;
                ASSERT_NOT_NULL(GREEDY_REALLOC(a, i / 2));
                ASSERT_GE(MALLOC_ELEMENTSOF(a), i / 2);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(a), (i / 2) * sizeof(int));
        }

        for (j = 0; j < i / 2; j++)
                ASSERT_EQ(a[j], (int) j);

        for (i = 30; i < 20480; i += 7) {
                ASSERT_NOT_NULL(GREEDY_REALLOC(b, i + 1));
                ASSERT_GE(MALLOC_ELEMENTSOF(b), i + 1);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(b), (i + 1) * sizeof(int));
                b[i] = (int) i;
                ASSERT_NOT_NULL(GREEDY_REALLOC(b, i / 2));
                ASSERT_GE(MALLOC_ELEMENTSOF(b), i / 2);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(b), (i / 2) * sizeof(int));
        }

        for (j = 30; j < i / 2; j += 7)
                ASSERT_EQ(b[j], (int) j);

        size_t n_from = 10;
        int from[n_from];
        for (i = 0; i < 2048; i++) {
                for (j = 0; j < n_from; j++)
                        from[j] = n_from * i + j;

                _cleanup_free_ int *before = NULL;
                size_t n_before = 0;
                ASSERT_NOT_NULL(GREEDY_REALLOC_APPEND(before, n_before, c, n_c));
                ASSERT_NOT_NULL(before);
                ASSERT_EQ(n_before, n_c);
                ASSERT_EQ(memcmp_safe(c, before, n_c), 0);

                ASSERT_NOT_NULL(GREEDY_REALLOC_APPEND(c, n_c, from, n_from));
                ASSERT_EQ(n_c, n_before + n_from);
                ASSERT_GE(MALLOC_ELEMENTSOF(c), n_c);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(c), n_c * sizeof(int));
                ASSERT_EQ(memcmp_safe(c, before, n_before), 0);
                ASSERT_EQ(memcmp_safe(&c[n_before], from, n_from), 0);

                before = mfree(before);
                ASSERT_NULL(before);
                n_before = 0;
                ASSERT_NOT_NULL(GREEDY_REALLOC_APPEND(before, n_before, c, n_c));
                ASSERT_NOT_NULL(before);
                ASSERT_EQ(n_before, n_c);
                ASSERT_EQ(memcmp_safe(c, before, n_c), 0);

                ASSERT_NOT_NULL(GREEDY_REALLOC_APPEND(c, n_c, NULL, 0));
                ASSERT_NOT_NULL(c);
                ASSERT_EQ(n_c, n_before);
                ASSERT_GE(MALLOC_ELEMENTSOF(c), n_c);
                ASSERT_GE(MALLOC_SIZEOF_SAFE(c), n_c * sizeof(int));
                ASSERT_EQ(memcmp_safe(c, before, n_c), 0);
        }

        for (j = 0; j < i * n_from; j++)
                ASSERT_EQ(c[j], (int) j);
}

TEST(memdup_multiply_and_greedy_realloc) {
        static const int org[] = { 1, 2, 3 };
        _cleanup_free_ int *dup;
        size_t i;
        int *p;

        dup = ASSERT_NOT_NULL(memdup_suffix0_multiply(org, 3, sizeof(int)));
        ASSERT_EQ(dup[0], 1);
        ASSERT_EQ(dup[1], 2);
        ASSERT_EQ(dup[2], 3);
        ASSERT_EQ(((uint8_t*) dup)[sizeof(int) * 3], 0);
        free(dup);

        dup = memdup_multiply(org, 3, sizeof(int));
        ASSERT_NOT_NULL(dup);
        ASSERT_EQ(dup[0], 1);
        ASSERT_EQ(dup[1], 2);
        ASSERT_EQ(dup[2], 3);

        memzero(dup + 3, MALLOC_SIZEOF_SAFE(dup) - sizeof(int) * 3);

        p = dup;
        ASSERT_PTR_EQ(GREEDY_REALLOC0(dup, 2), p);

        p = GREEDY_REALLOC0(dup, 10);
        ASSERT_PTR_EQ(p, dup);
        ASSERT_GE(MALLOC_ELEMENTSOF(p), 10U);
        ASSERT_EQ(p[0], 1);
        ASSERT_EQ(p[1], 2);
        ASSERT_EQ(p[2], 3);
        for (i = 3; i < MALLOC_ELEMENTSOF(p); i++)
                ASSERT_EQ(p[i], 0);
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

        ASSERT_TRUE(b);
        ASSERT_TRUE(c);
        ASSERT_TRUE(d);
        ASSERT_TRUE(e);
        ASSERT_FALSE(f);
        ASSERT_TRUE(g);
        ASSERT_FALSE(h);
}

static int cleanup_counter = 0;

static void cleanup1(void *a) {
        log_info("%s(%p)", __func__, a);
        ASSERT_EQ(++cleanup_counter, *(int*) a);
}
static void cleanup2(void *a) {
        log_info("%s(%p)", __func__, a);
        ASSERT_EQ(++cleanup_counter, *(int*) a);
}
static void cleanup3(void *a) {
        log_info("%s(%p)", __func__, a);
        ASSERT_EQ(++cleanup_counter, *(int*) a);
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

        /* use prime size, to ensure that there will be free space at the end of the allocation, since
         * malloc() enforces alignment */
        ASSERT_NOT_NULL(p1 = new(uint8_t, 4703));
        ASSERT_NOT_NULL(p2 = new(uint8_t, 4703));

        ASSERT_OK_ZERO(crypto_random_bytes(p1, 4703));

        /* before we exit the scope, do something with this data, so that the compiler won't optimize this away */
        memcpy(p2, p1, 4703);
        for (size_t i = 0; i < 4703; i++)
                ASSERT_EQ(p1[i], p2[i]);
}

#define TEST_SIZES(f, n)                                                \
        do {                                                            \
                log_debug("requested=%zu vs. malloc_size=%zu vs. gcc_size=%zu", \
                          n * sizeof(*f),                               \
                          malloc_usable_size(f),                        \
                          __builtin_object_size(f, 0));                 \
                ASSERT_GE(MALLOC_ELEMENTSOF(f), n);                     \
                ASSERT_GE(MALLOC_SIZEOF_SAFE(f), sizeof(*f) * n);       \
                ASSERT_GE(malloc_usable_size(f), sizeof(*f) * n);       \
                ASSERT_GE(__builtin_object_size(f, 0), sizeof(*f) * n); \
        } while (false)

TEST(malloc_size_safe) {
        _cleanup_free_ uint32_t *f = NULL;
        size_t n = 4711;

        /* Let's check the macros and built-ins work on NULL and return the expected values */
        ASSERT_EQ(MALLOC_ELEMENTSOF((float*) NULL), 0U);
        ASSERT_EQ(MALLOC_SIZEOF_SAFE((float*) NULL), 0U);
        ASSERT_EQ(malloc_usable_size(NULL), 0U); /* as per man page, this is safe and defined */
        ASSERT_EQ(__builtin_object_size(NULL, 0), SIZE_MAX); /* as per docs SIZE_MAX is returned for pointers where the size isn't known */

        /* Then, let's try these macros once with constant size values, so that __builtin_object_size()
         * definitely can work (as long as -O2 is used when compiling) */
        ASSERT_NOT_NULL(f = new(uint32_t, n));
        TEST_SIZES(f, n);

        /* Finally, let's use some dynamically sized allocations, to make sure this doesn't deteriorate */
        for (unsigned i = 0; i < 50; i++) {
                _cleanup_free_ uint64_t *g = NULL;
                size_t m;

                m = random_u64_range(16*1024);
                ASSERT_NOT_NULL(g = new(uint64_t, m));
                TEST_SIZES(g, m);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
