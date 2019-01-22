/* SPDX-License-Identifier: LGPL-2.1+ */

#include <malloc.h>
#include <stdint.h>

#include "alloc-util.h"
#include "macro.h"
#include "memory-util.h"

static void test_alloca(void) {
        static const uint8_t zero[997] = { };
        char *t;

        t = alloca_align(17, 512);
        assert_se(!((uintptr_t)t & 0xff));
        memzero(t, 17);

        t = alloca0_align(997, 1024);
        assert_se(!((uintptr_t)t & 0x1ff));
        assert_se(!memcmp(t, zero, 997));

        t = alloca_half_align(0x20, 0x10);
        assert_se((uintptr_t)t % 8 == 0);
        assert_se((uintptr_t)t % 0x10 != 0);

        t = alloca_half_align(0x100, 0x100);
        assert_se((uintptr_t)t % 0x80 == 0);
        assert_se((uintptr_t)t % 0x100 != 0);
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

static void test_malloca(void) {
        /* it should go on the stack */
        _mallocable_(char) *s1 = newmalloca(char, 17);
        assert_se(((uintptr_t)s1 & 1));
        /* it should go on the heap */
        _mallocable_(char) *h1 = newmalloca(char, 300);
        assert_se(!((uintptr_t)h1 & 1));

        /* it should go on the stack */
        _mallocable_(uint8_t) *su1 = newmalloca(uint8_t, 3);
        assert_se(((uintptr_t)su1 & 1));
        /* it should go on the heap */
        _mallocable_(uint8_t) *hu1 = newmalloca(uint8_t, 280);
        assert_se(!((uintptr_t)hu1 & 1));

        /* it should go on the stack */
        size_t ld_align = __alignof__(long double) * 2;
        _mallocable_full_(long double, long_double) *s2 = newmalloca(long double, 3);
        assert_se(((uintptr_t)s2 % ld_align != 0));
        /* it should go on the heap */
        _mallocable_full_(long double, long_double) *h2 = newmalloca(long double, 30);
        assert_se((uintptr_t)h2 % ld_align == 0);

        /* it should go on the stack */
        size_t ull_align = __alignof__(unsigned long long) * 2;
        _mallocable_full_(unsigned long long, unsigned_long_long) *s3 = newmalloca(unsigned long long, 17);
        assert_se((uintptr_t)s3 % ull_align != 0);
        /* it should go on the heap */
        _mallocable_full_(unsigned long long, unsigned_long_long) *h3 = newmalloca(unsigned long long, 400);
        assert_se((uintptr_t)h3 % ull_align == 0);
}

int main(int argc, char *argv[]) {
        test_alloca();
        test_GREEDY_REALLOC();
        test_memdup_multiply_and_greedy_realloc();
        test_bool_assign();
        test_malloca();

        return 0;
}
