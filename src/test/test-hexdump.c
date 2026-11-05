/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hexdump.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "tests.h"

TEST(hexdump) {
        uint8_t data[146];
        unsigned i;

        hexdump(stdout, NULL, 0);
        hexdump(stdout, "", 0);
        hexdump(stdout, "", SIZE_MAX);
        hexdump(stdout, "", 1);
        hexdump(stdout, "x", 1);
        hexdump(stdout, "x", SIZE_MAX);
        hexdump(stdout, "x", 2);
        hexdump(stdout, "foobar", 7);
        hexdump(stdout, "foobar", SIZE_MAX);
        hexdump(stdout, "f\nobar", 7);
        hexdump(stdout, "f\nobar", SIZE_MAX);
        hexdump(stdout, "xxxxxxxxxxxxxxxxxxxxyz", 23);

        for (i = 0; i < ELEMENTSOF(data); i++)
                data[i] = i*2;

        hexdump(stdout, data, sizeof(data));
}

TEST(hexdump_memcmp) {
        static const uint8_t a[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                     0x10, 0x11 };
        static const uint8_t b[] = { 0x00, 0x01, 0xff, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                     0x10 };

        /* Equal regions: no marker lines, just the two sides. */
        _cleanup_free_ char *s = ASSERT_NOT_NULL(hexdump_memcmp(a, sizeof(a), a, sizeof(a)));
        log_info("equal:\n%s", s);

        /* Differing byte and differing length. */
        free(s);
        s = ASSERT_NOT_NULL(hexdump_memcmp(a, sizeof(a), b, sizeof(b)));
        log_info("differ:\n%s", s);

        /* Empty regions are fine. */
        free(s);
        s = ASSERT_NOT_NULL(hexdump_memcmp(/* m1= */ NULL, /* l1= */ 0, /* m2= */ NULL, /* l2= */ 0));
        ASSERT_STREQ(s, "");
}

TEST(hexdump_memcmp_byte) {
        static const uint8_t a[] = { 'x', 'x', 'x', 'y', 'x', 'x' };

        /* All bytes match 'byte': no marker lines. */
        _cleanup_free_ char *s = ASSERT_NOT_NULL(hexdump_memcmp_byte('x', (const uint8_t[]) { 'x', 'x' }, 2));
        log_info("all equal:\n%s", s);

        /* One byte differs from 'byte'. */
        free(s);
        s = ASSERT_NOT_NULL(hexdump_memcmp_byte('x', a, sizeof(a)));
        log_info("differ:\n%s", s);

        /* Empty region is fine. */
        free(s);
        s = ASSERT_NOT_NULL(hexdump_memcmp_byte(0x00, /* data= */ NULL, /* length= */ 0));
        ASSERT_STREQ(s, "");
}

TEST(hexdump_iovw_compare) {
        struct iovec iov_a[] = { IOVEC_MAKE_STRING("foo"), IOVEC_MAKE_STRING("bar") };
        struct iovec iov_b[] = { IOVEC_MAKE_STRING("foo"), IOVEC_MAKE_STRING("baz") };
        struct iovec_wrapper wa = { .iovec = iov_a, .count = ELEMENTSOF(iov_a) };
        struct iovec_wrapper wb = { .iovec = iov_b, .count = ELEMENTSOF(iov_b) };

        /* Equal wrappers: empty dump. */
        _cleanup_free_ char *s = ASSERT_NOT_NULL(hexdump_iovw_compare(&wa, &wa));
        ASSERT_STREQ(s, "");

        /* One element differs. */
        free(s);
        s = ASSERT_NOT_NULL(hexdump_iovw_compare(&wa, &wb));
        log_info("differ:\n%s", s);

        /* Different element count. */
        struct iovec_wrapper wc = { .iovec = iov_a, .count = 1 };
        free(s);
        s = ASSERT_NOT_NULL(hexdump_iovw_compare(&wa, &wc));
        log_info("count differ:\n%s", s);
}

DEFINE_TEST_MAIN(LOG_INFO);
