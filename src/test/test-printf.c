/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <../musl/printf.h>

#include "memory-util.h"
#include "strv.h"
#include "tests.h"

static void test_parse_printf_format_one(const char *fmt) {
        int arg_types_x[128] = {}, arg_types_y[128] = {};
        size_t x, y;

        log_debug("/* %s(%s) */", __func__, fmt);

        x = parse_printf_format(fmt, ELEMENTSOF(arg_types_x), arg_types_x);
        y = missing_parse_printf_format(fmt, ELEMENTSOF(arg_types_y), arg_types_y);

        for (size_t i = 0; i < x; i++)
                log_debug("x[%zu]=%i", i, arg_types_x[i]);
        for (size_t i = 0; i < y; i++)
                log_debug("y[%zu]=%i", i, arg_types_y[i]);

        ASSERT_EQ(memcmp_nn(arg_types_x, x * sizeof(int), arg_types_y, y * sizeof(int)), 0);
}

TEST(parse_printf_format) {
        FOREACH_STRING(s, "d", "i", "o", "u", "x", "X", "n")
                FOREACH_STRING(p, "", "hh", "h", "l", "ll", "j", "z", "Z", "t") {
                        _cleanup_free_ char *fmt = NULL;

                        ASSERT_NOT_NULL(fmt = strjoin("%", p, s));
                        test_parse_printf_format_one(fmt);
                }

        FOREACH_STRING(s, "e", "E", "f", "F", "g", "G", "a", "A")
                FOREACH_STRING(p, "", "L") {
                        _cleanup_free_ char *fmt = NULL;

                        ASSERT_NOT_NULL(fmt = strjoin("%", p, s));
                        test_parse_printf_format_one(fmt);
                }

        FOREACH_STRING(s, "c", "s")
                FOREACH_STRING(p, "", "l") {
                        _cleanup_free_ char *fmt = NULL;

                        ASSERT_NOT_NULL(fmt = strjoin("%", p, s));
                        test_parse_printf_format_one(fmt);
                }

        FOREACH_STRING(s, "C", "S", "p", "m", "%") {
                _cleanup_free_ char *fmt = NULL;

                ASSERT_NOT_NULL(fmt = strjoin("%", s));
                test_parse_printf_format_one(fmt);
        }

        test_parse_printf_format_one("asfhghejmlahpgakdmsalc");
        test_parse_printf_format_one("%d%i%o%u%x%X");
        test_parse_printf_format_one("%e%E%f%F%g%G%a%A");
        test_parse_printf_format_one("%c%s%C%S%p%n%m%%");
        test_parse_printf_format_one("%03d%-05d%+i%hhu%hu%hx%lx");
        test_parse_printf_format_one("%llx%x%LE%ji%zi%zu%zi%zu%Zi%Zu%tu");
        test_parse_printf_format_one("%l");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
