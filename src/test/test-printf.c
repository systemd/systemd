/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <printf.h>

#include "memory-util.h"
#include "strv.h"
#include "tests.h"

static void test_parse_printf_format_one(const char *fmt, size_t m, const int *expected) {
        log_debug("/* %s(%s) */", __func__, fmt);

        int types[128] = {};
        size_t n = parse_printf_format(fmt, ELEMENTSOF(types), types);

        for (size_t i = 0; i < MAX(n, m); i++)
                if (i < MIN(n, m))
                        log_debug("types[%zu]=%i, expected[%zu]=%i", i, types[i], i, expected[i]);
                else if (i < n)
                        log_debug("types[%zu]=%i, expected[%zu]=n/a", i, types[i], i);
                else
                        log_debug("types[%zu]=n/a, expected[%zu]=%i", i, i, expected[i]);

        ASSERT_EQ(memcmp_nn(types, n * sizeof(int), expected, m * sizeof(int)), 0);
}

TEST(parse_printf_format) {
        static struct {
                const char *prefix;
                int expected;
        } integer_table[] = {
                { "", PA_INT },
                { "hh", PA_CHAR },
                { "h", PA_INT | PA_FLAG_SHORT },
                { "l", PA_INT | PA_FLAG_LONG },
#if ULLONG_MAX > ULONG_MAX
                { "ll", PA_INT | PA_FLAG_LONG_LONG },
#else
                { "ll", PA_INT | PA_FLAG_LONG },
#endif
#if UINTMAX_MAX > ULONG_MAX
                { "j", PA_INT | PA_FLAG_LONG_LONG },
#elif UINTMAX_MAX > UINT_MAX
                { "j", PA_INT | PA_FLAG_LONG },
#else
                { "j", PA_INT },
#endif
#if SIZE_MAX > ULONG_MAX
                { "z", PA_INT | PA_FLAG_LONG_LONG },
                { "Z", PA_INT | PA_FLAG_LONG_LONG },
                { "t", PA_INT | PA_FLAG_LONG_LONG },
#elif SIZE_MAX > UINT_MAX
                { "z", PA_INT | PA_FLAG_LONG },
                { "Z", PA_INT | PA_FLAG_LONG },
                { "t", PA_INT | PA_FLAG_LONG },
#else
                { "z", PA_INT },
                { "Z", PA_INT },
                { "t", PA_INT },
#endif
        }, float_table[] = {
                { "", PA_DOUBLE },
                { "L", PA_DOUBLE | PA_FLAG_LONG_DOUBLE },
        };

        FOREACH_ELEMENT(i, integer_table) {
                _cleanup_free_ char *fmt = NULL;

                FOREACH_STRING(s, "d", "i", "o", "u", "x", "X") {
                        ASSERT_NOT_NULL(fmt = strjoin("%", i->prefix, s));
                        test_parse_printf_format_one(fmt, 1, &i->expected);
                        fmt = mfree(fmt);
                }

                ASSERT_NOT_NULL(fmt = strjoin("%", i->prefix, "n"));
                test_parse_printf_format_one(fmt, 1, (int[]){ PA_INT | PA_FLAG_PTR });

                fmt = mfree(fmt);

                ASSERT_NOT_NULL(fmt = strjoin("%", i->prefix));
                test_parse_printf_format_one(fmt, 0, NULL);
        }

        FOREACH_ELEMENT(i, float_table) {
                _cleanup_free_ char *fmt = NULL;

                FOREACH_STRING(s, "e", "E", "f", "F", "g", "G", "a", "A") {
                        ASSERT_NOT_NULL(fmt = strjoin("%", i->prefix, s));
                        test_parse_printf_format_one(fmt, 1, &i->expected);
                        fmt = mfree(fmt);
                }

                ASSERT_NOT_NULL(fmt = strjoin("%", i->prefix));
                test_parse_printf_format_one(fmt, 0, NULL);
        }

        test_parse_printf_format_one("%c",  1, (int[]) { PA_CHAR });
        test_parse_printf_format_one("%lc", 1, (int[]) { PA_CHAR });
        test_parse_printf_format_one("%C",  1, (int[]) { PA_WCHAR });

        test_parse_printf_format_one("%s",  1, (int[]) { PA_STRING });
        test_parse_printf_format_one("%ls", 1, (int[]) { PA_STRING });
        test_parse_printf_format_one("%S",  1, (int[]) { PA_WSTRING });

        test_parse_printf_format_one("%p",  1, (int[]) { PA_POINTER });

        test_parse_printf_format_one("%m",  0, NULL);
        test_parse_printf_format_one("%%",  0, NULL);

        test_parse_printf_format_one("asfhghejmlahpgakdmsalc", 0, NULL);
        test_parse_printf_format_one(
                        "%d%i%o%u%x%X", 6,
                        (int[]) { PA_INT, PA_INT, PA_INT, PA_INT, PA_INT, PA_INT });
        test_parse_printf_format_one(
                        "%e%E%f%F%g%G%a%A", 8,
                        (int[]) { PA_DOUBLE, PA_DOUBLE, PA_DOUBLE, PA_DOUBLE, PA_DOUBLE, PA_DOUBLE, PA_DOUBLE, PA_DOUBLE });
        test_parse_printf_format_one(
                        "%c%s%C%S%p%n%m%%", 6,
                        (int[]) { PA_CHAR, PA_STRING, PA_WCHAR, PA_WSTRING, PA_POINTER, PA_INT | PA_FLAG_PTR });
        test_parse_printf_format_one(
                        "%03d%-05d%+i%hhu%hu%hx%lx", 7,
                        (int[]) { PA_INT, PA_INT, PA_INT, PA_CHAR, PA_INT | PA_FLAG_SHORT, PA_INT | PA_FLAG_SHORT, PA_INT | PA_FLAG_LONG });
}

DEFINE_TEST_MAIN(LOG_DEBUG);
