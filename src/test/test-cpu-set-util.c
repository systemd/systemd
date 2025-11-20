/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "tests.h"

#define ASSERT_CPUSET_EMPTY(c)                  \
        ASSERT_NULL(c.set);                     \
        ASSERT_EQ(c.allocated, 0u)

#define ASSERT_CPUSET_COUNT(c, n)                                       \
        ASSERT_NOT_NULL(c.set);                                         \
        ASSERT_GE(c.allocated, CPU_ALLOC_SIZE(n));                      \
        ASSERT_EQ(CPU_COUNT_S(c.allocated, c.set), (n))

#define ASSERT_CPUSET_ISSET(c, i)                               \
        ASSERT_TRUE(CPU_ISSET_S(i, c.allocated, c.set));

#define ASSERT_CPUSET_STRING(c, str, range, mask) \
        {                                                               \
                _cleanup_free_ char *s = NULL;                          \
                ASSERT_NOT_NULL(s = cpu_set_to_string(&c));             \
                log_info("cpu_set_to_string: %s", s);                   \
                ASSERT_STREQ(s, str);                                   \
                s = mfree(s);                                           \
                ASSERT_NOT_NULL(s = cpu_set_to_range_string(&c));       \
                log_info("cpu_set_to_range_string: %s", s);             \
                ASSERT_STREQ(s, range);                                 \
                s = mfree(s);                                           \
                ASSERT_NOT_NULL(s = cpu_set_to_mask_string(&c));        \
                log_info("cpu_set_to_mask_string: %s", s);              \
                ASSERT_STREQ(s, mask);                                  \
        }

TEST(parse_cpu_set) {
        CPUSet c = {};

        /* empty */
        ASSERT_CPUSET_EMPTY(c);
        ASSERT_CPUSET_STRING(c, "", "", "0");
        cpu_set_done(&c);

        /* Single value */
        ASSERT_OK(parse_cpu_set("0", &c));
        ASSERT_CPUSET_COUNT(c, 1);
        ASSERT_CPUSET_ISSET(c, 0);
        ASSERT_CPUSET_STRING(c, "0", "0", "1");
        cpu_set_done(&c);

        /* Simple range (from CPUAffinity example) */
        ASSERT_OK(parse_cpu_set("1 2 4", &c));
        ASSERT_CPUSET_COUNT(c, 3);
        ASSERT_CPUSET_ISSET(c, 1);
        ASSERT_CPUSET_ISSET(c, 2);
        ASSERT_CPUSET_ISSET(c, 4);
        ASSERT_CPUSET_STRING(c, "1 2 4", "1-2 4", "16");
        cpu_set_done(&c);

        /* A more interesting range */
        ASSERT_OK(parse_cpu_set("0 1 2 3 8 9 10 11", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 0; i < 4; i++)
                ASSERT_CPUSET_ISSET(c, i);
        for (unsigned i = 8; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 8 9 10 11", "0-3 8-11", "f0f");
        cpu_set_done(&c);

        /* Quoted strings */
        ASSERT_OK(parse_cpu_set("8 '9' 10 \"11\"", &c));
        ASSERT_CPUSET_COUNT(c, 4);
        for (unsigned i = 8; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "8 9 10 11", "8-11", "f00");
        cpu_set_done(&c);

        /* Use commas as separators */
        ASSERT_OK(parse_cpu_set("0,1,2,3 8,9,10,11", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 0; i < 4; i++)
                ASSERT_CPUSET_ISSET(c, i);
        for (unsigned i = 8; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 8 9 10 11", "0-3 8-11", "f0f");
        cpu_set_done(&c);

        /* Commas with spaces (and trailing comma, space) */
        ASSERT_OK(parse_cpu_set("0, 1, 2, 3, 4, 5, 6, 7, 63, ", &c));
        ASSERT_CPUSET_COUNT(c, 9);
        for (unsigned i = 0; i < 8; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_ISSET(c, 63);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 4 5 6 7 63", "0-7 63", "80000000,000000ff");
        cpu_set_done(&c);

        /* Ranges */
        ASSERT_OK(parse_cpu_set("0-3,8-11", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 0; i < 4; i++)
                ASSERT_CPUSET_ISSET(c, i);
        for (unsigned i = 8; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 8 9 10 11", "0-3 8-11", "f0f");
        cpu_set_done(&c);

        ASSERT_OK(parse_cpu_set("36-39,44-47", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 36; i < 40; i++)
                ASSERT_CPUSET_ISSET(c, i);
        for (unsigned i = 44; i < 48; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "36 37 38 39 44 45 46 47", "36-39 44-47", "f0f0,00000000");
        cpu_set_done(&c);

        ASSERT_OK(parse_cpu_set("64-71", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 64; i < 72; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "64 65 66 67 68 69 70 71", "64-71", "ff,00000000,00000000");
        cpu_set_done(&c);

        /* Ranges with trailing comma, space */
        ASSERT_OK(parse_cpu_set("0-3  8-11, ", &c));
        ASSERT_CPUSET_COUNT(c, 8);
        for (unsigned i = 0; i < 4; i++)
                ASSERT_CPUSET_ISSET(c, i);
        for (unsigned i = 8; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 8 9 10 11", "0-3 8-11", "f0f");
        cpu_set_done(&c);

        /* Overlapping ranges */
        ASSERT_OK(parse_cpu_set("0-7 4-11", &c));
        ASSERT_CPUSET_COUNT(c, 12);
        for (unsigned i = 0; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 1 2 3 4 5 6 7 8 9 10 11", "0-11", "fff");
        cpu_set_done(&c);

        /* Mix ranges and individual CPUs */
        ASSERT_OK(parse_cpu_set("0,2 4-11", &c));
        ASSERT_CPUSET_COUNT(c, 10);
        ASSERT_CPUSET_ISSET(c, 0);
        ASSERT_CPUSET_ISSET(c, 2);
        for (unsigned i = 4; i < 12; i++)
                ASSERT_CPUSET_ISSET(c, i);
        ASSERT_CPUSET_STRING(c, "0 2 4 5 6 7 8 9 10 11", "0 2 4-11", "ff5");
        cpu_set_done(&c);

        /* Negative range */
        ASSERT_ERROR(parse_cpu_set("3-0", &c), EINVAL);
        ASSERT_CPUSET_EMPTY(c);

        /* Garbage */
        ASSERT_ERROR(parse_cpu_set("0 1 2 3 garbage", &c), EINVAL);
        ASSERT_CPUSET_EMPTY(c);

        /* Range with garbage */
        ASSERT_ERROR(parse_cpu_set("0-3 8-garbage", &c), EINVAL);
        ASSERT_CPUSET_EMPTY(c);

        /* Empty string */
        ASSERT_OK(parse_cpu_set("", &c));
        ASSERT_CPUSET_EMPTY(c); /* empty string returns NULL */

        /* Runaway quoted string */
        ASSERT_ERROR(parse_cpu_set("0 1 2 3 \"4 5 6 7 ", &c), EINVAL);
        ASSERT_CPUSET_EMPTY(c);

        /* Maximum allocation */
        ASSERT_OK(parse_cpu_set("8000-8191", &c));
        ASSERT_CPUSET_COUNT(c, 192);

        _cleanup_free_ char *expected_str = NULL;
        for (size_t i = 8000; i < 8192; i++)
                ASSERT_OK(strextendf_with_separator(&expected_str, " ", "%zu", i));

        _cleanup_free_ char *expected_mask = NULL;
        for (size_t i = 0; i < 8192 / 32; i++)
                ASSERT_NOT_NULL(strextend_with_separator(&expected_mask, ",", i < 6 ? "ffffffff" : "00000000"));

        ASSERT_CPUSET_STRING(c, expected_str, "8000-8191", expected_mask);
        cpu_set_done(&c);
}

#define parse(str, c)                                                   \
        config_parse_cpu_set(                                           \
                        "unit",                                         \
                        "filename",                                     \
                        /* line = */ 0,                                 \
                        "[Section]",                                    \
                        /* section_line = */ 0,                         \
                        "CPUAffinity",                                  \
                        /* ltype = */ 0,                                \
                        str,                                            \
                        c,                                              \
                        /* userdata = */ NULL)

TEST(config_parse_cpu_set) {
        CPUSet c = {};

        ASSERT_OK_POSITIVE(parse("1 3", &c));
        ASSERT_CPUSET_COUNT(c, 2);
        ASSERT_CPUSET_STRING(c, "1 3", "1 3", "a");

        ASSERT_OK_POSITIVE(parse("4", &c));
        ASSERT_CPUSET_COUNT(c, 3);
        ASSERT_CPUSET_STRING(c, "1 3 4", "1 3-4", "1a");

        ASSERT_OK_POSITIVE(parse("", &c));
        ASSERT_CPUSET_EMPTY(c);
}

TEST(cpu_set_to_from_dbus) {
        _cleanup_(cpu_set_done) CPUSet c = {}, c2 = {};

        ASSERT_OK(parse_cpu_set("1 3 8 100-200", &c));
        ASSERT_CPUSET_COUNT(c, 104);

        _cleanup_free_ char *expected_str = strdup("1 3 8");
        ASSERT_NOT_NULL(expected_str);
        for (size_t i = 100; i <= 200; i++)
                ASSERT_OK(strextendf_with_separator(&expected_str, " ", "%zu", i));

        ASSERT_CPUSET_STRING(c, expected_str, "1 3 8 100-200", "1ff,ffffffff,ffffffff,fffffff0,00000000,00000000,0000010a");

        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;
        static const char expected[32] =
                "\x0A\x01\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\xF0\xFF\xFF\xFF"
                "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                "\xFF\x01";

        ASSERT_OK(cpu_set_to_dbus(&c, &array, &allocated));
        ASSERT_NOT_NULL(array);
        ASSERT_EQ(allocated, c.allocated);

        ASSERT_LE(allocated, sizeof expected);
        ASSERT_GE(allocated, DIV_ROUND_UP(201u, 8u)); /* We need at least 201 bits for our mask */
        ASSERT_EQ(memcmp(array, expected, allocated), 0);

        ASSERT_OK(cpu_set_from_dbus(array, allocated, &c2));
        ASSERT_CPUSET_COUNT(c2, 104);
        ASSERT_EQ(memcmp_nn(c.set, c.allocated, c2.set, c2.allocated), 0);
}

TEST(cpus_in_affinity_mask) {
        int r;

        ASSERT_OK_POSITIVE(r = cpus_in_affinity_mask());
        log_info("cpus_in_affinity_mask: %d", r);
}

TEST(print_cpu_alloc_size) {
        log_info("CPU_ALLOC_SIZE(1) = %zu", CPU_ALLOC_SIZE(1));
        log_info("CPU_ALLOC_SIZE(9) = %zu", CPU_ALLOC_SIZE(9));
        log_info("CPU_ALLOC_SIZE(64) = %zu", CPU_ALLOC_SIZE(64));
        log_info("CPU_ALLOC_SIZE(65) = %zu", CPU_ALLOC_SIZE(65));
        log_info("CPU_ALLOC_SIZE(1024) = %zu", CPU_ALLOC_SIZE(1024));
        log_info("CPU_ALLOC_SIZE(1025) = %zu", CPU_ALLOC_SIZE(1025));
        log_info("CPU_ALLOC_SIZE(8191) = %zu", CPU_ALLOC_SIZE(8191));
}

TEST(cpu_set_add) {
        _cleanup_(cpu_set_done) CPUSet c = {};

        for (size_t i = 0; i < 8192; i++)
                ASSERT_OK(cpu_set_add(&c, 8191));

        ASSERT_ERROR(cpu_set_add(&c, 8192), ERANGE);
        ASSERT_ERROR(cpu_set_add(&c, SIZE_MAX), ERANGE);
}

TEST(cpu_set_add_range) {
        _cleanup_(cpu_set_done) CPUSet c = {};

        ASSERT_ERROR(cpu_set_add_range(&c, 0, 8192), ERANGE);
        ASSERT_ERROR(cpu_set_add_range(&c, 0, SIZE_MAX), ERANGE);
        ASSERT_SIGNAL(cpu_set_add_range(&c, 100, 0), SIGABRT);

        ASSERT_OK(cpu_set_add_range(&c, 0, 0));
        ASSERT_OK(cpu_set_add_range(&c, 0, 8191));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
