/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "string-util.h"
#include "tests.h"
#include "macro.h"

TEST(parse_cpu_set) {
        CPUSet c = {};
        _cleanup_free_ char *str = NULL;
        int cpu;

        /* Single value */
        assert_se(parse_cpu_set_full("0", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.set);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_ISSET_S(0, c.allocated, c.set));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 1);

        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "1");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Simple range (from CPUAffinity example) */
        assert_se(parse_cpu_set_full("1 2 4", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.set);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_ISSET_S(1, c.allocated, c.set));
        assert_se(CPU_ISSET_S(2, c.allocated, c.set));
        assert_se(CPU_ISSET_S(4, c.allocated, c.set));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 3);

        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "1-2 4");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "16");
        str = mfree(str);
        cpu_set_reset(&c);

        /* A more interesting range */
        assert_se(parse_cpu_set_full("0 1 2 3 8 9 10 11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));

        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0-3 8-11");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "f0f");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Quoted strings */
        assert_se(parse_cpu_set_full("8 '9' 10 \"11\"", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "8-11");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "f00");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Use commas as separators */
        assert_se(parse_cpu_set_full("0,1,2,3 8,9,10,11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Commas with spaces (and trailing comma, space) */
        assert_se(parse_cpu_set_full("0, 1, 2, 3, 4, 5, 6, 7, 63, ", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 9);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));

        assert_se(CPU_ISSET_S(63, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0-7 63");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "80000000,000000ff");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Ranges */
        assert_se(parse_cpu_set_full("0-3,8-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);
        assert_se(parse_cpu_set_full("36-39,44-47", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 36; cpu < 40; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 44; cpu < 48; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "f0f0,00000000");
        str = mfree(str);
        cpu_set_reset(&c);
        assert_se(parse_cpu_set_full("64-71", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 64; cpu < 72; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "ff,00000000,00000000");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Ranges with trailing comma, space */
        assert_se(parse_cpu_set_full("0-3  8-11, ", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0-3 8-11");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "f0f");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Negative range (returns empty cpu_set) */
        assert_se(parse_cpu_set_full("3-0", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 0);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "0");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Overlapping ranges */
        assert_se(parse_cpu_set_full("0-7 4-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0-11");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "fff");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Mix ranges and individual CPUs */
        assert_se(parse_cpu_set_full("0,2 4-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= DIV_ROUND_UP(sizeof(__cpu_mask), 8));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 10);
        assert_se(CPU_ISSET_S(0, c.allocated, c.set));
        assert_se(CPU_ISSET_S(2, c.allocated, c.set));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "0 2 4-11");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "ff5");
        str = mfree(str);
        cpu_set_reset(&c);

        /* Garbage */
        assert_se(parse_cpu_set_full("0 1 2 3 garbage", &c, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c.set);
        assert_se(c.allocated == 0);

        /* Range with garbage */
        assert_se(parse_cpu_set_full("0-3 8-garbage", &c, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c.set);
        assert_se(c.allocated == 0);

        /* Empty string */
        assert_se(parse_cpu_set_full("", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(!c.set);                /* empty string returns NULL */
        assert_se(c.allocated == 0);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        ASSERT_STREQ(str, "0");
        str = mfree(str);

        /* Runaway quoted string */
        assert_se(parse_cpu_set_full("0 1 2 3 \"4 5 6 7 ", &c, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c.set);
        assert_se(c.allocated == 0);

        /* Maximum allocation */
        assert_se(parse_cpu_set_full("8000-8191", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 192);
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        assert_se(str = cpu_set_to_range_string(&c));
        log_info("cpu_set_to_range_string: %s", str);
        ASSERT_STREQ(str, "8000-8191");
        str = mfree(str);
        assert_se(str = cpu_set_to_mask_string(&c));
        log_info("cpu_set_to_mask_string: %s", str);
        for (size_t i = 0; i < strlen(str); i++) {
                if (i < 54) {
                        if (i >= 8 && (i + 1) % 9 == 0)
                                assert_se(str[i] == ',');
                        else
                                assert_se(str[i] == 'f');
                }
                else {
                        if (i >= 8 && (i + 1) % 9 == 0)
                                assert_se(str[i] == ',');
                        else
                                assert_se(str[i] == '0');
                }
        }
        str = mfree(str);
        cpu_set_reset(&c);
}

TEST(parse_cpu_set_extend) {
        CPUSet c = {};
        _cleanup_free_ char *s1 = NULL, *s2 = NULL;

        assert_se(parse_cpu_set_extend("1 3", &c, true, NULL, "fake", 1, "CPUAffinity") == 1);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 2);
        assert_se(s1 = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", s1);

        assert_se(parse_cpu_set_extend("4", &c, true, NULL, "fake", 1, "CPUAffinity") == 1);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 3);
        assert_se(s2 = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", s2);

        assert_se(parse_cpu_set_extend("", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(!c.set);
        assert_se(c.allocated == 0);
        log_info("cpu_set_to_string: (null)");
}

TEST(cpu_set_to_from_dbus) {
        _cleanup_(cpu_set_reset) CPUSet c = {}, c2 = {};
        _cleanup_free_ char *s = NULL;

        assert_se(parse_cpu_set_extend("1 3 8 100-200", &c, true, NULL, "fake", 1, "CPUAffinity") == 1);
        assert_se(s = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", s);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 104);

        _cleanup_free_ uint8_t *array = NULL;
        size_t allocated;
        static const char expected[32] =
                "\x0A\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                "\xFF\xFF\xFF\xFF\xFF\x01";

        assert_se(cpu_set_to_dbus(&c, &array, &allocated) == 0);
        assert_se(array);
        assert_se(allocated == c.allocated);

        assert_se(allocated <= sizeof expected);
        assert_se(allocated >= DIV_ROUND_UP(201u, 8u)); /* We need at least 201 bits for our mask */
        assert_se(memcmp(array, expected, allocated) == 0);

        assert_se(cpu_set_from_dbus(array, allocated, &c2) == 0);
        assert_se(c2.set);
        assert_se(c2.allocated == c.allocated);
        assert_se(memcmp(c.set, c2.set, c.allocated) == 0);
}

TEST(cpus_in_affinity_mask) {
        int r;

        r = cpus_in_affinity_mask();
        assert_se(r > 0);
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

DEFINE_TEST_MAIN(LOG_INFO);
