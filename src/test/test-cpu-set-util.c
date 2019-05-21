/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "macro.h"

static void test_parse_cpu_set(void) {
        cpu_set_t *c = NULL;
        _cleanup_free_ char *str = NULL;
        size_t allocated;
        int cpu;

        /* Simple range (from CPUAffinity example) */
        assert_se(parse_cpu_set_full("1 2", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_ISSET_S(1, allocated, c));
        assert_se(CPU_ISSET_S(2, allocated, c));
        assert_se(CPU_COUNT_S(allocated, c) == 2);

        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* A more interesting range */
        assert_se(parse_cpu_set_full("0 1 2 3 8 9 10 11", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Quoted strings */
        assert_se(parse_cpu_set_full("8 '9' 10 \"11\"", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Use commas as separators */
        assert_se(parse_cpu_set_full("0,1,2,3 8,9,10,11", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Commas with spaces (and trailing comma, space) */
        assert_se(parse_cpu_set_full("0, 1, 2, 3, 4, 5, 6, 7, ", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 8);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Ranges */
        assert_se(parse_cpu_set_full("0-3,8-11", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Ranges with trailing comma, space */
        assert_se(parse_cpu_set_full("0-3  8-11, ", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Negative range (returns empty cpu_set) */
        assert_se(parse_cpu_set_full("3-0", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 0);
        c = cpu_set_mfree(c);

        /* Overlapping ranges */
        assert_se(parse_cpu_set_full("0-7 4-11", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Mix ranges and individual CPUs */
        assert_se(parse_cpu_set_full("0,1 4-11", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(allocated, c) == 10);
        assert_se(CPU_ISSET_S(0, allocated, c));
        assert_se(CPU_ISSET_S(1, allocated, c));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, allocated, c));
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);

        /* Garbage */
        allocated = 0;
        assert_se(parse_cpu_set_full("0 1 2 3 garbage", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c);
        assert_se(allocated == 0);

        /* Range with garbage */
        assert_se(parse_cpu_set_full("0-3 8-garbage", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c);
        assert_se(allocated == 0);

        /* Empty string */
        assert_se(parse_cpu_set_full("", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(!c);                /* empty string returns NULL */
        assert_se(allocated == 0);

        /* Runaway quoted string */
        assert_se(parse_cpu_set_full("0 1 2 3 \"4 5 6 7 ", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") == -EINVAL);
        assert_se(!c);
        assert_se(allocated == 0);

        /* Maximum allocation */
        assert_se(parse_cpu_set_full("8000-8191", &c, &allocated, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(CPU_COUNT_S(allocated, c) == 192);
        assert_se(str = cpu_set_to_string(c, allocated));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        c = cpu_set_mfree(c);
}

int main(int argc, char *argv[]) {
        log_info("CPU_ALLOC_SIZE(1) = %zu", CPU_ALLOC_SIZE(1));
        log_info("CPU_ALLOC_SIZE(9) = %zu", CPU_ALLOC_SIZE(9));
        log_info("CPU_ALLOC_SIZE(64) = %zu", CPU_ALLOC_SIZE(64));
        log_info("CPU_ALLOC_SIZE(65) = %zu", CPU_ALLOC_SIZE(65));
        log_info("CPU_ALLOC_SIZE(1024) = %zu", CPU_ALLOC_SIZE(1024));
        log_info("CPU_ALLOC_SIZE(1025) = %zu", CPU_ALLOC_SIZE(1025));
        log_info("CPU_ALLOC_SIZE(8191) = %zu", CPU_ALLOC_SIZE(8191));

        test_parse_cpu_set();

        return 0;
}
