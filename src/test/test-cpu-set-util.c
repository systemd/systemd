/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "macro.h"

static void test_parse_cpu_set(void) {
        CPUSet c = {};
        _cleanup_free_ char *str = NULL;
        int cpu;

        log_info("/* %s */", __func__);

        /* Simple range (from CPUAffinity example) */
        assert_se(parse_cpu_set_full("1 2", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.set);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_ISSET_S(1, c.allocated, c.set));
        assert_se(CPU_ISSET_S(2, c.allocated, c.set));
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 2);

        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* A more interesting range */
        assert_se(parse_cpu_set_full("0 1 2 3 8 9 10 11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Quoted strings */
        assert_se(parse_cpu_set_full("8 '9' 10 \"11\"", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Use commas as separators */
        assert_se(parse_cpu_set_full("0,1,2,3 8,9,10,11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
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
        assert_se(parse_cpu_set_full("0, 1, 2, 3, 4, 5, 6, 7, ", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Ranges */
        assert_se(parse_cpu_set_full("0-3,8-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Ranges with trailing comma, space */
        assert_se(parse_cpu_set_full("0-3  8-11, ", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Negative range (returns empty cpu_set) */
        assert_se(parse_cpu_set_full("3-0", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 0);
        cpu_set_reset(&c);

        /* Overlapping ranges */
        assert_se(parse_cpu_set_full("0-7 4-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
        str = mfree(str);
        cpu_set_reset(&c);

        /* Mix ranges and individual CPUs */
        assert_se(parse_cpu_set_full("0,1 4-11", &c, true, NULL, "fake", 1, "CPUAffinity") >= 0);
        assert_se(c.allocated >= sizeof(__cpu_mask) / 8);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 10);
        assert_se(CPU_ISSET_S(0, c.allocated, c.set));
        assert_se(CPU_ISSET_S(1, c.allocated, c.set));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, c.allocated, c.set));
        assert_se(str = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", str);
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
        cpu_set_reset(&c);
}

static void test_parse_cpu_set_extend(void) {
        CPUSet c = {};
        _cleanup_free_ char *s1 = NULL, *s2 = NULL;

        log_info("/* %s */", __func__);

        assert_se(parse_cpu_set_extend("1 3", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 2);
        assert_se(s1 = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", s1);

        assert_se(parse_cpu_set_extend("4", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(CPU_COUNT_S(c.allocated, c.set) == 3);
        assert_se(s2 = cpu_set_to_string(&c));
        log_info("cpu_set_to_string: %s", s2);

        assert_se(parse_cpu_set_extend("", &c, true, NULL, "fake", 1, "CPUAffinity") == 0);
        assert_se(!c.set);
        assert_se(c.allocated == 0);
        log_info("cpu_set_to_string: (null)");
}

static void test_cpus_in_affinity_mask(void) {
        int r;

        r = cpus_in_affinity_mask();
        assert(r > 0);
        log_info("cpus_in_affinity_mask: %d", r);
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
        test_parse_cpu_set_extend();
        test_cpus_in_affinity_mask();

        return 0;
}
