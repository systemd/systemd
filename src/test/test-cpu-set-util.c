/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "macro.h"

static void test_parse_cpu_set(void) {
        cpu_set_t *c = NULL;
        int ncpus;
        int cpu;

        /* Simple range (from CPUAffinity example) */
        ncpus = parse_cpu_set_and_warn("1 2", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_ISSET_S(1, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_ISSET_S(2, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 2);
        c = cpu_set_mfree(c);

        /* A more interesting range */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 8 9 10 11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Quoted strings */
        ncpus = parse_cpu_set_and_warn("8 '9' 10 \"11\"", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Use commas as separators */
        ncpus = parse_cpu_set_and_warn("0,1,2,3 8,9,10,11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Commas with spaces (and trailing comma, space) */
        ncpus = parse_cpu_set_and_warn("0, 1, 2, 3, 4, 5, 6, 7, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Ranges */
        ncpus = parse_cpu_set_and_warn("0-3,8-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Ranges with trailing comma, space */
        ncpus = parse_cpu_set_and_warn("0-3  8-11, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Negative range (returns empty cpu_set) */
        ncpus = parse_cpu_set_and_warn("3-0", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 0);
        c = cpu_set_mfree(c);

        /* Overlapping ranges */
        ncpus = parse_cpu_set_and_warn("0-7 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Mix ranges and individual CPUs */
        ncpus = parse_cpu_set_and_warn("0,1 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 10);
        assert_se(CPU_ISSET_S(0, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_ISSET_S(1, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = cpu_set_mfree(c);

        /* Garbage */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 garbage", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);

        /* Range with garbage */
        ncpus = parse_cpu_set_and_warn("0-3 8-garbage", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);

        /* Empty string */
        c = NULL;
        ncpus = parse_cpu_set_and_warn("", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus == 0);  /* empty string returns 0 */
        assert_se(!c);

        /* Runaway quoted string */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 \"4 5 6 7 ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);
}

int main(int argc, char *argv[]) {
        test_parse_cpu_set();

        return 0;
}
