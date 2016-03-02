/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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
        c = mfree(c);

        /* A more interesting range */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 8 9 10 11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Quoted strings */
        ncpus = parse_cpu_set_and_warn("8 '9' 10 \"11\"", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 4);
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Use commas as separators */
        ncpus = parse_cpu_set_and_warn("0,1,2,3 8,9,10,11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Commas with spaces (and trailing comma, space) */
        ncpus = parse_cpu_set_and_warn("0, 1, 2, 3, 4, 5, 6, 7, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 8; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Ranges */
        ncpus = parse_cpu_set_and_warn("0-3,8-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Ranges with trailing comma, space */
        ncpus = parse_cpu_set_and_warn("0-3  8-11, ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 8);
        for (cpu = 0; cpu < 4; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 8; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Negative range (returns empty cpu_set) */
        ncpus = parse_cpu_set_and_warn("3-0", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 0);
        c = mfree(c);

        /* Overlapping ranges */
        ncpus = parse_cpu_set_and_warn("0-7 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 12);
        for (cpu = 0; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

        /* Mix ranges and individual CPUs */
        ncpus = parse_cpu_set_and_warn("0,1 4-11", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus >= 1024);
        assert_se(CPU_COUNT_S(CPU_ALLOC_SIZE(ncpus), c) == 10);
        assert_se(CPU_ISSET_S(0, CPU_ALLOC_SIZE(ncpus), c));
        assert_se(CPU_ISSET_S(1, CPU_ALLOC_SIZE(ncpus), c));
        for (cpu = 4; cpu < 12; cpu++)
                assert_se(CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(ncpus), c));
        c = mfree(c);

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

        /* Runnaway quoted string */
        ncpus = parse_cpu_set_and_warn("0 1 2 3 \"4 5 6 7 ", &c, NULL, "fake", 1, "CPUAffinity");
        assert_se(ncpus < 0);
        assert_se(!c);
}

int main(int argc, char *argv[]) {
        test_parse_cpu_set();

        return 0;
}
