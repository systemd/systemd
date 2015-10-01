/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2015 Lennart Poettering
  Copyright 2015 Filipe Brandenburger

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

#include "util.h"
#include "cpu-set-util.h"

cpu_set_t* cpu_set_malloc(unsigned *ncpus) {
        cpu_set_t *c;
        unsigned n = 1024;

        /* Allocates the cpuset in the right size */

        for (;;) {
                c = CPU_ALLOC(n);
                if (!c)
                        return NULL;

                if (sched_getaffinity(0, CPU_ALLOC_SIZE(n), c) >= 0) {
                        CPU_ZERO_S(CPU_ALLOC_SIZE(n), c);

                        if (ncpus)
                                *ncpus = n;

                        return c;
                }

                CPU_FREE(c);

                if (errno != EINVAL)
                        return NULL;

                n *= 2;
        }
}

int parse_cpu_set_and_warn(
                const char *rvalue,
                cpu_set_t **cpu_set,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        const char *whole_rvalue = rvalue;
        _cleanup_cpu_free_ cpu_set_t *c = NULL;
        unsigned ncpus = 0;

        assert(lvalue);
        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned cpu;
                int r;

                r = extract_first_word(&rvalue, &word, WHITESPACE, EXTRACT_QUOTES);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Invalid value for %s: %s", lvalue, whole_rvalue);
                        return r;
                }
                if (r == 0)
                        break;

                if (!c) {
                        c = cpu_set_malloc(&ncpus);
                        if (!c)
                                return log_oom();
                }

                r = safe_atou(word, &cpu);
                if (r < 0 || cpu >= ncpus) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CPU affinity '%s'", rvalue);
                        return -EINVAL;
                }

                CPU_SET_S(cpu, CPU_ALLOC_SIZE(ncpus), c);
        }

        /* On success, sets *cpu_set and returns ncpus for the system. */
        if (c) {
                *cpu_set = c;
                c = NULL;
        }

        return (int) ncpus;
}
