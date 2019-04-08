/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <syslog.h>

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "extract-word.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"

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

int parse_cpu_set_internal(
                const char *rvalue,
                cpu_set_t **cpu_set,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_cpu_free_ cpu_set_t *c = NULL;
        const char *p = rvalue;
        unsigned ncpus = 0;

        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned cpu, cpu_lower, cpu_upper;
                int r;

                r = extract_first_word(&p, &word, WHITESPACE ",", EXTRACT_QUOTES);
                if (r == -ENOMEM)
                        return warn ? log_oom() : -ENOMEM;
                if (r < 0)
                        return warn ? log_syntax(unit, LOG_ERR, filename, line, r, "Invalid value for %s: %s", lvalue, rvalue) : r;
                if (r == 0)
                        break;

                if (!c) {
                        c = cpu_set_malloc(&ncpus);
                        if (!c)
                                return warn ? log_oom() : -ENOMEM;
                }

                r = parse_range(word, &cpu_lower, &cpu_upper);
                if (r < 0)
                        return warn ? log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CPU affinity '%s'", word) : r;
                if (cpu_lower >= ncpus || cpu_upper >= ncpus)
                        return warn ? log_syntax(unit, LOG_ERR, filename, line, EINVAL, "CPU out of range '%s' ncpus is %u", word, ncpus) : -EINVAL;

                if (cpu_lower > cpu_upper) {
                        if (warn)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Range '%s' is invalid, %u > %u, ignoring", word, cpu_lower, cpu_upper);
                        continue;
                }

                for (cpu = cpu_lower; cpu <= cpu_upper; cpu++)
                        CPU_SET_S(cpu, CPU_ALLOC_SIZE(ncpus), c);
        }

        /* On success, sets *cpu_set and returns ncpus for the system. */
        if (c)
                *cpu_set = TAKE_PTR(c);

        return (int) ncpus;
}
