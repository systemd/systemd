/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "extract-word.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "parse-util.h"
#include "string-util.h"

char* cpu_set_to_string(const cpu_set_t *set, size_t setsize) {
        _cleanup_free_ char *str = NULL;
        size_t allocated = 0, len = 0;
        int i, r;

        for (i = 0; (size_t) i < setsize * 8; i++) {
                if (!CPU_ISSET_S(i, setsize, set))
                        continue;

                if (!GREEDY_REALLOC(str, allocated, len + 1 + DECIMAL_STR_MAX(int)))
                        return NULL;

                r = sprintf(str + len, len > 0 ? " %d" : "%d", i);
                assert_se(r > 0);
                len += r;
        }

        return TAKE_PTR(str) ?: strdup("");
}

char *cpu_set_to_range(const cpu_set_t *set, size_t setsize) {
        int i, r, range_start = 0, range_end;
        _cleanup_free_ char *str = NULL;
        size_t allocated = 0, len = 0;
        bool in_range = false;

        for (i = 0; (size_t) i < setsize * 8; i++) {
                bool b = !!CPU_ISSET_S(i, setsize, set);

                if (b) {
                        if (in_range)
                                range_end++;
                        else {
                                range_start = range_end = i;
                                in_range = true;
                        }
                } else if (!b && in_range) {
                        in_range = false;

                        if (!GREEDY_REALLOC(str, allocated, len + 2 + 2 * DECIMAL_STR_MAX(int)))
                                return NULL;

                        r = sprintf(str + len, len > 0 ? " %d-%d" : "%d-%d", range_start, range_end);
                        assert_se(r > 0);
                        len += r;
                }
        }

        if (in_range) {
                if (!GREEDY_REALLOC(str, allocated, len + 2 + 2 * DECIMAL_STR_MAX(int)))
                        return NULL;

                r = sprintf(str + len, len > 0 ? " %d-%d" : "%d-%d", range_start, range_end);
                assert_se(r > 0);
        }

        return TAKE_PTR(str) ?: strdup("");
}

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

static cpu_set_t* cpu_set_realloc(cpu_set_t **cpu_set, size_t *allocated, unsigned ncpus) {
        size_t need;

        need = CPU_ALLOC_SIZE(ncpus);
        if (need > *allocated) {
                cpu_set_t *t;

                t = realloc(*cpu_set, need);
                if (!t)
                        return NULL;

                memzero(t + *allocated, need - *allocated);
                *cpu_set = t;
                *allocated = need;
        }

        return *cpu_set;
}

static int cpu_set_add(cpu_set_t **cpu_set, size_t *allocated, unsigned cpu) {
        if (cpu >= 8192)
                /* As of kernel 5.1, CONFIG_NR_CPUS can be set to 8192 on PowerPC */
                return -ERANGE;

        if (!cpu_set_realloc(cpu_set, allocated, cpu + 1))
                return -ENOMEM;

        CPU_SET_S(cpu, *allocated, *cpu_set);
        return 0;
}

int cpu_set_add_all(cpu_set_t **cpu_set, size_t *allocated, const cpu_set_t *b, size_t b_allocated) {
        int r;

        /* Do this backwards, so if we fail, we fail before changing anything. */
        for (unsigned cpu_p1 = b_allocated * 8; cpu_p1 > 0; cpu_p1--)
                if (CPU_ISSET_S(cpu_p1 - 1, b_allocated, b)) {
                        r = cpu_set_add(cpu_set, allocated, cpu_p1 - 1);
                        if (r < 0)
                                return r;
                }

        return 0;
}

int parse_cpu_set_full(
                const char *rvalue,
                cpu_set_t **cpu_set,
                size_t *allocated,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_cpu_free_ cpu_set_t *c = NULL;
        size_t alloc = 0;
        const char *p = rvalue;

        assert(rvalue);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned cpu_lower, cpu_upper;
                int r;

                r = extract_first_word(&p, &word, WHITESPACE ",", EXTRACT_QUOTES);
                if (r == -ENOMEM)
                        return warn ? log_oom() : -ENOMEM;
                if (r < 0)
                        return warn ? log_syntax(unit, LOG_ERR, filename, line, r, "Invalid value for %s: %s", lvalue, rvalue) : r;
                if (r == 0)
                        break;

                r = parse_range(word, &cpu_lower, &cpu_upper);
                if (r < 0)
                        return warn ? log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse CPU affinity '%s'", word) : r;

                if (cpu_lower > cpu_upper) {
                        if (warn)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Range '%s' is invalid, %u > %u, ignoring.",
                                           word, cpu_lower, cpu_upper);

                        /* Make sure something is allocated, to distinguish this from the empty case */
                        if (!cpu_set_realloc(&c, &alloc, 1))
                                return -ENOMEM;
                }

                for (unsigned cpu_p1 = MIN(cpu_upper, UINT_MAX-1) + 1; cpu_p1 > cpu_lower; cpu_p1--) {
                        r = cpu_set_add(&c, &alloc, cpu_p1 - 1);
                        if (r < 0)
                                return warn ? log_syntax(unit, LOG_ERR, filename, line, r,
                                                         "Cannot add CPU %u to set: %m", cpu_p1 - 1) : r;
                }
        }

        /* On success, sets *cpu_set and *allocated */
        *cpu_set = TAKE_PTR(c);
        *allocated = alloc;

        return 0;
}

int parse_cpu_set_extend(
                const char *rvalue,
                cpu_set_t **old,
                size_t *old_allocated,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_cpu_free_ cpu_set_t *cpuset = NULL;
        size_t allocated;
        int r;

        r = parse_cpu_set_full(rvalue, &cpuset, &allocated, true, unit, filename, line, lvalue);
        if (r < 0)
                return r;

        if (allocated == 0) {
                /* An empty assignment resets the CPU list */
                *old = cpu_set_mfree(*old);
                *old_allocated = 0;
                return 0;
        }

        if (!*old) {
                *old = TAKE_PTR(cpuset);
                *old_allocated = allocated;
                return 0;
        }

        return cpu_set_add_all(old, old_allocated, cpuset, allocated);
}

int cpu_set_to_dbus(const cpu_set_t *set, size_t allocated, char **ret) {
        char *out;
        unsigned cpu;

        assert(set);
        assert(ret);

        out = new0(char, allocated);
        if (!out)
                return -ENOMEM;

        for (cpu = 0; cpu < allocated * 8; cpu++)
                if (CPU_ISSET_S(cpu, allocated, set))
                        out[cpu / 8] |= 1u << (cpu % 8);

        *ret = TAKE_PTR(out);

        return 0;
}

int cpu_set_from_dbus(const char *bits, size_t size, cpu_set_t **set, size_t *allocated) {
        _cleanup_cpu_free_ cpu_set_t *s = NULL;
        size_t alloc = 0;
        unsigned cpu;

        assert(bits);
        assert(set);
        assert(allocated);

        for (cpu = size * 8; cpu > 0; cpu--)
                if (bits[(cpu - 1) / 8] & (1u << ((cpu - 1) % 8))) {
                        int r;

                        r = cpu_set_add(&s, &alloc, cpu - 1);
                        if (r < 0)
                                return r;
                }

        *set = TAKE_PTR(s);
        *allocated = alloc;

        return 0;

}
