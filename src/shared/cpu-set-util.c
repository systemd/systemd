/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <syslog.h>

#include "alloc-util.h"
#include "cpu-set-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

char* cpu_set_to_string(const CPUSet *a) {
        _cleanup_free_ char *str = NULL;
        size_t len = 0;
        int i, r;

        for (i = 0; (size_t) i < a->allocated * 8; i++) {
                if (!CPU_ISSET_S(i, a->allocated, a->set))
                        continue;

                if (!GREEDY_REALLOC(str, len + 1 + DECIMAL_STR_MAX(int)))
                        return NULL;

                r = sprintf(str + len, len > 0 ? " %d" : "%d", i);
                assert_se(r > 0);
                len += r;
        }

        return TAKE_PTR(str) ?: strdup("");
}

char* cpu_set_to_range_string(const CPUSet *set) {
        unsigned range_start = 0, range_end;
        _cleanup_free_ char *str = NULL;
        bool in_range = false;
        size_t len = 0;
        int r;

        for (unsigned i = 0; i < set->allocated * 8; i++)
                if (CPU_ISSET_S(i, set->allocated, set->set)) {
                        if (in_range)
                                range_end++;
                        else {
                                range_start = range_end = i;
                                in_range = true;
                        }
                } else if (in_range) {
                        in_range = false;

                        if (!GREEDY_REALLOC(str, len + 2 + 2 * DECIMAL_STR_MAX(unsigned)))
                                return NULL;

                        if (range_end > range_start)
                                r = sprintf(str + len, len > 0 ? " %u-%u" : "%u-%u", range_start, range_end);
                        else
                                r = sprintf(str + len, len > 0 ? " %u" : "%u", range_start);
                        assert_se(r > 0);
                        len += r;
                }

        if (in_range) {
                if (!GREEDY_REALLOC(str, len + 2 + 2 * DECIMAL_STR_MAX(int)))
                        return NULL;

                if (range_end > range_start)
                        r = sprintf(str + len, len > 0 ? " %u-%u" : "%u-%u", range_start, range_end);
                else
                        r = sprintf(str + len, len > 0 ? " %u" : "%u", range_start);
                assert_se(r > 0);
        }

        return TAKE_PTR(str) ?: strdup("");
}

char* cpu_set_to_mask_string(const CPUSet *a) {
        _cleanup_free_ char *str = NULL;
        size_t len = 0;
        bool found_nonzero = false;

        assert(a);

        /* Return CPU set in hexadecimal bitmap mask, e.g.
         *   CPU   0 ->  "1"
         *   CPU   1 ->  "2"
         *   CPU 0,1 ->  "3"
         *   CPU 0-3 ->  "f"
         *   CPU 0-7 -> "ff"
         *   CPU 4-7 -> "f0"
         *   CPU   7 -> "80"
         *   None    ->  "0"
         *
         * When there are more than 32 CPUs, separate every 32 CPUs by comma, e.g.
         *  CPU 0-47 -> "ffff,ffffffff"
         *  CPU 0-63 -> "ffffffff,ffffffff"
         *  CPU 0-71 -> "ff,ffffffff,ffffffff" */

        for (ssize_t i = a->allocated * 8; i >= 0; i -= 4) {
                uint8_t m = 0;

                for (size_t j = 0; j < 4; j++)
                        if (CPU_ISSET_S(i + j, a->allocated, a->set))
                                m |= 1U << j;

                if (!found_nonzero)
                        found_nonzero = m > 0;

                if (!found_nonzero && m == 0)
                        /* Skip leading zeros */
                        continue;

                if (!GREEDY_REALLOC(str, len + 3))
                        return NULL;

                str[len++] = hexchar(m);
                if (i >= 4 && i % 32 == 0)
                        /* Separate by comma for each 32 CPUs. */
                        str[len++] = ',';
                str[len] = 0;
        }

        return TAKE_PTR(str) ?: strdup("0");
}

CPUSet* cpu_set_free(CPUSet *c) {
        if (!c)
                return c;

        cpu_set_reset(c);
        return mfree(c);
}

int cpu_set_realloc(CPUSet *cpu_set, unsigned ncpus) {
        size_t need;

        assert(cpu_set);

        need = CPU_ALLOC_SIZE(ncpus);
        if (need > cpu_set->allocated) {
                cpu_set_t *t;

                t = realloc(cpu_set->set, need);
                if (!t)
                        return -ENOMEM;

                memzero((uint8_t*) t + cpu_set->allocated, need - cpu_set->allocated);

                cpu_set->set = t;
                cpu_set->allocated = need;
        }

        return 0;
}

int cpu_set_add(CPUSet *cpu_set, unsigned cpu) {
        int r;

        if (cpu >= 8192)
                /* As of kernel 5.1, CONFIG_NR_CPUS can be set to 8192 on PowerPC */
                return -ERANGE;

        r = cpu_set_realloc(cpu_set, cpu + 1);
        if (r < 0)
                return r;

        CPU_SET_S(cpu, cpu_set->allocated, cpu_set->set);
        return 0;
}

int cpu_set_add_all(CPUSet *a, const CPUSet *b) {
        int r;

        /* Do this backwards, so if we fail, we fail before changing anything. */
        for (unsigned cpu_p1 = b->allocated * 8; cpu_p1 > 0; cpu_p1--)
                if (CPU_ISSET_S(cpu_p1 - 1, b->allocated, b->set)) {
                        r = cpu_set_add(a, cpu_p1 - 1);
                        if (r < 0)
                                return r;
                }

        return 1;
}

int parse_cpu_set_full(
                const char *rvalue,
                CPUSet *cpu_set,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_(cpu_set_reset) CPUSet c = {};
        const char *p = ASSERT_PTR(rvalue);

        assert(cpu_set);

        for (;;) {
                _cleanup_free_ char *word = NULL;
                unsigned cpu_lower, cpu_upper;
                int r;

                r = extract_first_word(&p, &word, WHITESPACE ",", EXTRACT_UNQUOTE);
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
                        r = cpu_set_realloc(&c, 1);
                        if (r < 0)
                                return r;
                }

                for (unsigned cpu_p1 = MIN(cpu_upper, UINT_MAX-1) + 1; cpu_p1 > cpu_lower; cpu_p1--) {
                        r = cpu_set_add(&c, cpu_p1 - 1);
                        if (r < 0)
                                return warn ? log_syntax(unit, LOG_ERR, filename, line, r,
                                                         "Cannot add CPU %u to set: %m", cpu_p1 - 1) : r;
                }
        }

        *cpu_set = TAKE_STRUCT(c);

        return 0;
}

int parse_cpu_set_extend(
                const char *rvalue,
                CPUSet *old,
                bool warn,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        _cleanup_(cpu_set_reset) CPUSet cpuset = {};
        int r;

        assert(old);

        r = parse_cpu_set_full(rvalue, &cpuset, true, unit, filename, line, lvalue);
        if (r < 0)
                return r;

        if (!cpuset.set) {
                /* An empty assignment resets the CPU list */
                cpu_set_reset(old);
                return 0;
        }

        if (!old->set) {
                *old = TAKE_STRUCT(cpuset);
                return 1;
        }

        return cpu_set_add_all(old, &cpuset);
}

int cpus_in_affinity_mask(void) {
        size_t n = 16;
        int r;

        for (;;) {
                cpu_set_t *c;

                c = CPU_ALLOC(n);
                if (!c)
                        return -ENOMEM;

                if (sched_getaffinity(0, CPU_ALLOC_SIZE(n), c) >= 0) {
                        int k;

                        k = CPU_COUNT_S(CPU_ALLOC_SIZE(n), c);
                        CPU_FREE(c);

                        if (k <= 0)
                                return -EINVAL;

                        return k;
                }

                r = -errno;
                CPU_FREE(c);

                if (r != -EINVAL)
                        return r;
                if (n > SIZE_MAX/2)
                        return -ENOMEM;
                n *= 2;
        }
}

int cpu_set_to_dbus(const CPUSet *set, uint8_t **ret, size_t *allocated) {
        uint8_t *out;

        assert(set);
        assert(ret);

        out = new0(uint8_t, set->allocated);
        if (!out)
                return -ENOMEM;

        for (unsigned cpu = 0; cpu < set->allocated * 8; cpu++)
                if (CPU_ISSET_S(cpu, set->allocated, set->set))
                        out[cpu / 8] |= 1u << (cpu % 8);

        *ret = out;
        *allocated = set->allocated;
        return 0;
}

int cpu_set_from_dbus(const uint8_t *bits, size_t size, CPUSet *set) {
        _cleanup_(cpu_set_reset) CPUSet s = {};
        int r;

        assert(bits);
        assert(set);

        for (unsigned cpu = size * 8; cpu > 0; cpu--)
                if (bits[(cpu - 1) / 8] & (1u << ((cpu - 1) % 8))) {
                        r = cpu_set_add(&s, cpu - 1);
                        if (r < 0)
                                return r;
                }

        *set = TAKE_STRUCT(s);
        return 0;
}

int cpu_mask_add_all(CPUSet *mask) {
        long m;
        int r;

        assert(mask);

        m = sysconf(_SC_NPROCESSORS_ONLN);
        if (m < 0)
                return -errno;

        for (unsigned i = 0; i < (unsigned) m; i++) {
                r = cpu_set_add(mask, i);
                if (r < 0)
                        return r;
        }

        return 0;
}
