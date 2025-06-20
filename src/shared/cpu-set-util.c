/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "cpu-set-util.h"
#include "extract-word.h"
#include "hexdecoct.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"

/* As of kernel 5.1, CONFIG_NR_CPUS can be set to 8192 on PowerPC */
#define CPU_SET_MAX_NCPU 8192

char* cpu_set_to_string(const CPUSet *c) {
        _cleanup_free_ char *str = NULL;

        assert(c);

        for (size_t i = 0; i < c->allocated * 8; i++) {
                if (!CPU_ISSET_S(i, c->allocated, c->set))
                        continue;

                if (strextendf_with_separator(&str, " ", "%zu", i) < 0)
                        return NULL;
        }

        return TAKE_PTR(str) ?: strdup("");
}

static int add_range(char **str, size_t start, size_t end) {
        assert(str);
        assert(start <= end);

        if (start == end)
                return strextendf_with_separator(str, " ", "%zu", start);

        return strextendf_with_separator(str, " ", "%zu-%zu", start, end);
}

char* cpu_set_to_range_string(const CPUSet *c) {
        _cleanup_free_ char *str = NULL;
        size_t start = 0, end;
        bool in_range = false;

        assert(c);

        for (size_t i = 0; i < c->allocated * 8; i++) {
                if (CPU_ISSET_S(i, c->allocated, c->set)) {
                        if (in_range)
                                end++;
                        else {
                                start = end = i;
                                in_range = true;
                        }
                        continue;
                }

                if (in_range && add_range(&str, start, end) < 0)
                        return NULL;

                in_range = false;
        }

        if (in_range && add_range(&str, start, end) < 0)
                return NULL;

        return TAKE_PTR(str) ?: strdup("");
}

char* cpu_set_to_mask_string(const CPUSet *c) {
        _cleanup_free_ char *str = NULL;
        bool found_nonzero = false;
        int r;

        assert(c);

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

        for (size_t i = c->allocated * 8; i > 0; ) {
                uint32_t m = 0;

                for (int j = (i % 32 ?: 32) - 1; j >= 0; j--)
                        if (CPU_ISSET_S(--i, c->allocated, c->set))
                                SET_BIT(m, j);

                if (!found_nonzero) {
                        if (m == 0)
                                continue;

                        r = strextendf_with_separator(&str, ",", "%" PRIx32, m);
                } else
                        r = strextendf_with_separator(&str, ",", "%08" PRIx32, m);
                if (r < 0)
                        return NULL;

                found_nonzero = true;
        }

        return TAKE_PTR(str) ?: strdup("0");
}

CPUSet* cpu_set_free(CPUSet *c) {
        if (!c)
                return c;

        cpu_set_reset(c);
        return mfree(c);
}

int cpu_set_realloc(CPUSet *c, size_t n) {
        assert(c);

        if (n > CPU_SET_MAX_NCPU)
                return -ERANGE;

        n = CPU_ALLOC_SIZE(n);
        if (n <= c->allocated)
                return 0;

        if (!GREEDY_REALLOC0(c->set, DIV_ROUND_UP(n, sizeof(cpu_set_t))))
                return -ENOMEM;

        c->allocated = n;
        return 0;
}

int cpu_set_add(CPUSet *c, size_t i) {
        int r;

        assert(c);

        /* cpu_set_realloc() has similar check, but for avoiding overflow. */
        if (i >= CPU_SET_MAX_NCPU)
                return -ERANGE;

        r = cpu_set_realloc(c, i + 1);
        if (r < 0)
                return r;

        CPU_SET_S(i, c->allocated, c->set);
        return 0;
}

int cpu_set_add_all(CPUSet *c, const CPUSet *src) {
        int r;

        assert(c);
        assert(src);

        r = cpu_set_realloc(c, src->allocated * 8);
        if (r < 0)
                return r;

        for (size_t i = 0; i < src->allocated * 8; i++)
                if (CPU_ISSET_S(i, src->allocated, src->set))
                        CPU_SET_S(i, c->allocated, c->set);

        return 1;
}

static int cpu_set_add_range(CPUSet *c, size_t start, size_t end) {
        int r;

        assert(c);
        assert(start <= end);

        /* cpu_set_realloc() has similar check, but for avoiding overflow. */
        if (end >= CPU_SET_MAX_NCPU)
                return -ERANGE;

        r = cpu_set_realloc(c, end + 1);
        if (r < 0)
                return r;

        for (size_t i = start; i <= end; i++)
                CPU_SET_S(i, c->allocated, c->set);

        return 0;
}

int cpu_mask_add_all(CPUSet *c) {
        assert(c);

        long m = sysconf(_SC_NPROCESSORS_ONLN);
        if (m < 0)
                return -errno;
        if (m == 0)
                return -ENXIO;

        return cpu_set_add_range(c, 0, m - 1);
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
