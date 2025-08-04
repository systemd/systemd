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

void cpu_set_done(CPUSet *c) {
        assert(c);

        if (c->set)
                CPU_FREE(c->set);

        *c = (CPUSet) {};
}

int cpu_set_realloc(CPUSet *c, size_t n) {
        assert(c);

        if (n > CPU_SET_MAX_NCPU)
                return -ERANGE;

        n = CPU_ALLOC_SIZE(n);
        if (n <= c->allocated) {
                assert(c->set || n == 0);
                return 0;
        }

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

int cpu_set_add_set(CPUSet *c, const CPUSet *src) {
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

int cpu_set_add_range(CPUSet *c, size_t start, size_t end) {
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

int cpu_set_add_all(CPUSet *c) {
        assert(c);

        long m = sysconf(_SC_NPROCESSORS_ONLN);
        if (m < 0)
                return -errno;
        if (m == 0)
                return -ENXIO;

        return cpu_set_add_range(c, 0, m - 1);
}

int config_parse_cpu_set(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype, /* 0 when used as conf parser, 1 when used as usual parser */
                const char *rvalue,
                void *data,
                void *userdata) {

        CPUSet *c = ASSERT_PTR(data);
        int r, level = ltype ? LOG_DEBUG : LOG_ERR;
        bool critical = ltype;

        assert(critical || lvalue);

        if (isempty(rvalue)) {
                cpu_set_done(c);
                return 1;
        }

        _cleanup_(cpu_set_done) CPUSet cpuset = {};
        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, WHITESPACE ",", EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom_full(level);
                if (r < 0) {
                        if (critical)
                                return log_debug_errno(r, "Failed to parse CPU set: %s", rvalue);

                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s= setting, ignoring assignment: %s",
                                   lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                unsigned lower, upper;
                r = parse_range(word, &lower, &upper);
                if (r < 0) {
                        if (critical)
                                return log_debug_errno(r, "Failed to parse CPU range: %s", word);

                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse CPU range, ignoring assignment: %s", word);
                        continue;
                }

                if (lower > upper) {
                        if (critical)
                                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid CPU range (%u > %u): %s",
                                                       lower, upper, word);

                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid CPU range (%u > %u), ignoring assignment: %s",
                                   lower, upper, word);
                        continue;
                }

                r = cpu_set_add_range(&cpuset, lower, upper);
                if (r == -ENOMEM)
                        return log_oom_full(level);
                if (r < 0) {
                        if (critical)
                                return log_debug_errno(r, "Failed to set CPU(s) '%s': %m", word);

                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to set CPU(s), ignoring assignment: %s", word);
                }
        }

        if (!c->set) {
                *c = TAKE_STRUCT(cpuset);
                return 1;
        }

        r = cpu_set_add_set(c, &cpuset);
        if (r == -ENOMEM)
                return log_oom_full(level);
        assert(r >= 0);

        return 1;
}

int parse_cpu_set(const char *s, CPUSet *ret) {
        _cleanup_(cpu_set_done) CPUSet c = {};
        int r;

        assert(s);
        assert(ret);

        r = config_parse_cpu_set(
                        /* unit = */ NULL,
                        /* filename = */ NULL,
                        /* line = */ 0,
                        /* section = */ NULL,
                        /* section_line = */ 0,
                        /* lvalue = */ NULL,
                        /* ltype = */ 1,
                        /* rvalue = */ s,
                        /* data = */ &c,
                        /* userdata = */ NULL);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(c);
        return 0;
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

int cpu_set_to_dbus(const CPUSet *c, uint8_t **ret, size_t *ret_size) {
        assert(c);
        assert(ret);
        assert(ret_size);

        uint8_t *buf = new0(uint8_t, c->allocated);
        if (!buf)
                return -ENOMEM;

        for (size_t i = 0; i < c->allocated * 8; i++)
                if (CPU_ISSET_S(i, c->allocated, c->set))
                        SET_BIT(buf[i / 8], i % 8);

        *ret = buf;
        *ret_size = c->allocated;
        return 0;
}

int cpu_set_from_dbus(const uint8_t *bits, size_t size, CPUSet *ret) {
        _cleanup_(cpu_set_done) CPUSet c = {};
        int r;

        assert(bits || size == 0);
        assert(ret);

        r = cpu_set_realloc(&c, size * 8);
        if (r < 0)
                return r;

        for (size_t i = 0; i < size * 8; i++)
                if (BIT_SET(bits[i / 8], i % 8))
                        CPU_SET_S(i, c.allocated, c.set);

        *ret = TAKE_STRUCT(c);
        return 0;
}
