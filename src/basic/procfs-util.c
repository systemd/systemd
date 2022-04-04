/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "stdio-util.h"
#include "string-util.h"

int procfs_get_pid_max(uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = read_one_line_file("/proc/sys/kernel/pid_max", &value);
        if (r < 0)
                return r;

        return safe_atou64(value, ret);
}

int procfs_get_threads_max(uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = read_one_line_file("/proc/sys/kernel/threads-max", &value);
        if (r < 0)
                return r;

        return safe_atou64(value, ret);
}

int procfs_tasks_set_limit(uint64_t limit) {
        char buffer[DECIMAL_STR_MAX(uint64_t)+1];
        uint64_t pid_max;
        int r;

        if (limit == 0) /* This makes no sense, we are userspace and hence count as tasks too, and we want to live,
                         * hence the limit conceptually has to be above 0. Also, most likely if anyone asks for a zero
                         * limit they probably mean "no limit", hence let's better refuse this to avoid
                         * confusion. */
                return -EINVAL;

        /* The Linux kernel doesn't allow this value to go below 20, hence don't allow this either, higher values than
         * TASKS_MAX are not accepted by the pid_max sysctl. We'll treat anything this high as "unbounded" and hence
         * set it to the maximum. */
        limit = CLAMP(limit, 20U, TASKS_MAX);

        r = procfs_get_pid_max(&pid_max);
        if (r < 0)
                return r;

        /* As pid_max is about the numeric pid_t range we'll bump it if necessary, but only ever increase it, never
         * decrease it, as threads-max is the much more relevant sysctl. */
        if (limit > pid_max-1) {
                sprintf(buffer, "%" PRIu64, limit+1); /* Add one, since PID 0 is not a valid PID */
                r = write_string_file("/proc/sys/kernel/pid_max", buffer, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return r;
        }

        sprintf(buffer, "%" PRIu64, limit);
        r = write_string_file("/proc/sys/kernel/threads-max", buffer, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0) {
                uint64_t threads_max;

                /* Hmm, we couldn't write this? If so, maybe it was already set properly? In that case let's not
                 * generate an error */

                if (procfs_get_threads_max(&threads_max) < 0)
                        return r; /* return original error */

                if (MIN(pid_max - 1, threads_max) != limit)
                        return r; /* return original error */

                /* Yay! Value set already matches what we were trying to set, hence consider this a success. */
        }

        return 0;
}

int procfs_tasks_get_current(uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        const char *p, *nr;
        size_t n;
        int r;

        assert(ret);

        r = read_one_line_file("/proc/loadavg", &value);
        if (r < 0)
                return r;

        /* Look for the second part of the fourth field, which is separated by a slash from the first part. None of the
         * earlier fields use a slash, hence let's use this to find the right spot. */
        p = strchr(value, '/');
        if (!p)
                return -EINVAL;

        p++;
        n = strspn(p, DIGITS);
        nr = strndupa_safe(p, n);

        return safe_atou64(nr, ret);
}

static uint64_t calc_gcd64(uint64_t a, uint64_t b) {

        while (b > 0) {
                uint64_t t;

                t = a % b;

                a = b;
                b = t;
        }

        return a;
}

int procfs_cpu_get_usage(nsec_t *ret) {
        _cleanup_free_ char *first_line = NULL;
        unsigned long user_ticks, nice_ticks, system_ticks, irq_ticks, softirq_ticks,
                guest_ticks = 0, guest_nice_ticks = 0;
        long ticks_per_second;
        uint64_t sum, gcd, a, b;
        const char *p;
        int r;

        assert(ret);

        r = read_one_line_file("/proc/stat", &first_line);
        if (r < 0)
                return r;

        p = first_word(first_line, "cpu");
        if (!p)
                return -EINVAL;

        if (sscanf(p, "%lu %lu %lu %*u %*u %lu %lu %*u %lu %lu",
                   &user_ticks,
                   &nice_ticks,
                   &system_ticks,
                   &irq_ticks,
                   &softirq_ticks,
                   &guest_ticks,
                   &guest_nice_ticks) < 5) /* we only insist on the first five fields */
                return -EINVAL;

        ticks_per_second = sysconf(_SC_CLK_TCK);
        if (ticks_per_second  < 0)
                return -errno;
        assert(ticks_per_second > 0);

        sum = (uint64_t) user_ticks + (uint64_t) nice_ticks + (uint64_t) system_ticks +
                (uint64_t) irq_ticks + (uint64_t) softirq_ticks +
                (uint64_t) guest_ticks + (uint64_t) guest_nice_ticks;

        /* Let's reduce this fraction before we apply it to avoid overflows when converting this to µsec */
        gcd = calc_gcd64(NSEC_PER_SEC, ticks_per_second);

        a = (uint64_t) NSEC_PER_SEC / gcd;
        b = (uint64_t) ticks_per_second / gcd;

        *ret = DIV_ROUND_UP((nsec_t) sum * (nsec_t) a, (nsec_t) b);
        return 0;
}

int convert_meminfo_value_to_uint64_bytes(const char *word, uint64_t *ret) {
        _cleanup_free_ char *w = NULL;
        char *digits, *e;
        uint64_t v;
        size_t n;
        int r;

        assert(word);
        assert(ret);

        w = strdup(word);
        if (!w)
                return -ENOMEM;

        /* Determine length of numeric value */
        n = strspn(w, WHITESPACE);
        digits = w + n;
        n = strspn(digits, DIGITS);
        if (n == 0)
                return -EINVAL;
        e = digits + n;

        /* Ensure the line ends in " kB" */
        n = strspn(e, WHITESPACE);
        if (n == 0)
                return -EINVAL;
        if (!streq(e + n, "kB"))
                return -EINVAL;

        *e = 0;
        r = safe_atou64(digits, &v);
        if (r < 0)
                return r;
        if (v == UINT64_MAX)
                return -EINVAL;

        if (v > UINT64_MAX/1024)
                return -EOVERFLOW;

        *ret = v * 1024U;
        return 0;
}

int procfs_memory_get(uint64_t *ret_total, uint64_t *ret_used) {
        uint64_t mem_total = UINT64_MAX, mem_available = UINT64_MAX;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        f = fopen("/proc/meminfo", "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                uint64_t *v;
                char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL; /* EOF: Couldn't find one or both fields? */

                p = first_word(line, "MemTotal:");
                if (p)
                        v = &mem_total;
                else {
                        p = first_word(line, "MemAvailable:");
                        if (p)
                                v = &mem_available;
                        else
                                continue;
                }

                r = convert_meminfo_value_to_uint64_bytes(p, v);
                if (r < 0)
                        return r;

                if (mem_total != UINT64_MAX && mem_available != UINT64_MAX)
                        break;
        }

        if (mem_available > mem_total)
                return -EINVAL;

        if (ret_total)
                *ret_total = mem_total;
        if (ret_used)
                *ret_used = mem_total - mem_available;
        return 0;
}
