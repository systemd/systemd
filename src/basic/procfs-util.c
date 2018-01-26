/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>

#include "alloc-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "process-util.h"
#include "procfs-util.h"
#include "stdio-util.h"
#include "string-util.h"

int procfs_tasks_get_limit(uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        uint64_t pid_max, threads_max;
        int r;

        assert(ret);

        /* So there are two sysctl files that control the system limit of processes:
         *
         * 1. kernel.threads-max: this is probably the sysctl that makes more sense, as it directly puts a limit on
         *    concurrent tasks.
         *
         * 2. kernel.pid_max: this limits the numeric range PIDs can take, and thus indirectly also limits the number
         *    of concurrent threads. AFAICS it's primarily a compatibility concept: some crappy old code used a signed
         *    16bit type for PIDs, hence the kernel provides a way to ensure the PIDs never go beyond INT16_MAX by
         *    default.
         *
         * By default #2 is set to much lower values than #1, hence the limit people come into contact with first, as
         * it's the lowest boundary they need to bump when they want higher number of processes.
         *
         * Also note the weird definition of #2: PIDs assigned will be kept below this value, which means the number of
         * tasks that can be created is one lower, as PID 0 is not a valid process ID. */

        r = read_one_line_file("/proc/sys/kernel/pid_max", &value);
        if (r < 0)
                return r;

        r = safe_atou64(value, &pid_max);
        if (r < 0)
                return r;

        value = mfree(value);
        r = read_one_line_file("/proc/sys/kernel/threads-max", &value);
        if (r < 0)
                return r;

        r = safe_atou64(value, &threads_max);
        if (r < 0)
                return r;

        /* Subtract one from pid_max, since PID 0 is not a valid PID */
        *ret = MIN(pid_max-1, threads_max);
        return 0;
}

int procfs_tasks_set_limit(uint64_t limit) {
        char buffer[DECIMAL_STR_MAX(uint64_t)+1];
        _cleanup_free_ char *value = NULL;
        uint64_t pid_max;
        int r;

        if (limit == 0) /* This makes no sense, we are userspace and hence count as tasks too, and we want to live,
                         * hence the limit conceptually has to be above 0. Also, most likely if anyone asks for a zero
                         * limit he/she probably means "no limit", hence let's better refuse this to avoid
                         * confusion. */
                return -EINVAL;

        /* The Linux kernel doesn't allow this value to go below 20, hence don't allow this either, higher values than
         * TASKS_MAX are not accepted by the pid_max sysctl. We'll treat anything this high as "unbounded" and hence
         * set it to the maximum. */
        limit = CLAMP(limit, 20U, TASKS_MAX);

        r = read_one_line_file("/proc/sys/kernel/pid_max", &value);
        if (r < 0)
                return r;
        r = safe_atou64(value, &pid_max);
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

                value = mfree(value);
                if (read_one_line_file("/proc/sys/kernel/threads-max", &value) < 0)
                        return r; /* return original error */

                if (safe_atou64(value, &threads_max) < 0)
                        return r; /* return original error */

                if (MIN(pid_max-1, threads_max) != limit)
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
        nr = strndupa(p, n);

        return safe_atou64(nr, ret);
}
