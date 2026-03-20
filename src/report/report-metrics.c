/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "log.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "metrics.h"
#include "parse-util.h"
#include "report-metrics.h"
#include "time-util.h"

static int proc_pid1_stat_read_cpu_times(usec_t *ret_utime, usec_t *ret_stime) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        unsigned long utime, stime;
        int r;

        r = read_one_line_file("/proc/1/stat", &line);
        if (r < 0)
                return r;

        /* Skip past the comm field (which may contain spaces/parens) by finding the last ')' */
        p = strrchr(line, ')');
        if (!p)
                return -EINVAL;
        p++;

        /* Fields after ')': state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime
         * Skip 11 fields (state through cmajflt) to reach utime, then read utime and stime */
        for (int i = 0; i < 11; i++) {
                p += strspn(p, " ");
                p += strcspn(p, " ");
        }
        p += strspn(p, " ");

        if (sscanf(p, "%lu %lu", &utime, &stime) != 2)
                return -EINVAL;

        if (ret_utime)
                *ret_utime = jiffies_to_usec(utime);
        if (ret_stime)
                *ret_stime = jiffies_to_usec(stime);

        return 0;
}

static int pid1_cpu_time_build_json(MetricFamilyContext *context, void *userdata) {
        usec_t utime, stime;
        int r;

        assert(context);

        r = proc_pid1_stat_read_cpu_times(&utime, &stime);
        if (r < 0)
                return log_debug_errno(r, "Failed to read PID1 CPU times, skipping metric: %m"), 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *kernel_fields = NULL;
        r = sd_json_buildo(&kernel_fields, SD_JSON_BUILD_PAIR_STRING("mode", "kernel"));
        if (r < 0)
                return r;

        r = metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        stime,
                        kernel_fields);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *user_fields = NULL;
        r = sd_json_buildo(&user_fields, SD_JSON_BUILD_PAIR_STRING("mode", "user"));
        if (r < 0)
                return r;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        utime,
                        user_fields);
}

static int pid1_fd_count_build_json(MetricFamilyContext *context, void *userdata) {
        _cleanup_closedir_ DIR *d = NULL;
        uint64_t count = 0;

        assert(context);

        d = opendir("/proc/1/fd");
        if (!d)
                return log_debug_errno(errno, "Failed to open /proc/1/fd, skipping metric: %m"), 0;

        FOREACH_DIRENT_ALL(de, d, break)
                if (!dot_or_dot_dot(de->d_name))
                        count++;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        count,
                        /* fields= */ NULL);
}

static int pid1_memory_usage_build_json(MetricFamilyContext *context, void *userdata) {
        _cleanup_free_ char *value = NULL;
        uint64_t kb;
        int r;

        assert(context);

        r = get_proc_field("/proc/1/status", "VmRSS", &value);
        if (r < 0)
                return log_debug_errno(r, "Failed to read VmRSS, skipping metric: %m"), 0;

        r = safe_atou64(value, &kb);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse VmRSS value '%s', skipping metric: %m", value), 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        kb * 1024,
                        /* fields= */ NULL);
}

static int pid1_tasks_build_json(MetricFamilyContext *context, void *userdata) {
        _cleanup_free_ char *value = NULL;
        uint64_t threads;
        int r;

        assert(context);

        r = get_proc_field("/proc/1/status", "Threads", &value);
        if (r < 0)
                return log_debug_errno(r, "Failed to read Threads, skipping metric: %m"), 0;

        r = safe_atou64(value, &threads);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse Threads value '%s', skipping metric: %m", value), 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        threads,
                        /* fields= */ NULL);
}

static const MetricFamily pid1_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "CpuTime",
                .description = "PID1 CPU time in microseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = pid1_cpu_time_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "FdCount",
                .description = "Number of open file descriptors of PID1",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_fd_count_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "MemoryUsage",
                .description = "PID1 resident memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_memory_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "Tasks",
                .description = "Number of threads of PID1",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_tasks_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(pid1_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(pid1_metric_family_table, link, parameters, flags, userdata);
}
