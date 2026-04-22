/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <fcntl.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "metrics.h"
#include "parse-util.h"
#include "report-pid1.h"
#include "string-util.h"
#include "time-util.h"

static int pid1_count_fds(uint64_t *ret) {
        _cleanup_closedir_ DIR *d = NULL;
        uint64_t n = 0;

        assert(ret);

        d = opendir("/proc/1/fd");
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, return -errno)
                n++;

        *ret = n;
        return 0;
}

static int pid1_parse_stat_cpu_times(int stat_fd, uint64_t *ret_utime_jiffies, uint64_t *ret_stime_jiffies) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        unsigned long utime, stime;
        int r;

        assert(stat_fd >= 0);
        assert(ret_utime_jiffies);
        assert(ret_stime_jiffies);

        r = read_one_line_from_fd(stat_fd, &line);
        if (r < 0)
                return r;

        /* The comm field is enclosed in () but does not escape any () inside, so skip past the last ')'. */
        p = strrchr(line, ')');
        if (!p)
                return -EIO;
        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*u "  /* ppid */
                   "%*u "  /* pgrp */
                   "%*u "  /* session */
                   "%*u "  /* tty_nr */
                   "%*u "  /* tpgid */
                   "%*u "  /* flags */
                   "%*u "  /* minflt */
                   "%*u "  /* cminflt */
                   "%*u "  /* majflt */
                   "%*u "  /* cmajflt */
                   "%lu "  /* utime */
                   "%lu ", /* stime */
                   &utime, &stime) != 2)
                return -EIO;

        *ret_utime_jiffies = utime;
        *ret_stime_jiffies = stime;
        return 0;
}

static int pid1_parse_memory_bytes(int status_fd, uint64_t *ret) {
        _cleanup_free_ char *s = NULL;
        uint64_t v;
        int r;

        assert(status_fd >= 0);
        assert(ret);

        r = get_proc_field_from_fd(status_fd, "VmRSS", &s);
        if (r < 0)
                return r;

        r = safe_atou64(s, &v);
        if (r < 0)
                return r;

        if (!MUL_ASSIGN_SAFE(&v, U64_KB))
                return -EOVERFLOW;

        *ret = v;
        return 0;
}

static int pid1_parse_threads(int status_fd, uint64_t *ret) {
        _cleanup_free_ char *s = NULL;
        int n, r;

        assert(status_fd >= 0);
        assert(ret);

        r = get_proc_field_from_fd(status_fd, "Threads", &s);
        if (r < 0)
                return r;

        r = safe_atoi(s, &n);
        if (r < 0)
                return r;
        if (n < 0)
                return -EINVAL;

        *ret = (uint64_t) n;
        return 0;
}

void pid1_context_collect_privileged(Pid1Context *ctx, int *ret_stat_fd, int *ret_status_fd) {
        int r;

        assert(ctx);
        assert(ret_stat_fd);
        assert(ret_status_fd);

        /* Count /proc/1/fd now — this must happen while privileged (mode 0500, root-owned), and the result
         * is a single number so there is no fd to carry across the privilege drop. */
        r = pid1_count_fds(&ctx->fd_count);
        if (r < 0) {
                ctx->fd_result = r;
                log_debug_errno(r, "Failed to count /proc/1/fd, skipping FD metric: %m");
        } else
                ctx->fd_result = 1;

        /* Open /proc/1/stat and /proc/1/status now, while we still have root (and therefore satisfy any
         * ProtectProc=hidepid check). The actual parsing happens in _unprivileged() from these fds; the
         * kernel's access check is already passed at open(). */
        *ret_stat_fd = RET_NERRNO(open("/proc/1/stat", O_RDONLY|O_CLOEXEC));
        if (*ret_stat_fd < 0) {
                ctx->stat_result = *ret_stat_fd;
                log_debug_errno(*ret_stat_fd, "Failed to open /proc/1/stat, skipping CPU metrics: %m");
        }

        *ret_status_fd = RET_NERRNO(open("/proc/1/status", O_RDONLY|O_CLOEXEC));
        if (*ret_status_fd < 0) {
                ctx->memory_result = *ret_status_fd;
                ctx->threads_result = *ret_status_fd;
                log_debug_errno(*ret_status_fd,
                                "Failed to open /proc/1/status, skipping memory and tasks metrics: %m");
        }
}

void pid1_context_collect_unprivileged(Pid1Context *ctx, int stat_fd, int status_fd) {
        _cleanup_close_ int _stat_fd = stat_fd, _status_fd = status_fd;
        int r;

        assert(ctx);

        if (_stat_fd >= 0) {
                r = pid1_parse_stat_cpu_times(_stat_fd, &ctx->utime_jiffies, &ctx->stime_jiffies);
                if (r < 0) {
                        ctx->stat_result = r;
                        log_debug_errno(r, "Failed to parse /proc/1/stat, skipping CPU metrics: %m");
                } else
                        ctx->stat_result = 1;
        }

        if (_status_fd >= 0) {
                r = pid1_parse_memory_bytes(_status_fd, &ctx->memory_bytes);
                if (r < 0) {
                        ctx->memory_result = r;
                        log_debug_errno(r, "Failed to parse VmRSS, skipping memory metric: %m");
                } else
                        ctx->memory_result = 1;

                r = pid1_parse_threads(_status_fd, &ctx->threads);
                if (r < 0) {
                        ctx->threads_result = r;
                        log_debug_errno(r, "Failed to parse Threads, skipping tasks metric: %m");
                } else
                        ctx->threads_result = 1;
        }
}

static int cpu_time_build_json(MetricFamilyContext *context, void *userdata) {
        Pid1Context *ctx = ASSERT_PTR(userdata);
        int r;

        assert(context);

        if (ctx->stat_result != 1)
                return 0;

        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("mode", "user"));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                jiffies_to_usec(ctx->utime_jiffies) * NSEC_PER_USEC,
                                fields);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

        r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("mode", "kernel"));
        if (r < 0)
                return r;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        jiffies_to_usec(ctx->stime_jiffies) * NSEC_PER_USEC,
                        fields);
}

static int fd_count_build_json(MetricFamilyContext *context, void *userdata) {
        Pid1Context *ctx = ASSERT_PTR(userdata);

        assert(context);

        if (ctx->fd_result != 1)
                return 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        ctx->fd_count,
                        /* fields= */ NULL);
}

static int memory_usage_build_json(MetricFamilyContext *context, void *userdata) {
        Pid1Context *ctx = ASSERT_PTR(userdata);

        assert(context);

        if (ctx->memory_result != 1)
                return 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        ctx->memory_bytes,
                        /* fields= */ NULL);
}

static int tasks_build_json(MetricFamilyContext *context, void *userdata) {
        Pid1Context *ctx = ASSERT_PTR(userdata);

        assert(context);

        if (ctx->threads_result != 1)
                return 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        ctx->threads,
                        /* fields= */ NULL);
}

static const MetricFamily pid1_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "CpuTime",
                .description = "PID1 CPU time in nanoseconds, split by mode (user or kernel)",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = cpu_time_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "FDCount",
                .description = "PID1 open file descriptor count",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = fd_count_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "MemoryUsage",
                .description = "PID1 resident memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = memory_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_PID1_PREFIX "Tasks",
                .description = "PID1 thread count",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = tasks_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(pid1_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(pid1_metric_family_table, link, parameters, flags, userdata);
}
