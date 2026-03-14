/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "cgroup.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "manager.h"
#include "metrics.h"
#include "parse-util.h"
#include "service.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit.h"
#include "varlink-metrics.h"

static int active_enter_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->active_enter_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int active_exit_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->active_exit_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cpu_usage_nsec_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                nsec_t nsec;

                r = unit_get_cpu_usage(unit, &nsec);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                nsec,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int inactive_exit_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->inactive_exit_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int io_read_bytes_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                uint64_t val;

                r = unit_get_io_accounting(unit, CGROUP_IO_READ_BYTES, &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int io_read_operations_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                uint64_t val;

                r = unit_get_io_accounting(unit, CGROUP_IO_READ_OPERATIONS, &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int memory_available_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                uint64_t val;

                r = unit_get_memory_available(unit, &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int memory_current_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                uint64_t val;

                r = unit_get_memory_accounting(unit, CGROUP_MEMORY_CURRENT, &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int restart_usec_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                SERVICE(unit)->restart_usec,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int state_change_timestamp_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                if (key != unit->id)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                unit->state_change_timestamp.realtime,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int status_errno_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                (uint64_t) SERVICE(unit)->status_errno,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int tasks_current_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                uint64_t val;

                r = unit_get_tasks_current(unit, &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int timeout_clean_usec_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                const ExecContext *ec = unit_get_exec_context(unit);
                if (!ec)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                ec->timeout_clean_usec,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int watchdog_usec_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context,
                                unit->id,
                                service_get_watchdog_usec(SERVICE(unit)),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_active_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                context,
                                unit->id,
                                unit_active_state_to_string(unit_active_state(unit)),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int unit_load_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                r = metric_build_send_string(
                                context,
                                unit->id,
                                unit_load_state_to_string(unit->load_state),
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int nrestarts_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        LIST_FOREACH(units_by_type, unit, manager->units_by_type[UNIT_SERVICE]) {
                r = metric_build_send_unsigned(
                                context, unit->id, SERVICE(unit)->n_restarts, /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_type_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(context);

        for (UnitType type = 0; type < _UNIT_TYPE_MAX; type++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                uint64_t counter = 0;

                LIST_FOREACH(units_by_type, _u, manager->units_by_type[type])
                        counter++;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", unit_type_to_string(type)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counter,
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_by_state_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        UnitActiveState counters[_UNIT_ACTIVE_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(context);

        /* TODO need a rework probably with state counter */
        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                counters[unit_active_state(unit)]++;
        }

        for (UnitActiveState state = 0; state < _UNIT_ACTIVE_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("state", unit_active_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int jobs_queued_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(context);

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        hashmap_size(manager->jobs),
                        /* fields= */ NULL);
}

static int proc_self_stat_read_cpu_times(usec_t *ret_utime, usec_t *ret_stime) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        unsigned long utime, stime;
        int r;

        r = read_one_line_file("/proc/self/stat", &line);
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

static int pid1_cpu_time_kernel_build_json(MetricFamilyContext *context, void *userdata) {
        usec_t stime;
        int r;

        assert(context);

        r = proc_self_stat_read_cpu_times(/* ret_utime= */ NULL, &stime);
        if (r < 0)
                return log_debug_errno(r, "Failed to read PID1 CPU times, skipping metric: %m"), 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        stime,
                        /* fields= */ NULL);
}

static int pid1_cpu_time_user_build_json(MetricFamilyContext *context, void *userdata) {
        usec_t utime;
        int r;

        assert(context);

        r = proc_self_stat_read_cpu_times(&utime, /* ret_stime= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to read PID1 CPU times, skipping metric: %m"), 0;

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        utime,
                        /* fields= */ NULL);
}

static int pid1_fd_count_build_json(MetricFamilyContext *context, void *userdata) {
        _cleanup_closedir_ DIR *d = NULL;
        uint64_t count = 0;

        assert(context);

        d = opendir("/proc/self/fd");
        if (!d)
                return log_debug_errno(errno, "Failed to open /proc/self/fd, skipping metric: %m"), 0;

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

        r = get_proc_field("/proc/self/status", "VmRSS", &value);
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

        r = get_proc_field("/proc/self/status", "Threads", &value);
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

static int system_state_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        assert(context);

        return metric_build_send_string(
                        context,
                        /* object= */ NULL,
                        manager_state_to_string(manager_state(manager)),
                        /* fields= */ NULL);
}

static int units_by_load_state_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        uint64_t counters[_UNIT_LOAD_STATE_MAX] = {};
        Unit *unit;
        char *key;
        int r;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                counters[unit->load_state]++;
        }

        for (UnitLoadState state = 0; state < _UNIT_LOAD_STATE_MAX; state++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("load_state", unit_load_state_to_string(state)));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(
                                context,
                                /* object= */ NULL,
                                counters[state],
                                fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int units_total_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Unit *unit;
        char *key;
        uint64_t count = 0;

        assert(context);

        HASHMAP_FOREACH_KEY(unit, key, manager->units) {
                /* ignore aliases */
                if (key != unit->id)
                        continue;

                count++;
        }

        return metric_build_send_unsigned(
                        context,
                        /* object= */ NULL,
                        count,
                        /* fields= */ NULL);
}

static const MetricFamily metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ActiveEnterTimestampUSec",
                .description = "Per unit metric: timestamp when the unit last entered the active state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = active_enter_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "ActiveExitTimestampUSec",
                .description = "Per unit metric: timestamp when the unit last exited the active state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = active_exit_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "CpuUsageNSec",
                .description = "Per service metric: CPU usage in nanoseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = cpu_usage_nsec_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "IOReadBytes",
                .description = "Per service metric: IO bytes read",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_bytes_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "IOReadOperations",
                .description = "Per service metric: IO read operations",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_operations_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "InactiveExitTimestampUSec",
                .description = "Per unit metric: timestamp when the unit last exited the inactive state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = inactive_exit_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "JobsQueued",
                .description = "Number of jobs currently queued",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = jobs_queued_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "MemoryAvailable",
                .description = "Per service metric: available memory in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = memory_available_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "MemoryCurrent",
                .description = "Per service metric: current memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = memory_current_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "NRestarts",
                .description = "Per unit metric: number of restarts",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = nrestarts_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Pid1CpuTimeKernelUSec",
                .description = "PID1 kernel CPU time in microseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = pid1_cpu_time_kernel_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Pid1CpuTimeUserUSec",
                .description = "PID1 user CPU time in microseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = pid1_cpu_time_user_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Pid1FdCount",
                .description = "Number of open file descriptors of PID1",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_fd_count_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Pid1MemoryUsageBytes",
                .description = "PID1 resident memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_memory_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "Pid1Tasks",
                .description = "Number of threads of PID1",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = pid1_tasks_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "RestartUSec",
                .description = "Per service metric: configured restart delay in microseconds",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = restart_usec_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StateChangeTimestampUSec",
                .description = "Per unit metric: timestamp of the last state change",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = state_change_timestamp_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "StatusErrno",
                .description = "Per service metric: errno status of the service",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = status_errno_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "SystemState",
                .description = "Overall system state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = system_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "TasksCurrent",
                .description = "Per service metric: current number of tasks",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = tasks_current_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "TimeoutCleanUSec",
                .description = "Per service metric: cleanup timeout in microseconds",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = timeout_clean_usec_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitActiveState",
                .description = "Per unit metric: active state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = unit_active_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitLoadState",
                .description = "Per unit metric: load state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = unit_load_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByLoadStateTotal",
                .description = "Total number of units by load state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_load_state_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByStateTotal",
                .description = "Total number of units of different state",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_state_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsByTypeTotal",
                .description = "Total number of units of different types",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_by_type_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "UnitsTotal",
                .description = "Total number of units",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = units_total_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_MANAGER_PREFIX "WatchdogUSec",
                .description = "Per service metric: watchdog timeout in microseconds",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = watchdog_usec_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(metric_family_table, link, parameters, flags, userdata);
}
