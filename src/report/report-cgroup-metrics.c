/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "parse-util.h"
#include "report-cgroup-metrics.h"
#include "string-util.h"
#include "time-util.h"

typedef struct UnitCGroupInfo {
        char *name;
        char *cgroup_path;
} UnitCGroupInfo;

static UnitCGroupInfo *unit_cgroup_info_free(UnitCGroupInfo *info) {
        if (!info)
                return NULL;
        free(info->name);
        free(info->cgroup_path);
        return mfree(info);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitCGroupInfo*, unit_cgroup_info_free);

static void unit_cgroup_info_array_free(UnitCGroupInfo **infos, size_t n) {
        FOREACH_ARRAY(i, infos, n)
                unit_cgroup_info_free(*i);
        free(infos);
}

/* Cached unit list, populated lazily on first metric generate call */
static UnitCGroupInfo **cached_units = NULL;
static size_t cached_n_units = 0;

static void flush_cache(void) {
        unit_cgroup_info_array_free(cached_units, cached_n_units);
        cached_units = NULL;
        cached_n_units = 0;
}

static int query_units(UnitCGroupInfo ***ret, size_t *ret_n) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        int r;

        /* Return cached result if available */
        if (cached_units) {
                *ret = cached_units;
                *ret_n = cached_n_units;
                return 0;
        }

        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Manager");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to PID1 varlink: %m");

        r = sd_varlink_set_relative_timeout(vl, 30 * USEC_PER_SEC);
        if (r < 0)
                return log_debug_errno(r, "Failed to set varlink timeout: %m");

        r = sd_varlink_collect(vl, "io.systemd.Unit.List", /* parameters= */ NULL, &reply, /* ret_error_id= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to list units from PID1: %m");

        if (!sd_json_variant_is_array(reply))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected reply from PID1.");

        UnitCGroupInfo **infos = NULL;
        size_t n_infos = 0;
        CLEANUP_ARRAY(infos, n_infos, unit_cgroup_info_array_free);

        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, reply) {
                sd_json_variant *context_v = sd_json_variant_by_key(entry, "context");
                if (!context_v)
                        continue;

                /* Only collect service units */
                const char *type = sd_json_variant_string(sd_json_variant_by_key(context_v, "Type"));
                if (!streq_ptr(type, "service"))
                        continue;

                const char *name = sd_json_variant_string(sd_json_variant_by_key(context_v, "ID"));
                if (!name)
                        continue;

                sd_json_variant *runtime_v = sd_json_variant_by_key(entry, "runtime");
                if (!runtime_v)
                        continue;

                sd_json_variant *cgroup_v = sd_json_variant_by_key(runtime_v, "CGroup");
                if (!cgroup_v)
                        continue;

                const char *cgroup_path = sd_json_variant_string(sd_json_variant_by_key(cgroup_v, "Path"));
                if (isempty(cgroup_path))
                        continue;

                _cleanup_(unit_cgroup_info_freep) UnitCGroupInfo *info = new(UnitCGroupInfo, 1);
                if (!info)
                        return log_oom();

                *info = (UnitCGroupInfo) {
                        .name = strdup(name),
                        .cgroup_path = strdup(cgroup_path),
                };

                if (!info->name || !info->cgroup_path)
                        return log_oom();

                if (!GREEDY_REALLOC(infos, n_infos + 1))
                        return log_oom();

                infos[n_infos++] = TAKE_PTR(info);
        }

        cached_units = TAKE_PTR(infos);
        cached_n_units = n_infos;

        *ret = cached_units;
        *ret_n = cached_n_units;
        return 0;
}

static int cpu_usage_build_json(MetricFamilyContext *context, void *userdata) {
        UnitCGroupInfo **units;
        size_t n_units;
        int r;

        assert(context);

        r = query_units(&units, &n_units);
        if (r < 0)
                return 0; /* Skip metric on failure */

        FOREACH_ARRAY(u, units, n_units) {
                _cleanup_free_ char *val = NULL;
                uint64_t us;

                r = cg_get_keyed_attribute((*u)->cgroup_path, "cpu.stat", STRV_MAKE("usage_usec"), &val);
                if (r < 0)
                        continue;

                r = safe_atou64(val, &us);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*u)->name,
                                us * NSEC_PER_USEC,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int memory_usage_build_json(MetricFamilyContext *context, void *userdata) {
        UnitCGroupInfo **units;
        size_t n_units;
        int r;

        assert(context);

        r = query_units(&units, &n_units);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(u, units, n_units) {
                uint64_t current = 0, limit = UINT64_MAX;

                r = cg_get_attribute_as_uint64((*u)->cgroup_path, "memory.current", &current);
                if (r >= 0) {
                        /* Walk up the cgroup tree to find the tightest memory limit */
                        _cleanup_free_ char *path_buf = strdup((*u)->cgroup_path);
                        if (!path_buf)
                                return log_oom();

                        for (char *p = path_buf; !isempty(p); ) {
                                uint64_t high, max;

                                r = cg_get_attribute_as_uint64(p, "memory.max", &max);
                                if (r >= 0 && max < limit)
                                        limit = max;

                                r = cg_get_attribute_as_uint64(p, "memory.high", &high);
                                if (r >= 0 && high < limit)
                                        limit = high;

                                /* Move to parent */
                                char *slash = strrchr(p, '/');
                                if (!slash || slash == p)
                                        break;
                                *slash = '\0';
                        }

                        if (limit != UINT64_MAX && limit > current) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", "available"));
                                if (r < 0)
                                        return r;

                                r = metric_build_send_unsigned(
                                                context,
                                                (*u)->name,
                                                limit - current,
                                                fields);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                        r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", "current"));
                        if (r < 0)
                                return r;

                        r = metric_build_send_unsigned(
                                        context,
                                        (*u)->name,
                                        current,
                                        fields);
                        if (r < 0)
                                return r;
                }

                uint64_t val;
                r = cg_get_attribute_as_uint64((*u)->cgroup_path, "memory.peak", &val);
                if (r >= 0) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                        r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", "peak"));
                        if (r < 0)
                                return r;

                        r = metric_build_send_unsigned(
                                        context,
                                        (*u)->name,
                                        val,
                                        fields);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int io_read_bytes_build_json(MetricFamilyContext *context, void *userdata) {
        UnitCGroupInfo **units;
        size_t n_units;
        int r;

        assert(context);

        r = query_units(&units, &n_units);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(u, units, n_units) {
                _cleanup_free_ char *path = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                uint64_t total = 0;

                r = cg_get_path((*u)->cgroup_path, "io.stat", &path);
                if (r < 0)
                        continue;

                f = fopen(path, "re");
                if (!f)
                        continue;

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        const char *p;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r <= 0)
                                break;

                        p = line;
                        p += strcspn(p, WHITESPACE);
                        p += strspn(p, WHITESPACE);

                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                                if (r <= 0)
                                        break;

                                const char *v = startswith(word, "rbytes=");
                                if (v) {
                                        uint64_t val;
                                        if (safe_atou64(v, &val) >= 0)
                                                total += val;
                                }
                        }
                }

                r = metric_build_send_unsigned(
                                context,
                                (*u)->name,
                                total,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int io_read_operations_build_json(MetricFamilyContext *context, void *userdata) {
        UnitCGroupInfo **units;
        size_t n_units;
        int r;

        assert(context);

        r = query_units(&units, &n_units);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(u, units, n_units) {
                _cleanup_free_ char *path = NULL;
                _cleanup_fclose_ FILE *f = NULL;
                uint64_t total = 0;

                r = cg_get_path((*u)->cgroup_path, "io.stat", &path);
                if (r < 0)
                        continue;

                f = fopen(path, "re");
                if (!f)
                        continue;

                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        const char *p;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r <= 0)
                                break;

                        p = line;
                        p += strcspn(p, WHITESPACE);
                        p += strspn(p, WHITESPACE);

                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                                if (r <= 0)
                                        break;

                                const char *v = startswith(word, "rios=");
                                if (v) {
                                        uint64_t val;
                                        if (safe_atou64(v, &val) >= 0)
                                                total += val;
                                }
                        }
                }

                r = metric_build_send_unsigned(
                                context,
                                (*u)->name,
                                total,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int tasks_current_build_json(MetricFamilyContext *context, void *userdata) {
        UnitCGroupInfo **units;
        size_t n_units;
        int r;

        assert(context);

        r = query_units(&units, &n_units);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(u, units, n_units) {
                uint64_t val;

                r = cg_get_attribute_as_uint64((*u)->cgroup_path, "pids.current", &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*u)->name,
                                val,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily cgroup_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "CpuUsage",
                .description = "Per service metric: CPU usage in nanoseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = cpu_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadBytes",
                .description = "Per service metric: IO bytes read",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_bytes_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadOperations",
                .description = "Per service metric: IO read operations",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_operations_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "MemoryUsage",
                .description = "Per service metric: memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = memory_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "TasksCurrent",
                .description = "Per service metric: current number of tasks",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = tasks_current_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(cgroup_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = metrics_method_list(cgroup_metric_family_table, link, parameters, flags, userdata);

        flush_cache();

        return r;
}
