/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "cgroup-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "metrics.h"
#include "parse-util.h"
#include "path-util.h"
#include "report-cgroup.h"
#include "string-util.h"
#include "time-util.h"

/* Parse cpu.stat for a cgroup once, extracting usage_usec, user_usec and system_usec
 * in a single read so each scrape only opens the file once per cgroup. */
static int cpu_stat_parse(const char *cgroup_path, uint64_t ret[static 3]) {
        char* strings[3] = {};
        CLEANUP_ELEMENTS(strings, free_many_charp);
        uint64_t values[3];
        int r;

        assert(cgroup_path);

        r = cg_get_keyed_attribute(
                        cgroup_path,
                        "cpu.stat",
                        STRV_MAKE("usage_usec", "user_usec", "system_usec"),
                        strings);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < 3; i++) {
                r = safe_atou64(strings[i], &values[i]);
                if (r < 0)
                        return r;
        }

        for (unsigned i = 0; i < 3; i++)
                ret[i] = values[i] * NSEC_PER_USEC;
        return 0;
}

static int cpu_usage_send(
                const MetricFamily *mf,
                sd_varlink *link,
                const char *path,
                const char *unit) {

        static const char* const types[] = { "total", "user", "system" };
        uint64_t values[3];
        int r;

        assert(mf && mf->name);
        assert(link);
        assert(path);
        assert(unit);

        r = cpu_stat_parse(path, values);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s/%s, ignoring: %m", path, "cpu.stat");
                return 0;
        }

        for (unsigned i = 0; i < 3; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;

                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", types[i]));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(mf, link, unit, values[i], fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Parse io.stat for a cgroup once, summing both rbytes= and rios= fields in a
 * single pass to avoid reading the file twice. */
static int io_stat_parse(const char *cgroup_path, uint64_t ret[static 2]) {
        _cleanup_free_ char *path = NULL;
        uint64_t rbytes = 0, rios = 0;
        int r;

        assert(ret);

        r = cg_get_path(cgroup_path, "io.stat", &path);
        if (r < 0)
                return r;

        _cleanup_fclose_ FILE *f = fopen(path, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                p = line;
                p += strcspn(p, WHITESPACE);
                p += strspn(p, WHITESPACE);

                for (;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        const char *v;
                        uint64_t val;

                        v = startswith(word, "rbytes=");
                        if (v && safe_atou64(v, &val) >= 0) {
                                rbytes += val;
                                continue;
                        }

                        v = startswith(word, "rios=");
                        if (v && safe_atou64(v, &val) >= 0)
                                rios += val;
                }
        }

        ret[0] = rbytes;
        ret[1] = rios;
        return 0;
}

static int io_read_send(
                const MetricFamily mf[static 2],
                sd_varlink *link,
                const char *path,
                const char *unit) {

        uint64_t values[2];
        int r;

        assert(mf && mf[0].name && mf[1].name);
        assert(link);
        assert(path);
        assert(unit);

        r = io_stat_parse(path, values);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s/%s, ignoring: %m", path, "io.stat");
                return 0;
        }

        for (unsigned i = 0; i < 2; i++) {
                r = metric_build_send_unsigned(mf + i, link, unit, values[i], /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int memory_usage_send(
                const MetricFamily *mf,
                sd_varlink *link,
                const char *path,
                const char *unit) {

        static const char* const types[] = { "current", "available", "peak" };
        bool bad[ELEMENTSOF(types)] = {};
        uint64_t current = 0, limit = UINT64_MAX, peak = 0;
        int r;

        assert(mf && mf->name);
        assert(link);
        assert(path);
        assert(unit);

        r = cg_get_attribute_as_uint64(path, "memory.current", &current);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s/%s, ignoring: %m", path, "memory.current");

                bad[0] = bad[1] = true;

        } else {
                /* Walk up the cgroup tree to find the tightest memory limit */
                _cleanup_free_ char *path_buf = strdup(path);
                if (!path_buf)
                        return log_oom();

                for (char *p = path_buf;;) {
                        uint64_t high, max;

                        r = cg_get_attribute_as_uint64(p, "memory.max", &max);
                        if (r >= 0 && max < limit)
                                limit = max;

                        r = cg_get_attribute_as_uint64(p, "memory.high", &high);
                        if (r >= 0 && high < limit)
                                limit = high;

                        /* Move to parent */
                        const char *e;
                        r = path_find_last_component(p, /* accept_dot_dot= */ false, &e, NULL);
                        if (r <= 0)
                                break;
                        p[e - p] = '\0';
                }

                if (limit == UINT64_MAX || limit <= current)
                        bad[1] = true;
        }

        r = cg_get_attribute_as_uint64(path, "memory.peak", &peak);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s/%s, ignoring: %m", path, "memory.peak");
                bad[2] = true;
        }

        uint64_t values[] = { current, limit - current, peak };
        for (unsigned i = 0; i < ELEMENTSOF(values); i++) {
                if (bad[i])
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", types[i]));
                if (r < 0)
                        return r;

                r = metric_build_send_unsigned(mf, link, unit, values[i], fields);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int tasks_current_send(
                const MetricFamily *mf,
                sd_varlink *link,
                const char *path,
                const char *unit) {

        uint64_t val;
        int r;

        assert(mf && mf->name);
        assert(link);
        assert(path);
        assert(unit);

        r = cg_get_attribute_as_uint64(path, "pids.current", &val);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read %s/%s, ignoring: %m", path, "pids.current");
                return 0;
        }

        return metric_build_send_unsigned(mf, link, unit, val, /* fields= */ NULL);
}

static int walk_cgroups(
                const MetricFamily mf[static 5],
                sd_varlink *link,
                const char *path) {

        int r;

        assert(mf && mf[0].name && mf[1].name && mf[2].name && mf[3].name && mf[4].name);
        assert(mf[0].generate && !mf[1].generate && !mf[2].generate && !mf[3].generate && !mf[4].generate);
        assert(path);

        _cleanup_free_ char *unit = NULL;
        r = cg_path_get_unit(path, &unit);
        if (r >= 0) {
                r = cpu_usage_send(mf + 0, link, path, unit);
                if (r < 0)
                        return r;

                r = io_read_send(mf + 1, link, path, unit);
                if (r < 0)
                        return r;

                r = memory_usage_send(mf + 3, link, path, unit);
                if (r < 0)
                        return r;

                r = tasks_current_send(mf + 4, link, path, unit);
                if (r < 0)
                        return r;

                return 0; /* Unit cgroups are leaf nodes for our purposes */
        }

        /* Stop at delegation boundaries — don't descend into delegated subtrees */
        r = cg_is_delegated(path);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to check delegation for '%s': %m", path);
        if (r > 0)
                return 0;

        _cleanup_closedir_ DIR *d = NULL;
        r = cg_enumerate_subgroups(path, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate cgroup '%s': %m", path);

        for (;;) {
                _cleanup_free_ char *fn = NULL, *child = NULL;

                r = cg_read_subgroup(d, &fn);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read subgroup from '%s': %m", path);
                if (r == 0)
                        break;

                child = path_join(empty_to_root(path), fn);
                if (!child)
                        return log_oom();

                path_simplify(child);

                r = walk_cgroups(mf, link, child);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int cgroup_stats_send(
                const MetricFamily mf[static 5],
                sd_varlink *link,
                void *userdata) {

        assert(mf);
        assert(link);
        assert(!userdata);

        return walk_cgroups(mf, link, "");
}

static const MetricFamily cgroup_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "CpuUsage",
                "Per unit metric: CPU usage in nanoseconds (type=total|user|system)",
                METRIC_FAMILY_TYPE_COUNTER,
                .generate = cgroup_stats_send,
        },
        {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadBytes",
                "Per unit metric: IO bytes read",
                METRIC_FAMILY_TYPE_COUNTER,
                .generate = NULL,
        },
        {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadOperations",
                "Per unit metric: IO read operations",
                METRIC_FAMILY_TYPE_COUNTER,
                .generate = NULL,
        },
        {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "MemoryUsage",
                "Per unit metric: memory usage in bytes",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {
                METRIC_IO_SYSTEMD_CGROUP_PREFIX "TasksCurrent",
                "Per unit metric: current number of tasks",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = NULL,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(cgroup_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(cgroup_metric_family_table, link, parameters, flags, userdata);
}
