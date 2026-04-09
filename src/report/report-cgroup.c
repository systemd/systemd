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

typedef struct CGroupInfo {
        char *unit;
        char *path;
        uint64_t io_rbytes;
        uint64_t io_rios;
        int io_stat_cached; /* 0 = not attempted, > 0 = cached, < 0 = -errno */
} CGroupInfo;

static CGroupInfo *cgroup_info_free(CGroupInfo *info) {
        if (!info)
                return NULL;
        free(info->unit);
        free(info->path);
        return mfree(info);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(CGroupInfo*, cgroup_info_free);

static void cgroup_info_array_free(CGroupInfo **infos, size_t n) {
        FOREACH_ARRAY(i, infos, n)
                cgroup_info_free(*i);
        free(infos);
}

static void cgroup_context_flush(CGroupContext *ctx) {
        assert(ctx);
        cgroup_info_array_free(ctx->cgroups, ctx->n_cgroups);
        ctx->cgroups = NULL;
        ctx->n_cgroups = 0;
        ctx->cache_populated = false;
}

CGroupContext *cgroup_context_free(CGroupContext *ctx) {
        if (!ctx)
                return NULL;
        cgroup_context_flush(ctx);
        return mfree(ctx);
}

static int walk_cgroups_recursive(const char *path, CGroupInfo ***infos, size_t *n_infos) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(path);
        assert(infos);
        assert(n_infos);

        /* Collect any unit cgroup we encounter */
        _cleanup_free_ char *name = NULL;
        r = cg_path_get_unit(path, &name);
        if (r >= 0) {
                _cleanup_(cgroup_info_freep) CGroupInfo *info = new(CGroupInfo, 1);
                if (!info)
                        return log_oom();

                *info = (CGroupInfo) {
                        .unit = TAKE_PTR(name),
                        .path = strdup(path),
                };
                if (!info->path)
                        return log_oom();

                if (!GREEDY_REALLOC(*infos, *n_infos + 1))
                        return log_oom();

                (*infos)[(*n_infos)++] = TAKE_PTR(info);
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

                r = walk_cgroups_recursive(child, infos, n_infos);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int walk_cgroups(CGroupContext *ctx, CGroupInfo ***ret, size_t *ret_n) {
        int r;

        assert(ctx);
        assert(ret);
        assert(ret_n);

        /* Return cached result if available */
        if (ctx->cache_populated) {
                *ret = ctx->cgroups;
                *ret_n = ctx->n_cgroups;
                return 0;
        }

        CGroupInfo **infos = NULL;
        size_t n_infos = 0;
        CLEANUP_ARRAY(infos, n_infos, cgroup_info_array_free);

        r = walk_cgroups_recursive("", &infos, &n_infos);
        if (r < 0)
                return r;

        ctx->cgroups = TAKE_PTR(infos);
        ctx->n_cgroups = TAKE_GENERIC(n_infos, size_t, 0);
        ctx->cache_populated = true;

        *ret = ctx->cgroups;
        *ret_n = ctx->n_cgroups;
        return 0;
}

static int cpu_usage_build_json(MetricFamilyContext *context, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        CGroupInfo **cgroups;
        size_t n_cgroups;
        int r;

        assert(context);

        r = walk_cgroups(ctx, &cgroups, &n_cgroups);
        if (r < 0)
                return 0; /* Skip metric on failure */

        FOREACH_ARRAY(c, cgroups, n_cgroups) {
                uint64_t us;

                r = cg_get_keyed_attribute_uint64((*c)->path, "cpu.stat", "usage_usec", &us);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*c)->unit,
                                us * NSEC_PER_USEC,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int memory_usage_build_json(MetricFamilyContext *context, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        CGroupInfo **cgroups;
        size_t n_cgroups;
        int r;

        assert(context);

        r = walk_cgroups(ctx, &cgroups, &n_cgroups);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(c, cgroups, n_cgroups) {
                uint64_t current = 0, limit = UINT64_MAX;

                r = cg_get_attribute_as_uint64((*c)->path, "memory.current", &current);
                if (r >= 0) {
                        /* Walk up the cgroup tree to find the tightest memory limit */
                        _cleanup_free_ char *path_buf = strdup((*c)->path);
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

                        if (limit != UINT64_MAX && limit > current) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                                r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", "available"));
                                if (r < 0)
                                        return r;

                                r = metric_build_send_unsigned(
                                                context,
                                                (*c)->unit,
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
                                        (*c)->unit,
                                        current,
                                        fields);
                        if (r < 0)
                                return r;
                }

                uint64_t val;
                r = cg_get_attribute_as_uint64((*c)->path, "memory.peak", &val);
                if (r >= 0) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
                        r = sd_json_buildo(&fields, SD_JSON_BUILD_PAIR_STRING("type", "peak"));
                        if (r < 0)
                                return r;

                        r = metric_build_send_unsigned(
                                        context,
                                        (*c)->unit,
                                        val,
                                        fields);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

/* Parse io.stat for a cgroup once, summing both rbytes= and rios= fields in a
 * single pass to avoid reading the file twice. */
static int io_stat_parse(const char *cgroup_path, uint64_t *ret_rbytes, uint64_t *ret_rios) {
        _cleanup_free_ char *path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        uint64_t rbytes = 0, rios = 0;
        int r;

        r = cg_get_path(cgroup_path, "io.stat", &path);
        if (r < 0)
                return r;

        f = fopen(path, "re");
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

        *ret_rbytes = rbytes;
        *ret_rios = rios;
        return 0;
}

static int ensure_io_stat_cached(CGroupInfo *info) {
        int r;

        assert(info);

        if (info->io_stat_cached > 0)
                return 0;
        if (info->io_stat_cached < 0)
                return info->io_stat_cached;

        r = io_stat_parse(info->path, &info->io_rbytes, &info->io_rios);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to parse IO stats for '%s': %m", info->path);
                info->io_stat_cached = r;
                return r;
        }

        info->io_stat_cached = 1;
        return 0;
}

static int io_read_bytes_build_json(MetricFamilyContext *context, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        CGroupInfo **cgroups;
        size_t n_cgroups;
        int r;

        assert(context);

        r = walk_cgroups(ctx, &cgroups, &n_cgroups);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(c, cgroups, n_cgroups) {
                if (ensure_io_stat_cached(*c) < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*c)->unit,
                                (*c)->io_rbytes,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int io_read_operations_build_json(MetricFamilyContext *context, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        CGroupInfo **cgroups;
        size_t n_cgroups;
        int r;

        assert(context);

        r = walk_cgroups(ctx, &cgroups, &n_cgroups);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(c, cgroups, n_cgroups) {
                if (ensure_io_stat_cached(*c) < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*c)->unit,
                                (*c)->io_rios,
                                /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int tasks_current_build_json(MetricFamilyContext *context, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        CGroupInfo **cgroups;
        size_t n_cgroups;
        int r;

        assert(context);

        r = walk_cgroups(ctx, &cgroups, &n_cgroups);
        if (r < 0)
                return 0;

        FOREACH_ARRAY(c, cgroups, n_cgroups) {
                uint64_t val;

                r = cg_get_attribute_as_uint64((*c)->path, "pids.current", &val);
                if (r < 0)
                        continue;

                r = metric_build_send_unsigned(
                                context,
                                (*c)->unit,
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
                .description = "Per unit metric: CPU usage in nanoseconds",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = cpu_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadBytes",
                .description = "Per unit metric: IO bytes read",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_bytes_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "IOReadOperations",
                .description = "Per unit metric: IO read operations",
                .type = METRIC_FAMILY_TYPE_COUNTER,
                .generate = io_read_operations_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "MemoryUsage",
                .description = "Per unit metric: memory usage in bytes",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = memory_usage_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_CGROUP_PREFIX "TasksCurrent",
                .description = "Per unit metric: current number of tasks",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = tasks_current_build_json,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(cgroup_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        CGroupContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = metrics_method_list(cgroup_metric_family_table, link, parameters, flags, userdata);

        cgroup_context_flush(ctx);

        return r;
}
