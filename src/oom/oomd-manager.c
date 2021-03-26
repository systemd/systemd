/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-log-control-api.h"
#include "bus-util.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "memory-util.h"
#include "oomd-manager-bus.h"
#include "oomd-manager.h"
#include "path-util.h"
#include "percent-util.h"

typedef struct ManagedOOMReply {
        ManagedOOMMode mode;
        char *path;
        char *property;
        uint32_t limit;
} ManagedOOMReply;

static void managed_oom_reply_destroy(ManagedOOMReply *reply) {
        assert(reply);
        free(reply->path);
        free(reply->property);
}

static int managed_oom_mode(const char *name, JsonVariant *v, JsonDispatchFlags flags, void *userdata) {
        ManagedOOMMode *mode = userdata, m;
        const char *s;

        assert(mode);
        assert_se(s = json_variant_string(v));

        m = managed_oom_mode_from_string(s);
        if (m < 0)
                return json_log(v, flags, m, "%s is not a valid ManagedOOMMode", s);

        *mode = m;
        return 0;
}

static int process_managed_oom_reply(
                Varlink *link,
                JsonVariant *parameters,
                const char *error_id,
                VarlinkReplyFlags flags,
                void *userdata) {
        JsonVariant *c, *cgroups;
        Manager *m = userdata;
        int r = 0;

        assert(m);

        static const JsonDispatch dispatch_table[] = {
                { "mode",     JSON_VARIANT_STRING,   managed_oom_mode,     offsetof(ManagedOOMReply, mode),     JSON_MANDATORY },
                { "path",     JSON_VARIANT_STRING,   json_dispatch_string, offsetof(ManagedOOMReply, path),     JSON_MANDATORY },
                { "property", JSON_VARIANT_STRING,   json_dispatch_string, offsetof(ManagedOOMReply, property), JSON_MANDATORY },
                { "limit",    JSON_VARIANT_UNSIGNED, json_dispatch_uint32, offsetof(ManagedOOMReply, limit),    0 },
                {},
        };

        if (error_id) {
                r = -EIO;
                log_debug("Error getting ManagedOOM cgroups: %s", error_id);
                goto finish;
        }

        cgroups = json_variant_by_key(parameters, "cgroups");
        if (!cgroups) {
                r = -EINVAL;
                goto finish;
        }

        /* Skip malformed elements and keep processing in case the others are good */
        JSON_VARIANT_ARRAY_FOREACH(c, cgroups) {
                _cleanup_(managed_oom_reply_destroy) ManagedOOMReply reply = {};
                OomdCGroupContext *ctx;
                Hashmap *monitor_hm;
                loadavg_t limit;
                int ret;

                if (!json_variant_is_object(c))
                        continue;

                ret = json_dispatch(c, dispatch_table, NULL, 0, &reply);
                if (ret == -ENOMEM) {
                        r = ret;
                        goto finish;
                }
                if (ret < 0)
                        continue;

                monitor_hm = streq(reply.property, "ManagedOOMSwap") ?
                                m->monitored_swap_cgroup_contexts : m->monitored_mem_pressure_cgroup_contexts;

                if (reply.mode == MANAGED_OOM_AUTO) {
                        (void) oomd_cgroup_context_free(hashmap_remove(monitor_hm, empty_to_root(reply.path)));
                        continue;
                }

                limit = m->default_mem_pressure_limit;

                if (streq(reply.property, "ManagedOOMMemoryPressure") && reply.limit > 0) {
                        int permyriad = UINT32_SCALE_TO_PERMYRIAD(reply.limit);

                        ret = store_loadavg_fixed_point(
                                        (unsigned long) permyriad / 100,
                                        (unsigned long) permyriad % 100,
                                        &limit);
                        if (ret < 0)
                                continue;
                }

                ret = oomd_insert_cgroup_context(NULL, monitor_hm, reply.path);
                if (ret == -ENOMEM) {
                        r = ret;
                        goto finish;
                }
                if (ret < 0 && ret != -EEXIST)
                        log_debug_errno(ret, "Failed to insert reply, ignoring: %m");

                /* Always update the limit in case it was changed. For non-memory pressure detection the value is
                 * ignored so always updating it here is not a problem. */
                ctx = hashmap_get(monitor_hm, empty_to_root(reply.path));
                if (ctx)
                        ctx->mem_pressure_limit = limit;
        }

finish:
        if (!FLAGS_SET(flags, VARLINK_REPLY_CONTINUES))
                m->varlink = varlink_close_unref(link);

        return r;
}

/* Fill `new_h` with `path`'s descendent OomdCGroupContexts. Only include descendent cgroups that are possible
 * candidates for action. That is, only leaf cgroups or cgroups with memory.oom.group set to "1".
 *
 * This function ignores most errors in order to handle cgroups that may have been cleaned up while populating
 * the hashmap.
 *
 * `new_h` is of the form { key: cgroup paths -> value: OomdCGroupContext } */
static int recursively_get_cgroup_context(Hashmap *new_h, const char *path) {
        _cleanup_free_ char *subpath = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(new_h);
        assert(path);

        r = cg_enumerate_subgroups(SYSTEMD_CGROUP_CONTROLLER, path, &d);
        if (r < 0)
                return r;

        r = cg_read_subgroup(d, &subpath);
        if (r < 0)
                return r;
        else if (r == 0) { /* No subgroups? We're a leaf node */
                r = oomd_insert_cgroup_context(NULL, new_h, path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to insert context for %s, ignoring: %m", path);
                return 0;
        }

        do {
                _cleanup_free_ char *cg_path = NULL;
                bool oom_group;

                cg_path = path_join(empty_to_root(path), subpath);
                if (!cg_path)
                        return -ENOMEM;

                subpath = mfree(subpath);

                r = cg_get_attribute_as_bool("memory", cg_path, "memory.oom.group", &oom_group);
                /* The cgroup might be gone. Skip it as a candidate since we can't get information on it. */
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.oom.group from %s, ignoring: %m", cg_path);
                        return 0;
                }

                if (oom_group)
                        r = oomd_insert_cgroup_context(NULL, new_h, cg_path);
                else
                        r = recursively_get_cgroup_context(new_h, cg_path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to insert or recursively get from %s, ignoring: %m", cg_path);
        } while ((r = cg_read_subgroup(d, &subpath)) > 0);

        return 0;
}

static int update_monitored_cgroup_contexts(Hashmap **monitored_cgroups) {
        _cleanup_hashmap_free_ Hashmap *new_base = NULL;
        OomdCGroupContext *ctx;
        int r;

        assert(monitored_cgroups);

        new_base = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!new_base)
                return -ENOMEM;

        HASHMAP_FOREACH(ctx, *monitored_cgroups) {
                /* Skip most errors since the cgroup we're trying to update might not exist anymore. */
                r = oomd_insert_cgroup_context(*monitored_cgroups, new_base, ctx->path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0 && !IN_SET(r, -EEXIST, -ENOENT))
                        log_debug_errno(r, "Failed to insert context for %s, ignoring: %m", ctx->path);
        }

        hashmap_free(*monitored_cgroups);
        *monitored_cgroups = TAKE_PTR(new_base);

        return 0;
}

static int get_monitored_cgroup_contexts_candidates(Hashmap *monitored_cgroups, Hashmap **ret_candidates) {
        _cleanup_hashmap_free_ Hashmap *candidates = NULL;
        OomdCGroupContext *ctx;
        int r;

        assert(monitored_cgroups);
        assert(ret_candidates);

        candidates = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!candidates)
                return -ENOMEM;

        HASHMAP_FOREACH(ctx, monitored_cgroups) {
                r = recursively_get_cgroup_context(candidates, ctx->path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to recursively get contexts for %s, ignoring: %m", ctx->path);
        }

        *ret_candidates = TAKE_PTR(candidates);

        return 0;
}

static int update_monitored_cgroup_contexts_candidates(Hashmap *monitored_cgroups, Hashmap **candidates) {
        _cleanup_hashmap_free_ Hashmap *new_candidates = NULL;
        int r;

        assert(monitored_cgroups);
        assert(candidates);
        assert(*candidates);

        r = get_monitored_cgroup_contexts_candidates(monitored_cgroups, &new_candidates);
        if (r < 0)
                return log_debug_errno(r, "Failed to get candidate contexts: %m");

        oomd_update_cgroup_contexts_between_hashmaps(*candidates, new_candidates);

        hashmap_free(*candidates);
        *candidates = TAKE_PTR(new_candidates);

        return 0;
}

static int acquire_managed_oom_connect(Manager *m) {
        _cleanup_(varlink_close_unrefp) Varlink *link = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = varlink_connect_address(&link, VARLINK_ADDR_PATH_MANAGED_OOM);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to %s: %m", VARLINK_ADDR_PATH_MANAGED_OOM);

        (void) varlink_set_userdata(link, m);
        (void) varlink_set_description(link, "oomd");
        (void) varlink_set_relative_timeout(link, USEC_INFINITY);

        r = varlink_attach_event(link, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = varlink_bind_reply(link, process_managed_oom_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        r = varlink_observe(link, "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to observe varlink call: %m");

        m->varlink = TAKE_PTR(link);
        return 0;
}

static int monitor_cgroup_contexts_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_set_free_ Set *targets = NULL;
        Manager *m = userdata;
        usec_t usec_now;
        int r;

        assert(s);
        assert(userdata);

        /* Reset timer */
        r = sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &usec_now);
        if (r < 0)
                return log_error_errno(r, "Failed to reset event timer: %m");

        r = sd_event_source_set_time_relative(s, INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set relative time for timer: %m");

        /* Reconnect if our connection dropped */
        if (!m->varlink) {
                r = acquire_managed_oom_connect(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire varlink connection: %m");
        }

        /* Update the cgroups used for detection/action */
        r = update_monitored_cgroup_contexts(&m->monitored_swap_cgroup_contexts);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to update monitored swap cgroup contexts, ignoring: %m");

        r = update_monitored_cgroup_contexts(&m->monitored_mem_pressure_cgroup_contexts);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to update monitored memory pressure cgroup contexts, ignoring: %m");

        r = update_monitored_cgroup_contexts_candidates(
                        m->monitored_mem_pressure_cgroup_contexts, &m->monitored_mem_pressure_cgroup_contexts_candidates);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to update monitored memory pressure candidate cgroup contexts, ignoring: %m");

        r = oomd_system_context_acquire("/proc/swaps", &m->system_context);
        /* If there aren't units depending on swap actions, the only error we exit on is ENOMEM.
         * Allow ENOENT in the event that swap is disabled on the system. */
        if (r == -ENOMEM || (r < 0 && r != -ENOENT && !hashmap_isempty(m->monitored_swap_cgroup_contexts)))
                return log_error_errno(r, "Failed to acquire system context: %m");
        else if (r == -ENOENT)
                zero(m->system_context);

        if (oomd_memory_reclaim(m->monitored_mem_pressure_cgroup_contexts))
                m->last_reclaim_at = usec_now;

        /* If we're still recovering from a kill, don't try to kill again yet */
        if (m->post_action_delay_start > 0) {
                if (m->post_action_delay_start + POST_ACTION_DELAY_USEC > usec_now)
                        return 0;
                else
                        m->post_action_delay_start = 0;
        }

        r = oomd_pressure_above(m->monitored_mem_pressure_cgroup_contexts, m->default_mem_pressure_duration_usec, &targets);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to check if memory pressure exceeded limits, ignoring: %m");
        else if (r == 1) {
                /* Check if there was reclaim activity in the given interval. The concern is the following case:
                 * Pressure climbed, a lot of high-frequency pages were reclaimed, and we killed the offending
                 * cgroup. Even after this, well-behaved processes will fault in recently resident pages and
                 * this will cause pressure to remain high. Thus if there isn't any reclaim pressure, no need
                 * to kill something (it won't help anyways). */
                if ((usec_now - m->last_reclaim_at) <= RECLAIM_DURATION_USEC) {
                        OomdCGroupContext *t;

                        SET_FOREACH(t, targets) {
                                _cleanup_free_ char *selected = NULL;
                                char ts[FORMAT_TIMESPAN_MAX];

                                log_debug("Memory pressure for %s is %lu.%02lu%% > %lu.%02lu%% for > %s with reclaim activity",
                                          t->path,
                                          LOAD_INT(t->memory_pressure.avg10), LOAD_FRAC(t->memory_pressure.avg10),
                                          LOAD_INT(t->mem_pressure_limit), LOAD_FRAC(t->mem_pressure_limit),
                                          format_timespan(ts, sizeof ts,
                                                          m->default_mem_pressure_duration_usec,
                                                          USEC_PER_SEC));

                                r = oomd_kill_by_pgscan_rate(m->monitored_mem_pressure_cgroup_contexts_candidates, t->path, m->dry_run, &selected);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        log_notice_errno(r, "Failed to kill any cgroup(s) under %s based on pressure: %m", t->path);
                                else {
                                        /* Don't act on all the high pressure cgroups at once; return as soon as we kill one */
                                        m->post_action_delay_start = usec_now;
                                        if (selected)
                                                log_notice("Killed %s due to memory pressure for %s being %lu.%02lu%% > %lu.%02lu%%"
                                                           " for > %s with reclaim activity",
                                                           selected, t->path,
                                                           LOAD_INT(t->memory_pressure.avg10), LOAD_FRAC(t->memory_pressure.avg10),
                                                           LOAD_INT(t->mem_pressure_limit), LOAD_FRAC(t->mem_pressure_limit),
                                                           format_timespan(ts, sizeof ts,
                                                                           m->default_mem_pressure_duration_usec,
                                                                           USEC_PER_SEC));
                                        return 0;
                                }
                        }
                }
        }

        if (oomd_swap_free_below(&m->system_context, 10000 - m->swap_used_limit_permyriad)) {
                _cleanup_hashmap_free_ Hashmap *candidates = NULL;
                _cleanup_free_ char *selected = NULL;

                log_debug("Swap used (%"PRIu64") / total (%"PRIu64") is more than " PERMYRIAD_AS_PERCENT_FORMAT_STR,
                          m->system_context.swap_used, m->system_context.swap_total,
                          PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad));

                r = get_monitored_cgroup_contexts_candidates(m->monitored_swap_cgroup_contexts, &candidates);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_debug_errno(r, "Failed to get monitored swap cgroup candidates, ignoring: %m");

                r = oomd_kill_by_swap_usage(candidates, m->dry_run, &selected);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_notice_errno(r, "Failed to kill any cgroup(s) based on swap: %m");
                else {
                        m->post_action_delay_start = usec_now;
                        if (selected)
                                log_notice("Killed %s due to swap used (%"PRIu64") / total (%"PRIu64") being more than "
                                           PERMYRIAD_AS_PERCENT_FORMAT_STR,
                                           selected, m->system_context.swap_used, m->system_context.swap_total,
                                           PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad));
                        return 0;
                }
        }

        return 0;
}

static int monitor_cgroup_contexts(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = sd_event_add_time(m->event, &s, CLOCK_MONOTONIC, 0, 0, monitor_cgroup_contexts_handler, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(s, true);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "oomd-timer");

        m->cgroup_context_event_source = TAKE_PTR(s);
        return 0;
}

Manager* manager_free(Manager *m) {
        assert(m);

        varlink_close_unref(m->varlink);
        sd_event_source_unref(m->cgroup_context_event_source);
        sd_event_unref(m->event);

        bus_verify_polkit_async_registry_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        hashmap_free(m->monitored_swap_cgroup_contexts);
        hashmap_free(m->monitored_mem_pressure_cgroup_contexts);
        hashmap_free(m->monitored_mem_pressure_cgroup_contexts_candidates);

        return mfree(m);
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_event_add_signal(m->event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return r;

        m->monitored_swap_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->monitored_swap_cgroup_contexts)
                return -ENOMEM;

        m->monitored_mem_pressure_cgroup_contexts = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->monitored_mem_pressure_cgroup_contexts)
                return -ENOMEM;

        m->monitored_mem_pressure_cgroup_contexts_candidates = hashmap_new(&oomd_cgroup_ctx_hash_ops);
        if (!m->monitored_mem_pressure_cgroup_contexts_candidates)
                return -ENOMEM;

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-oom");
        if (r < 0)
                return log_error_errno(r, "Failed to connect to bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.oom1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}

int manager_start(
                Manager *m,
                bool dry_run,
                int swap_used_limit_permyriad,
                int mem_pressure_limit_permyriad,
                usec_t mem_pressure_usec) {

        unsigned long l, f;
        int r;

        assert(m);

        m->dry_run = dry_run;

        m->swap_used_limit_permyriad = swap_used_limit_permyriad >= 0 ? swap_used_limit_permyriad : DEFAULT_SWAP_USED_LIMIT_PERCENT * 100;
        assert(m->swap_used_limit_permyriad <= 10000);

        if (mem_pressure_limit_permyriad >= 0) {
                assert(mem_pressure_limit_permyriad <= 10000);

                l = mem_pressure_limit_permyriad / 100;
                f = mem_pressure_limit_permyriad % 100;
        } else {
                l = DEFAULT_MEM_PRESSURE_LIMIT_PERCENT;
                f = 0;
        }
        r = store_loadavg_fixed_point(l, f, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;

        m->default_mem_pressure_duration_usec = mem_pressure_usec ?: DEFAULT_MEM_PRESSURE_DURATION_USEC;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = acquire_managed_oom_connect(m);
        if (r < 0)
                return r;

        r = monitor_cgroup_contexts(m);
        if (r < 0)
                return r;

        return 0;
}

int manager_get_dump_string(Manager *m, char **ret) {
        _cleanup_free_ char *dump = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char buf[FORMAT_TIMESPAN_MAX];
        OomdCGroupContext *c;
        size_t size;
        char *key;
        int r;

        assert(m);
        assert(ret);

        f = open_memstream_unlocked(&dump, &size);
        if (!f)
                return -errno;

        fprintf(f,
                "Dry Run: %s\n"
                "Swap Used Limit: " PERMYRIAD_AS_PERCENT_FORMAT_STR "\n"
                "Default Memory Pressure Limit: %lu.%02lu%%\n"
                "Default Memory Pressure Duration: %s\n"
                "System Context:\n",
                yes_no(m->dry_run),
                PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad),
                LOAD_INT(m->default_mem_pressure_limit), LOAD_FRAC(m->default_mem_pressure_limit),
                format_timespan(buf, sizeof(buf), m->default_mem_pressure_duration_usec, USEC_PER_SEC));
        oomd_dump_system_context(&m->system_context, f, "\t");

        fprintf(f, "Swap Monitored CGroups:\n");
        HASHMAP_FOREACH_KEY(c, key, m->monitored_swap_cgroup_contexts)
                oomd_dump_swap_cgroup_context(c, f, "\t");

        fprintf(f, "Memory Pressure Monitored CGroups:\n");
        HASHMAP_FOREACH_KEY(c, key, m->monitored_mem_pressure_cgroup_contexts)
                oomd_dump_memory_pressure_cgroup_context(c, f, "\t");

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        f = safe_fclose(f);

        *ret = TAKE_PTR(dump);
        return 0;
}
