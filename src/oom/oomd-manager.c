/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-log-control-api.h"
#include "bus-util.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "oomd-manager-bus.h"
#include "oomd-manager.h"
#include "path-util.h"

typedef struct ManagedOOMReply {
        ManagedOOMMode mode;
        char *path;
        char *property;
        unsigned limit;
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
                return json_log(v, flags, SYNTHETIC_ERRNO(EINVAL), "%s is not a valid ManagedOOMMode", s);

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
                { "mode",     JSON_VARIANT_STRING,   managed_oom_mode,       offsetof(ManagedOOMReply, mode),     JSON_MANDATORY },
                { "path",     JSON_VARIANT_STRING,   json_dispatch_string,   offsetof(ManagedOOMReply, path),     JSON_MANDATORY },
                { "property", JSON_VARIANT_STRING,   json_dispatch_string,   offsetof(ManagedOOMReply, property), JSON_MANDATORY },
                { "limit",    JSON_VARIANT_UNSIGNED, json_dispatch_unsigned, offsetof(ManagedOOMReply, limit),    0 },
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
                } else if (ret < 0)
                        continue;

                monitor_hm = streq(reply.property, "ManagedOOMSwap") ?
                                m->monitored_swap_cgroup_contexts : m->monitored_mem_pressure_cgroup_contexts;

                if (reply.mode == MANAGED_OOM_AUTO) {
                        (void) oomd_cgroup_context_free(hashmap_remove(monitor_hm, reply.path));
                        continue;
                }

                limit = m->default_mem_pressure_limit;

                if (streq(reply.property, "ManagedOOMMemoryPressure")) {
                        if (reply.limit > 100)
                                continue;
                        else if (reply.limit != 0) {
                                ret = store_loadavg_fixed_point((unsigned long) reply.limit, 0, &limit);
                                if (ret < 0)
                                        continue;
                        }
                }

                ret = oomd_insert_cgroup_context(NULL, monitor_hm, reply.path);
                if (ret == -ENOMEM) {
                        r = ret;
                        goto finish;
                }

                /* Always update the limit in case it was changed. For non-memory pressure detection the value is
                 * ignored so always updating it here is not a problem. */
                ctx = hashmap_get(monitor_hm, reply.path);
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
                return (r == -ENOMEM) ? r : 0;
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
                if (r < 0)
                        return (r == -ENOMEM) ? r : 0;

                if (oom_group)
                        r = oomd_insert_cgroup_context(NULL, new_h, cg_path);
                else
                        r = recursively_get_cgroup_context(new_h, cg_path);
                if (r == -ENOMEM)
                        return r;
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
        }

        *ret_candidates = TAKE_PTR(candidates);

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
                return log_error_errno(r, "Failed to reset event timer");

        r = sd_event_source_set_time_relative(s, INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set relative time for timer");

        /* Reconnect if our connection dropped */
        if (!m->varlink) {
                r = acquire_managed_oom_connect(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire varlink connection");
        }

        /* Update the cgroups used for detection/action */
        r = update_monitored_cgroup_contexts(&m->monitored_swap_cgroup_contexts);
        if (r == -ENOMEM)
                return log_error_errno(r, "Failed to update monitored swap cgroup contexts");

        r = update_monitored_cgroup_contexts(&m->monitored_mem_pressure_cgroup_contexts);
        if (r == -ENOMEM)
                return log_error_errno(r, "Failed to update monitored memory pressure cgroup contexts");

        r = oomd_system_context_acquire("/proc/swaps", &m->system_context);
        /* If there aren't units depending on swap actions, the only error we exit on is ENOMEM */
        if (r == -ENOMEM || (r < 0 && !hashmap_isempty(m->monitored_swap_cgroup_contexts)))
                return log_error_errno(r, "Failed to acquire system context");

        /* If we're still recovering from a kill, don't try to kill again yet */
        if (m->post_action_delay_start > 0) {
                if (m->post_action_delay_start + POST_ACTION_DELAY_USEC > usec_now)
                        return 0;
                else
                        m->post_action_delay_start = 0;
        }

        r = oomd_pressure_above(m->monitored_mem_pressure_cgroup_contexts, PRESSURE_DURATION_USEC, &targets);
        if (r == -ENOMEM)
                return log_error_errno(r, "Failed to check if memory pressure exceeded limits");
        else if (r == 1) {
                /* Check if there was reclaim activity in the last interval. The concern is the following case:
                 * Pressure climbed, a lot of high-frequency pages were reclaimed, and we killed the offending
                 * cgroup. Even after this, well-behaved processes will fault in recently resident pages and
                 * this will cause pressure to remain high. Thus if there isn't any reclaim pressure, no need
                 * to kill something (it won't help anyways). */
                if (oomd_memory_reclaim(m->monitored_mem_pressure_cgroup_contexts)) {
                        _cleanup_hashmap_free_ Hashmap *candidates = NULL;
                        OomdCGroupContext *t;

                        r = get_monitored_cgroup_contexts_candidates(m->monitored_mem_pressure_cgroup_contexts, &candidates);
                        if (r == -ENOMEM)
                                return log_error_errno(r, "Failed to get monitored memory pressure cgroup candidates");

                        SET_FOREACH(t, targets) {
                                log_notice("Memory pressure for %s is greater than %lu for more than %"PRIu64" seconds and there was reclaim activity",
                                        t->path, LOAD_INT(t->mem_pressure_limit), PRESSURE_DURATION_USEC / USEC_PER_SEC);

                                r = oomd_kill_by_pgscan(candidates, t->path, m->dry_run);
                                if (r == -ENOMEM)
                                        return log_error_errno(r, "Failed to kill cgroup processes by pgscan");
                                if (r < 0)
                                        log_info("Failed to kill any cgroup(s) under %s based on pressure", t->path);
                                else {
                                        /* Don't act on all the high pressure cgroups at once; return as soon as we kill one */
                                        m->post_action_delay_start = usec_now;
                                        return 0;
                                }
                        }
                }
        }

        if (oomd_swap_free_below(&m->system_context, (100 - m->swap_used_limit))) {
                _cleanup_hashmap_free_ Hashmap *candidates = NULL;

                log_notice("Swap used (%"PRIu64") / total (%"PRIu64") is more than %u%%",
                        m->system_context.swap_used, m->system_context.swap_total, m->swap_used_limit);

                r = get_monitored_cgroup_contexts_candidates(m->monitored_swap_cgroup_contexts, &candidates);
                if (r == -ENOMEM)
                        return log_error_errno(r, "Failed to get monitored swap cgroup candidates");

                r = oomd_kill_by_swap_usage(candidates, m->dry_run);
                if (r == -ENOMEM)
                        return log_error_errno(r, "Failed to kill cgroup processes by swap usage");
                if (r < 0)
                        log_info("Failed to kill any cgroup(s) based on swap");
                else {
                        m->post_action_delay_start = usec_now;
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

void manager_free(Manager *m) {
        assert(m);

        varlink_close_unref(m->varlink);
        sd_event_source_unref(m->cgroup_context_event_source);
        sd_event_unref(m->event);

        bus_verify_polkit_async_registry_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        hashmap_free(m->monitored_swap_cgroup_contexts);
        hashmap_free(m->monitored_mem_pressure_cgroup_contexts);

        free(m);
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

int manager_start(Manager *m, bool dry_run, int swap_used_limit, int mem_pressure_limit) {
        unsigned long l;
        int r;

        assert(m);

        m->dry_run = dry_run;

        m->swap_used_limit = swap_used_limit != -1 ? swap_used_limit : DEFAULT_SWAP_USED_LIMIT;
        assert(m->swap_used_limit <= 100);

        l = mem_pressure_limit != -1 ? mem_pressure_limit : DEFAULT_MEM_PRESSURE_LIMIT;
        r = store_loadavg_fixed_point(l, 0, &m->default_mem_pressure_limit);
        if (r < 0)
                return r;

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
                "Swap Used Limit: %u%%\n"
                "Default Memory Pressure Limit: %lu%%\n"
                "System Context:\n",
                yes_no(m->dry_run),
                m->swap_used_limit,
                LOAD_INT(m->default_mem_pressure_limit));
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
