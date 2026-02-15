/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "constants.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "json-util.h"
#include "memstream-util.h"
#include "oomd-conf.h"
#include "oomd-manager.h"
#include "oomd-manager-bus.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "set.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-io.systemd.oom.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

typedef struct ManagedOOMMessage {
        ManagedOOMMode mode;
        char *path;
        char *property;
        uint32_t limit;
        usec_t duration;
} ManagedOOMMessage;

static void managed_oom_message_destroy(ManagedOOMMessage *message) {
        assert(message);
        free(message->path);
        free(message->property);
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_managed_oom_mode, ManagedOOMMode, managed_oom_mode_from_string);

static int process_managed_oom_message(Manager *m, uid_t uid, sd_json_variant *parameters) {
        sd_json_variant *c, *cgroups;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "mode",     SD_JSON_VARIANT_STRING,        dispatch_managed_oom_mode, offsetof(ManagedOOMMessage, mode),     SD_JSON_MANDATORY },
                { "path",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMMessage, path),     SD_JSON_MANDATORY },
                { "property", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,   offsetof(ManagedOOMMessage, property), SD_JSON_MANDATORY },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,   offsetof(ManagedOOMMessage, limit),    0                 },
                { "duration", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,   offsetof(ManagedOOMMessage, duration), 0                 },
                {},
        };

        assert(m);
        assert(parameters);

        cgroups = sd_json_variant_by_key(parameters, "cgroups");
        if (!cgroups)
                return -EINVAL;

        /* Skip malformed elements and keep processing in case the others are good */
        JSON_VARIANT_ARRAY_FOREACH(c, cgroups) {
                _cleanup_(managed_oom_message_destroy) ManagedOOMMessage message = {
                        .duration = USEC_INFINITY,
                };
                OomdCGroupContext *ctx;
                Hashmap *monitor_hm;
                loadavg_t limit;
                usec_t duration;

                if (!sd_json_variant_is_object(c))
                        continue;

                r = sd_json_dispatch(c, dispatch_table, 0, &message);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        continue;

                if (uid != 0) {
                        uid_t cg_uid;

                        r = cg_path_get_owner_uid(message.path, &cg_uid);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to get cgroup %s owner uid: %m", message.path);
                                continue;
                        }

                        /* Let's not be lenient for permission errors and skip processing if we receive an
                        * update for a cgroup that doesn't belong to the user. */
                        if (uid != cg_uid)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "cgroup path owner UID does not match sender uid "
                                                       "(" UID_FMT " != " UID_FMT ")", uid, cg_uid);
                }

                monitor_hm = streq(message.property, "ManagedOOMSwap") ?
                                m->monitored_swap_cgroup_contexts : m->monitored_mem_pressure_cgroup_contexts;

                if (message.mode == MANAGED_OOM_AUTO) {
                        (void) oomd_cgroup_context_unref(hashmap_remove(monitor_hm, empty_to_root(message.path)));
                        continue;
                }

                limit = m->default_mem_pressure_limit;

                if (streq(message.property, "ManagedOOMMemoryPressure") && message.limit > 0) {
                        int permyriad = UINT32_SCALE_TO_PERMYRIAD(message.limit);

                        r = store_loadavg_fixed_point(permyriad / 100LU, permyriad % 100LU, &limit);
                        if (r < 0)
                                continue;
                }

                if (streq(message.property, "ManagedOOMMemoryPressure") && message.duration != USEC_INFINITY)
                        duration = message.duration;
                else
                        duration = m->default_mem_pressure_duration_usec;

                r = oomd_insert_cgroup_context(NULL, monitor_hm, message.path);
                if (r == -ENOMEM)
                        return r;
                if (r < 0 && r != -EEXIST)
                        log_debug_errno(r, "Failed to insert message, ignoring: %m");

                /* Always update the limit in case it was changed. For non-memory pressure detection the value is
                 * ignored so always updating it here is not a problem. */
                ctx = hashmap_get(monitor_hm, empty_to_root(message.path));
                if (ctx) {
                        ctx->mem_pressure_limit = limit;
                        ctx->mem_pressure_duration_usec = duration;
                }
        }

        /* Toggle wake-ups for "ManagedOOMSwap" if entries are present. */
        r = sd_event_source_set_enabled(m->swap_context_event_source,
                                        hashmap_isempty(m->monitored_swap_cgroup_contexts) ? SD_EVENT_OFF : SD_EVENT_ON);
        if (r < 0)
                return log_error_errno(r, "Failed to toggle enabled state of swap context source: %m");

        return 0;
}

static int process_managed_oom_request(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to get varlink peer uid: %m");

        return process_managed_oom_message(m, uid, parameters);
}

static int process_managed_oom_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        if (error_id) {
                r = -EIO;
                log_debug("Error getting ManagedOOM cgroups: %s", error_id);
                goto finish;
        }

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0) {
                log_error_errno(r, "Failed to get varlink peer uid: %m");
                goto finish;
        }

        r = process_managed_oom_message(m, uid, parameters);

finish:
        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                m->varlink_client = sd_varlink_close_unref(link);

        return r;
}

/* Fill 'new_h' with 'path's descendant OomdCGroupContexts. Only include descendant cgroups that are possible
 * candidates for action. That is, only leaf cgroups or cgroups with memory.oom.group set to "1".
 *
 * This function ignores most errors in order to handle cgroups that may have been cleaned up while
 * populating the hashmap.
 *
 * 'new_h' is of the form { key: cgroup paths -> value: OomdCGroupContext } */
static int recursively_get_cgroup_context(Hashmap *new_h, const char *path) {
        _cleanup_free_ char *subpath = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(new_h);
        assert(path);

        r = cg_enumerate_subgroups(path, &d);
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

                cg_path = path_join(empty_to_root(path), subpath);
                if (!cg_path)
                        return -ENOMEM;

                subpath = mfree(subpath);

                r = cg_get_attribute_as_bool(cg_path, "memory.oom.group");
                /* The cgroup might be gone. Skip it as a candidate since we can't get information on it. */
                if (r == -ENOMEM)
                        return r;
                if (r < 0) {
                        log_debug_errno(r, "Failed to read memory.oom.group from %s, ignoring: %m", cg_path);
                        return 0;
                }
                if (r > 0)
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
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *link = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = sd_varlink_connect_address(&link, VARLINK_PATH_MANAGED_OOM_SYSTEM);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to %s: %m", VARLINK_PATH_MANAGED_OOM_SYSTEM);

        (void) sd_varlink_set_userdata(link, m);
        (void) sd_varlink_set_description(link, "oomd");
        (void) sd_varlink_set_relative_timeout(link, USEC_INFINITY);

        r = sd_varlink_attach_event(link, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_bind_reply(link, process_managed_oom_reply);
        if (r < 0)
                return log_error_errno(r, "Failed to bind reply callback: %m");

        r = sd_varlink_observe(link, "io.systemd.ManagedOOM.SubscribeManagedOOMCGroups", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to observe varlink call: %m");

        m->varlink_client = TAKE_PTR(link);
        return 0;
}

static int monitor_swap_contexts_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(!hashmap_isempty(m->monitored_swap_cgroup_contexts));

        /* Reset timer */
        r = sd_event_source_set_time_relative(s, SWAP_INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set relative time for timer: %m");

        /* Reconnect if our connection dropped */
        if (!m->varlink_client) {
                r = acquire_managed_oom_connect(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire varlink connection: %m");
        }

        /* We still try to acquire system information for oomctl even if no units want swap monitoring */
        r = oomd_system_context_acquire("/proc/meminfo", &m->system_context);
        /* If there are no units depending on swap actions, the only error we exit on is ENOMEM. */
        if (r < 0)
                return log_error_errno(r, "Failed to acquire system context: %m");

        /* Note that m->monitored_swap_cgroup_contexts does not need to be updated every interval because only the
         * system context is used for deciding whether the swap threshold is hit. m->monitored_swap_cgroup_contexts
         * is only used to decide which cgroups to kill (and even then only the resource usages of its descendent
         * nodes are the ones that matter). */

        /* Check amount of memory available and swap free so we don't free up swap when memory is still available. */
        if (oomd_mem_available_below(&m->system_context, 10000 - m->swap_used_limit_permyriad) &&
                        oomd_swap_free_below(&m->system_context, 10000 - m->swap_used_limit_permyriad)) {
                _cleanup_hashmap_free_ Hashmap *candidates = NULL;
                OomdCGroupContext *selected = NULL;
                uint64_t threshold;

                log_debug("Memory used (%"PRIu64") / total (%"PRIu64") and "
                          "swap used (%"PRIu64") / total (%"PRIu64") is more than " PERMYRIAD_AS_PERCENT_FORMAT_STR,
                          m->system_context.mem_used, m->system_context.mem_total,
                          m->system_context.swap_used, m->system_context.swap_total,
                          PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad));

                r = get_monitored_cgroup_contexts_candidates(m->monitored_swap_cgroup_contexts, &candidates);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_debug_errno(r, "Failed to get monitored swap cgroup candidates, ignoring: %m");

                threshold = m->system_context.swap_total * THRESHOLD_SWAP_USED_PERCENT / 100;
                r = oomd_select_by_swap_usage(candidates, threshold, &selected);
                if (r < 0)
                        return log_error_errno(r, "Failed to select any cgroups based on swap: %m");
                if (r == 0) {
                        log_debug("No cgroup candidates found for swap-based OOM action");
                        return 0;
                }

                r = oomd_cgroup_kill_mark(m, selected);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        log_error_errno(r, "Failed to select any cgroups based on swap: %m");
                else {
                        if (selected && r > 0) {
                                log_notice("Marked %s for killing due to memory used (%"PRIu64") / total (%"PRIu64") and "
                                           "swap used (%"PRIu64") / total (%"PRIu64") being more than "
                                           PERMYRIAD_AS_PERCENT_FORMAT_STR,
                                           selected->path,
                                           m->system_context.mem_used, m->system_context.mem_total,
                                           m->system_context.swap_used, m->system_context.swap_total,
                                           PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad));
                        }
                        return 0;
                }
        }

        return 0;
}

static void clear_candidate_hashmapp(Manager **m) {
        if (*m)
                hashmap_clear((*m)->monitored_mem_pressure_cgroup_contexts_candidates);
}

static int monitor_memory_pressure_contexts_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        /* Don't want to use stale candidate data. Setting this will clear the candidate hashmap on return unless we
         * update the candidate data (in which case clear_candidates will be NULL). */
        _unused_ _cleanup_(clear_candidate_hashmapp) Manager *clear_candidates = userdata;
        _cleanup_set_free_ Set *targets = NULL;
        bool in_post_action_delay = false;
        Manager *m = ASSERT_PTR(userdata);
        usec_t usec_now;
        int r;

        assert(s);

        /* Reset timer */
        r = sd_event_now(sd_event_source_get_event(s), CLOCK_MONOTONIC, &usec_now);
        if (r < 0)
                return log_error_errno(r, "Failed to reset event timer: %m");

        r = sd_event_source_set_time_relative(s, MEM_PRESSURE_INTERVAL_USEC);
        if (r < 0)
                return log_error_errno(r, "Failed to set relative time for timer: %m");

        /* Reconnect if our connection dropped */
        if (!m->varlink_client) {
                r = acquire_managed_oom_connect(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire varlink connection: %m");
        }

        /* Return early if nothing is requesting memory pressure monitoring */
        if (hashmap_isempty(m->monitored_mem_pressure_cgroup_contexts))
                return 0;

        /* Update the cgroups used for detection/action */
        r = update_monitored_cgroup_contexts(&m->monitored_mem_pressure_cgroup_contexts);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to update monitored memory pressure cgroup contexts, ignoring: %m");

        /* Since pressure counters are lagging, we need to wait a bit after a kill to ensure we don't read stale
         * values and go on a kill storm. */
        if (m->mem_pressure_post_action_delay_start > 0) {
                if (m->mem_pressure_post_action_delay_start + POST_ACTION_DELAY_USEC > usec_now)
                        in_post_action_delay = true;
                else
                        m->mem_pressure_post_action_delay_start = 0;
        }

        r = oomd_pressure_above(m->monitored_mem_pressure_cgroup_contexts, &targets);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                log_debug_errno(r, "Failed to check if memory pressure exceeded limits, ignoring: %m");
        else if (r == 1 && !in_post_action_delay) {
                OomdCGroupContext *t;
                SET_FOREACH(t, targets) {
                        OomdCGroupContext *selected = NULL;

                        /* Check if there was reclaim activity in the given interval. The concern is the following case:
                         * Pressure climbed, a lot of high-frequency pages were reclaimed, and we killed the offending
                         * cgroup. Even after this, well-behaved processes will fault in recently resident pages and
                         * this will cause pressure to remain high. Thus if there isn't any reclaim pressure, no need
                         * to kill something (it won't help anyways). */
                        if ((now(CLOCK_MONOTONIC) - t->last_had_mem_reclaim) > RECLAIM_DURATION_USEC)
                                continue;

                        log_debug("Memory pressure for %s is %lu.%02lu%% > %lu.%02lu%% for > %s with reclaim activity",
                                  t->path,
                                  LOADAVG_INT_SIDE(t->memory_pressure.avg10), LOADAVG_DECIMAL_SIDE(t->memory_pressure.avg10),
                                  LOADAVG_INT_SIDE(t->mem_pressure_limit), LOADAVG_DECIMAL_SIDE(t->mem_pressure_limit),
                                  FORMAT_TIMESPAN(t->mem_pressure_duration_usec, USEC_PER_SEC));

                        r = update_monitored_cgroup_contexts_candidates(
                                        m->monitored_mem_pressure_cgroup_contexts, &m->monitored_mem_pressure_cgroup_contexts_candidates);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                log_debug_errno(r, "Failed to update monitored memory pressure candidate cgroup contexts, ignoring: %m");
                        else
                                clear_candidates = NULL;

                        r = oomd_select_by_pgscan_rate(m->monitored_mem_pressure_cgroup_contexts_candidates,
                                                       /* prefix= */ t->path,
                                                       &selected);
                        if (r < 0)
                                return log_error_errno(r, "Failed to select any cgroups based on swap, ignoring: %m");
                        if (r == 0) {
                                log_debug("No cgroup candidates found for memory pressure-based OOM action for %s", t->path);
                                return 0;
                        }

                        r = oomd_cgroup_kill_mark(m, selected);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                log_error_errno(r, "Failed to select any cgroups under %s based on pressure, ignoring: %m", t->path);
                        else {
                                /* Don't act on all the high pressure cgroups at once; return as soon as we kill one.
                                 * If r == 0 then the cgroup is already queued for kill by an earlier iteration.
                                 * In either case, go through the event loop again and select a new candidate if
                                 * pressure is still high. */
                                m->mem_pressure_post_action_delay_start = usec_now;
                                if (selected && r > 0) {
                                        log_notice("Marked %s for killing due to memory pressure for %s being %lu.%02lu%% > %lu.%02lu%%"
                                                   " for > %s with reclaim activity",
                                                   selected->path, t->path,
                                                   LOADAVG_INT_SIDE(t->memory_pressure.avg10), LOADAVG_DECIMAL_SIDE(t->memory_pressure.avg10),
                                                   LOADAVG_INT_SIDE(t->mem_pressure_limit), LOADAVG_DECIMAL_SIDE(t->mem_pressure_limit),
                                                   FORMAT_TIMESPAN(t->mem_pressure_duration_usec, USEC_PER_SEC));
                                }
                                return 0;
                        }
                }
        } else {
                /* If any monitored cgroup is over their pressure limit, get all the kill candidates for every
                 * monitored cgroup. This saves CPU cycles from doing it every interval by only doing it when a kill
                 * might happen.
                 * Candidate cgroup data will continue to get updated during the post-action delay period in case
                 * pressure continues to be high after a kill. */
                OomdCGroupContext *c;
                HASHMAP_FOREACH(c, m->monitored_mem_pressure_cgroup_contexts) {
                        if (c->mem_pressure_limit_hit_start == 0)
                                continue;

                        r = update_monitored_cgroup_contexts_candidates(
                                        m->monitored_mem_pressure_cgroup_contexts, &m->monitored_mem_pressure_cgroup_contexts_candidates);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                log_debug_errno(r, "Failed to update monitored memory pressure candidate cgroup contexts, ignoring: %m");
                        else {
                                clear_candidates = NULL;
                                break;
                        }
                }
        }

        return 0;
}

static int monitor_swap_contexts(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = sd_event_add_time(m->event, &s, CLOCK_MONOTONIC, 0, 0, monitor_swap_contexts_handler, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(s, true);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "oomd-swap-timer");

        m->swap_context_event_source = TAKE_PTR(s);
        return 0;
}

static int monitor_memory_pressure_contexts(Manager *m) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(m);
        assert(m->event);

        r = sd_event_add_time(m->event, &s, CLOCK_MONOTONIC, 0, 0, monitor_memory_pressure_contexts_handler, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_exit_on_failure(s, true);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "oomd-memory-pressure-timer");

        m->mem_pressure_context_event_source = TAKE_PTR(s);
        return 0;
}

Manager* manager_free(Manager *m) {
        assert(m);

        sd_varlink_server_unref(m->varlink_server);
        sd_varlink_close_unref(m->varlink_client);
        sd_event_source_unref(m->swap_context_event_source);
        sd_event_source_unref(m->mem_pressure_context_event_source);
        sd_event_unref(m->event);

        hashmap_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);

        hashmap_free(m->monitored_swap_cgroup_contexts);
        hashmap_free(m->monitored_mem_pressure_cgroup_contexts);
        hashmap_free(m->monitored_mem_pressure_cgroup_contexts_candidates);

        set_free(m->kill_states);

        return mfree(m);
}

static int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) notify_reloading();

        manager_set_defaults(m);
        manager_parse_config_file(m);

        (void) sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        return 0;
}

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        manager_set_defaults(m);
        manager_parse_config_file(m);

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        (void) sd_event_set_watchdog(m->event, true);

        r = sd_event_add_signal(m->event, /* ret= */ NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, manager_dispatch_reload_signal, m);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
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

static int manager_varlink_init(Manager *m, int fd) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);
        assert(!m->varlink_server);

        r = varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_oom,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interfaces to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.oom.ReportManagedOOMCGroups", process_managed_oom_request,
                        "io.systemd.service.Ping",                varlink_method_ping,
                        "io.systemd.service.SetLogLevel",         varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment",      varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        if (fd < 0)
                r = sd_varlink_server_listen_address(s, VARLINK_PATH_MANAGED_OOM_USER, 0666);
        else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket %s: %m",
                                       VARLINK_PATH_MANAGED_OOM_USER);

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        log_debug("Initialized systemd-oomd varlink server");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

int manager_start(
                Manager *m,
                bool dry_run,
                int fd) {

        int r;

        assert(m);

        m->dry_run = dry_run;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = acquire_managed_oom_connect(m);
        if (r < 0)
                return r;

        r = manager_varlink_init(m, fd);
        if (r < 0)
                return r;

        r = monitor_memory_pressure_contexts(m);
        if (r < 0)
                return r;

        r = monitor_swap_contexts(m);
        if (r < 0)
                return r;

        return 0;
}

int manager_get_dump_string(Manager *m, char **ret) {
        _cleanup_(memstream_done) MemStream ms = {};
        _cleanup_free_ OomdCGroupContext **sorted = NULL;
        size_t n;
        FILE *f;
        int r;

        assert(m);
        assert(ret);

        /* Always reread memory/swap info here. Otherwise it may be outdated if swap monitoring is off.
         * Let's make sure to always report up-to-date data. */
        r = oomd_system_context_acquire("/proc/meminfo", &m->system_context);
        if (r < 0)
                log_debug_errno(r, "Failed to acquire system context, ignoring: %m");

        f = memstream_init(&ms);
        if (!f)
                return -ENOMEM;

        fprintf(f,
                "Dry Run: %s\n"
                "Swap Used Limit: " PERMYRIAD_AS_PERCENT_FORMAT_STR "\n"
                "Default Memory Pressure Limit: %lu.%02lu%%\n"
                "Default Memory Pressure Duration: %s\n"
                "System Context:\n",
                yes_no(m->dry_run),
                PERMYRIAD_AS_PERCENT_FORMAT_VAL(m->swap_used_limit_permyriad),
                LOADAVG_INT_SIDE(m->default_mem_pressure_limit), LOADAVG_DECIMAL_SIDE(m->default_mem_pressure_limit),
                FORMAT_TIMESPAN(m->default_mem_pressure_duration_usec, USEC_PER_SEC));
        oomd_dump_system_context(&m->system_context, f, "\t");

        r = hashmap_dump_sorted(m->monitored_swap_cgroup_contexts, (void***) &sorted, &n);
        if (r < 0)
                return r;

        fprintf(f, "Swap Monitored CGroups:\n");
        FOREACH_ARRAY(c, sorted, n)
                oomd_dump_swap_cgroup_context(*c, f, "\t");

        sorted = mfree(sorted);
        r = hashmap_dump_sorted(m->monitored_mem_pressure_cgroup_contexts, (void***) &sorted, &n);
        if (r < 0)
                return r;

        fprintf(f, "Memory Pressure Monitored CGroups:\n");
        FOREACH_ARRAY(c, sorted, n)
                oomd_dump_memory_pressure_cgroup_context(*c, f, "\t");

        return memstream_finalize(&ms, ret, NULL);
}
