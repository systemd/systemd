/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "alloc-util.h"
#include "cgroup-setup.h"
#include "dbus-scope.h"
#include "dbus-unit.h"
#include "exit-status.h"
#include "load-dropin.h"
#include "log.h"
#include "process-util.h"
#include "random-util.h"
#include "scope.h"
#include "serialize.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"
#include "user-util.h"

static const UnitActiveState state_translation_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD]         = UNIT_INACTIVE,
        [SCOPE_START_CHOWN]  = UNIT_ACTIVATING,
        [SCOPE_RUNNING]      = UNIT_ACTIVE,
        [SCOPE_ABANDONED]    = UNIT_ACTIVE,
        [SCOPE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SCOPE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SCOPE_FAILED]       = UNIT_FAILED,
};

static int scope_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);

static void scope_init(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        assert(u->load_state == UNIT_STUB);

        s->runtime_max_usec = USEC_INFINITY;
        s->timeout_stop_usec = u->manager->defaults.timeout_stop_usec;
        u->ignore_on_isolate = true;
        s->user = s->group = NULL;
        s->oom_policy = _OOM_POLICY_INVALID;
}

static void scope_done(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        s->controller = mfree(s->controller);
        s->controller_track = sd_bus_track_unref(s->controller_track);

        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);

        s->user = mfree(s->user);
        s->group = mfree(s->group);
}

static usec_t scope_running_timeout(Scope *s) {
        usec_t delta = 0;

        assert(s);

        if (s->runtime_rand_extra_usec != 0) {
                delta = random_u64_range(s->runtime_rand_extra_usec);
                log_unit_debug(UNIT(s), "Adding delta of %s sec to timeout", FORMAT_TIMESPAN(delta, USEC_PER_SEC));
        }

        return usec_add(usec_add(UNIT(s)->active_enter_timestamp.monotonic,
                                 s->runtime_max_usec),
                        delta);
}

static int scope_arm_timer(Scope *s, bool relative, usec_t usec) {
        assert(s);

        return unit_arm_timer(UNIT(s), &s->timer_event_source, relative, usec, scope_dispatch_timer);
}

static void scope_set_state(Scope *s, ScopeState state) {
        ScopeState old_state;

        assert(s);

        if (s->state != state)
                bus_unit_send_pending_change_signal(UNIT(s), false);

        old_state = s->state;
        s->state = state;

        if (!IN_SET(state, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL, SCOPE_START_CHOWN, SCOPE_RUNNING))
                s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);

        if (!IN_SET(old_state, SCOPE_DEAD, SCOPE_FAILED) && IN_SET(state, SCOPE_DEAD, SCOPE_FAILED)) {
                unit_unwatch_all_pids(UNIT(s));
                unit_dequeue_rewatch_pids(UNIT(s));
        }

        if (state != old_state)
                log_unit_debug(UNIT(s), "Changed %s -> %s",
                               scope_state_to_string(old_state), scope_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], /* reload_success = */ true);
}

static int scope_add_default_dependencies(Scope *s) {
        int r;

        assert(s);

        if (!UNIT(s)->default_dependencies)
                return 0;

        /* Make sure scopes are unloaded on shutdown */
        r = unit_add_two_dependencies_by_name(
                        UNIT(s),
                        UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, true,
                        UNIT_DEPENDENCY_DEFAULT);
        if (r < 0)
                return r;

        return 0;
}

static int scope_verify(Scope *s) {
        assert(s);
        assert(UNIT(s)->load_state == UNIT_LOADED);

        if (set_isempty(UNIT(s)->pids) &&
            !MANAGER_IS_RELOADING(UNIT(s)->manager) &&
            !unit_has_name(UNIT(s), SPECIAL_INIT_SCOPE))
                return log_unit_error_errno(UNIT(s), SYNTHETIC_ERRNO(ENOENT), "Scope has no PIDs. Refusing.");

        return 0;
}

static int scope_load_init_scope(Unit *u) {
        assert(u);

        if (!unit_has_name(u, SPECIAL_INIT_SCOPE))
                return 0;

        u->transient = true;
        u->perpetual = true;

        /* init.scope is a bit special, as it has to stick around forever. Because of its special semantics we
         * synthesize it here, instead of relying on the unit file on disk. */

        u->default_dependencies = false;

        /* Prettify things, if we can. */
        if (!u->description)
                u->description = strdup("System and Service Manager");
        if (!u->documentation)
                (void) strv_extend(&u->documentation, "man:systemd(1)");

        return 1;
}

static int scope_add_extras(Scope *s) {
        int r;

        r = unit_patch_contexts(UNIT(s));
        if (r < 0)
                return r;

        r = unit_set_default_slice(UNIT(s));
        if (r < 0)
                return r;

        if (s->oom_policy < 0)
                s->oom_policy = s->cgroup_context.delegate ? OOM_CONTINUE : UNIT(s)->manager->defaults.oom_policy;

        s->cgroup_context.memory_oom_group = s->oom_policy == OOM_KILL;

        return scope_add_default_dependencies(s);
}

static int scope_load(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));
        int r;

        assert(u->load_state == UNIT_STUB);

        if (!u->transient && !MANAGER_IS_RELOADING(u->manager))
                /* Refuse to load non-transient scope units, but allow them while reloading. */
                return -ENOENT;

        r = scope_load_init_scope(u);
        if (r < 0)
                return r;

        r = unit_load_fragment_and_dropin(u, false);
        if (r < 0)
                return r;

        if (u->load_state != UNIT_LOADED)
                return 0;

        r = scope_add_extras(s);
        if (r < 0)
                return r;

        return scope_verify(s);
}

static usec_t scope_coldplug_timeout(Scope *s) {
        assert(s);

        switch (s->deserialized_state) {

        case SCOPE_RUNNING:
                return scope_running_timeout(s);

        case SCOPE_STOP_SIGKILL:
        case SCOPE_STOP_SIGTERM:
                return usec_add(UNIT(s)->state_change_timestamp.monotonic, s->timeout_stop_usec);

        default:
                return USEC_INFINITY;
        }
}

static int scope_coldplug(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));
        int r;

        assert(s->state == SCOPE_DEAD);

        if (s->deserialized_state == s->state)
                return 0;

        r = scope_arm_timer(s, /* relative= */ false, scope_coldplug_timeout(s));
        if (r < 0)
                return r;

        if (!IN_SET(s->deserialized_state, SCOPE_DEAD, SCOPE_FAILED)) {
                if (u->pids) {
                        PidRef *pid;

                        SET_FOREACH(pid, u->pids) {
                                r = unit_watch_pidref(u, pid, /* exclusive= */ false);
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }
                } else
                        (void) unit_enqueue_rewatch_pids(u);
        }

        bus_scope_track_controller(s);

        scope_set_state(s, s->deserialized_state);
        return 0;
}

static void scope_dump(Unit *u, FILE *f, const char *prefix) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        assert(f);
        assert(prefix);

        fprintf(f,
                "%sScope State: %s\n"
                "%sResult: %s\n"
                "%sRuntimeMaxSec: %s\n"
                "%sRuntimeRandomizedExtraSec: %s\n"
                "%sOOMPolicy: %s\n",
                prefix, scope_state_to_string(s->state),
                prefix, scope_result_to_string(s->result),
                prefix, FORMAT_TIMESPAN(s->runtime_max_usec, USEC_PER_SEC),
                prefix, FORMAT_TIMESPAN(s->runtime_rand_extra_usec, USEC_PER_SEC),
                prefix, oom_policy_to_string(s->oom_policy));

        cgroup_context_dump(u, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);
}

static void scope_enter_dead(Scope *s, ScopeResult f) {
        assert(s);

        if (s->result == SCOPE_SUCCESS)
                s->result = f;

        unit_log_result(UNIT(s), s->result == SCOPE_SUCCESS, scope_result_to_string(s->result));
        scope_set_state(s, s->result != SCOPE_SUCCESS ? SCOPE_FAILED : SCOPE_DEAD);
}

static void scope_enter_signal(Scope *s, ScopeState state, ScopeResult f) {
        bool skip_signal = false;
        int r;

        assert(s);

        if (s->result == SCOPE_SUCCESS)
                s->result = f;

        /* Before sending any signal, make sure we track all members of this cgroup */
        (void) unit_watch_all_pids(UNIT(s));

        /* Also, enqueue a job that we recheck all our PIDs a bit later, given that it's likely some processes have
         * died now */
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        /* If we have a controller set let's ask the controller nicely to terminate the scope, instead of us going
         * directly into SIGTERM berserk mode */
        if (state == SCOPE_STOP_SIGTERM)
                skip_signal = bus_scope_send_request_stop(s) > 0;

        if (skip_signal)
                r = 1; /* wait */
        else {
                r = unit_kill_context(
                                UNIT(s),
                                state != SCOPE_STOP_SIGTERM ? KILL_KILL :
                                s->was_abandoned            ? KILL_TERMINATE_AND_LOG :
                                                              KILL_TERMINATE);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");
                        goto fail;
                }
        }

        if (r > 0) {
                r = scope_arm_timer(s, /* relative= */ true, s->timeout_stop_usec);
                if (r < 0) {
                        log_unit_warning_errno(UNIT(s), r, "Failed to install timer: %m");
                        goto fail;
                }

                scope_set_state(s, state);
        } else if (state == SCOPE_STOP_SIGTERM)
                scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_SUCCESS);
        else
                scope_enter_dead(s, SCOPE_SUCCESS);

        return;

fail:
        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
}

static int scope_enter_start_chown(Scope *s) {
        Unit *u = UNIT(ASSERT_PTR(s));
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert(s->user);

        if (!s->cgroup_runtime)
                return -EINVAL;

        r = scope_arm_timer(s, /* relative= */ true, u->manager->defaults.timeout_start_usec);
        if (r < 0)
                return r;

        r = unit_fork_helper_process(u, "(sd-chown-cgroup)", /* into_cgroup= */ true, &pidref);
        if (r < 0)
                goto fail;

        if (r == 0) {
                uid_t uid = UID_INVALID;
                gid_t gid = GID_INVALID;

                if (!isempty(s->user)) {
                        const char *user = s->user;

                        r = get_user_creds(&user, &uid, &gid, NULL, NULL, 0);
                        if (r < 0) {
                                log_unit_error_errno(UNIT(s), r, "Failed to resolve user \"%s\": %m", user);
                                _exit(EXIT_USER);
                        }
                }

                if (!isempty(s->group)) {
                        const char *group = s->group;

                        r = get_group_creds(&group, &gid, 0);
                        if (r < 0) {
                                log_unit_error_errno(UNIT(s), r, "Failed to resolve group \"%s\": %m", group);
                                _exit(EXIT_GROUP);
                        }
                }

                r = cg_set_access(SYSTEMD_CGROUP_CONTROLLER, s->cgroup_runtime->cgroup_path, uid, gid);
                if (r < 0) {
                        log_unit_error_errno(UNIT(s), r, "Failed to adjust control group access: %m");
                        _exit(EXIT_CGROUP);
                }

                _exit(EXIT_SUCCESS);
        }

        r = unit_watch_pidref(UNIT(s), &pidref, /* exclusive= */ true);
        if (r < 0)
                goto fail;

        scope_set_state(s, SCOPE_START_CHOWN);

        return 1;
fail:
        s->timer_event_source = sd_event_source_disable_unref(s->timer_event_source);
        return r;
}

static int scope_enter_running(Scope *s) {
        Unit *u = UNIT(ASSERT_PTR(s));
        int r;

        (void) bus_scope_track_controller(s);

        r = unit_acquire_invocation_id(u);
        if (r < 0)
                return r;

        unit_export_state_files(u);

        r = unit_attach_pids_to_cgroup(u, u->pids, NULL);
        if (r < 0) {
                log_unit_warning_errno(u, r, "Failed to add PIDs to scope's control group: %m");
                goto fail;
        }
        if (r == 0) {
                r = log_unit_warning_errno(u, SYNTHETIC_ERRNO(ECHILD), "No PIDs left to attach to the scope's control group, refusing.");
                goto fail;
        }
        log_unit_debug(u, "%i %s added to scope's control group.", r, r == 1 ? "process" : "processes");

        s->result = SCOPE_SUCCESS;

        scope_set_state(s, SCOPE_RUNNING);

        /* Set the maximum runtime timeout. */
        scope_arm_timer(s, /* relative= */ false, scope_running_timeout(s));

        /* On unified we use proper notifications hence we can unwatch the PIDs
         * we just attached to the scope. This can also be done on legacy as
         * we're going to update the list of the processes we watch with the
         * PIDs currently in the scope anyway. */
        unit_unwatch_all_pids(u);

        /* Start watching the PIDs currently in the scope (legacy hierarchy only) */
        (void) unit_enqueue_rewatch_pids(u);
        return 1;

fail:
        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
        return r;
}

static int scope_start(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                return -EPERM;

        if (s->state == SCOPE_FAILED)
                return -EPERM;

        /* We can't fulfill this right now, please try again later */
        if (IN_SET(s->state, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL))
                return -EAGAIN;

        assert(s->state == SCOPE_DEAD);

        if (!u->transient && !MANAGER_IS_RELOADING(u->manager))
                return -ENOENT;

        (void) unit_realize_cgroup(u);
        (void) unit_reset_accounting(u);

        /* We check only for User= option to keep behavior consistent with logic for service units,
         * i.e. having 'Delegate=true Group=foo' w/o specifying User= has no effect. */
        if (s->user && unit_cgroup_delegate(u))
                return scope_enter_start_chown(s);

        return scope_enter_running(s);
}

static int scope_stop(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        if (IN_SET(s->state, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL))
                return 0;

        assert(IN_SET(s->state, SCOPE_RUNNING, SCOPE_ABANDONED));

        scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_SUCCESS);
        return 1;
}

static void scope_reset_failed(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        if (s->state == SCOPE_FAILED)
                scope_set_state(s, SCOPE_DEAD);

        s->result = SCOPE_SUCCESS;
}

static int scope_get_timeout(Unit *u, usec_t *timeout) {
        Scope *s = ASSERT_PTR(SCOPE(u));
        usec_t t;
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY)
                return 0;

        *timeout = t;
        return 1;
}

static int scope_serialize(Unit *u, FILE *f, FDSet *fds) {
        Scope *s = ASSERT_PTR(SCOPE(u));
        PidRef *pid;

        assert(f);
        assert(fds);

        (void) serialize_item(f, "state", scope_state_to_string(s->state));
        (void) serialize_bool(f, "was-abandoned", s->was_abandoned);

        if (s->controller)
                (void) serialize_item(f, "controller", s->controller);

        SET_FOREACH(pid, u->pids)
                serialize_pidref(f, fds, "pids", pid);

        return 0;
}

static int scope_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Scope *s = ASSERT_PTR(SCOPE(u));
        int r;

        assert(key);
        assert(value);
        assert(fds);

        if (streq(key, "state")) {
                ScopeState state;

                state = scope_state_from_string(value);
                if (state < 0)
                        log_unit_debug(u, "Failed to parse state value: %s", value);
                else
                        s->deserialized_state = state;

        } else if (streq(key, "was-abandoned")) {
                int k;

                k = parse_boolean(value);
                if (k < 0)
                        log_unit_debug(u, "Failed to parse boolean value: %s", value);
                else
                        s->was_abandoned = k;
        } else if (streq(key, "controller")) {

                r = free_and_strdup(&s->controller, value);
                if (r < 0)
                        return log_oom();

        } else if (streq(key, "pids")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                /* We don't check if we already received the pid before here because unit_watch_pidref()
                 * does this check internally and discards the new pidref if we already received it before. */
                if (deserialize_pidref(fds, value, &pidref) >= 0) {
                        r = unit_watch_pidref(u, &pidref, /* exclusive= */ false);
                        if (r < 0)
                                log_unit_debug(u, "Failed to watch PID, ignoring: %s", value);
                }
        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static void scope_notify_cgroup_empty_event(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        log_unit_debug(u, "cgroup is empty");

        if (IN_SET(s->state, SCOPE_RUNNING, SCOPE_ABANDONED, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL))
                scope_enter_dead(s, SCOPE_SUCCESS);
}

static void scope_notify_cgroup_oom_event(Unit *u, bool managed_oom) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        if (managed_oom)
                log_unit_debug(u, "Process(es) of control group were killed by systemd-oomd.");
        else
                log_unit_debug(u, "Process of control group was killed by the OOM killer.");

        if (s->oom_policy == OOM_CONTINUE)
                return;

        switch (s->state) {

        case SCOPE_START_CHOWN:
        case SCOPE_RUNNING:
                scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_FAILURE_OOM_KILL);
                break;

        case SCOPE_STOP_SIGTERM:
                scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_FAILURE_OOM_KILL);
                break;

        case SCOPE_STOP_SIGKILL:
                if (s->result == SCOPE_SUCCESS)
                        s->result = SCOPE_FAILURE_OOM_KILL;
                break;
        /* SCOPE_DEAD, SCOPE_ABANDONED, and SCOPE_FAILED end up in default */
        default:
                ;
        }
}

static void scope_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        if (s->state == SCOPE_START_CHOWN) {
                if (!is_clean_exit(code, status, EXIT_CLEAN_COMMAND, NULL))
                        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
                else
                        scope_enter_running(s);
                return;
        }

        /* If we get a SIGCHLD event for one of the processes we were interested in, then we look for others to
         * watch, under the assumption that we'll sooner or later get a SIGCHLD for them, as the original
         * process we watched was probably the parent of them, and they are hence now our children. */

        (void) unit_enqueue_rewatch_pids(u);
}

static int scope_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Scope *s = ASSERT_PTR(SCOPE(userdata));

        assert(s->timer_event_source == source);

        switch (s->state) {

        case SCOPE_RUNNING:
                log_unit_warning(UNIT(s), "Scope reached runtime time limit. Stopping.");
                scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_FAILURE_TIMEOUT);
                break;

        case SCOPE_STOP_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_unit_warning(UNIT(s), "Stopping timed out. Killing.");
                        scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_FAILURE_TIMEOUT);
                } else {
                        log_unit_warning(UNIT(s), "Stopping timed out. Skipping SIGKILL.");
                        scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                }

                break;

        case SCOPE_STOP_SIGKILL:
                log_unit_warning(UNIT(s), "Still around after SIGKILL. Ignoring.");
                scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                break;

        case SCOPE_START_CHOWN:
                log_unit_warning(UNIT(s), "User lookup timed out. Entering failed state.");
                scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

int scope_abandon(Scope *s) {
        assert(s);

        if (unit_has_name(UNIT(s), SPECIAL_INIT_SCOPE))
                return -EPERM;

        if (!IN_SET(s->state, SCOPE_RUNNING, SCOPE_ABANDONED))
                return -ESTALE;

        s->was_abandoned = true;

        s->controller = mfree(s->controller);
        s->controller_track = sd_bus_track_unref(s->controller_track);

        scope_set_state(s, SCOPE_ABANDONED);

        /* The client is no longer watching the remaining processes, so let's step in here, under the assumption that
         * the remaining processes will be sooner or later reassigned to us as parent. */
        (void) unit_enqueue_rewatch_pids(UNIT(s));

        return 0;
}

static UnitActiveState scope_active_state(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        return state_translation_table[s->state];
}

static const char *scope_sub_state_to_string(Unit *u) {
        Scope *s = ASSERT_PTR(SCOPE(u));

        return scope_state_to_string(s->state);
}

static void scope_enumerate_perpetual(Manager *m) {
        Unit *u;
        int r;

        assert(m);

        /* Let's unconditionally add the "init.scope" special unit
         * that encapsulates PID 1. Note that PID 1 already is in the
         * cgroup for this, we hence just need to allocate the object
         * for it and that's it. */

        u = manager_get_unit(m, SPECIAL_INIT_SCOPE);
        if (!u) {
                r = unit_new_for_name(m, sizeof(Scope), SPECIAL_INIT_SCOPE, &u);
                if (r < 0)  {
                        log_error_errno(r, "Failed to allocate the special " SPECIAL_INIT_SCOPE " unit: %m");
                        return;
                }
        }

        u->transient = true;
        u->perpetual = true;
        SCOPE(u)->deserialized_state = SCOPE_RUNNING;

        unit_add_to_load_queue(u);
        unit_add_to_dbus_queue(u);
        /* Enqueue an explicit cgroup realization here. Unlike other cgroups this one already exists and is
         * populated (by us, after all!) already, even when we are not in a reload cycle. Hence we cannot
         * apply the settings at creation time anymore, but let's at least apply them asynchronously. */
        unit_add_to_cgroup_realize_queue(u);
}

static const char* const scope_result_table[_SCOPE_RESULT_MAX] = {
        [SCOPE_SUCCESS]           = "success",
        [SCOPE_FAILURE_RESOURCES] = "resources",
        [SCOPE_FAILURE_TIMEOUT]   = "timeout",
        [SCOPE_FAILURE_OOM_KILL]  = "oom-kill",
};

DEFINE_STRING_TABLE_LOOKUP(scope_result, ScopeResult);

const UnitVTable scope_vtable = {
        .object_size = sizeof(Scope),
        .cgroup_context_offset = offsetof(Scope, cgroup_context),
        .kill_context_offset = offsetof(Scope, kill_context),
        .cgroup_runtime_offset = offsetof(Scope, cgroup_runtime),

        .sections =
                "Unit\0"
                "Scope\0"
                "Install\0",
        .private_section = "Scope",

        .can_transient = true,
        .can_delegate = true,
        .can_fail = true,
        .once_only = true,
        .can_set_managed_oom = true,

        .init = scope_init,
        .load = scope_load,
        .done = scope_done,

        .coldplug = scope_coldplug,

        .dump = scope_dump,

        .start = scope_start,
        .stop = scope_stop,

        .freezer_action = unit_cgroup_freezer_action,

        .get_timeout = scope_get_timeout,

        .serialize = scope_serialize,
        .deserialize_item = scope_deserialize_item,

        .active_state = scope_active_state,
        .sub_state_to_string = scope_sub_state_to_string,

        .sigchld_event = scope_sigchld_event,

        .reset_failed = scope_reset_failed,

        .notify_cgroup_empty = scope_notify_cgroup_empty_event,
        .notify_cgroup_oom = scope_notify_cgroup_oom_event,

        .bus_set_property = bus_scope_set_property,
        .bus_commit_properties = bus_scope_commit_properties,

        .enumerate_perpetual = scope_enumerate_perpetual,
};
