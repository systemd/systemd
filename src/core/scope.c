/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "strv.h"
#include "special.h"
#include "unit-name.h"
#include "unit.h"
#include "scope.h"
#include "dbus-scope.h"
#include "load-dropin.h"

static const UnitActiveState state_translation_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD] = UNIT_INACTIVE,
        [SCOPE_RUNNING] = UNIT_ACTIVE,
        [SCOPE_ABANDONED] = UNIT_ACTIVE,
        [SCOPE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SCOPE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SCOPE_FAILED] = UNIT_FAILED
};

static int scope_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata);

static void scope_init(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_stop_usec = u->manager->default_timeout_stop_usec;

        UNIT(s)->ignore_on_isolate = true;
        UNIT(s)->ignore_on_snapshot = true;
}

static void scope_done(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);

        free(s->controller);

        s->timer_event_source = sd_event_source_unref(s->timer_event_source);
}

static int scope_arm_timer(Scope *s) {
        int r;

        assert(s);

        if (s->timeout_stop_usec <= 0) {
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);
                return 0;
        }

        if (s->timer_event_source) {
                r = sd_event_source_set_time(s->timer_event_source, now(CLOCK_MONOTONIC) + s->timeout_stop_usec);
                if (r < 0)
                        return r;

                return sd_event_source_set_enabled(s->timer_event_source, SD_EVENT_ONESHOT);
        }

        r = sd_event_add_time(
                        UNIT(s)->manager->event,
                        &s->timer_event_source,
                        CLOCK_MONOTONIC,
                        now(CLOCK_MONOTONIC) + s->timeout_stop_usec, 0,
                        scope_dispatch_timer, s);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->timer_event_source, "scope-timer");

        return 0;
}

static void scope_set_state(Scope *s, ScopeState state) {
        ScopeState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (!IN_SET(state, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL))
                s->timer_event_source = sd_event_source_unref(s->timer_event_source);

        if (IN_SET(state, SCOPE_DEAD, SCOPE_FAILED))
                unit_unwatch_all_pids(UNIT(s));

        if (state != old_state)
                log_debug("%s changed %s -> %s", UNIT(s)->id, scope_state_to_string(old_state), scope_state_to_string(state));

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state], true);
}

static int scope_add_default_dependencies(Scope *s) {
        int r;

        assert(s);

        /* Make sure scopes are unloaded on shutdown */
        r = unit_add_two_dependencies_by_name(
                        UNIT(s),
                        UNIT_BEFORE, UNIT_CONFLICTS,
                        SPECIAL_SHUTDOWN_TARGET, NULL, true);
        if (r < 0)
                return r;

        return 0;
}

static int scope_verify(Scope *s) {
        assert(s);

        if (UNIT(s)->load_state != UNIT_LOADED)
                return 0;

        if (set_isempty(UNIT(s)->pids) &&
            !manager_is_reloading_or_reexecuting(UNIT(s)->manager) &&
            !unit_has_name(UNIT(s), SPECIAL_INIT_SCOPE)) {
                log_unit_error(UNIT(s), "Scope has no PIDs. Refusing.");
                return -EINVAL;
        }

        return 0;
}

static int scope_load(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(u->load_state == UNIT_STUB);

        if (!u->transient && !manager_is_reloading_or_reexecuting(u->manager))
                return -ENOENT;

        u->load_state = UNIT_LOADED;

        r = unit_load_dropin(u);
        if (r < 0)
                return r;

        r = unit_patch_contexts(u);
        if (r < 0)
                return r;

        r = unit_set_default_slice(u);
        if (r < 0)
                return r;

        if (u->default_dependencies) {
                r = scope_add_default_dependencies(s);
                if (r < 0)
                        return r;
        }

        return scope_verify(s);
}

static int scope_coldplug(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(s->state == SCOPE_DEAD);

        if (s->deserialized_state != s->state) {

                if (IN_SET(s->deserialized_state, SCOPE_STOP_SIGKILL, SCOPE_STOP_SIGTERM)) {
                        r = scope_arm_timer(s);
                        if (r < 0)
                                return r;
                }

                if (!IN_SET(s->deserialized_state, SCOPE_DEAD, SCOPE_FAILED))
                        unit_watch_all_pids(UNIT(s));

                scope_set_state(s, s->deserialized_state);
        }

        return 0;
}

static void scope_dump(Unit *u, FILE *f, const char *prefix) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(f);

        fprintf(f,
                "%sScope State: %s\n"
                "%sResult: %s\n",
                prefix, scope_state_to_string(s->state),
                prefix, scope_result_to_string(s->result));

        cgroup_context_dump(&s->cgroup_context, f, prefix);
        kill_context_dump(&s->kill_context, f, prefix);
}

static void scope_enter_dead(Scope *s, ScopeResult f) {
        assert(s);

        if (f != SCOPE_SUCCESS)
                s->result = f;

        scope_set_state(s, s->result != SCOPE_SUCCESS ? SCOPE_FAILED : SCOPE_DEAD);
}

static void scope_enter_signal(Scope *s, ScopeState state, ScopeResult f) {
        bool skip_signal = false;
        int r;

        assert(s);

        if (f != SCOPE_SUCCESS)
                s->result = f;

        unit_watch_all_pids(UNIT(s));

        /* If we have a controller set let's ask the controller nicely
         * to terminate the scope, instead of us going directly into
         * SIGTERM beserk mode */
        if (state == SCOPE_STOP_SIGTERM)
                skip_signal = bus_scope_send_request_stop(s) > 0;

        if (!skip_signal) {
                r = unit_kill_context(
                                UNIT(s),
                                &s->kill_context,
                                state != SCOPE_STOP_SIGTERM ? KILL_KILL : KILL_TERMINATE,
                                -1, -1, false);
                if (r < 0)
                        goto fail;
        } else
                r = 1;

        if (r > 0) {
                r = scope_arm_timer(s);
                if (r < 0)
                        goto fail;

                scope_set_state(s, state);
        } else if (state == SCOPE_STOP_SIGTERM)
                scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_SUCCESS);
        else
                scope_enter_dead(s, SCOPE_SUCCESS);

        return;

fail:
        log_unit_warning_errno(UNIT(s), r, "Failed to kill processes: %m");

        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
}

static int scope_start(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);

        if (unit_has_name(u, SPECIAL_INIT_SCOPE))
                return -EPERM;

        if (s->state == SCOPE_FAILED)
                return -EPERM;

        /* We can't fulfill this right now, please try again later */
        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return -EAGAIN;

        assert(s->state == SCOPE_DEAD);

        if (!u->transient && !manager_is_reloading_or_reexecuting(u->manager))
                return -ENOENT;

        (void) unit_realize_cgroup(u);
        (void) unit_reset_cpu_usage(u);

        r = unit_attach_pids_to_cgroup(u);
        if (r < 0) {
                log_unit_warning_errno(UNIT(s), r, "Failed to add PIDs to scope's control group: %m");
                scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
                return r;
        }

        s->result = SCOPE_SUCCESS;

        scope_set_state(s, SCOPE_RUNNING);
        return 1;
}

static int scope_stop(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);

        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return 0;

        assert(s->state == SCOPE_RUNNING ||
               s->state == SCOPE_ABANDONED);

        scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_SUCCESS);
        return 1;
}

static void scope_reset_failed(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);

        if (s->state == SCOPE_FAILED)
                scope_set_state(s, SCOPE_DEAD);

        s->result = SCOPE_SUCCESS;
}

static int scope_kill(Unit *u, KillWho who, int signo, sd_bus_error *error) {
        return unit_kill_common(u, who, signo, -1, -1, error);
}

static int scope_get_timeout(Unit *u, uint64_t *timeout) {
        Scope *s = SCOPE(u);
        int r;

        if (!s->timer_event_source)
                return 0;

        r = sd_event_source_get_time(s->timer_event_source, timeout);
        if (r < 0)
                return r;

        return 1;
}

static int scope_serialize(Unit *u, FILE *f, FDSet *fds) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(f);
        assert(fds);

        unit_serialize_item(u, f, "state", scope_state_to_string(s->state));
        return 0;
}

static int scope_deserialize_item(Unit *u, const char *key, const char *value, FDSet *fds) {
        Scope *s = SCOPE(u);

        assert(u);
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

        } else
                log_unit_debug(u, "Unknown serialization key: %s", key);

        return 0;
}

static bool scope_check_gc(Unit *u) {
        assert(u);

        /* Never clean up scopes that still have a process around,
         * even if the scope is formally dead. */

        if (u->cgroup_path) {
                int r;

                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path);
                if (r <= 0)
                        return true;
        }

        return false;
}

static void scope_notify_cgroup_empty_event(Unit *u) {
        Scope *s = SCOPE(u);
        assert(u);

        log_unit_debug(u, "cgroup is empty");

        if (IN_SET(s->state, SCOPE_RUNNING, SCOPE_ABANDONED, SCOPE_STOP_SIGTERM, SCOPE_STOP_SIGKILL))
                scope_enter_dead(s, SCOPE_SUCCESS);
}

static void scope_sigchld_event(Unit *u, pid_t pid, int code, int status) {

        /* If we get a SIGCHLD event for one of the processes we were
           interested in, then we look for others to watch, under the
           assumption that we'll sooner or later get a SIGCHLD for
           them, as the original process we watched was probably the
           parent of them, and they are hence now our children. */

        unit_tidy_watch_pids(u, 0, 0);
        unit_watch_all_pids(u);

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(u->pids))
                scope_notify_cgroup_empty_event(u);
}

static int scope_dispatch_timer(sd_event_source *source, usec_t usec, void *userdata) {
        Scope *s = SCOPE(userdata);

        assert(s);
        assert(s->timer_event_source == source);

        switch (s->state) {

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

        default:
                assert_not_reached("Timeout at wrong time.");
        }

        return 0;
}

int scope_abandon(Scope *s) {
        assert(s);

        if (unit_has_name(UNIT(s), SPECIAL_INIT_SCOPE))
                return -EPERM;

        if (!IN_SET(s->state, SCOPE_RUNNING, SCOPE_ABANDONED))
                return -ESTALE;

        s->controller = mfree(s->controller);

        /* The client is no longer watching the remaining processes,
         * so let's step in here, under the assumption that the
         * remaining processes will be sooner or later reassigned to
         * us as parent. */

        unit_tidy_watch_pids(UNIT(s), 0, 0);
        unit_watch_all_pids(UNIT(s));

        /* If the PID set is empty now, then let's finish this off */
        if (set_isempty(UNIT(s)->pids))
                scope_notify_cgroup_empty_event(UNIT(s));
        else
                scope_set_state(s, SCOPE_ABANDONED);

        return 0;
}

_pure_ static UnitActiveState scope_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SCOPE(u)->state];
}

_pure_ static const char *scope_sub_state_to_string(Unit *u) {
        assert(u);

        return scope_state_to_string(SCOPE(u)->state);
}

static int scope_enumerate(Manager *m) {
        Unit *u;
        int r;

        assert(m);

        /* Let's unconditionally add the "init.scope" special unit
         * that encapsulates PID 1. Note that PID 1 already is in the
         * cgroup for this, we hence just need to allocate the object
         * for it and that's it. */

        u = manager_get_unit(m, SPECIAL_INIT_SCOPE);
        if (!u) {
                u = unit_new(m, sizeof(Scope));
                if (!u)
                        return log_oom();

                r = unit_add_name(u, SPECIAL_INIT_SCOPE);
                if (r < 0)  {
                        unit_free(u);
                        return log_error_errno(r, "Failed to add init.scope name");
                }
        }

        u->transient = true;
        u->default_dependencies = false;
        u->no_gc = true;
        SCOPE(u)->deserialized_state = SCOPE_RUNNING;
        SCOPE(u)->kill_context.kill_signal = SIGRTMIN+14;

        /* Prettify things, if we can. */
        if (!u->description)
                u->description = strdup("System and Service Manager");
        if (!u->documentation)
                (void) strv_extend(&u->documentation, "man:systemd(1)");

        unit_add_to_load_queue(u);
        unit_add_to_dbus_queue(u);

        return 0;
}

static const char* const scope_result_table[_SCOPE_RESULT_MAX] = {
        [SCOPE_SUCCESS] = "success",
        [SCOPE_FAILURE_RESOURCES] = "resources",
        [SCOPE_FAILURE_TIMEOUT] = "timeout",
};

DEFINE_STRING_TABLE_LOOKUP(scope_result, ScopeResult);

const UnitVTable scope_vtable = {
        .object_size = sizeof(Scope),
        .cgroup_context_offset = offsetof(Scope, cgroup_context),
        .kill_context_offset = offsetof(Scope, kill_context),

        .sections =
                "Unit\0"
                "Scope\0"
                "Install\0",
        .private_section = "Scope",

        .no_alias = true,
        .no_instances = true,

        .init = scope_init,
        .load = scope_load,
        .done = scope_done,

        .coldplug = scope_coldplug,

        .dump = scope_dump,

        .start = scope_start,
        .stop = scope_stop,

        .kill = scope_kill,

        .get_timeout = scope_get_timeout,

        .serialize = scope_serialize,
        .deserialize_item = scope_deserialize_item,

        .active_state = scope_active_state,
        .sub_state_to_string = scope_sub_state_to_string,

        .check_gc = scope_check_gc,

        .sigchld_event = scope_sigchld_event,

        .reset_failed = scope_reset_failed,

        .notify_cgroup_empty = scope_notify_cgroup_empty_event,

        .bus_vtable = bus_scope_vtable,
        .bus_set_property = bus_scope_set_property,
        .bus_commit_properties = bus_scope_commit_properties,

        .can_transient = true,

        .enumerate = scope_enumerate,
};
