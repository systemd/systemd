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
#include <signal.h>
#include <unistd.h>

#include "unit.h"
#include "scope.h"
#include "load-fragment.h"
#include "log.h"
#include "dbus-scope.h"
#include "special.h"
#include "unit-name.h"
#include "load-dropin.h"

static const UnitActiveState state_translation_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD] = UNIT_INACTIVE,
        [SCOPE_RUNNING] = UNIT_ACTIVE,
        [SCOPE_STOP_SIGTERM] = UNIT_DEACTIVATING,
        [SCOPE_STOP_SIGKILL] = UNIT_DEACTIVATING,
        [SCOPE_FAILED] = UNIT_FAILED
};

static void scope_init(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);
        assert(u->load_state == UNIT_STUB);

        s->timeout_stop_usec = DEFAULT_TIMEOUT_USEC;

        watch_init(&s->timer_watch);

        cgroup_context_init(&s->cgroup_context);
        kill_context_init(&s->kill_context);

        UNIT(s)->ignore_on_isolate = true;
        UNIT(s)->ignore_on_snapshot = true;
}

static void scope_done(Unit *u) {
        Scope *s = SCOPE(u);

        assert(u);

        cgroup_context_done(&s->cgroup_context);

        set_free(s->pids);
        s->pids = NULL;

        unit_unwatch_timer(u, &s->timer_watch);
}

static void scope_set_state(Scope *s, ScopeState state) {
        ScopeState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SCOPE_STOP_SIGTERM &&
            state != SCOPE_STOP_SIGKILL)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state != old_state)
                log_debug("%s changed %s -> %s",
                          UNIT(s)->id,
                          scope_state_to_string(old_state),
                          scope_state_to_string(state));

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

        if (set_size(s->pids) <= 0 && UNIT(s)->manager->n_reloading <= 0) {
                log_error_unit(UNIT(s)->id, "Scope %s has no PIDs. Refusing.", UNIT(s)->id);
                return -EINVAL;
        }

        return 0;
}

static int scope_load(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(u->load_state == UNIT_STUB);

        if (!u->transient && UNIT(s)->manager->n_reloading <= 0)
                return -ENOENT;

        u->load_state = UNIT_LOADED;

        r = unit_load_dropin(u);
        if (r < 0)
                return r;

        r = unit_add_default_slice(u);
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

                if ((s->deserialized_state == SCOPE_STOP_SIGKILL || s->deserialized_state == SCOPE_STOP_SIGTERM)
                    && s->timeout_stop_usec > 0) {
                        r = unit_watch_timer(UNIT(s), CLOCK_MONOTONIC, true, s->timeout_stop_usec, &s->timer_watch);
                        if (r < 0)

                                return r;
                }

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
        int r;

        assert(s);

        if (f != SCOPE_SUCCESS)
                s->result = f;

        r = unit_kill_context(
                        UNIT(s),
                        &s->kill_context,
                        state != SCOPE_STOP_SIGTERM,
                        -1, -1, false);
        if (r < 0)
                goto fail;

        if (r > 0) {
                if (s->timeout_stop_usec > 0) {
                        r = unit_watch_timer(UNIT(s), CLOCK_MONOTONIC, true, s->timeout_stop_usec, &s->timer_watch);
                        if (r < 0)
                                goto fail;
                }

                scope_set_state(s, state);
        } else
                scope_enter_dead(s, SCOPE_SUCCESS);

        return;

fail:
        log_warning_unit(UNIT(s)->id,
                         "%s failed to kill processes: %s", UNIT(s)->id, strerror(-r));

        scope_enter_dead(s, SCOPE_FAILURE_RESOURCES);
}

static int scope_start(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);

        if (s->state == SCOPE_FAILED)
                return -EPERM;

        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return -EAGAIN;

        assert(s->state == SCOPE_DEAD);

        if (!u->transient && UNIT(s)->manager->n_reloading <= 0)
                return -ENOENT;

        r = unit_realize_cgroup(u);
        if (r < 0) {
                log_error("Failed to realize cgroup: %s", strerror(-r));
                return r;
        }

        r = cg_attach_many_everywhere(u->manager->cgroup_supported, u->cgroup_path, s->pids);
        if (r < 0)
                return r;

        set_free(s->pids);
        s->pids = NULL;

        s->result = SCOPE_SUCCESS;

        scope_set_state(s, SCOPE_RUNNING);
        return 0;
}

static int scope_stop(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(s->state == SCOPE_RUNNING);

        if (s->state == SCOPE_STOP_SIGTERM ||
            s->state == SCOPE_STOP_SIGKILL)
                return 0;

        assert(s->state == SCOPE_RUNNING);

        scope_enter_signal(s, SCOPE_STOP_SIGTERM, SCOPE_SUCCESS);
        return 0;
}

static void scope_reset_failed(Unit *u) {
        Scope *s = SCOPE(u);

        assert(s);

        if (s->state == SCOPE_FAILED)
                scope_set_state(s, SCOPE_DEAD);

        s->result = SCOPE_SUCCESS;
}

static int scope_kill(Unit *u, KillWho who, int signo, DBusError *error) {
        return unit_kill_common(u, who, signo, -1, -1, error);
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
                        log_debug("Failed to parse state value %s", value);
                else
                        s->deserialized_state = state;

        } else
                log_debug("Unknown serialization key '%s'", key);

        return 0;
}

static bool scope_check_gc(Unit *u) {
        Scope *s = SCOPE(u);
        int r;

        assert(s);

        /* Never clean up scopes that still have a process around,
         * even if the scope is formally dead. */

        if (UNIT(s)->cgroup_path) {
                r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, UNIT(s)->cgroup_path, true);
                if (r <= 0)
                        return true;
        }

        return false;
}

static void scope_timer_event(Unit *u, uint64_t elapsed, Watch*w) {
        Scope *s = SCOPE(u);

        assert(s);
        assert(elapsed == 1);
        assert(w == &s->timer_watch);

        switch (s->state) {

        case SCOPE_STOP_SIGTERM:
                if (s->kill_context.send_sigkill) {
                        log_warning_unit(u->id, "%s stopping timed out. Killing.", u->id);
                        scope_enter_signal(s, SCOPE_STOP_SIGKILL, SCOPE_FAILURE_TIMEOUT);
                } else {
                        log_warning_unit(u->id, "%s stopping timed out. Skipping SIGKILL.", u->id);
                        scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                }

                break;

        case SCOPE_STOP_SIGKILL:
                log_warning_unit(u->id, "%s still around after SIGKILL. Ignoring.", u->id);
                scope_enter_dead(s, SCOPE_FAILURE_TIMEOUT);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

static void scope_notify_cgroup_empty_event(Unit *u) {
        Scope *s = SCOPE(u);
        assert(u);

        log_debug_unit(u->id, "%s: cgroup is empty", u->id);

        switch (s->state) {

        case SCOPE_RUNNING:
        case SCOPE_STOP_SIGTERM:
        case SCOPE_STOP_SIGKILL:
                scope_enter_dead(s, SCOPE_SUCCESS);

                break;

        default:
                ;
        }
}

_pure_ static UnitActiveState scope_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SCOPE(u)->state];
}

_pure_ static const char *scope_sub_state_to_string(Unit *u) {
        assert(u);

        return scope_state_to_string(SCOPE(u)->state);
}

static const char* const scope_state_table[_SCOPE_STATE_MAX] = {
        [SCOPE_DEAD] = "dead",
        [SCOPE_RUNNING] = "running",
        [SCOPE_STOP_SIGTERM] = "stop-sigterm",
        [SCOPE_STOP_SIGKILL] = "stop-sigkill",
        [SCOPE_FAILED] = "failed",
};

DEFINE_STRING_TABLE_LOOKUP(scope_state, ScopeState);

static const char* const scope_result_table[_SCOPE_RESULT_MAX] = {
        [SCOPE_SUCCESS] = "success",
        [SCOPE_FAILURE_RESOURCES] = "resources",
        [SCOPE_FAILURE_TIMEOUT] = "timeout",
};

DEFINE_STRING_TABLE_LOOKUP(scope_result, ScopeResult);

const UnitVTable scope_vtable = {
        .object_size = sizeof(Scope),
        .sections =
                "Unit\0"
                "Scope\0"
                "Install\0",

        .private_section = "Scope",
        .cgroup_context_offset = offsetof(Scope, cgroup_context),

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

        .serialize = scope_serialize,
        .deserialize_item = scope_deserialize_item,

        .active_state = scope_active_state,
        .sub_state_to_string = scope_sub_state_to_string,

        .check_gc = scope_check_gc,

        .timer_event = scope_timer_event,

        .reset_failed = scope_reset_failed,

        .notify_cgroup_empty = scope_notify_cgroup_empty_event,

        .bus_interface = "org.freedesktop.systemd1.Scope",
        .bus_message_handler = bus_scope_message_handler,
        .bus_set_property = bus_scope_set_property,
        .bus_commit_properties = bus_scope_commit_properties,

        .can_transient = true
};
