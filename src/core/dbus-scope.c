/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-get-properties.h"
#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-scope.h"
#include "dbus-unit.h"
#include "dbus-util.h"
#include "dbus.h"
#include "scope.h"
#include "selinux-access.h"
#include "unit.h"

int bus_scope_method_abandon(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Scope *s = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = mac_selinux_unit_access_check(UNIT(s), message, "stop", error);
        if (r < 0)
                return r;

        r = bus_verify_manage_units_async(UNIT(s)->manager, message, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = scope_abandon(s);
        if (r == -ESTALE)
                return sd_bus_error_setf(error, BUS_ERROR_SCOPE_NOT_RUNNING, "Scope %s is not running, cannot abandon.", UNIT(s)->id);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, NULL);
}

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_result, scope_result, ScopeResult);
static BUS_DEFINE_SET_TRANSIENT_PARSE(oom_policy, OOMPolicy, oom_policy_from_string);

const sd_bus_vtable bus_scope_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Controller", "s", NULL, offsetof(Scope, controller), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Scope, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Scope, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("RuntimeMaxUSec", "t", bus_property_get_usec, offsetof(Scope, runtime_max_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("RuntimeRandomizedExtraUSec", "t", bus_property_get_usec, offsetof(Scope, runtime_rand_extra_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("OOMPolicy", "s", bus_property_get_oom_policy, offsetof(Scope, oom_policy), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_SIGNAL("RequestStop", NULL, 0),
        SD_BUS_METHOD("Abandon", NULL, NULL, bus_scope_method_abandon, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

static int bus_scope_set_transient_property(
                Scope *s,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Unit *u = UNIT(s);
        int r;

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "TimeoutStopUSec"))
                return bus_set_transient_usec(u, name, &s->timeout_stop_usec, message, flags, error);

        if (streq(name, "RuntimeMaxUSec"))
                return bus_set_transient_usec(u, name, &s->runtime_max_usec, message, flags, error);

        if (streq(name, "RuntimeRandomizedExtraUSec"))
                return bus_set_transient_usec(u, name, &s->runtime_rand_extra_usec, message, flags, error);

        if (streq(name, "OOMPolicy"))
                return bus_set_transient_oom_policy(u, name, &s->oom_policy, message, flags, error);

        if (streq(name, "PIDs")) {
                _cleanup_(pidref_done) PidRef sender_pidref = PIDREF_NULL;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "u");
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                        uint32_t upid;
                        PidRef *p;

                        r = sd_bus_message_read(message, "u", &upid);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        if (upid == 0) {
                                if (!pidref_is_set(&sender_pidref)) {
                                        r = bus_query_sender_pidref(message, &sender_pidref);
                                        if (r < 0)
                                                return r;
                                }

                                p = &sender_pidref;
                        } else {
                                r = pidref_set_pid(&pidref, upid);
                                if (r < 0)
                                        return r;

                                p = &pidref;
                        }

                        r = unit_pid_attachable(u, p, error);
                        if (r < 0)
                                return r;

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = unit_watch_pidref(u, p, /* exclusive= */ false);
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                return n <= 0 ? -EINVAL : 1;
        }

        if (streq(name, "PIDFDs")) {
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "h");
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                        int fd;

                        r = sd_bus_message_read(message, "h", &fd);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = pidref_set_pidfd(&pidref, fd);
                        if (r < 0)
                                return r;

                        r = unit_pid_attachable(u, &pidref, error);
                        if (r < 0)
                                return r;

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = unit_watch_pidref(u, &pidref, /* exclusive= */ false);
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                return n <= 0 ? -EINVAL : 1;
        }

        if (streq(name, "Controller")) {
                const char *controller;

                /* We can't support direct connections with this, as direct connections know no service or unique name
                 * concept, but the Controller field stores exactly that. */
                if (sd_bus_message_get_bus(message) != u->manager->api_bus)
                        return sd_bus_error_set(error, SD_BUS_ERROR_NOT_SUPPORTED, "Sorry, Controller= logic only supported via the bus.");

                r = sd_bus_message_read(message, "s", &controller);
                if (r < 0)
                        return r;

                if (!isempty(controller) && !sd_bus_service_name_is_valid(controller))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Controller '%s' is not a valid bus name.", controller);

                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                        r = free_and_strdup(&s->controller, empty_to_null(controller));
                        if (r < 0)
                                return r;
                }

                return 1;
        }

        return 0;
}

int bus_scope_set_property(
                Unit *u,
                const char *name,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        Scope *s = SCOPE(u);
        int r;

        assert(s);
        assert(name);
        assert(message);

        r = bus_cgroup_set_property(u, &s->cgroup_context, name, message, flags, error);
        if (r != 0)
                return r;

        if (u->load_state == UNIT_STUB) {
                /* While we are created we still accept PIDs */

                r = bus_scope_set_transient_property(s, name, message, flags, error);
                if (r != 0)
                        return r;

                r = bus_kill_context_set_transient_property(u, &s->kill_context, name, message, flags, error);
                if (r != 0)
                        return r;

                if (streq(name, "User"))
                        return bus_set_transient_user_relaxed(u, name, &s->user, message, flags, error);

                if (streq(name, "Group"))
                        return bus_set_transient_user_relaxed(u, name, &s->group, message, flags, error);
        }

        return 0;
}

int bus_scope_commit_properties(Unit *u) {
        assert(u);

        (void) unit_realize_cgroup(u);

        return 0;
}

int bus_scope_send_request_stop(Scope *s) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(s);

        if (!s->controller)
                return 0;

        p = unit_dbus_path(UNIT(s));
        if (!p)
                return -ENOMEM;

        r = sd_bus_message_new_signal(
                        UNIT(s)->manager->api_bus,
                        &m,
                        p,
                        "org.freedesktop.systemd1.Scope",
                        "RequestStop");
        if (r < 0)
                return r;

        return sd_bus_send_to(UNIT(s)->manager->api_bus, m, s->controller, NULL);
}

static int on_controller_gone(sd_bus_track *track, void *userdata) {
        Scope *s = userdata;

        assert(track);

        if (s->controller) {
                log_unit_debug(UNIT(s), "Controller %s disappeared from bus.", s->controller);
                unit_add_to_dbus_queue(UNIT(s));
                s->controller = mfree(s->controller);
        }

        s->controller_track = sd_bus_track_unref(s->controller_track);

        return 0;
}

int bus_scope_track_controller(Scope *s) {
        int r;

        assert(s);

        if (!s->controller || s->controller_track)
                return 0;

        r = sd_bus_track_new(UNIT(s)->manager->api_bus, &s->controller_track, on_controller_gone, s);
        if (r < 0)
                return r;

        r = sd_bus_track_add_name(s->controller_track, s->controller);
        if (r < 0) {
                s->controller_track = sd_bus_track_unref(s->controller_track);
                return r;
        }

        return 0;
}
