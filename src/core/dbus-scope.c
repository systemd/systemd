/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "dbus-cgroup.h"
#include "dbus-kill.h"
#include "dbus-scope.h"
#include "dbus-unit.h"
#include "dbus-util.h"
#include "dbus.h"
#include "scope.h"
#include "selinux-access.h"
#include "unit.h"

int bus_scope_method_abandon(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Scope *s = userdata;
        int r;

        assert(message);
        assert(s);

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

const sd_bus_vtable bus_scope_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Controller", "s", NULL, offsetof(Scope, controller), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("TimeoutStopUSec", "t", bus_property_get_usec, offsetof(Scope, timeout_stop_usec), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("Result", "s", property_get_result, offsetof(Scope, result), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
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

        int r;

        assert(s);
        assert(name);
        assert(message);

        flags |= UNIT_PRIVATE;

        if (streq(name, "TimeoutStopUSec"))
                return bus_set_transient_usec(UNIT(s), name, &s->timeout_stop_usec, message, flags, error);

        if (streq(name, "PIDs")) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
                unsigned n = 0;

                r = sd_bus_message_enter_container(message, 'a', "u");
                if (r < 0)
                        return r;

                for (;;) {
                        uint32_t upid;
                        pid_t pid;

                        r = sd_bus_message_read(message, "u", &upid);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        if (upid == 0) {
                                if (!creds) {
                                        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_PID, &creds);
                                        if (r < 0)
                                                return r;
                                }

                                r = sd_bus_creds_get_pid(creds, &pid);
                                if (r < 0)
                                        return r;
                        } else
                                pid = (uid_t) upid;

                        r = unit_pid_attachable(UNIT(s), pid, error);
                        if (r < 0)
                                return r;

                        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                                r = unit_watch_pid(UNIT(s), pid, false);
                                if (r < 0 && r != -EEXIST)
                                        return r;
                        }

                        n++;
                }

                r = sd_bus_message_exit_container(message);
                if (r < 0)
                        return r;

                if (n <= 0)
                        return -EINVAL;

                return 1;

        } else if (streq(name, "Controller")) {
                const char *controller;

                /* We can't support direct connections with this, as direct connections know no service or unique name
                 * concept, but the Controller field stores exactly that. */
                if (sd_bus_message_get_bus(message) != UNIT(s)->manager->api_bus)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_NOT_SUPPORTED, "Sorry, Controller= logic only supported via the bus.");

                r = sd_bus_message_read(message, "s", &controller);
                if (r < 0)
                        return r;

                if (!isempty(controller) && !service_name_is_valid(controller))
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
        }

        return 0;
}

int bus_scope_commit_properties(Unit *u) {
        assert(u);

        unit_invalidate_cgroup_members_masks(u);
        unit_realize_cgroup(u);

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
