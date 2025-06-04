/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-object.h"
#include "bus-util.h"
#include "dbus.h"
#include "dbus-automount.h"
#include "dbus-cgroup.h"
#include "dbus-device.h"
#include "dbus-execute.h"
#include "dbus-job.h"
#include "dbus-kill.h"
#include "dbus-manager.h"
#include "dbus-mount.h"
#include "dbus-path.h"
#include "dbus-scope.h"
#include "dbus-service.h"
#include "dbus-slice.h"
#include "dbus-socket.h"
#include "dbus-swap.h"
#include "dbus-target.h"
#include "dbus-timer.h"
#include "dbus-unit.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "manager.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "selinux-access.h"
#include "serialize.h"
#include "set.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "umask-util.h"

#define CONNECTIONS_MAX 4096

static void destroy_bus(Manager *m, sd_bus **bus);

void bus_send_pending_reload_message(Manager *m) {
        int r;

        assert(m);

        if (!m->pending_reload_message)
                return;

        /* If we cannot get rid of this message we won't dispatch any D-Bus messages, so that we won't end up wanting
         * to queue another message. */

        r = sd_bus_send(NULL, m->pending_reload_message, NULL);
        if (r < 0)
                log_warning_errno(r, "Failed to send queued reload message, ignoring: %m");

        m->pending_reload_message = sd_bus_message_unref(m->pending_reload_message);

        return;
}

static int signal_disconnected(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        sd_bus *bus;

        assert(message);
        assert_se(bus = sd_bus_message_get_bus(message));

        if (bus == m->api_bus) {
                log_notice("Got disconnect on API bus.");
                bus_done_api(m);
        }
        if (bus == m->system_bus) {
                /* If we are the system manager, this is already logged by the API bus. */
                if (!MANAGER_IS_SYSTEM(m))
                        log_notice("Got disconnect on system bus.");
                bus_done_system(m);
        }

        if (set_remove(m->private_buses, bus)) {
                log_debug("Got disconnect on private connection.");
                destroy_bus(m, &bus);
        }

        return 0;
}

static int signal_activation_request(sd_bus_message *message, void *userdata, sd_bus_error *ret_error) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        Manager *m = ASSERT_PTR(userdata);
        const char *name;
        Unit *u;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &name);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SOCKET) ||
            manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SERVICE)) {
                r = sd_bus_error_set(&error, BUS_ERROR_SHUTTING_DOWN, "Refusing activation, D-Bus is shutting down.");
                goto failed;
        }

        r = manager_load_unit(m, name, NULL, &error, &u);
        if (r < 0)
                goto failed;

        if (u->refuse_manual_start) {
                r = sd_bus_error_setf(&error, BUS_ERROR_ONLY_BY_DEPENDENCY, "Operation refused, %s may be requested by dependency only (it is configured to refuse manual start/stop).", u->id);
                goto failed;
        }

        r = manager_add_job(m, JOB_START, u, JOB_REPLACE, &error, /* ret = */ NULL);
        if (r < 0)
                goto failed;

        /* Successfully queued, that's it for us */
        return 0;

failed:
        if (!sd_bus_error_is_set(&error))
                sd_bus_error_set_errno(&error, r);

        log_debug("D-Bus activation failed for %s: %s", name, bus_error_message(&error, r));

        r = sd_bus_message_new_signal(sd_bus_message_get_bus(message), &reply, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Activator", "ActivationFailure");
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_message_append(reply, "sss", name, error.name, error.message);
        if (r < 0) {
                bus_log_create_error(r);
                return 0;
        }

        r = sd_bus_send_to(NULL, reply, "org.freedesktop.DBus", NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to respond with to bus activation request: %m");

        return 0;
}

#if HAVE_SELINUX
static int mac_selinux_filter(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = userdata;
        const char *verb, *path;
        Unit *u = NULL;
        Job *j;
        int r;

        assert(message);

        /* Our own method calls are all protected individually with
         * selinux checks, but the built-in interfaces need to be
         * protected too. */

        if (sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Set"))
                verb = "reload";
        else if (sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Properties", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.ObjectManager", NULL) ||
                 sd_bus_message_is_method_call(message, "org.freedesktop.DBus.Peer", NULL))
                verb = "status";
        else
                return 0;

        path = sd_bus_message_get_path(message);
        if (!path)
                return 0;

        if (object_path_startswith("/org/freedesktop/systemd1", path)) {
                r = mac_selinux_access_check(message, verb, error);
                if (r < 0)
                        return r;

                return 0;
        }

        if (streq(path, "/org/freedesktop/systemd1/unit/self")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return 0;

                u = manager_get_unit_by_pidref(m, &pidref);
        } else {
                r = manager_get_job_from_dbus_path(m, path, &j);
                if (r >= 0)
                        u = j->unit;
                else
                        (void) manager_load_unit_from_dbus_path(m, path, NULL, &u);
        }
        if (!u)
                return 0;

        r = mac_selinux_unit_access_check(u, message, verb, error);
        if (r < 0)
                return r;

        return 0;
}
#endif

static int find_unit(Manager *m, sd_bus *bus, const char *path, Unit **unit, sd_bus_error *error) {
        Unit *u = NULL;  /* just to appease gcc, initialization is not really necessary */
        int r;

        assert(m);
        assert(bus);
        assert(path);

        if (streq(path, "/org/freedesktop/systemd1/unit/self")) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                sd_bus_message *message;

                message = sd_bus_get_current_message(bus);
                if (!message)
                        return 0;

                r = bus_query_sender_pidref(message, &pidref);
                if (r < 0)
                        return r;

                u = manager_get_unit_by_pidref(m, &pidref);
                if (!u)
                        return 0;
        } else {
                r = manager_load_unit_from_dbus_path(m, path, error, &u);
                if (r < 0)
                        return 0;
                assert(u);
        }

        *unit = u;
        return 1;
}

static int bus_unit_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        return find_unit(m, bus, path, (Unit**) found, error);
}

static int bus_unit_interface_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        *found = u;
        return 1;
}

static int bus_unit_cgroup_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        if (!UNIT_HAS_CGROUP_CONTEXT(u))
                return 0;

        *found = u;
        return 1;
}

static int bus_cgroup_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        CGroupContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_cgroup_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_exec_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        ExecContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_exec_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_unit_exec_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        if (!UNIT_HAS_EXEC_CONTEXT(u))
                return 0;

        *found = u;
        return 1;
}

static int bus_kill_context_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        KillContext *c;
        Unit *u;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(found);

        r = find_unit(m, bus, path, &u, error);
        if (r <= 0)
                return r;

        if (!streq_ptr(interface, unit_dbus_interface_from_type(u->type)))
                return 0;

        c = unit_get_kill_context(u);
        if (!c)
                return 0;

        *found = c;
        return 1;
}

static int bus_unit_enumerate(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error) {
        _cleanup_strv_free_ char **l = NULL;
        Manager *m = userdata;
        unsigned k = 0;
        Unit *u;

        l = new0(char*, hashmap_size(m->units)+1);
        if (!l)
                return -ENOMEM;

        HASHMAP_FOREACH(u, m->units) {
                l[k] = unit_dbus_path(u);
                if (!l[k])
                        return -ENOMEM;

                k++;
        }

        *nodes = TAKE_PTR(l);

        return k;
}

static const BusObjectImplementation unit_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Unit",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_unit_vtable,        bus_unit_find }),
        .node_enumerator = bus_unit_enumerate,
};

static const BusObjectImplementation bus_automount_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Automount",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_automount_vtable,   bus_unit_interface_find }),
};

static const BusObjectImplementation bus_device_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Device",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_device_vtable,      bus_unit_interface_find }),
};

static const BusObjectImplementation bus_mount_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Mount",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_mount_vtable,       bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find },
                { bus_exec_vtable,        bus_exec_context_find },
                { bus_unit_exec_vtable,   bus_unit_exec_context_find },
                { bus_kill_vtable,        bus_kill_context_find }),
};

static const BusObjectImplementation bus_path_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Path",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_path_vtable,        bus_unit_interface_find }),
};

static const BusObjectImplementation bus_scope_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Scope",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_scope_vtable,       bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find },
                { bus_kill_vtable,        bus_kill_context_find }),
};

static const BusObjectImplementation bus_service_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Service",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_service_vtable,     bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find },
                { bus_exec_vtable,        bus_exec_context_find },
                { bus_unit_exec_vtable,   bus_unit_exec_context_find },
                { bus_kill_vtable,        bus_kill_context_find }),
};

static const BusObjectImplementation bus_slice_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Slice",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_slice_vtable,       bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find }),
};

static const BusObjectImplementation bus_socket_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Socket",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_socket_vtable,      bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find },
                { bus_exec_vtable,        bus_exec_context_find },
                { bus_unit_exec_vtable,   bus_unit_exec_context_find },
                { bus_kill_vtable,        bus_kill_context_find }),
};

static const BusObjectImplementation bus_swap_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Swap",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_swap_vtable,        bus_unit_interface_find },
                { bus_unit_cgroup_vtable, bus_unit_cgroup_find },
                { bus_cgroup_vtable,      bus_cgroup_context_find },
                { bus_exec_vtable,        bus_exec_context_find },
                { bus_unit_exec_vtable,   bus_unit_exec_context_find },
                { bus_kill_vtable,        bus_kill_context_find }),
};

static const BusObjectImplementation bus_target_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Target",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_target_vtable,      bus_unit_interface_find }),
};

static const BusObjectImplementation bus_timer_object = {
        "/org/freedesktop/systemd1/unit",
        "org.freedesktop.systemd1.Timer",
        .fallback_vtables = BUS_FALLBACK_VTABLES(
                { bus_timer_vtable,       bus_unit_interface_find }),
};

static const BusObjectImplementation bus_manager_object = {
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        .vtables = BUS_VTABLES(bus_manager_vtable),
        .children = BUS_IMPLEMENTATIONS(
                        &job_object,
                        &unit_object,
                        &bus_automount_object,
                        &bus_device_object,
                        &bus_mount_object,
                        &bus_path_object,
                        &bus_scope_object,
                        &bus_service_object,
                        &bus_slice_object,
                        &bus_socket_object,
                        &bus_swap_object,
                        &bus_target_object,
                        &bus_timer_object),
};

static const BusObjectImplementation manager_log_control_object = {
        "/org/freedesktop/LogControl1",
        "org.freedesktop.LogControl1",
        .vtables = BUS_VTABLES(bus_manager_log_control_vtable),
};

int bus_manager_introspect_implementations(FILE *out, const char *pattern) {
        return bus_introspect_implementations(
                        out,
                        pattern,
                        BUS_IMPLEMENTATIONS(&bus_manager_object,
                                            &manager_log_control_object));
}

static int bus_setup_api_vtables(Manager *m, sd_bus *bus) {
        int r;

        assert(m);
        assert(bus);

#if HAVE_SELINUX
        r = sd_bus_add_filter(bus, NULL, mac_selinux_filter, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add SELinux access filter: %m");
#endif

        r = bus_add_implementation(bus, &bus_manager_object, m);
        if (r < 0)
                return r;

        return bus_add_implementation(bus, &manager_log_control_object, m);
}

static int bus_setup_disconnected_match(Manager *m, sd_bus *bus) {
        int r;

        assert(m);
        assert(bus);

        r = sd_bus_match_signal_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "/org/freedesktop/DBus/Local",
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        signal_disconnected, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for Disconnected message: %m");

        return 0;
}

static int bus_on_connection(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int nfd = -EBADF;
        Manager *m = ASSERT_PTR(userdata);
        sd_id128_t id;
        int r;

        assert(s);

        nfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (nfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                log_warning_errno(errno, "Failed to accept private connection, ignoring: %m");
                return 0;
        }

        if (set_size(m->private_buses) >= CONNECTIONS_MAX) {
                log_warning("Too many concurrent connections, refusing");
                return 0;
        }

        r = sd_bus_new(&bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to allocate new private connection bus: %m");
                return 0;
        }

        (void) sd_bus_set_description(bus, "private-bus-connection");

        r = sd_bus_set_fd(bus, nfd, nfd);
        if (r < 0) {
                log_warning_errno(r, "Failed to set fd on new connection bus: %m");
                return 0;
        }

        TAKE_FD(nfd);

        r = bus_check_peercred(bus);
        if (r < 0) {
                log_warning_errno(r, "Incoming private connection from unprivileged client, refusing: %m");
                return 0;
        }

        assert_se(sd_id128_randomize(&id) >= 0);

        r = sd_bus_set_server(bus, 1, id);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable server support for new connection bus: %m");
                return 0;
        }

        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT|
                                   SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION);
        if (r < 0) {
                log_warning_errno(r, "Failed to enable credentials for new connection: %m");
                return 0;
        }

        r = sd_bus_set_sender(bus, "org.freedesktop.systemd1");
        if (r < 0) {
                log_warning_errno(r, "Failed to set direct connection sender: %m");
                return 0;
        }

        r = sd_bus_start(bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to start new connection bus: %m");
                return 0;
        }

        if (DEBUG_LOGGING) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *c = NULL;
                const char *comm = NULL, *description = NULL;
                pid_t pid = 0;

                r = sd_bus_get_owner_creds(bus, SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|SD_BUS_CREDS_DESCRIPTION, &c);
                if (r < 0)
                        log_warning_errno(r, "Failed to get peer creds, ignoring: %m");
                else {
                        (void) sd_bus_creds_get_pid(c, &pid);
                        (void) sd_bus_creds_get_comm(c, &comm);
                        (void) sd_bus_creds_get_description(c, &description);
                }

                log_debug("Accepting direct incoming connection from " PID_FMT " (%s) [%s]", pid, strna(comm), strna(description));
        }

        r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
        if (r < 0) {
                log_warning_errno(r, "Failed to attach new connection bus to event loop: %m");
                return 0;
        }

        r = bus_setup_disconnected_match(m, bus);
        if (r < 0)
                return 0;

        r = bus_setup_api_vtables(m, bus);
        if (r < 0) {
                log_warning_errno(r, "Failed to set up API vtables on new connection bus: %m");
                return 0;
        }

        r = bus_register_malloc_status(bus, "org.freedesktop.systemd1");
        if (r < 0)
                log_warning_errno(r, "Failed to register MemoryAllocation1, ignoring: %m");

        r = set_ensure_put(&m->private_buses, NULL, bus);
        if (r == -ENOMEM) {
                log_oom();
                return 0;
        }
        if (r < 0) {
                log_warning_errno(r, "Failed to add new connection bus to set: %m");
                return 0;
        }

        TAKE_PTR(bus);

        log_debug("Accepted new private connection.");

        return 0;
}

static int bus_track_coldplug(sd_bus *bus, sd_bus_track **t, char * const *l) {
        int r;

        assert(bus);
        assert(t);

        if (strv_isempty(l))
                return 0;

        if (!*t) {
                r = sd_bus_track_new(bus, t, NULL, NULL);
                if (r < 0)
                        return r;
        }

        return bus_track_add_name_many(*t, l);
}

static int bus_setup_api(Manager *m, sd_bus *bus) {
        char *name;
        Unit *u;
        int r;

        assert(m);
        assert(bus);

        /* Let's make sure we have enough credential bits so that we can make security and selinux decisions */
        r = sd_bus_negotiate_creds(bus, 1,
                                   SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|
                                   SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS|
                                   SD_BUS_CREDS_SELINUX_CONTEXT);
        if (r < 0)
                log_warning_errno(r, "Failed to enable credential passing, ignoring: %m");

        r = bus_setup_api_vtables(m, bus);
        if (r < 0)
                return r;

        HASHMAP_FOREACH_KEY(u, name, m->watch_bus) {
                r = unit_install_bus_match(u, bus, name);
                if (r < 0)
                        log_error_errno(r, "Failed to subscribe to NameOwnerChanged signal for '%s': %m", name);
        }

        r = sd_bus_match_signal_async(
                        bus,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.systemd1.Activator",
                        "ActivationRequest",
                        signal_activation_request, NULL, m);
        if (r < 0)
                log_warning_errno(r, "Failed to subscribe to activation signal: %m");

        /* Allow replacing of our name, to ease implementation of reexecution, where we keep the old connection open
         * until after the new connection is set up and the name installed to allow clients to synchronously wait for
         * reexecution to finish */
        r = sd_bus_request_name_async(bus, NULL, "org.freedesktop.systemd1", SD_BUS_NAME_REPLACE_EXISTING|SD_BUS_NAME_ALLOW_REPLACEMENT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = bus_register_malloc_status(bus, "org.freedesktop.systemd1");
        if (r < 0)
                log_warning_errno(r, "Failed to register MemoryAllocation1, ignoring: %m");

        log_debug("Successfully connected to API bus.");

        return 0;
}

int bus_init_api(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(m);

        if (m->api_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->system_bus)
                bus = sd_bus_ref(m->system_bus);
        else {
                if (MANAGER_IS_SYSTEM(m))
                        r = sd_bus_open_system_with_description(&bus, "bus-api-system");
                else
                        r = sd_bus_open_user_with_description(&bus, "bus-api-user");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to API bus: %m");

                r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach API bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        r = bus_setup_api(m, bus);
        if (r < 0)
                return log_error_errno(r, "Failed to set up API bus: %m");

        r = bus_get_instance_id(bus, &m->bus_id);
        if (r < 0)
                log_warning_errno(r, "Failed to query API bus instance ID, not deserializing subscriptions: %m");
        else if (sd_id128_is_null(m->deserialized_bus_id) || sd_id128_equal(m->bus_id, m->deserialized_bus_id))
                (void) bus_track_coldplug(bus, &m->subscribed, m->subscribed_as_strv);
        m->subscribed_as_strv = strv_free(m->subscribed_as_strv);
        m->deserialized_bus_id = SD_ID128_NULL;

        m->api_bus = TAKE_PTR(bus);
        return 0;
}

int bus_init_system(Manager *m) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (m->system_bus)
                return 0;

        /* The API and system bus is the same if we are running in system mode */
        if (MANAGER_IS_SYSTEM(m) && m->api_bus)
                bus = sd_bus_ref(m->api_bus);
        else {
                r = sd_bus_open_system_with_description(&bus, "bus-system");
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to system bus: %m");

                r = sd_bus_attach_event(bus, m->event, EVENT_PRIORITY_IPC);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach system bus to event loop: %m");

                r = bus_setup_disconnected_match(m, bus);
                if (r < 0)
                        return r;
        }

        m->system_bus = TAKE_PTR(bus);

        log_debug("Successfully connected to system bus.");

        return 0;
}

int bus_init_private(Manager *m) {
        _cleanup_close_ int fd = -EBADF;
        union sockaddr_union sa;
        socklen_t sa_len;
        sd_event_source *s;
        int r;

        assert(m);

        if (m->private_listen_fd >= 0)
                return 0;

        if (MANAGER_IS_SYSTEM(m)) {

                /* We want the private bus only when running as init */
                if (getpid_cached() != 1)
                        return 0;

                r = sockaddr_un_set_path(&sa.un, "/run/systemd/private");
        } else {
                _cleanup_free_ char *p = NULL;

                p = path_join(m->prefix[EXEC_DIRECTORY_RUNTIME], "systemd/private");
                if (!p)
                        return log_oom();

                r = sockaddr_un_set_path(&sa.un, p);
        }
        if (r < 0)
                return log_error_errno(r, "Failed set socket path for private bus: %m");
        sa_len = r;

        (void) sockaddr_un_unlink(&sa.un);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate private socket: %m");

        WITH_UMASK(0077)
                r = bind(fd, &sa.sa, sa_len);
        if (r < 0)
                return log_error_errno(errno, "Failed to bind private socket: %m");

        r = listen(fd, SOMAXCONN_DELUXE);
        if (r < 0)
                return log_error_errno(errno, "Failed to make private socket listening: %m");

        /* Generate an inotify event in case somebody waits for this socket to appear using inotify() */
        (void) touch(sa.un.sun_path);

        r = sd_event_add_io(m->event, &s, fd, EPOLLIN, bus_on_connection, m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event source: %m");

        (void) sd_event_source_set_description(s, "bus-connection");

        m->private_listen_fd = TAKE_FD(fd);
        m->private_listen_event_source = s;

        log_debug("Successfully created private D-Bus server.");

        return 0;
}

static void destroy_bus(Manager *m, sd_bus **bus) {
        Unit *u;
        Job *j;

        assert(m);
        assert(bus);

        if (!*bus)
                return;

        /* Make sure all bus slots watching names are released. */
        HASHMAP_FOREACH(u, m->watch_bus) {
                if (u->match_bus_slot && sd_bus_slot_get_bus(u->match_bus_slot) == *bus)
                        u->match_bus_slot = sd_bus_slot_unref(u->match_bus_slot);
                if (u->get_name_owner_slot && sd_bus_slot_get_bus(u->get_name_owner_slot) == *bus)
                        u->get_name_owner_slot = sd_bus_slot_unref(u->get_name_owner_slot);
        }

        /* Get rid of tracked clients on this bus */
        if (m->subscribed && sd_bus_track_get_bus(m->subscribed) == *bus) {
                _cleanup_strv_free_ char **subscribed = NULL;
                int r;

                r = bus_track_to_strv(m->subscribed, &subscribed);
                if (r < 0)
                        log_warning_errno(r, "Failed to serialize api subscribers, ignoring: %m");
                strv_free_and_replace(m->subscribed_as_strv, subscribed);

                m->deserialized_bus_id = m->bus_id;
                m->bus_id = SD_ID128_NULL;

                m->subscribed = sd_bus_track_unref(m->subscribed);
        }

        HASHMAP_FOREACH(j, m->jobs)
                if (j->bus_track && sd_bus_track_get_bus(j->bus_track) == *bus)
                        j->bus_track = sd_bus_track_unref(j->bus_track);

        HASHMAP_FOREACH(u, m->units) {
                if (u->bus_track && sd_bus_track_get_bus(u->bus_track) == *bus)
                        u->bus_track = sd_bus_track_unref(u->bus_track);

                /* Get rid of pending freezer messages on this bus */
                if (u->pending_freezer_invocation && sd_bus_message_get_bus(u->pending_freezer_invocation) == *bus)
                        u->pending_freezer_invocation = sd_bus_message_unref(u->pending_freezer_invocation);
        }

        /* Get rid of queued message on this bus */
        if (m->pending_reload_message && sd_bus_message_get_bus(m->pending_reload_message) == *bus)
                m->pending_reload_message = sd_bus_message_unref(m->pending_reload_message);

        /* Possibly flush unwritten data, but only if we are
         * unprivileged, since we don't want to sync here */
        if (!MANAGER_IS_SYSTEM(m))
                sd_bus_flush(*bus);

        /* And destroy the object */
        *bus = sd_bus_close_unref(*bus);
}

void bus_done_api(Manager *m) {
        destroy_bus(m, &m->api_bus);
}

void bus_done_system(Manager *m) {
        destroy_bus(m, &m->system_bus);
}

void bus_done_private(Manager *m) {
        sd_bus *b;

        assert(m);

        while ((b = set_steal_first(m->private_buses)))
                destroy_bus(m, &b);

        m->private_buses = set_free(m->private_buses);

        m->private_listen_event_source = sd_event_source_disable_unref(m->private_listen_event_source);
        m->private_listen_fd = safe_close(m->private_listen_fd);
}

void bus_done(Manager *m) {
        assert(m);

        bus_done_api(m);
        bus_done_system(m);
        bus_done_private(m);

        assert(!m->subscribed);

        m->polkit_registry = hashmap_free(m->polkit_registry);
}

int bus_fdset_add_all(Manager *m, FDSet *fds) {
        sd_bus *b;
        int fd;

        assert(m);
        assert(fds);

        /* When we are about to reexecute we add all D-Bus fds to the
         * set to pass over to the newly executed systemd. They won't
         * be used there however, except thatt they are closed at the
         * very end of deserialization, those making it possible for
         * clients to synchronously wait for systemd to reexec by
         * simply waiting for disconnection */

        if (m->api_bus) {
                fd = sd_bus_get_fd(m->api_bus);
                if (fd >= 0) {
                        fd = fdset_put_dup(fds, fd);
                        if (fd < 0)
                                return fd;
                }
        }

        SET_FOREACH(b, m->private_buses) {
                fd = sd_bus_get_fd(b);
                if (fd >= 0) {
                        fd = fdset_put_dup(fds, fd);
                        if (fd < 0)
                                return fd;
                }
        }

        /* We don't offer any APIs on the system bus (well, unless it
         * is the same as the API bus) hence we don't bother with it
         * here */

        return 0;
}

int bus_foreach_bus(
                Manager *m,
                sd_bus_track *subscribed2,
                int (*send_message)(sd_bus *bus, void *userdata),
                void *userdata) {

        int r = 0;

        assert(m);
        assert(send_message);

        /* Send to all direct buses, unconditionally */
        sd_bus *b;
        SET_FOREACH(b, m->private_buses) {

                /* Don't bother with enqueuing these messages to clients that haven't started yet */
                if (sd_bus_is_ready(b) <= 0)
                        continue;

                RET_GATHER(r, send_message(b, userdata));
        }

        /* Send to API bus, but only if somebody is subscribed */
        if (m->api_bus &&
            (sd_bus_track_count(m->subscribed) > 0 ||
             sd_bus_track_count(subscribed2) > 0))
                RET_GATHER(r, send_message(m->api_bus, userdata));

        return r;
}

void bus_track_serialize(sd_bus_track *t, FILE *f, const char *prefix) {
        const char *n;

        assert(f);
        assert(prefix);

        for (n = sd_bus_track_first(t); n; n = sd_bus_track_next(t)) {
                int c, j;

                c = sd_bus_track_count_name(t, n);
                for (j = 0; j < c; j++)
                        (void) serialize_item(f, prefix, n);
        }
}

uint64_t manager_bus_n_queued_write(Manager *m) {
        uint64_t c = 0;
        sd_bus *b;
        int r;

        /* Returns the total number of messages queued for writing on all our direct and API buses. */

        SET_FOREACH(b, m->private_buses) {
                uint64_t k;

                r = sd_bus_get_n_queued_write(b, &k);
                if (r < 0)
                        log_debug_errno(r, "Failed to query queued messages for private bus: %m");
                else
                        c += k;
        }

        if (m->api_bus) {
                uint64_t k;

                r = sd_bus_get_n_queued_write(m->api_bus, &k);
                if (r < 0)
                        log_debug_errno(r, "Failed to query queued messages for API bus: %m");
                else
                        c += k;
        }

        return c;
}

static void vtable_dump_bus_properties(FILE *f, const sd_bus_vtable *table) {
        const sd_bus_vtable *i;

        for (i = table; i->type != _SD_BUS_VTABLE_END; i++) {
                if (!IN_SET(i->type, _SD_BUS_VTABLE_PROPERTY, _SD_BUS_VTABLE_WRITABLE_PROPERTY) ||
                    (i->flags & (SD_BUS_VTABLE_DEPRECATED | SD_BUS_VTABLE_HIDDEN)) != 0)
                        continue;

                fprintf(f, "%s\n", i->x.property.member);
        }
}

void dump_bus_properties(FILE *f) {
        assert(f);

        vtable_dump_bus_properties(f, bus_automount_vtable);
        vtable_dump_bus_properties(f, bus_cgroup_vtable);
        vtable_dump_bus_properties(f, bus_device_vtable);
        vtable_dump_bus_properties(f, bus_exec_vtable);
        vtable_dump_bus_properties(f, bus_unit_exec_vtable);
        vtable_dump_bus_properties(f, bus_job_vtable);
        vtable_dump_bus_properties(f, bus_kill_vtable);
        vtable_dump_bus_properties(f, bus_manager_vtable);
        vtable_dump_bus_properties(f, bus_mount_vtable);
        vtable_dump_bus_properties(f, bus_path_vtable);
        vtable_dump_bus_properties(f, bus_scope_vtable);
        vtable_dump_bus_properties(f, bus_service_vtable);
        vtable_dump_bus_properties(f, bus_slice_vtable);
        vtable_dump_bus_properties(f, bus_socket_vtable);
        vtable_dump_bus_properties(f, bus_swap_vtable);
        vtable_dump_bus_properties(f, bus_target_vtable);
        vtable_dump_bus_properties(f, bus_timer_vtable);
        vtable_dump_bus_properties(f, bus_unit_vtable);
        vtable_dump_bus_properties(f, bus_unit_cgroup_vtable);
}
