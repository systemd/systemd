/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus.h>

#include "dbus.h"
#include "log.h"
#include "strv.h"
#include "mkdir.h"
#include "missing.h"
#include "dbus-unit.h"
#include "dbus-job.h"
#include "dbus-manager.h"
#include "dbus-service.h"
#include "dbus-socket.h"
#include "dbus-target.h"
#include "dbus-device.h"
#include "dbus-mount.h"
#include "dbus-automount.h"
#include "dbus-snapshot.h"
#include "dbus-swap.h"
#include "dbus-timer.h"
#include "dbus-path.h"
#include "bus-errors.h"
#include "special.h"
#include "dbus-common.h"

#define CONNECTIONS_MAX 512

/* Well-known address (http://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-types) */
#define DBUS_SYSTEM_BUS_DEFAULT_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"
/* Only used as a fallback */
#define DBUS_SESSION_BUS_DEFAULT_ADDRESS "autolaunch:"

static const char bus_properties_interface[] = BUS_PROPERTIES_INTERFACE;
static const char bus_introspectable_interface[] = BUS_INTROSPECTABLE_INTERFACE;

const char *const bus_interface_table[] = {
        "org.freedesktop.DBus.Properties",     bus_properties_interface,
        "org.freedesktop.DBus.Introspectable", bus_introspectable_interface,
        "org.freedesktop.systemd1.Manager",    bus_manager_interface,
        "org.freedesktop.systemd1.Job",        bus_job_interface,
        "org.freedesktop.systemd1.Unit",       bus_unit_interface,
        "org.freedesktop.systemd1.Service",    bus_service_interface,
        "org.freedesktop.systemd1.Socket",     bus_socket_interface,
        "org.freedesktop.systemd1.Target",     bus_target_interface,
        "org.freedesktop.systemd1.Device",     bus_device_interface,
        "org.freedesktop.systemd1.Mount",      bus_mount_interface,
        "org.freedesktop.systemd1.Automount",  bus_automount_interface,
        "org.freedesktop.systemd1.Snapshot",   bus_snapshot_interface,
        "org.freedesktop.systemd1.Swap",       bus_swap_interface,
        "org.freedesktop.systemd1.Timer",      bus_timer_interface,
        "org.freedesktop.systemd1.Path",       bus_path_interface,
        NULL
};

static void bus_done_api(Manager *m);
static void bus_done_system(Manager *m);
static void bus_done_private(Manager *m);
static void shutdown_connection(Manager *m, DBusConnection *c);

static void bus_dispatch_status(DBusConnection *bus, DBusDispatchStatus status, void *data)  {
        Manager *m = data;

        assert(bus);
        assert(m);

        /* We maintain two sets, one for those connections where we
         * requested a dispatch, and another where we didn't. And then,
         * we move the connections between the two sets. */

        if (status == DBUS_DISPATCH_COMPLETE)
                set_move_one(m->bus_connections, m->bus_connections_for_dispatch, bus);
        else
                set_move_one(m->bus_connections_for_dispatch, m->bus_connections, bus);
}

void bus_watch_event(Manager *m, Watch *w, int events) {
        assert(m);
        assert(w);

        /* This is called by the event loop whenever there is
         * something happening on D-Bus' file handles. */

        if (!dbus_watch_get_enabled(w->data.bus_watch))
                return;

        dbus_watch_handle(w->data.bus_watch, bus_events_to_flags(events));
}

static dbus_bool_t bus_add_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(bus_watch);
        assert(m);

        if (!(w = new0(Watch, 1)))
                return FALSE;

        w->fd = dbus_watch_get_unix_fd(bus_watch);
        w->type = WATCH_DBUS_WATCH;
        w->data.bus_watch = bus_watch;

        zero(ev);
        ev.events = bus_flags_to_events(bus_watch);
        ev.data.ptr = w;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0) {

                if (errno != EEXIST) {
                        free(w);
                        return FALSE;
                }

                /* Hmm, bloody D-Bus creates multiple watches on the
                 * same fd. epoll() does not like that. As a dirty
                 * hack we simply dup() the fd and hence get a second
                 * one we can safely add to the epoll(). */

                if ((w->fd = dup(w->fd)) < 0) {
                        free(w);
                        return FALSE;
                }

                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0) {
                        close_nointr_nofail(w->fd);
                        free(w);
                        return FALSE;
                }

                w->fd_is_dupped = true;
        }

        dbus_watch_set_data(bus_watch, w, NULL);

        return TRUE;
}

static void bus_remove_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;

        assert(bus_watch);
        assert(m);

        w = dbus_watch_get_data(bus_watch);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_WATCH);
        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);

        if (w->fd_is_dupped)
                close_nointr_nofail(w->fd);

        free(w);
}

static void bus_toggle_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(bus_watch);
        assert(m);

        w = dbus_watch_get_data(bus_watch);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_WATCH);

        zero(ev);
        ev.events = bus_flags_to_events(bus_watch);
        ev.data.ptr = w;

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_MOD, w->fd, &ev) == 0);
}

static int bus_timeout_arm(Manager *m, Watch *w) {
        struct itimerspec its = {};

        assert(m);
        assert(w);

        if (dbus_timeout_get_enabled(w->data.bus_timeout)) {
                timespec_store(&its.it_value, dbus_timeout_get_interval(w->data.bus_timeout) * USEC_PER_MSEC);
                its.it_interval = its.it_value;
        }

        if (timerfd_settime(w->fd, 0, &its, NULL) < 0)
                return -errno;

        return 0;
}

void bus_timeout_event(Manager *m, Watch *w, int events) {
        assert(m);
        assert(w);

        /* This is called by the event loop whenever there is
         * something happening on D-Bus' file handles. */

        if (!(dbus_timeout_get_enabled(w->data.bus_timeout)))
                return;

        dbus_timeout_handle(w->data.bus_timeout);
}

static dbus_bool_t bus_add_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(timeout);
        assert(m);

        if (!(w = new0(Watch, 1)))
                return FALSE;

        if ((w->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC)) < 0)
                goto fail;

        w->type = WATCH_DBUS_TIMEOUT;
        w->data.bus_timeout = timeout;

        if (bus_timeout_arm(m, w) < 0)
                goto fail;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = w;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0)
                goto fail;

        dbus_timeout_set_data(timeout, w, NULL);

        return TRUE;

fail:
        if (w->fd >= 0)
                close_nointr_nofail(w->fd);

        free(w);
        return FALSE;
}

static void bus_remove_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;

        assert(timeout);
        assert(m);

        w = dbus_timeout_get_data(timeout);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_TIMEOUT);

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);
        close_nointr_nofail(w->fd);
        free(w);
}

static void bus_toggle_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;
        int r;

        assert(timeout);
        assert(m);

        w = dbus_timeout_get_data(timeout);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_TIMEOUT);

        if ((r = bus_timeout_arm(m, w)) < 0)
                log_error("Failed to rearm timer: %s", strerror(-r));
}

static DBusHandlerResult api_bus_message_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        Manager *m = data;
        DBusError error;
        DBusMessage *reply = NULL;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL ||
            dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL)
                log_debug("Got D-Bus request: %s.%s() on %s",
                          dbus_message_get_interface(message),
                          dbus_message_get_member(message),
                          dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_debug("API D-Bus connection terminated.");
                bus_done_api(m);

        } else if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
                const char *name, *old_owner, *new_owner;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_STRING, &old_owner,
                                           DBUS_TYPE_STRING, &new_owner,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse NameOwnerChanged message: %s", bus_error_message(&error));
                else  {
                        if (set_remove(BUS_CONNECTION_SUBSCRIBED(m, connection), (char*) name))
                                log_debug("Subscription client vanished: %s (left: %u)", name, set_size(BUS_CONNECTION_SUBSCRIBED(m, connection)));

                        if (old_owner[0] == 0)
                                old_owner = NULL;

                        if (new_owner[0] == 0)
                                new_owner = NULL;

                        manager_dispatch_bus_name_owner_changed(m, name, old_owner, new_owner);
                }
        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Activator", "ActivationRequest")) {
                const char *name;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse ActivationRequest message: %s", bus_error_message(&error));
                else  {
                        int r;
                        Unit *u;

                        log_debug("Got D-Bus activation request for %s", name);

                        if (manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SERVICE) ||
                            manager_unit_inactive_or_pending(m, SPECIAL_DBUS_SOCKET)) {
                                r = -EADDRNOTAVAIL;
                                dbus_set_error(&error, BUS_ERROR_SHUTTING_DOWN, "Refusing activation, D-Bus is shutting down.");
                        } else {
                                r = manager_load_unit(m, name, NULL, &error, &u);

                                if (r >= 0 && u->refuse_manual_start)
                                        r = -EPERM;

                                if (r >= 0)
                                        r = manager_add_job(m, JOB_START, u, JOB_REPLACE, true, &error, NULL);
                        }

                        if (r < 0) {
                                const char *id, *text;

                                log_debug("D-Bus activation failed for %s: %s", name, strerror(-r));

                                if (!(reply = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Activator", "ActivationFailure")))
                                        goto oom;

                                id = error.name ? error.name : bus_errno_to_dbus(r);
                                text = bus_error(&error, r);

                                if (!dbus_message_set_destination(reply, DBUS_SERVICE_DBUS) ||
                                    !dbus_message_append_args(reply,
                                                              DBUS_TYPE_STRING, &name,
                                                              DBUS_TYPE_STRING, &id,
                                                              DBUS_TYPE_STRING, &text,
                                                              DBUS_TYPE_INVALID))
                                        goto oom;
                        }

                        /* On success we don't do anything, the service will be spawned now */
                }
        }

        dbus_error_free(&error);

        if (reply) {
                if (!bus_maybe_send_reply(connection, message, reply))
                        goto oom;

                dbus_message_unref(reply);
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult system_bus_message_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        Manager *m = data;
        DBusError error;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (m->api_bus != m->system_bus &&
            (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL ||
             dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL))
                log_debug("Got D-Bus request on system bus: %s.%s() on %s",
                          dbus_message_get_interface(message),
                          dbus_message_get_member(message),
                          dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_debug("System D-Bus connection terminated.");
                bus_done_system(m);

        } else if (m->running_as != SYSTEMD_SYSTEM &&
                   dbus_message_is_signal(message, "org.freedesktop.systemd1.Agent", "Released")) {

                const char *cgroup;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &cgroup,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse Released message: %s", bus_error_message(&error));
                else
                        manager_notify_cgroup_empty(m, cgroup);
        }

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult private_bus_message_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        Manager *m = data;
        DBusError error;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL ||
            dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL)
                log_debug("Got D-Bus request: %s.%s() on %s",
                          dbus_message_get_interface(message),
                          dbus_message_get_member(message),
                          dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected"))
                shutdown_connection(m, connection);
        else if (m->running_as == SYSTEMD_SYSTEM &&
                 dbus_message_is_signal(message, "org.freedesktop.systemd1.Agent", "Released")) {

                const char *cgroup;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &cgroup,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse Released message: %s", bus_error_message(&error));
                else
                        manager_notify_cgroup_empty(m, cgroup);

                /* Forward the message to the system bus, so that user
                 * instances are notified as well */

                if (m->system_bus)
                        dbus_connection_send(m->system_bus, message, NULL);
        }

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

unsigned bus_dispatch(Manager *m) {
        DBusConnection *c;

        assert(m);

        if (m->queued_message) {
                /* If we cannot get rid of this message we won't
                 * dispatch any D-Bus messages, so that we won't end
                 * up wanting to queue another message. */

                if (m->queued_message_connection)
                        if (!dbus_connection_send(m->queued_message_connection, m->queued_message, NULL))
                                return 0;

                dbus_message_unref(m->queued_message);
                m->queued_message = NULL;
                m->queued_message_connection = NULL;
        }

        if ((c = set_first(m->bus_connections_for_dispatch))) {
                if (dbus_connection_dispatch(c) == DBUS_DISPATCH_COMPLETE)
                        set_move_one(m->bus_connections, m->bus_connections_for_dispatch, c);

                return 1;
        }

        return 0;
}

static void request_name_pending_cb(DBusPendingCall *pending, void *userdata) {
        DBusMessage *reply;
        DBusError error;

        dbus_error_init(&error);

        assert_se(reply = dbus_pending_call_steal_reply(pending));

        switch (dbus_message_get_type(reply)) {

        case DBUS_MESSAGE_TYPE_ERROR:

                assert_se(dbus_set_error_from_message(&error, reply));
                log_warning("RequestName() failed: %s", bus_error_message(&error));
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                uint32_t r;

                if (!dbus_message_get_args(reply,
                                           &error,
                                           DBUS_TYPE_UINT32, &r,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse RequestName() reply: %s", bus_error_message(&error));
                        break;
                }

                if (r == 1)
                        log_debug("Successfully acquired name.");
                else
                        log_error("Name already owned.");

                break;
        }

        default:
                assert_not_reached("Invalid reply message");
        }

        dbus_message_unref(reply);
        dbus_error_free(&error);
}

static int request_name(Manager *m) {
        const char *name = "org.freedesktop.systemd1";
        /* Allow replacing of our name, to ease implementation of
         * reexecution, where we keep the old connection open until
         * after the new connection is set up and the name installed
         * to allow clients to synchronously wait for reexecution to
         * finish */
        uint32_t flags = DBUS_NAME_FLAG_ALLOW_REPLACEMENT|DBUS_NAME_FLAG_REPLACE_EXISTING;
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;

        if (!(message = dbus_message_new_method_call(
                              DBUS_SERVICE_DBUS,
                              DBUS_PATH_DBUS,
                              DBUS_INTERFACE_DBUS,
                              "RequestName")))
                goto oom;

        if (!dbus_message_append_args(
                            message,
                            DBUS_TYPE_STRING, &name,
                            DBUS_TYPE_UINT32, &flags,
                            DBUS_TYPE_INVALID))
                goto oom;

        if (!dbus_connection_send_with_reply(m->api_bus, message, &pending, -1))
                goto oom;

        if (!dbus_pending_call_set_notify(pending, request_name_pending_cb, m, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        /* We simple ask for the name and don't wait for it. Sooner or
         * later we'll have it. */

        return 0;

oom:
        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}

static void query_name_list_pending_cb(DBusPendingCall *pending, void *userdata) {
        DBusMessage *reply;
        DBusError error;
        Manager *m = userdata;

        assert(m);

        dbus_error_init(&error);

        assert_se(reply = dbus_pending_call_steal_reply(pending));

        switch (dbus_message_get_type(reply)) {

        case DBUS_MESSAGE_TYPE_ERROR:

                assert_se(dbus_set_error_from_message(&error, reply));
                log_warning("ListNames() failed: %s", bus_error_message(&error));
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                int r;
                char **l;

                if ((r = bus_parse_strv(reply, &l)) < 0)
                        log_warning("Failed to parse ListNames() reply: %s", strerror(-r));
                else {
                        char **t;

                        STRV_FOREACH(t, l)
                                /* This is a bit hacky, we say the
                                 * owner of the name is the name
                                 * itself, because we don't want the
                                 * extra traffic to figure out the
                                 * real owner. */
                                manager_dispatch_bus_name_owner_changed(m, *t, NULL, *t);

                        strv_free(l);
                }

                break;
        }

        default:
                assert_not_reached("Invalid reply message");
        }

        dbus_message_unref(reply);
        dbus_error_free(&error);
}

static int query_name_list(Manager *m) {
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;

        /* Asks for the currently installed bus names */

        if (!(message = dbus_message_new_method_call(
                              DBUS_SERVICE_DBUS,
                              DBUS_PATH_DBUS,
                              DBUS_INTERFACE_DBUS,
                              "ListNames")))
                goto oom;

        if (!dbus_connection_send_with_reply(m->api_bus, message, &pending, -1))
                goto oom;

        if (!dbus_pending_call_set_notify(pending, query_name_list_pending_cb, m, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        /* We simple ask for the list and don't wait for it. Sooner or
         * later we'll get it. */

        return 0;

oom:
        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}

static int bus_setup_loop(Manager *m, DBusConnection *bus) {
        assert(m);
        assert(bus);

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (!dbus_connection_set_watch_functions(bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_connection_set_timeout_functions(bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL))
                return log_oom();

        if (set_put(m->bus_connections_for_dispatch, bus) < 0)
                return log_oom();

        dbus_connection_set_dispatch_status_function(bus, bus_dispatch_status, m, NULL);
        return 0;
}

static dbus_bool_t allow_only_same_user(DBusConnection *connection, unsigned long uid, void *data) {
        return uid == 0 || uid == geteuid();
}

static void bus_new_connection(
                DBusServer *server,
                DBusConnection *new_connection,
                void *data) {

        Manager *m = data;

        assert(m);

        if (set_size(m->bus_connections) >= CONNECTIONS_MAX) {
                log_error("Too many concurrent connections.");
                return;
        }

        dbus_connection_set_unix_user_function(new_connection, allow_only_same_user, NULL, NULL);

        if (bus_setup_loop(m, new_connection) < 0)
                return;

        if (!dbus_connection_register_object_path(new_connection, "/org/freedesktop/systemd1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(new_connection, "/org/freedesktop/systemd1/unit", &bus_unit_vtable, m) ||
            !dbus_connection_register_fallback(new_connection, "/org/freedesktop/systemd1/job", &bus_job_vtable, m) ||
            !dbus_connection_add_filter(new_connection, private_bus_message_filter, m, NULL)) {
                log_oom();
                return;
        }

        log_debug("Accepted connection on private bus.");

        dbus_connection_ref(new_connection);
}

static int init_registered_system_bus(Manager *m) {
        char *id;

        if (!dbus_connection_add_filter(m->system_bus, system_bus_message_filter, m, NULL))
                return log_oom();

        if (m->running_as != SYSTEMD_SYSTEM) {
                DBusError error;

                dbus_error_init(&error);

                dbus_bus_add_match(m->system_bus,
                                   "type='signal',"
                                   "interface='org.freedesktop.systemd1.Agent',"
                                   "member='Released',"
                                   "path='/org/freedesktop/systemd1/agent'",
                                   &error);

                if (dbus_error_is_set(&error)) {
                        log_error("Failed to register match: %s", bus_error_message(&error));
                        dbus_error_free(&error);
                        return -1;
                }
        }

        log_debug("Successfully connected to system D-Bus bus %s as %s",
                 strnull((id = dbus_connection_get_server_id(m->system_bus))),
                 strnull(dbus_bus_get_unique_name(m->system_bus)));
        dbus_free(id);

        return 0;
}

static int init_registered_api_bus(Manager *m) {
        int r;

        if (!dbus_connection_register_object_path(m->api_bus, "/org/freedesktop/systemd1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->api_bus, "/org/freedesktop/systemd1/unit", &bus_unit_vtable, m) ||
            !dbus_connection_register_fallback(m->api_bus, "/org/freedesktop/systemd1/job", &bus_job_vtable, m) ||
            !dbus_connection_add_filter(m->api_bus, api_bus_message_filter, m, NULL))
                return log_oom();

        /* Get NameOwnerChange messages */
        dbus_bus_add_match(m->api_bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='"DBUS_INTERFACE_DBUS"',"
                           "member='NameOwnerChanged',"
                           "path='"DBUS_PATH_DBUS"'",
                           NULL);

        /* Get activation requests */
        dbus_bus_add_match(m->api_bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='org.freedesktop.systemd1.Activator',"
                           "member='ActivationRequest',"
                           "path='"DBUS_PATH_DBUS"'",
                           NULL);

        r = request_name(m);
        if (r < 0)
                return r;

        r = query_name_list(m);
        if (r < 0)
                return r;

        if (m->running_as == SYSTEMD_USER) {
                char *id;
                log_debug("Successfully connected to API D-Bus bus %s as %s",
                         strnull((id = dbus_connection_get_server_id(m->api_bus))),
                         strnull(dbus_bus_get_unique_name(m->api_bus)));
                dbus_free(id);
        } else
                log_debug("Successfully initialized API on the system bus");

        return 0;
}

static void bus_register_cb(DBusPendingCall *pending, void *userdata) {
        Manager *m = userdata;
        DBusConnection **conn;
        DBusMessage *reply;
        DBusError error;
        const char *name;
        int r = 0;

        dbus_error_init(&error);

        conn = dbus_pending_call_get_data(pending, m->conn_data_slot);
        assert(conn == &m->system_bus || conn == &m->api_bus);

        reply = dbus_pending_call_steal_reply(pending);

        switch (dbus_message_get_type(reply)) {
        case DBUS_MESSAGE_TYPE_ERROR:
                assert_se(dbus_set_error_from_message(&error, reply));
                log_warning("Failed to register to bus: %s", bus_error_message(&error));
                r = -1;
                break;
        case DBUS_MESSAGE_TYPE_METHOD_RETURN:
                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse Hello reply: %s", bus_error_message(&error));
                        r = -1;
                        break;
                }

                log_debug("Received name %s in reply to Hello", name);
                if (!dbus_bus_set_unique_name(*conn, name)) {
                        log_error("Failed to set unique name");
                        r = -1;
                        break;
                }

                if (conn == &m->system_bus) {
                        r = init_registered_system_bus(m);
                        if (r == 0 && m->running_as == SYSTEMD_SYSTEM)
                                r = init_registered_api_bus(m);
                } else
                        r = init_registered_api_bus(m);

                break;
        default:
                assert_not_reached("Invalid reply message");
        }

        dbus_message_unref(reply);
        dbus_error_free(&error);

        if (r < 0) {
                if (conn == &m->system_bus) {
                        log_debug("Failed setting up the system bus");
                        bus_done_system(m);
                } else {
                        log_debug("Failed setting up the API bus");
                        bus_done_api(m);
                }
        }
}

static int manager_bus_async_register(Manager *m, DBusConnection **conn) {
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;

        message = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                               DBUS_PATH_DBUS,
                                               DBUS_INTERFACE_DBUS,
                                               "Hello");
        if (!message)
                goto oom;

        if (!dbus_connection_send_with_reply(*conn, message, &pending, -1))
                goto oom;

        if (!dbus_pending_call_set_data(pending, m->conn_data_slot, conn, NULL))
                goto oom;

        if (!dbus_pending_call_set_notify(pending, bus_register_cb, m, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        return 0;
oom:
        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}

static DBusConnection* manager_bus_connect_private(Manager *m, DBusBusType type) {
        const char *address;
        DBusConnection *connection;
        DBusError error;

        switch (type) {
        case DBUS_BUS_SYSTEM:
                address = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");
                if (!address || !address[0])
                        address = DBUS_SYSTEM_BUS_DEFAULT_ADDRESS;
                break;
        case DBUS_BUS_SESSION:
                address = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
                if (!address || !address[0])
                        address = DBUS_SESSION_BUS_DEFAULT_ADDRESS;
                break;
        default:
                assert_not_reached("Invalid bus type");
        }

        dbus_error_init(&error);

        connection = dbus_connection_open_private(address, &error);
        if (!connection) {
                log_warning("Failed to open private bus connection: %s", bus_error_message(&error));
                goto fail;
        }

        return connection;

fail:
        dbus_error_free(&error);
        return NULL;
}

static int bus_init_system(Manager *m) {
        int r;

        if (m->system_bus)
                return 0;

        m->system_bus = manager_bus_connect_private(m, DBUS_BUS_SYSTEM);
        if (!m->system_bus) {
                log_debug("Failed to connect to system D-Bus, retrying later");
                r = 0;
                goto fail;
        }

        r = bus_setup_loop(m, m->system_bus);
        if (r < 0)
                goto fail;

        r = manager_bus_async_register(m, &m->system_bus);
        if (r < 0)
                goto fail;

        return 0;
fail:
        bus_done_system(m);

        return r;
}

static int bus_init_api(Manager *m) {
        int r;

        if (m->api_bus)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM) {
                m->api_bus = m->system_bus;
                /* In this mode there is no distinct connection to the API bus,
                 * the API is published on the system bus.
                 * bus_register_cb() is aware of that and will init the API
                 * when the system bus gets registered.
                 * No need to setup anything here. */
                return 0;
        }

        m->api_bus = manager_bus_connect_private(m, DBUS_BUS_SESSION);
        if (!m->api_bus) {
                log_debug("Failed to connect to API D-Bus, retrying later");
                r = 0;
                goto fail;
        }

        r = bus_setup_loop(m, m->api_bus);
        if (r < 0)
                goto fail;

        r = manager_bus_async_register(m, &m->api_bus);
        if (r < 0)
                goto fail;

        return 0;
fail:
        bus_done_api(m);

        return r;
}

static int bus_init_private(Manager *m) {
        DBusError error;
        int r;
        static const char *const external_only[] = {
                "EXTERNAL",
                NULL
        };

        assert(m);

        dbus_error_init(&error);

        if (m->private_bus)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM) {

                /* We want the private bus only when running as init */
                if (getpid() != 1)
                        return 0;

                unlink("/run/systemd/private");
                m->private_bus = dbus_server_listen("unix:path=/run/systemd/private", &error);
        } else {
                const char *e;
                char *p;
                char *escaped;

                e = secure_getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return 0;

                if (asprintf(&p, "%s/systemd/private", e) < 0) {
                        r = log_oom();
                        goto fail;
                }

                mkdir_parents_label(p, 0755);
                unlink(p);
                free(p);

                escaped = dbus_address_escape_value(e);
                if (!escaped) {
                        r = log_oom();
                        goto fail;
                }
                if (asprintf(&p, "unix:path=%s/systemd/private", escaped) < 0) {
                        dbus_free(escaped);
                        r = log_oom();
                        goto fail;
                }
                dbus_free(escaped);

                m->private_bus = dbus_server_listen(p, &error);
                free(p);
        }

        if (!m->private_bus) {
                log_error("Failed to create private D-Bus server: %s", bus_error_message(&error));
                r = -EIO;
                goto fail;
        }

        if (!dbus_server_set_auth_mechanisms(m->private_bus, (const char**) external_only) ||
            !dbus_server_set_watch_functions(m->private_bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_server_set_timeout_functions(m->private_bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL)) {
                r = log_oom();
                goto fail;
        }

        dbus_server_set_new_connection_function(m->private_bus, bus_new_connection, m, NULL);

        log_debug("Successfully created private D-Bus server.");

        return 0;

fail:
        bus_done_private(m);
        dbus_error_free(&error);

        return r;
}

int bus_init(Manager *m, bool try_bus_connect) {
        int r;

        if (set_ensure_allocated(&m->bus_connections, trivial_hash_func, trivial_compare_func) < 0 ||
            set_ensure_allocated(&m->bus_connections_for_dispatch, trivial_hash_func, trivial_compare_func) < 0)
                return log_oom();

        if (m->name_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->name_data_slot))
                        return log_oom();

        if (m->conn_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->conn_data_slot))
                        return log_oom();

        if (m->subscribed_data_slot < 0)
                if (!dbus_connection_allocate_data_slot(&m->subscribed_data_slot))
                        return log_oom();

        if (try_bus_connect) {
                if ((r = bus_init_system(m)) < 0 ||
                    (r = bus_init_api(m)) < 0)
                        return r;
        }

        r = bus_init_private(m);
        if (r < 0)
                return r;

        return 0;
}

static void shutdown_connection(Manager *m, DBusConnection *c) {
        Job *j;
        Iterator i;

        HASHMAP_FOREACH(j, m->jobs, i) {
                JobBusClient *cl, *nextcl;
                LIST_FOREACH_SAFE(client, cl, nextcl, j->bus_client_list) {
                        if (cl->bus == c) {
                                LIST_REMOVE(JobBusClient, client, j->bus_client_list, cl);
                                free(cl);
                        }
                }
        }

        set_remove(m->bus_connections, c);
        set_remove(m->bus_connections_for_dispatch, c);
        set_free_free(BUS_CONNECTION_SUBSCRIBED(m, c));

        if (m->queued_message_connection == c) {
                m->queued_message_connection = NULL;

                if (m->queued_message) {
                        dbus_message_unref(m->queued_message);
                        m->queued_message = NULL;
                }
        }

        dbus_connection_set_dispatch_status_function(c, NULL, NULL, NULL);
        /* system manager cannot afford to block on DBus */
        if (m->running_as != SYSTEMD_SYSTEM)
                dbus_connection_flush(c);
        dbus_connection_close(c);
        dbus_connection_unref(c);
}

static void bus_done_api(Manager *m) {
        if (!m->api_bus)
                return;

        if (m->running_as == SYSTEMD_USER)
                shutdown_connection(m, m->api_bus);

        m->api_bus = NULL;

        if (m->queued_message) {
                dbus_message_unref(m->queued_message);
                m->queued_message = NULL;
        }
}

static void bus_done_system(Manager *m) {
        if (!m->system_bus)
                return;

        if (m->running_as == SYSTEMD_SYSTEM)
                bus_done_api(m);

        shutdown_connection(m, m->system_bus);
        m->system_bus = NULL;
}

static void bus_done_private(Manager *m) {
        if (!m->private_bus)
                return;

        dbus_server_disconnect(m->private_bus);
        dbus_server_unref(m->private_bus);
        m->private_bus = NULL;
}

void bus_done(Manager *m) {
        DBusConnection *c;

        bus_done_api(m);
        bus_done_system(m);
        bus_done_private(m);

        while ((c = set_steal_first(m->bus_connections)))
                shutdown_connection(m, c);

        while ((c = set_steal_first(m->bus_connections_for_dispatch)))
                shutdown_connection(m, c);

        set_free(m->bus_connections);
        set_free(m->bus_connections_for_dispatch);

        if (m->name_data_slot >= 0)
                dbus_pending_call_free_data_slot(&m->name_data_slot);

        if (m->conn_data_slot >= 0)
                dbus_pending_call_free_data_slot(&m->conn_data_slot);

        if (m->subscribed_data_slot >= 0)
                dbus_connection_free_data_slot(&m->subscribed_data_slot);
}

static void query_pid_pending_cb(DBusPendingCall *pending, void *userdata) {
        Manager *m = userdata;
        DBusMessage *reply;
        DBusError error;
        const char *name;

        dbus_error_init(&error);

        assert_se(name = BUS_PENDING_CALL_NAME(m, pending));
        assert_se(reply = dbus_pending_call_steal_reply(pending));

        switch (dbus_message_get_type(reply)) {

        case DBUS_MESSAGE_TYPE_ERROR:

                assert_se(dbus_set_error_from_message(&error, reply));
                log_warning("GetConnectionUnixProcessID() failed: %s", bus_error_message(&error));
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                uint32_t r;

                if (!dbus_message_get_args(reply,
                                           &error,
                                           DBUS_TYPE_UINT32, &r,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse GetConnectionUnixProcessID() reply: %s", bus_error_message(&error));
                        break;
                }

                manager_dispatch_bus_query_pid_done(m, name, (pid_t) r);
                break;
        }

        default:
                assert_not_reached("Invalid reply message");
        }

        dbus_message_unref(reply);
        dbus_error_free(&error);
}

int bus_query_pid(Manager *m, const char *name) {
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;
        char *n = NULL;

        assert(m);
        assert(name);

        if (!(message = dbus_message_new_method_call(
                              DBUS_SERVICE_DBUS,
                              DBUS_PATH_DBUS,
                              DBUS_INTERFACE_DBUS,
                              "GetConnectionUnixProcessID")))
                goto oom;

        if (!(dbus_message_append_args(
                              message,
                              DBUS_TYPE_STRING, &name,
                              DBUS_TYPE_INVALID)))
                goto oom;

        if (!dbus_connection_send_with_reply(m->api_bus, message, &pending, -1))
                goto oom;

        if (!(n = strdup(name)))
                goto oom;

        if (!dbus_pending_call_set_data(pending, m->name_data_slot, n, free))
                goto oom;

        n = NULL;

        if (!dbus_pending_call_set_notify(pending, query_pid_pending_cb, m, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        return 0;

oom:
        free(n);

        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}

int bus_broadcast(Manager *m, DBusMessage *message) {
        bool oom = false;
        Iterator i;
        DBusConnection *c;

        assert(m);
        assert(message);

        SET_FOREACH(c, m->bus_connections_for_dispatch, i)
                if (c != m->system_bus || m->running_as == SYSTEMD_SYSTEM)
                        oom = !dbus_connection_send(c, message, NULL);

        SET_FOREACH(c, m->bus_connections, i)
                if (c != m->system_bus || m->running_as == SYSTEMD_SYSTEM)
                        oom = !dbus_connection_send(c, message, NULL);

        return oom ? -ENOMEM : 0;
}

bool bus_has_subscriber(Manager *m) {
        Iterator i;
        DBusConnection *c;

        assert(m);

        /* If we are reloading then we might not have deserialized the
           subscribers yet, hence let's assume that there are some */

        if (m->n_reloading > 0)
                return true;

        SET_FOREACH(c, m->bus_connections_for_dispatch, i)
                if (bus_connection_has_subscriber(m, c))
                        return true;

        SET_FOREACH(c, m->bus_connections, i)
                if (bus_connection_has_subscriber(m, c))
                        return true;

        return false;
}

bool bus_connection_has_subscriber(Manager *m, DBusConnection *c) {
        assert(m);
        assert(c);

        return !set_isempty(BUS_CONNECTION_SUBSCRIBED(m, c));
}

int bus_fdset_add_all(Manager *m, FDSet *fds) {
        Iterator i;
        DBusConnection *c;

        assert(m);
        assert(fds);

        /* When we are about to reexecute we add all D-Bus fds to the
         * set to pass over to the newly executed systemd. They won't
         * be used there however, except that they are closed at the
         * very end of deserialization, those making it possible for
         * clients to synchronously wait for systemd to reexec by
         * simply waiting for disconnection */

        SET_FOREACH(c, m->bus_connections_for_dispatch, i) {
                int fd;

                if (dbus_connection_get_unix_fd(c, &fd)) {
                        fd = fdset_put_dup(fds, fd);

                        if (fd < 0)
                                return fd;
                }
        }

        SET_FOREACH(c, m->bus_connections, i) {
                int fd;

                if (dbus_connection_get_unix_fd(c, &fd)) {
                        fd = fdset_put_dup(fds, fd);

                        if (fd < 0)
                                return fd;
                }
        }

        return 0;
}

void bus_broadcast_finished(
                Manager *m,
                usec_t firmware_usec,
                usec_t loader_usec,
                usec_t kernel_usec,
                usec_t initrd_usec,
                usec_t userspace_usec,
                usec_t total_usec) {

        _cleanup_dbus_message_unref_ DBusMessage *message = NULL;

        assert(m);

        message = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartupFinished");
        if (!message) {
                log_oom();
                return;
        }

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));
        if (!dbus_message_append_args(message,
                                      DBUS_TYPE_UINT64, &firmware_usec,
                                      DBUS_TYPE_UINT64, &loader_usec,
                                      DBUS_TYPE_UINT64, &kernel_usec,
                                      DBUS_TYPE_UINT64, &initrd_usec,
                                      DBUS_TYPE_UINT64, &userspace_usec,
                                      DBUS_TYPE_UINT64, &total_usec,
                                      DBUS_TYPE_INVALID)) {
                log_oom();
                return;
        }


        if (bus_broadcast(m, message) < 0) {
                log_oom();
                return;
        }
}

void bus_broadcast_reloading(Manager *m, bool active) {

        _cleanup_dbus_message_unref_ DBusMessage *message = NULL;
        dbus_bool_t b = active;

        assert(m);

        message = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Reloading");
        if (!message) {
                log_oom();
                return;
        }

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));
        if (!dbus_message_append_args(message,
                                      DBUS_TYPE_BOOLEAN, &b,
                                      DBUS_TYPE_INVALID)) {
                log_oom();
                return;
        }


        if (bus_broadcast(m, message) < 0) {
                log_oom();
                return;
        }
}

Set *bus_acquire_subscribed(Manager *m, DBusConnection *c) {
        Set *s;

        assert(m);
        assert(c);

        s = BUS_CONNECTION_SUBSCRIBED(m, c);
        if (s)
                return s;

        s = set_new(string_hash_func, string_compare_func);
        if (!s)
                return NULL;

        if (!dbus_connection_set_data(c, m->subscribed_data_slot, s, NULL)) {
                set_free(s);
                return NULL;
        }

        return s;
}

void bus_serialize(Manager *m, FILE *f) {
        char *client;
        Iterator i;
        Set *s;

        assert(m);
        assert(f);

        if (!m->api_bus)
                return;

        s = BUS_CONNECTION_SUBSCRIBED(m, m->api_bus);
        SET_FOREACH(client, s, i)
                fprintf(f, "subscribed=%s\n", client);
}

int bus_deserialize_item(Manager *m, const char *line) {
        const char *e;
        char *b;
        Set *s;

        assert(m);
        assert(line);

        if (!m->api_bus)
                return 0;

        e = startswith(line, "subscribed=");
        if (!e)
                return 0;

        s = bus_acquire_subscribed(m, m->api_bus);
        if (!s)
                return -ENOMEM;

        b = strdup(e);
        if (!b)
                return -ENOMEM;

        set_consume(s, b);

        return 1;
}
