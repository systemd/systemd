/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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
#include "cgroup.h"
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

#define CONNECTIONS_MAX 52

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

static const char *error_to_dbus(int error);
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

static uint32_t bus_flags_to_events(DBusWatch *bus_watch) {
        unsigned flags;
        uint32_t events = 0;

        assert(bus_watch);

        /* no watch flags for disabled watches */
        if (!dbus_watch_get_enabled(bus_watch))
                return 0;

        flags = dbus_watch_get_flags(bus_watch);

        if (flags & DBUS_WATCH_READABLE)
                events |= EPOLLIN;
        if (flags & DBUS_WATCH_WRITABLE)
                events |= EPOLLOUT;

        return events | EPOLLHUP | EPOLLERR;
}

static unsigned events_to_bus_flags(uint32_t events) {
        unsigned flags = 0;

        if (events & EPOLLIN)
                flags |= DBUS_WATCH_READABLE;
        if (events & EPOLLOUT)
                flags |= DBUS_WATCH_WRITABLE;
        if (events & EPOLLHUP)
                flags |= DBUS_WATCH_HANGUP;
        if (events & EPOLLERR)
                flags |= DBUS_WATCH_ERROR;

        return flags;
}

void bus_watch_event(Manager *m, Watch *w, int events) {
        assert(m);
        assert(w);

        /* This is called by the event loop whenever there is
         * something happening on D-Bus' file handles. */

        if (!dbus_watch_get_enabled(w->data.bus_watch))
                return;

        dbus_watch_handle(w->data.bus_watch, events_to_bus_flags(events));
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
                        free(w);
                        close_nointr_nofail(w->fd);
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

        if (!(w = dbus_watch_get_data(bus_watch)))
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

        assert_se(w = dbus_watch_get_data(bus_watch));
        assert(w->type == WATCH_DBUS_WATCH);

        zero(ev);
        ev.events = bus_flags_to_events(bus_watch);
        ev.data.ptr = w;

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_MOD, w->fd, &ev) == 0);
}

static int bus_timeout_arm(Manager *m, Watch *w) {
        struct itimerspec its;

        assert(m);
        assert(w);

        zero(its);

        if (dbus_timeout_get_enabled(w->data.bus_timeout)) {
                timespec_store(&its.it_value, dbus_timeout_get_interval(w->data.bus_timeout) * USEC_PER_MSEC);
                its.it_interval = its.it_interval;
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

        if (!(w->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC)) < 0)
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

        if (!(w = dbus_timeout_get_data(timeout)))
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

        assert_se(w = dbus_timeout_get_data(timeout));
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

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! API D-Bus connection terminated.");
                bus_done_api(m);

        } else if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
                const char *name, *old_owner, *new_owner;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_STRING, &old_owner,
                                           DBUS_TYPE_STRING, &new_owner,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse NameOwnerChanged message: %s", error.message);
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
                        log_error("Failed to parse ActivationRequest message: %s", error.message);
                else  {
                        int r;
                        Unit *u;

                        log_debug("Got D-Bus activation request for %s", name);

                        r = manager_load_unit(m, name, NULL, &u);

                        if (r >= 0 && u->meta.only_by_dependency)
                                r = -EPERM;

                        if (r >= 0)
                                r = manager_add_job(m, JOB_START, u, JOB_REPLACE, true, NULL);

                        if (r < 0) {
                                const char *id, *text;

                                log_warning("D-Bus activation failed for %s: %s", name, strerror(-r));

                                if (!(reply = dbus_message_new_signal("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Activator", "ActivationFailure")))
                                        goto oom;

                                id = error_to_dbus(r);
                                text = strerror(-r);

                                if (!dbus_message_set_destination(reply, DBUS_SERVICE_DBUS) ||
                                    !dbus_message_append_args(reply,
                                                              DBUS_TYPE_STRING, &name,
                                                              DBUS_TYPE_STRING, &id,
                                                              DBUS_TYPE_STRING, &text,
                                                              DBUS_TYPE_INVALID))
                                        goto oom;
                        }

                        /* On success we don't do anything, the service will be spwaned now */
                }
        }

        dbus_error_free(&error);

        if (reply) {
                if (!dbus_connection_send(connection, reply, NULL))
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

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! System D-Bus connection terminated.");
                bus_done_system(m);

        } else if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Agent", "Released")) {
                const char *cgroup;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &cgroup,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse Released message: %s", error.message);
                else
                        cgroup_notify_empty(m, cgroup);
        }

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult private_bus_message_filter(DBusConnection *connection, DBusMessage *message, void *data) {
        Manager *m = data;

        assert(connection);
        assert(message);
        assert(m);

        log_debug("Got D-Bus request: %s.%s() on %s",
                  dbus_message_get_interface(message),
                  dbus_message_get_member(message),
                  dbus_message_get_path(message));

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected"))
                shutdown_connection(m, connection);

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
                log_warning("RequestName() failed: %s", error.message);
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                uint32_t r;

                if (!dbus_message_get_args(reply,
                                           &error,
                                           DBUS_TYPE_UINT32, &r,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse RequestName() reply: %s", error.message);
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
        uint32_t flags = 0;
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
                log_warning("ListNames() failed: %s", error.message);
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
            !dbus_connection_set_timeout_functions(bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL)) {
                log_error("Not enough memory");
                return -ENOMEM;
        }

        if (set_put(m->bus_connections_for_dispatch, bus) < 0) {
                log_error("Not enough memory");
                return -ENOMEM;
        }

        dbus_connection_set_dispatch_status_function(bus, bus_dispatch_status, m, NULL);
        return 0;
}

static dbus_bool_t allow_only_root(DBusConnection *connection, unsigned long uid, void *data) {
        return uid == 0;
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

        dbus_connection_set_unix_user_function(new_connection, allow_only_root, NULL, NULL);

        if (bus_setup_loop(m, new_connection) < 0)
                return;

        if (!dbus_connection_register_object_path(new_connection, "/org/freedesktop/systemd1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(new_connection, "/org/freedesktop/systemd1/unit", &bus_unit_vtable, m) ||
            !dbus_connection_register_fallback(new_connection, "/org/freedesktop/systemd1/job", &bus_job_vtable, m) ||
            !dbus_connection_add_filter(new_connection, private_bus_message_filter, m, NULL)) {
                log_error("Not enough memory.");
                return;
        }

        log_debug("Accepted connection on private bus.");

        dbus_connection_ref(new_connection);
}

static int bus_init_system(Manager *m) {
        DBusError error;
        char *id;
        int r;

        assert(m);

        dbus_error_init(&error);

        if (m->system_bus)
                return 0;

        if (m->running_as == MANAGER_SYSTEM && m->api_bus)
                m->system_bus = m->api_bus;
        else {
                if (!(m->system_bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error))) {
                        log_debug("Failed to get system D-Bus connection, retrying later: %s", error.message);
                        r = 0;
                        goto fail;
                }

                if ((r = bus_setup_loop(m, m->system_bus)) < 0)
                        goto fail;
        }

        if (!dbus_connection_add_filter(m->system_bus, system_bus_message_filter, m, NULL)) {
                log_error("Not enough memory");
                r = -EIO;
                goto fail;
        }

        dbus_bus_add_match(m->system_bus,
                           "type='signal',"
                           "interface='org.freedesktop.systemd1.Agent',"
                           "member='Released',"
                           "path='/org/freedesktop/systemd1/agent'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                r = -EIO;
                goto fail;
        }

        log_info("Successfully connected to system D-Bus bus %s as %s",
                 strnull((id = dbus_connection_get_server_id(m->system_bus))),
                 strnull(dbus_bus_get_unique_name(m->system_bus)));
        dbus_free(id);

        return 0;

fail:
        bus_done_system(m);
        dbus_error_free(&error);

        return r;
}

static int bus_init_api(Manager *m) {
        DBusError error;
        char *id;
        int r;

        assert(m);

        dbus_error_init(&error);

        if (m->api_bus)
                return 0;

        if (m->running_as == MANAGER_SYSTEM && m->system_bus)
                m->api_bus = m->system_bus;
        else {
                if (!(m->api_bus = dbus_bus_get_private(m->running_as == MANAGER_SESSION ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &error))) {
                        log_debug("Failed to get API D-Bus connection, retrying later: %s", error.message);
                        r = 0;
                        goto fail;
                }

                if ((r = bus_setup_loop(m, m->api_bus)) < 0)
                        goto fail;
        }

        if (!dbus_connection_register_object_path(m->api_bus, "/org/freedesktop/systemd1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->api_bus, "/org/freedesktop/systemd1/unit", &bus_unit_vtable, m) ||
            !dbus_connection_register_fallback(m->api_bus, "/org/freedesktop/systemd1/job", &bus_job_vtable, m) ||
            !dbus_connection_add_filter(m->api_bus, api_bus_message_filter, m, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
                goto fail;
        }

        /* Get NameOwnerChange messages */
        dbus_bus_add_match(m->api_bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='"DBUS_INTERFACE_DBUS"',"
                           "member='NameOwnerChanged',"
                           "path='"DBUS_PATH_DBUS"'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                r = -EIO;
                goto fail;
        }

        /* Get activation requests */
        dbus_bus_add_match(m->api_bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='org.freedesktop.systemd1.Activator',"
                           "member='ActivationRequest',"
                           "path='"DBUS_PATH_DBUS"'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                r = -EIO;
                goto fail;
        }

        if ((r = request_name(m)) < 0)
                goto fail;

        if ((r = query_name_list(m)) < 0)
                goto fail;

        log_info("Successfully connected to API D-Bus bus %s as %s",
                 strnull((id = dbus_connection_get_server_id(m->api_bus))),
                 strnull(dbus_bus_get_unique_name(m->api_bus)));
        dbus_free(id);

        return 0;

fail:
        bus_done_api(m);
        dbus_error_free(&error);

        return r;
}

static int bus_init_private(Manager *m) {
        DBusError error;
        int r;
        const char *const external_only[] = {
                "EXTERNAL",
                NULL
        };

        assert(m);

        dbus_error_init(&error);

        if (m->private_bus)
                return 0;

        /* We want the private bus only when running as init */
        if (m->running_as != MANAGER_SYSTEM)
                return 0;

        if (!(m->private_bus = dbus_server_listen("unix:abstract=/org/freedesktop/systemd1/private", &error))) {
                log_error("Failed to create private D-Bus server: %s", error.message);
                r = -EIO;
                goto fail;
        }

        if (!dbus_server_set_auth_mechanisms(m->private_bus, (const char**) external_only) ||
            !dbus_server_set_watch_functions(m->private_bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_server_set_timeout_functions(m->private_bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
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

int bus_init(Manager *m) {
        int r;

        if (set_ensure_allocated(&m->bus_connections, trivial_hash_func, trivial_compare_func) < 0 ||
            set_ensure_allocated(&m->bus_connections_for_dispatch, trivial_hash_func, trivial_compare_func) < 0) {
                log_error("Not enough memory");
                return -ENOMEM;
        }

        if (m->name_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->name_data_slot)) {
                        log_error("Not enough memory");
                        return -ENOMEM;
                }

        if (m->subscribed_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->subscribed_data_slot)) {
                        log_error("Not enough memory");
                        return -ENOMEM;
                }

        if ((r = bus_init_system(m)) < 0 ||
            (r = bus_init_api(m)) < 0 ||
            (r = bus_init_private(m)) < 0)
                return r;

        return 0;
}

static void shutdown_connection(Manager *m, DBusConnection *c) {
        Set *s;
        Job *j;
        Iterator i;

        HASHMAP_FOREACH(j, m->jobs, i)
                if (j->bus == c) {
                        free(j->bus_client);
                        j->bus_client = NULL;

                        j->bus = NULL;
                }

        set_remove(m->bus_connections, c);
        set_remove(m->bus_connections_for_dispatch, c);

        if ((s = BUS_CONNECTION_SUBSCRIBED(m, c))) {
                char *t;

                while ((t = set_steal_first(s)))
                        free(t);

                set_free(s);
        }

        if (m->queued_message_connection == c) {
                m->queued_message_connection = NULL;

                if (m->queued_message) {
                        dbus_message_unref(m->queued_message);
                        m->queued_message = NULL;
                }
        }

        dbus_connection_set_dispatch_status_function(c, NULL, NULL, NULL);
        dbus_connection_flush(c);
        dbus_connection_close(c);
        dbus_connection_unref(c);
}

static void bus_done_api(Manager *m) {
        assert(m);

        if (m->api_bus) {
                if (m->system_bus == m->api_bus)
                        m->system_bus = NULL;

                shutdown_connection(m, m->api_bus);
                m->api_bus = NULL;
        }


       if (m->queued_message) {
               dbus_message_unref(m->queued_message);
               m->queued_message = NULL;
       }
}

static void bus_done_system(Manager *m) {
        assert(m);

        if (m->system_bus == m->api_bus)
                bus_done_api(m);

        if (m->system_bus) {
                shutdown_connection(m, m->system_bus);
                m->system_bus = NULL;
        }
}

static void bus_done_private(Manager *m) {

        if (m->private_bus) {
                dbus_server_disconnect(m->private_bus);
                dbus_server_unref(m->private_bus);
                m->private_bus = NULL;
        }
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

        if (m->subscribed_data_slot >= 0)
                dbus_pending_call_free_data_slot(&m->subscribed_data_slot);
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
                log_warning("GetConnectionUnixProcessID() failed: %s", error.message);
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                uint32_t r;

                if (!dbus_message_get_args(reply,
                                           &error,
                                           DBUS_TYPE_UINT32, &r,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse GetConnectionUnixProcessID() reply: %s", error.message);
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

DBusHandlerResult bus_default_message_handler(Manager *m, DBusConnection *c, DBusMessage *message, const char*introspection, const BusProperty *properties) {
        DBusError error;
        DBusMessage *reply = NULL;
        int r;

        assert(m);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect") && introspection) {

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection, DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Get") && properties) {
                const char *interface, *property;
                const BusProperty *p;

                if (!dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_STRING, &interface,
                            DBUS_TYPE_STRING, &property,
                            DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, c, message, &error, -EINVAL);

                for (p = properties; p->property; p++)
                        if (streq(p->interface, interface) && streq(p->property, property))
                                break;

                if (p->property) {
                        DBusMessageIter iter, sub;

                        if (!(reply = dbus_message_new_method_return(message)))
                                goto oom;

                        dbus_message_iter_init_append(reply, &iter);

                        if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, p->signature, &sub))
                                goto oom;

                        if ((r = p->append(m, &sub, property, (void*) p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(m, c, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&iter, &sub))
                                goto oom;
                }
        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "GetAll") && properties) {
                const char *interface;
                const BusProperty *p;
                DBusMessageIter iter, sub, sub2, sub3;

                if (!dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_STRING, &interface,
                            DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, c, message, &error, -EINVAL);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub))
                        goto oom;

                for (p = properties; p->property; p++) {
                        if (interface[0] && !streq(p->interface, interface))
                                continue;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, NULL, &sub2) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &p->property) ||
                            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, p->signature, &sub3))
                                goto oom;

                        if ((r = p->append(m, &sub3, p->property, (void*) p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(m, c, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&sub2, &sub3) ||
                            !dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;
        }

        if (reply) {
                if (!dbus_connection_send(c, reply, NULL))
                        goto oom;

                dbus_message_unref(reply);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static const char *error_to_dbus(int error) {

        switch(error) {

        case -EINVAL:
                return DBUS_ERROR_INVALID_ARGS;

        case -ENOMEM:
                return DBUS_ERROR_NO_MEMORY;

        case -EPERM:
        case -EACCES:
                return DBUS_ERROR_ACCESS_DENIED;

        case -ESRCH:
                return DBUS_ERROR_UNIX_PROCESS_ID_UNKNOWN;

        case -ENOENT:
                return DBUS_ERROR_FILE_NOT_FOUND;

        case -EEXIST:
                return DBUS_ERROR_FILE_EXISTS;

        case -ETIMEDOUT:
                return DBUS_ERROR_TIMEOUT;

        case -EIO:
                return DBUS_ERROR_IO_ERROR;

        case -ENETRESET:
        case -ECONNABORTED:
        case -ECONNRESET:
                return DBUS_ERROR_DISCONNECTED;
        }

        return DBUS_ERROR_FAILED;
}

DBusHandlerResult bus_send_error_reply(Manager *m, DBusConnection *c, DBusMessage *message, DBusError *bus_error, int error) {
        DBusMessage *reply = NULL;
        const char *name, *text;

        if (bus_error && dbus_error_is_set(bus_error)) {
                name = bus_error->name;
                text = bus_error->message;
        } else {
                name = error_to_dbus(error);
                text = strerror(-error);
        }

        if (!(reply = dbus_message_new_error(message, name, text)))
                goto oom;

        if (!dbus_connection_send(c, reply, NULL))
                goto oom;

        dbus_message_unref(reply);

        if (bus_error)
                dbus_error_free(bus_error);

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        if (bus_error)
                dbus_error_free(bus_error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

int bus_broadcast(Manager *m, DBusMessage *message) {
        bool oom = false;
        Iterator i;
        DBusConnection *c;

        assert(m);
        assert(message);

        SET_FOREACH(c, m->bus_connections_for_dispatch, i)
                if (c != m->system_bus || m->running_as == MANAGER_SYSTEM)
                        oom = !dbus_connection_send(c, message, NULL);

        SET_FOREACH(c, m->bus_connections, i)
                if (c != m->system_bus || m->running_as == MANAGER_SYSTEM)
                        oom = !dbus_connection_send(c, message, NULL);

        return oom ? -ENOMEM : 0;
}

int bus_property_append_string(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        const char *t = data;

        assert(m);
        assert(i);
        assert(property);

        if (!t)
                t = "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

int bus_property_append_strv(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        char **t = data;

        assert(m);
        assert(i);
        assert(property);

        if (!dbus_message_iter_open_container(i, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        STRV_FOREACH(t, t)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, t))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(i, &sub))
                return -ENOMEM;

        return 0;
}

int bus_property_append_bool(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        bool *b = data;
        dbus_bool_t db;

        assert(m);
        assert(i);
        assert(property);
        assert(b);

        db = *b;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &db))
                return -ENOMEM;

        return 0;
}

int bus_property_append_uint64(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        assert(m);
        assert(i);
        assert(property);
        assert(data);

        /* Let's ensure that pid_t is actually 64bit, and hence this
         * function can be used for usec_t */
        assert_cc(sizeof(uint64_t) == sizeof(usec_t));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_uint32(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        assert(m);
        assert(i);
        assert(property);
        assert(data);

        /* Let's ensure that pid_t and mode_t is actually 32bit, and
         * hence this function can be used for pid_t/mode_t */
        assert_cc(sizeof(uint32_t) == sizeof(pid_t));
        assert_cc(sizeof(uint32_t) == sizeof(mode_t));
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT32, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_int32(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        assert(m);
        assert(i);
        assert(property);
        assert(data);

        assert_cc(sizeof(int32_t) == sizeof(int));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_INT32, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_size(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        uint64_t u;

        assert(m);
        assert(i);
        assert(property);
        assert(data);

        u = (uint64_t) *(size_t*) data;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

int bus_property_append_ul(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        uint64_t u;

        assert(m);
        assert(i);
        assert(property);
        assert(data);

        u = (uint64_t) *(unsigned long*) data;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

int bus_parse_strv(DBusMessage *m, char ***_l) {
        DBusMessageIter iter, sub;
        unsigned n = 0, i = 0;
        char **l;

        assert(m);
        assert(_l);

        if (!dbus_message_iter_init(m, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRING)
            return -EINVAL;

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                n++;
                dbus_message_iter_next(&sub);
        }

        if (!(l = new(char*, n+1)))
                return -ENOMEM;

        assert_se(dbus_message_iter_init(m, &iter));
        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *s;

                assert_se(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                dbus_message_iter_get_basic(&sub, &s);

                if (!(l[i++] = strdup(s))) {
                        strv_free(l);
                        return -ENOMEM;
                }

                dbus_message_iter_next(&sub);
        }

        assert(i == n);
        l[i] = NULL;

        if (_l)
                *_l = l;

        return 0;
}

bool bus_has_subscriber(Manager *m) {
        Iterator i;
        DBusConnection *c;

        assert(m);

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
