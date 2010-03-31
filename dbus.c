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

#include <dbus/dbus.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <unistd.h>

#include "dbus.h"
#include "log.h"
#include "strv.h"
#include "cgroup.h"

static void bus_dispatch_status(DBusConnection *bus, DBusDispatchStatus status, void *data)  {
        Manager *m = data;

        assert(bus);
        assert(m);
        assert(m->bus == bus);

        m->request_bus_dispatch = status != DBUS_DISPATCH_COMPLETE;
}

static void system_bus_dispatch_status(DBusConnection *bus, DBusDispatchStatus status, void *data)  {
        Manager *m = data;

        assert(bus);
        assert(m);
        assert(m->system_bus == bus);

        m->request_system_bus_dispatch = status != DBUS_DISPATCH_COMPLETE;
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

static DBusHandlerResult bus_message_filter(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        DBusError error;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        /* log_debug("Got D-Bus request: %s.%s() on %s", */
        /*           dbus_message_get_interface(message), */
        /*           dbus_message_get_member(message), */
        /*           dbus_message_get_path(message)); */

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");

                /* FIXME: we probably should restart D-Bus here */

        } else if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS, "NameOwnerChanged")) {
                const char *name, *old, *new;

                if (!dbus_message_get_args(message, &error,
                                           DBUS_TYPE_STRING, &name,
                                           DBUS_TYPE_STRING, &old,
                                           DBUS_TYPE_STRING, &new,
                                           DBUS_TYPE_INVALID))
                        log_error("Failed to parse NameOwnerChanged message: %s", error.message);
                else  {
                        if (set_remove(m->subscribed, (char*) name))
                                log_debug("Subscription client vanished: %s (left: %u)", name, set_size(m->subscribed));
                }
        }

        dbus_error_free(&error);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult system_bus_message_filter(DBusConnection  *connection, DBusMessage  *message, void *data) {
        Manager *m = data;
        DBusError error;

        assert(connection);
        assert(message);
        assert(m);

        dbus_error_init(&error);

        /* log_debug("Got D-Bus request: %s.%s() on %s", */
        /*           dbus_message_get_interface(message), */
        /*           dbus_message_get_member(message), */
        /*           dbus_message_get_path(message)); */

        if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected")) {
                log_error("Warning! D-Bus connection terminated.");

                /* FIXME: we probably should restart D-Bus here */

        } if (dbus_message_is_signal(message, "org.freedesktop.systemd1.Agent", "Released")) {
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

unsigned bus_dispatch(Manager *m) {
        assert(m);

        if (m->request_bus_dispatch)
                if (dbus_connection_dispatch(m->bus) == DBUS_DISPATCH_COMPLETE) {
                        m->request_bus_dispatch = false;
                        return 1;
                }

        if (m->request_system_bus_dispatch)
                if (dbus_connection_dispatch(m->system_bus) == DBUS_DISPATCH_COMPLETE) {
                        m->request_system_bus_dispatch = false;
                        return 1;
                }

        return 0;
}

static int request_name(Manager *m) {
        DBusMessage *message;
        const char *name = "org.freedesktop.systemd1";
        uint32_t flags = 0;

        if (!(message = dbus_message_new_method_call(
                              DBUS_SERVICE_DBUS,
                              DBUS_PATH_DBUS,
                              DBUS_INTERFACE_DBUS,
                              "RequestName")))
                return -ENOMEM;

        if (!dbus_message_append_args(
                            message,
                            DBUS_TYPE_STRING, &name,
                            DBUS_TYPE_UINT32, &flags,
                            DBUS_TYPE_INVALID)) {
                dbus_message_unref(message);
                return -ENOMEM;
        }

        if (!dbus_connection_send(m->bus, message, NULL)) {
                dbus_message_unref(message);
                return -ENOMEM;
        }

        /* We simple ask for the name and don't wait for it. Sooner or
         * later we'll have it, and we wouldn't know what to do on
         * error anyway. */

        dbus_message_unref(message);

        return 0;
}

static int bus_setup_loop(Manager *m, DBusConnection *bus) {
        assert(m);
        assert(bus);

        dbus_connection_set_exit_on_disconnect(bus, FALSE);
        if (!dbus_connection_set_watch_functions(bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_connection_set_timeout_functions(bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL))
                return -ENOMEM;

        return 0;
}

int bus_init(Manager *m) {
        DBusError error;
        char *id;
        int r;

        assert(m);

        if (m->bus)
                return 0;

        if (!(m->subscribed = set_new(string_hash_func, string_compare_func)))
                return -ENOMEM;

        dbus_connection_set_change_sigpipe(FALSE);

        dbus_error_init(&error);
        if (!(m->bus = dbus_bus_get_private(m->running_as == MANAGER_SESSION ? DBUS_BUS_SESSION : DBUS_BUS_SYSTEM, &error))) {
                log_error("Failed to get D-Bus connection: %s", error.message);
                dbus_error_free(&error);
                bus_done(m);
                return -ECONNREFUSED;
        }

        if ((r = bus_setup_loop(m, m->bus)) < 0) {
                bus_done(m);
                return r;
        }

        dbus_connection_set_dispatch_status_function(m->bus, bus_dispatch_status, m, NULL);

        if (m->running_as == MANAGER_SESSION) {
                if (!(m->system_bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error))) {
                        log_error("Failed to get D-Bus connection: %s", error.message);
                        dbus_error_free(&error);
                        bus_done(m);
                        return -ECONNREFUSED;
                }

                if ((r = bus_setup_loop(m, m->system_bus)) < 0) {
                        bus_done(m);
                        return r;
                }

                dbus_connection_set_dispatch_status_function(m->system_bus, system_bus_dispatch_status, m, NULL);
        } else
                m->system_bus = m->bus;

        if (!dbus_connection_register_object_path(m->bus, "/org/freedesktop/systemd1", &bus_manager_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/systemd1/unit", &bus_unit_vtable, m) ||
            !dbus_connection_register_fallback(m->bus, "/org/freedesktop/systemd1/job", &bus_job_vtable, m) ||
            !dbus_connection_add_filter(m->bus, bus_message_filter, m, NULL) ||
            !dbus_connection_add_filter(m->system_bus, system_bus_message_filter, m, NULL)) {
                bus_done(m);
                return -ENOMEM;
        }

        dbus_bus_add_match(m->bus,
                           "type='signal',"
                           "sender='"DBUS_SERVICE_DBUS"',"
                           "interface='"DBUS_INTERFACE_DBUS"',"
                           "path='"DBUS_PATH_DBUS"'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                dbus_error_free(&error);
                return -ENOMEM;
        }

        if ((r = request_name(m)) < 0) {
                bus_done(m);
                return r;
        }

        dbus_bus_add_match(m->system_bus,
                           "type='signal',"
                           "interface='org.freedesktop.systemd1.Agent',"
                           "path='/org/freedesktop/systemd1/agent'",
                           &error);

        if (dbus_error_is_set(&error)) {
                log_error("Failed to register match: %s", error.message);
                dbus_error_free(&error);
                bus_done(m);
                return -ENOMEM;
        }

        log_debug("Successfully connected to D-Bus bus %s as %s",
                  strnull((id = dbus_connection_get_server_id(m->bus))),
                  strnull(dbus_bus_get_unique_name(m->bus)));
        dbus_free(id);

        log_debug("Successfully connected to system D-Bus bus %s as %s",
                  strnull((id = dbus_connection_get_server_id(m->system_bus))),
                  strnull(dbus_bus_get_unique_name(m->system_bus)));
        dbus_free(id);

        m->request_bus_dispatch = true;
        m->request_system_bus_dispatch = true;

        return 0;
}

void bus_done(Manager *m) {
        assert(m);

        if (m->system_bus && m->system_bus != m->bus) {
                dbus_connection_close(m->system_bus);
                dbus_connection_unref(m->system_bus);
                m->system_bus = NULL;
        }

        if (m->bus) {
                dbus_connection_close(m->bus);
                dbus_connection_unref(m->bus);
                m->bus = NULL;
        }

        if (m->subscribed) {
                char *c;

                while ((c = set_steal_first(m->subscribed)))
                        free(c);

                set_free(m->subscribed);
                m->subscribed = NULL;
        }
}

DBusHandlerResult bus_default_message_handler(Manager *m, DBusMessage *message, const char*introspection, const BusProperty *properties) {
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
                        return bus_send_error_reply(m, message, &error, -EINVAL);

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

                        if ((r = p->append(m, &sub, property, p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(m, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&iter, &sub))
                                goto oom;
                }
        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "GetAll") && properties) {
                const char *interface;
                const BusProperty *p;
                DBusMessageIter iter, sub, sub2, sub3;
                bool any = false;

                if (!dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_STRING, &interface,
                            DBUS_TYPE_INVALID))
                        return bus_send_error_reply(m, message, &error, -EINVAL);

                if (!(reply = dbus_message_new_method_return(message)))
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub))
                        goto oom;

                for (p = properties; p->property; p++) {
                        if (!streq(p->interface, interface))
                                continue;

                        if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, NULL, &sub2) ||
                            !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &p->property) ||
                            !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, p->signature, &sub3))
                                goto oom;

                        if ((r = p->append(m, &sub3, p->property, p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(m, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&sub2, &sub3) ||
                            !dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;

                        any = true;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;
        }

        if (reply) {
                if (!dbus_connection_send(m->bus, reply, NULL))
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

DBusHandlerResult bus_send_error_reply(Manager *m, DBusMessage *message, DBusError *bus_error, int error) {
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

        if (!dbus_connection_send(m->bus, reply, NULL))
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

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_uint32(Manager *m, DBusMessageIter *i, const char *property, void *data) {
        assert(m);
        assert(i);
        assert(property);
        assert(data);

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT32, data))
                return -ENOMEM;

        return 0;
}
