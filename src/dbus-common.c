/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <assert.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dbus/dbus.h>
#include <string.h>
#include <sys/epoll.h>

#include "log.h"
#include "dbus-common.h"
#include "util.h"
#include "def.h"
#include "strv.h"

int bus_check_peercred(DBusConnection *c) {
        int fd;
        struct ucred ucred;
        socklen_t l;

        assert(c);

        assert_se(dbus_connection_get_unix_fd(c, &fd));

        l = sizeof(struct ucred);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0) {
                log_error("SO_PEERCRED failed: %m");
                return -errno;
        }

        if (l != sizeof(struct ucred)) {
                log_error("SO_PEERCRED returned wrong size.");
                return -E2BIG;
        }

        if (ucred.uid != 0)
                return -EPERM;

        return 1;
}

static int sync_auth(DBusConnection *bus, DBusError *error) {
        usec_t begin, tstamp;

        assert(bus);

        /* This complexity should probably move into D-Bus itself:
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=35189 */

        begin = tstamp = now(CLOCK_MONOTONIC);
        for (;;) {

                if (tstamp > begin + DEFAULT_TIMEOUT_USEC)
                        break;

                if (dbus_connection_get_is_authenticated(bus))
                        break;

                if (!dbus_connection_read_write_dispatch(bus, ((begin + DEFAULT_TIMEOUT_USEC - tstamp) + USEC_PER_MSEC - 1) / USEC_PER_MSEC))
                        break;

                tstamp = now(CLOCK_MONOTONIC);
        }

        if (!dbus_connection_get_is_connected(bus)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_SERVER, "Connection terminated during authentication.");
                return -ECONNREFUSED;
        }

        if (!dbus_connection_get_is_authenticated(bus)) {
                dbus_set_error_const(error, DBUS_ERROR_TIMEOUT, "Failed to authenticate in time.");
                return -EACCES;
        }

        return 0;
}

int bus_connect(DBusBusType t, DBusConnection **_bus, bool *private, DBusError *error) {
        DBusConnection *bus;
        int r;

        assert(_bus);

        /* If we are root, then let's not go via the bus */
        if (geteuid() == 0 && t == DBUS_BUS_SYSTEM) {

                if (!(bus = dbus_connection_open_private("unix:path=/run/systemd/private", error))) {
#ifndef LEGACY
                        dbus_error_free(error);

                        /* Retry with the pre v21 socket name, to ease upgrades */
                        if (!(bus = dbus_connection_open_private("unix:abstract=/org/freedesktop/systemd1/private", error)))
#endif
                                return -EIO;
                }

                dbus_connection_set_exit_on_disconnect(bus, FALSE);

                if (bus_check_peercred(bus) < 0) {
                        dbus_connection_close(bus);
                        dbus_connection_unref(bus);

                        dbus_set_error_const(error, DBUS_ERROR_ACCESS_DENIED, "Failed to verify owner of bus.");
                        return -EACCES;
                }

                if (private)
                        *private = true;

        } else {
                if (!(bus = dbus_bus_get_private(t, error)))
                        return -EIO;

                dbus_connection_set_exit_on_disconnect(bus, FALSE);

                if (private)
                        *private = false;
        }

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

int bus_connect_system_ssh(const char *user, const char *host, DBusConnection **_bus, DBusError *error) {
        DBusConnection *bus;
        char *p = NULL;
        int r;

        assert(_bus);
        assert(user || host);

        if (user && host)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s@%s,argv3=systemd-stdio-bridge", user, host);
        else if (user)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s@localhost,argv3=systemd-stdio-bridge", user);
        else if (host)
                asprintf(&p, "exec:path=ssh,argv1=-xT,argv2=%s,argv3=systemd-stdio-bridge", host);

        if (!p) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return -ENOMEM;
        }

        bus = dbus_connection_open_private(p, error);
        free(p);

        if (!bus)
                return -EIO;

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        if (!dbus_bus_register(bus, error)) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

int bus_connect_system_polkit(DBusConnection **_bus, DBusError *error) {
        DBusConnection *bus;
        int r;

        assert(_bus);

        /* Don't bother with PolicyKit if we are root */
        if (geteuid() == 0)
                return bus_connect(DBUS_BUS_SYSTEM, _bus, NULL, error);

        if (!(bus = dbus_connection_open_private("exec:path=pkexec,argv1=" SYSTEMD_STDIO_BRIDGE_BINARY_PATH, error)))
                return -EIO;

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if ((r = sync_auth(bus, error)) < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        if (!dbus_bus_register(bus, error)) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        *_bus = bus;
        return 0;
}

const char *bus_error_message(const DBusError *error) {
        assert(error);

        /* Sometimes the D-Bus server is a little bit too verbose with
         * its error messages, so let's override them here */
        if (dbus_error_has_name(error, DBUS_ERROR_ACCESS_DENIED))
                return "Access denied";

        return error->message;
}

DBusHandlerResult bus_default_message_handler(
                DBusConnection *c,
                DBusMessage *message,
                const char *introspection,
                const char *interfaces,
                const BusProperty *properties) {

        DBusError error;
        DBusMessage *reply = NULL;
        int r;

        assert(c);
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
                        return bus_send_error_reply(c, message, &error, -EINVAL);

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

                        if ((r = p->append(&sub, property, (void*) p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(c, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&iter, &sub))
                                goto oom;
                } else {
                        if (!nulstr_contains(interfaces, interface))
                                dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                        else
                                dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");

                        return bus_send_error_reply(c, message, &error, -EINVAL);
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
                        return bus_send_error_reply(c, message, &error, -EINVAL);

                if (interface[0] && !nulstr_contains(interfaces, interface)) {
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                        return bus_send_error_reply(c, message, &error, -EINVAL);
                }

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

                        if ((r = p->append(&sub3, p->property, (void*) p->data)) < 0) {

                                if (r == -ENOMEM)
                                        goto oom;

                                dbus_message_unref(reply);
                                return bus_send_error_reply(c, message, NULL, r);
                        }

                        if (!dbus_message_iter_close_container(&sub2, &sub3) ||
                            !dbus_message_iter_close_container(&sub, &sub2))
                                goto oom;
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Set") && properties) {
                const char *interface, *property;
                DBusMessageIter iter;
                const BusProperty *p;

                if (!dbus_message_iter_init(message, &iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                        return bus_send_error_reply(c, message, NULL, -EINVAL);

                dbus_message_iter_get_basic(&iter, &interface);

                if (!dbus_message_iter_next(&iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
                        return bus_send_error_reply(c, message, NULL, -EINVAL);

                dbus_message_iter_get_basic(&iter, &property);

                if (!dbus_message_iter_next(&iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT ||
                    dbus_message_iter_has_next(&iter))
                        return bus_send_error_reply(c, message, NULL, -EINVAL);

                for (p = properties; p->property; p++)
                        if (streq(p->interface, interface) && streq(p->property, property))
                                break;

                if (p->set) {
                        DBusMessageIter sub;
                        char *sig;

                        dbus_message_iter_recurse(&iter, &sub);

                        if (!(sig = dbus_message_iter_get_signature(&sub)))
                                goto oom;

                        if (!streq(sig, p->signature)) {
                                dbus_free(sig);
                                return bus_send_error_reply(c, message, NULL, -EINVAL);
                        }

                        dbus_free(sig);

                        if ((r = p->set(&sub, property)) < 0) {
                                if (r == -ENOMEM)
                                        goto oom;
                                return bus_send_error_reply(c, message, NULL, r);
                        }

                        if (!(reply = dbus_message_new_method_return(message)))
                                goto oom;
                } else {
                        if (p->property)
                                dbus_set_error_const(&error, DBUS_ERROR_PROPERTY_READ_ONLY, "Property read-only");
                        else if (!nulstr_contains(interfaces, interface))
                                dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                        else
                                dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");

                        return bus_send_error_reply(c, message, &error, -EINVAL);
                }

        } else {
                const char *interface = dbus_message_get_interface(message);

                if (!interface || !nulstr_contains(interfaces, interface)) {
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                        return bus_send_error_reply(c, message, &error, -EINVAL);
                }
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

int bus_property_append_string(DBusMessageIter *i, const char *property, void *data) {
        const char *t = data;

        assert(i);
        assert(property);

        if (!t)
                t = "";

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_STRING, &t))
                return -ENOMEM;

        return 0;
}

int bus_property_append_strv(DBusMessageIter *i, const char *property, void *data) {
        DBusMessageIter sub;
        char **t = data;

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

int bus_property_append_bool(DBusMessageIter *i, const char *property, void *data) {
        bool *b = data;
        dbus_bool_t db;

        assert(i);
        assert(property);
        assert(b);

        db = *b;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &db))
                return -ENOMEM;

        return 0;
}

int bus_property_append_uint64(DBusMessageIter *i, const char *property, void *data) {
        assert(i);
        assert(property);
        assert(data);

        /* Let's ensure that usec_t is actually 64bit, and hence this
         * function can be used for usec_t */
        assert_cc(sizeof(uint64_t) == sizeof(usec_t));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_uint32(DBusMessageIter *i, const char *property, void *data) {
        assert(i);
        assert(property);
        assert(data);

        /* Let's ensure that pid_t, mode_t, uid_t, gid_t are actually
         * 32bit, and hence this function can be used for
         * pid_t/mode_t/uid_t/gid_t */
        assert_cc(sizeof(uint32_t) == sizeof(pid_t));
        assert_cc(sizeof(uint32_t) == sizeof(mode_t));
        assert_cc(sizeof(uint32_t) == sizeof(unsigned));
        assert_cc(sizeof(uint32_t) == sizeof(uid_t));
        assert_cc(sizeof(uint32_t) == sizeof(gid_t));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT32, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_int32(DBusMessageIter *i, const char *property, void *data) {
        assert(i);
        assert(property);
        assert(data);

        assert_cc(sizeof(int32_t) == sizeof(int));

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_INT32, data))
                return -ENOMEM;

        return 0;
}

int bus_property_append_size(DBusMessageIter *i, const char *property, void *data) {
        uint64_t u;

        assert(i);
        assert(property);
        assert(data);

        u = (uint64_t) *(size_t*) data;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

int bus_property_append_ul(DBusMessageIter *i, const char *property, void *data) {
        uint64_t u;

        assert(i);
        assert(property);
        assert(data);

        u = (uint64_t) *(unsigned long*) data;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_UINT64, &u))
                return -ENOMEM;

        return 0;
}

int bus_property_append_long(DBusMessageIter *i, const char *property, void *data) {
        int64_t l;

        assert(i);
        assert(property);
        assert(data);

        l = (int64_t) *(long*) data;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_INT64, &l))
                return -ENOMEM;

        return 0;
}

const char *bus_errno_to_dbus(int error) {

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
        case -ETIME:
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

DBusHandlerResult bus_send_error_reply(DBusConnection *c, DBusMessage *message, DBusError *berror, int error) {
        DBusMessage *reply = NULL;
        const char *name, *text;

        if (berror && dbus_error_is_set(berror)) {
                name = berror->name;
                text = berror->message;
        } else {
                name = bus_errno_to_dbus(error);
                text = strerror(-error);
        }

        if (!(reply = dbus_message_new_error(message, name, text)))
                goto oom;

        if (!dbus_connection_send(c, reply, NULL))
                goto oom;

        dbus_message_unref(reply);

        if (berror)
                dbus_error_free(berror);

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        if (berror)
                dbus_error_free(berror);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

DBusMessage* bus_properties_changed_new(const char *path, const char *interface, const char *properties) {
        DBusMessage *m;
        DBusMessageIter iter, sub;
        const char *i;

        assert(interface);
        assert(properties);

        if (!(m = dbus_message_new_signal(path, "org.freedesktop.DBus.Properties", "PropertiesChanged")))
                goto oom;

        dbus_message_iter_init_append(m, &iter);

        /* We won't send any property values, since they might be
         * large and sometimes not cheap to generated */

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub) ||
            !dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub))
                goto oom;

        NULSTR_FOREACH(i, properties)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &i))
                        goto oom;

        if (!dbus_message_iter_close_container(&iter, &sub))
                goto oom;

        return m;

oom:
        if (m)
                dbus_message_unref(m);

        return NULL;
}

uint32_t bus_flags_to_events(DBusWatch *bus_watch) {
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

unsigned bus_events_to_flags(uint32_t events) {
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
