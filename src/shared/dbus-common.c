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
#include "missing.h"
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

        if (ucred.uid != 0 && ucred.uid != geteuid())
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

int bus_connect(DBusBusType t, DBusConnection **_bus, bool *_private, DBusError *error) {
        DBusConnection *bus = NULL;
        int r;
        bool private = true;

        assert(_bus);

        if (geteuid() == 0 && t == DBUS_BUS_SYSTEM) {
                /* If we are root, then let's talk directly to the
                 * system instance, instead of going via the bus */

                bus = dbus_connection_open_private("unix:path=/run/systemd/private", error);
                if (!bus)
                        return -EIO;

        } else {
                if (t == DBUS_BUS_SESSION) {
                        const char *e;

                        /* If we are supposed to talk to the instance,
                         * try via XDG_RUNTIME_DIR first, then
                         * fallback to normal bus access */

                        e = secure_getenv("XDG_RUNTIME_DIR");
                        if (e) {
                                char *p;

                                if (asprintf(&p, "unix:path=%s/systemd/private", e) < 0)
                                        return -ENOMEM;

                                bus = dbus_connection_open_private(p, NULL);
                                free(p);
                        }
                }

                if (!bus) {
                        bus = dbus_bus_get_private(t, error);
                        if (!bus)
                                return -EIO;

                        private = false;
                }
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (private) {
                if (bus_check_peercred(bus) < 0) {
                        dbus_connection_close(bus);
                        dbus_connection_unref(bus);

                        dbus_set_error_const(error, DBUS_ERROR_ACCESS_DENIED, "Failed to verify owner of bus.");
                        return -EACCES;
                }
        }

        r = sync_auth(bus, error);
        if (r < 0) {
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
                return r;
        }

        if (_private)
                *_private = private;

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
                asprintf(&p, "unixexec:path=ssh,argv1=-xT,argv2=%s%%40%s,argv3=systemd-stdio-bridge", user, host);
        else if (user)
                asprintf(&p, "unixexec:path=ssh,argv1=-xT,argv2=%s%%40localhost,argv3=systemd-stdio-bridge", user);
        else if (host)
                asprintf(&p, "unixexec:path=ssh,argv1=-xT,argv2=%s,argv3=systemd-stdio-bridge", host);

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

        bus = dbus_connection_open_private("unixexec:path=pkexec,argv1=" SYSTEMD_STDIO_BRIDGE_BINARY_PATH, error);
        if (!bus)
                return -EIO;

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        r = sync_auth(bus, error);
        if (r < 0) {
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
        if (!error)
                return NULL;

        /* Sometimes the D-Bus server is a little bit too verbose with
         * its error messages, so let's override them here */
        if (dbus_error_has_name(error, DBUS_ERROR_ACCESS_DENIED))
                return "Access denied";

        return error->message;
}

const char *bus_error(const DBusError *error, int err) {
        if (error && dbus_error_is_set(error))
                return bus_error_message(error);

        return strerror(err < 0 ? -err : err);
}

DBusHandlerResult bus_default_message_handler(
                DBusConnection *c,
                DBusMessage *message,
                const char *introspection,
                const char *interfaces,
                const BusBoundProperties *bound_properties) {

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;

        assert(c);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Introspectable", "Introspect") && introspection) {

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection, DBUS_TYPE_INVALID))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Get") && bound_properties) {
                const char *interface, *property;
                const BusBoundProperties *bp;
                const BusProperty *p;
                void *data;
                DBusMessageIter iter, sub;

                if (!dbus_message_get_args(
                            message,
                            &error,
                            DBUS_TYPE_STRING, &interface,
                            DBUS_TYPE_STRING, &property,
                            DBUS_TYPE_INVALID))
                        return bus_send_error_reply(c, message, &error, -EINVAL);

                for (bp = bound_properties; bp->interface; bp++) {
                        if (!streq(bp->interface, interface))
                                continue;

                        for (p = bp->properties; p->property; p++)
                                if (streq(p->property, property))
                                        goto get_prop;
                }

                /* no match */
                if (!nulstr_contains(interfaces, interface))
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                else
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");

                return bus_send_error_reply(c, message, &error, -EINVAL);

get_prop:
                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, p->signature, &sub))
                        goto oom;

                data = (char*)bp->base + p->offset;
                if (p->indirect)
                        data = *(void**)data;

                r = p->append(&sub, property, data);
                if (r == -ENOMEM)
                        goto oom;
                if (r < 0)
                        return bus_send_error_reply(c, message, NULL, r);

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "GetAll") && bound_properties) {
                const char *interface;
                const BusBoundProperties *bp;
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

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                dbus_message_iter_init_append(reply, &iter);

                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub))
                        goto oom;

                for (bp = bound_properties; bp->interface; bp++) {
                        if (interface[0] && !streq(bp->interface, interface))
                                continue;

                        for (p = bp->properties; p->property; p++) {
                                void *data;

                                if (!dbus_message_iter_open_container(&sub, DBUS_TYPE_DICT_ENTRY, NULL, &sub2) ||
                                    !dbus_message_iter_append_basic(&sub2, DBUS_TYPE_STRING, &p->property) ||
                                    !dbus_message_iter_open_container(&sub2, DBUS_TYPE_VARIANT, p->signature, &sub3))
                                        goto oom;

                                data = (char*)bp->base + p->offset;
                                if (p->indirect)
                                        data = *(void**)data;
                                r = p->append(&sub3, p->property, data);
                                if (r == -ENOMEM)
                                        goto oom;
                                if (r < 0)
                                        return bus_send_error_reply(c, message, NULL, r);

                                if (!dbus_message_iter_close_container(&sub2, &sub3) ||
                                    !dbus_message_iter_close_container(&sub, &sub2))
                                        goto oom;
                        }
                }

                if (!dbus_message_iter_close_container(&iter, &sub))
                        goto oom;

        } else if (dbus_message_is_method_call(message, "org.freedesktop.DBus.Properties", "Set") && bound_properties) {
                const char *interface, *property;
                DBusMessageIter iter;
                const BusBoundProperties *bp;
                const BusProperty *p;
                DBusMessageIter sub;
                char *sig;
                void *data;
                DBusMessage *changed;

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

                for (bp = bound_properties; bp->interface; bp++) {
                        if (!streq(bp->interface, interface))
                                continue;

                        for (p = bp->properties; p->property; p++)
                                if (streq(p->property, property))
                                        goto set_prop;
                }

                /* no match */
                if (!nulstr_contains(interfaces, interface))
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                else
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");

                return bus_send_error_reply(c, message, &error, -EINVAL);

set_prop:
                if (!p->set) {
                        dbus_set_error_const(&error, DBUS_ERROR_PROPERTY_READ_ONLY, "Property read-only");
                        return bus_send_error_reply(c, message, &error, -EINVAL);
                }

                dbus_message_iter_recurse(&iter, &sub);

                sig = dbus_message_iter_get_signature(&sub);
                if (!sig)
                        goto oom;

                if (!streq(sig, p->signature)) {
                        dbus_free(sig);
                        return bus_send_error_reply(c, message, NULL, -EINVAL);
                }
                dbus_free(sig);

                data = (uint8_t*) bp->base + p->offset;
                if (p->indirect)
                        data = *(void**)data;

                r = p->set(&sub, property, data);
                if (r == -ENOMEM)
                        goto oom;
                else if (r < 0)
                        return bus_send_error_reply(c, message, NULL, r);

                reply = dbus_message_new_method_return(message);
                if (!reply)
                        goto oom;

                /* Send out a signal about this, but it doesn't really
                 * matter if this fails, so eat all errors */
                changed = bus_properties_changed_one_new(
                                dbus_message_get_path(message),
                                interface,
                                property);
                if (changed) {
                        dbus_connection_send(c, changed, NULL);
                        dbus_message_unref(changed);
                }


        } else {
                const char *interface = dbus_message_get_interface(message);

                if (!interface || !nulstr_contains(interfaces, interface)) {
                        dbus_set_error_const(&error, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
                        return bus_send_error_reply(c, message, &error, -EINVAL);
                }
        }

        if (reply) {
                if (!bus_maybe_send_reply(c, message, reply))
                        goto oom;

                return DBUS_HANDLER_RESULT_HANDLED;
        }

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

oom:
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
        char **t = data;

        assert(i);
        assert(property);

        return bus_append_strv_iter(i, t);
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

int bus_property_append_tristate_false(DBusMessageIter *i, const char *property, void *data) {
        int *b = data;
        dbus_bool_t db;

        assert(i);
        assert(property);
        assert(b);

        db = *b > 0;

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

int bus_property_set_uint64(DBusMessageIter *i, const char *property, void *data) {
        uint64_t *t = data;

        assert(i);
        assert(property);

        dbus_message_iter_get_basic(i, t);
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

dbus_bool_t bus_maybe_send_reply (DBusConnection   *c,
                                  DBusMessage *message,
                                  DBusMessage *reply)
{
        /* Some parts of systemd "reply" to signals, which of course
         * have the no-reply flag set.  We will be defensive here and
         * still send out a reply if we're passed a signal.
         */
        if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL &&
            dbus_message_get_no_reply(message))
                return TRUE;
        return dbus_connection_send(c, reply, NULL);
}

DBusHandlerResult bus_send_error_reply(DBusConnection *c, DBusMessage *message, DBusError *berror, int error) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *name, *text;

        if (berror && dbus_error_is_set(berror)) {
                name = berror->name;
                text = berror->message;
        } else {
                name = bus_errno_to_dbus(error);
                text = strerror(-error);
        }

        reply = dbus_message_new_error(message, name, text);
        if (!reply)
                goto oom;

        if (!bus_maybe_send_reply(c, message, reply))
                goto oom;

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

        m = dbus_message_new_signal(path, "org.freedesktop.DBus.Properties", "PropertiesChanged");
        if (!m)
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

DBusMessage* bus_properties_changed_one_new(const char *path, const char *interface, const char *property) {
        DBusMessage *m;
        DBusMessageIter iter, sub;

        assert(interface);
        assert(property);

        m = dbus_message_new_signal(path, "org.freedesktop.DBus.Properties", "PropertiesChanged");
        if (!m)
                goto oom;

        dbus_message_iter_init_append(m, &iter);

        /* We won't send any property values, since they might be
         * large and sometimes not cheap to generated */

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &sub) ||
            !dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub))
                goto oom;

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &property))
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

int bus_parse_strv(DBusMessage *m, char ***_l) {
        DBusMessageIter iter;

        assert(m);
        assert(_l);

        if (!dbus_message_iter_init(m, &iter))
                return -EINVAL;

        return bus_parse_strv_iter(&iter, _l);
}

int bus_parse_strv_iter(DBusMessageIter *iter, char ***_l) {
        DBusMessageIter sub;
        unsigned n = 0, i = 0;
        char **l;

        assert(iter);
        assert(_l);

        if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(iter) != DBUS_TYPE_STRING)
            return -EINVAL;

        dbus_message_iter_recurse(iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                n++;
                dbus_message_iter_next(&sub);
        }

        l = new(char*, n+1);
        if (!l)
                return -ENOMEM;

        dbus_message_iter_recurse(iter, &sub);

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

int bus_parse_strv_pairs_iter(DBusMessageIter *iter, char ***_l) {
        DBusMessageIter sub, sub2;
        unsigned n = 0, i = 0;
        char **l;

        assert(iter);
        assert(_l);

        if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(iter) != DBUS_TYPE_STRUCT)
            return -EINVAL;

        dbus_message_iter_recurse(iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                n++;
                dbus_message_iter_next(&sub);
        }

        l = new(char*, n*2+1);
        if (!l)
                return -ENOMEM;

        dbus_message_iter_recurse(iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *a, *b;

                assert_se(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRUCT);

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &a, true) < 0 ||
                    bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &b, false) < 0)
                        return -EINVAL;

                l[i] = strdup(a);
                if (!l[i]) {
                        strv_free(l);
                        return -ENOMEM;
                }

                l[++i] = strdup(b);
                if (!l[i]) {
                        strv_free(l);
                        return -ENOMEM;
                }

                i++;
                dbus_message_iter_next(&sub);
        }

        assert(i == n*2);
        l[i] = NULL;

        if (_l)
                *_l = l;

        return 0;
}

int bus_parse_unit_info(DBusMessageIter *iter, struct unit_info *u) {
        DBusMessageIter sub;

        assert(iter);
        assert(u);

        if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRUCT)
                return -EINVAL;

        dbus_message_iter_recurse(iter, &sub);

        if (bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->id, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->description, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->load_state, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->active_state, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->sub_state, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->following, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_OBJECT_PATH, &u->unit_path, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_UINT32, &u->job_id, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_STRING, &u->job_type, true) < 0 ||
            bus_iter_get_basic_and_next(&sub, DBUS_TYPE_OBJECT_PATH, &u->job_path, false) < 0) {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        return 0;
}

int bus_append_strv_iter(DBusMessageIter *iter, char **l) {
        DBusMessageIter sub;

        assert(iter);

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "s", &sub))
                return -ENOMEM;

        STRV_FOREACH(l, l)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, l))
                        return -ENOMEM;

        if (!dbus_message_iter_close_container(iter, &sub))
                return -ENOMEM;

        return 0;
}

int bus_iter_get_basic_and_next(DBusMessageIter *iter, int type, void *data, bool next) {

        assert(iter);
        assert(data);

        if (dbus_message_iter_get_arg_type(iter) != type)
                return -EIO;

        dbus_message_iter_get_basic(iter, data);

        if (!dbus_message_iter_next(iter) != !next)
                return -EIO;

        return 0;
}

int generic_print_property(const char *name, DBusMessageIter *iter, bool all) {
        assert(name);
        assert(iter);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;
                dbus_message_iter_get_basic(iter, &s);

                if (all || !isempty(s))
                        printf("%s=%s\n", name, s);

                return 1;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;

                dbus_message_iter_get_basic(iter, &b);
                printf("%s=%s\n", name, yes_no(b));

                return 1;
        }

        case DBUS_TYPE_UINT64: {
                uint64_t u;
                dbus_message_iter_get_basic(iter, &u);

                /* Yes, heuristics! But we can change this check
                 * should it turn out to not be sufficient */

                if (endswith(name, "Timestamp")) {
                        char timestamp[FORMAT_TIMESTAMP_MAX], *t;

                        t = format_timestamp(timestamp, sizeof(timestamp), u);
                        if (t || all)
                                printf("%s=%s\n", name, strempty(t));

                } else if (strstr(name, "USec")) {
                        char timespan[FORMAT_TIMESPAN_MAX];

                        printf("%s=%s\n", name, format_timespan(timespan, sizeof(timespan), u, 0));
                } else
                        printf("%s=%llu\n", name, (unsigned long long) u);

                return 1;
        }

        case DBUS_TYPE_UINT32: {
                uint32_t u;
                dbus_message_iter_get_basic(iter, &u);

                if (strstr(name, "UMask") || strstr(name, "Mode"))
                        printf("%s=%04o\n", name, u);
                else
                        printf("%s=%u\n", name, (unsigned) u);

                return 1;
        }

        case DBUS_TYPE_INT32: {
                int32_t i;
                dbus_message_iter_get_basic(iter, &i);

                printf("%s=%i\n", name, (int) i);
                return 1;
        }

        case DBUS_TYPE_DOUBLE: {
                double d;
                dbus_message_iter_get_basic(iter, &d);

                printf("%s=%g\n", name, d);
                return 1;
        }

        case DBUS_TYPE_ARRAY:

                if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING) {
                        DBusMessageIter sub;
                        bool space = false;

                        dbus_message_iter_recurse(iter, &sub);
                        if (all ||
                            dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                printf("%s=", name);

                                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                        const char *s;

                                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                                        dbus_message_iter_get_basic(&sub, &s);
                                        printf("%s%s", space ? " " : "", s);

                                        space = true;
                                        dbus_message_iter_next(&sub);
                                }

                                puts("");
                        }

                        return 1;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_BYTE) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        if (all ||
                            dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                printf("%s=", name);

                                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                        uint8_t u;

                                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_BYTE);
                                        dbus_message_iter_get_basic(&sub, &u);
                                        printf("%02x", u);

                                        dbus_message_iter_next(&sub);
                                }

                                puts("");
                        }

                        return 1;

                } else if (dbus_message_iter_get_element_type(iter) == DBUS_TYPE_UINT32) {
                        DBusMessageIter sub;

                        dbus_message_iter_recurse(iter, &sub);
                        if (all ||
                            dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                printf("%s=", name);

                                while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                                        uint32_t u;

                                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_UINT32);
                                        dbus_message_iter_get_basic(&sub, &u);
                                        printf("%08x", u);

                                        dbus_message_iter_next(&sub);
                                }

                                puts("");
                        }

                        return 1;
                }

                break;
        }

        return 0;
}

static void release_name_pending_cb(DBusPendingCall *pending, void *userdata) {
        DBusMessage *reply;
        DBusConnection *bus = userdata;

        assert_se(reply = dbus_pending_call_steal_reply(pending));
        dbus_message_unref(reply);

        dbus_connection_close(bus);
}

void bus_async_unregister_and_exit(DBusConnection *bus, const char *name) {
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        DBusPendingCall *pending = NULL;

        assert(bus);

        /* We unregister the name here, but we continue to process
         * requests, until we get the response for it, so that all
         * requests are guaranteed to be processed. */

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "ReleaseName");
        if (!m)
                goto oom;

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING,
                            &name,
                            DBUS_TYPE_INVALID))
                goto oom;

        if (!dbus_connection_send_with_reply(bus, m, &pending, -1))
                goto oom;

        if (!dbus_pending_call_set_notify(pending, release_name_pending_cb, bus, NULL))
                goto oom;

        dbus_pending_call_unref(pending);

        return;

oom:
        log_oom();

        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }
}

DBusHandlerResult bus_exit_idle_filter(DBusConnection *bus, DBusMessage *m, void *userdata) {
        usec_t *remain_until = userdata;

        assert(bus);
        assert(m);
        assert(remain_until);

        /* Every time we get a new message we reset out timeout */
        *remain_until = now(CLOCK_MONOTONIC) + DEFAULT_EXIT_USEC;

        if (dbus_message_is_signal(m, DBUS_INTERFACE_LOCAL, "Disconnected"))
                dbus_connection_close(bus);

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* This mimics dbus_bus_get_unix_user() */
pid_t bus_get_unix_process_id(
                DBusConnection *connection,
                const char *name,
                DBusError *error) {

        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        uint32_t pid = 0;

        m = dbus_message_new_method_call(
                        DBUS_SERVICE_DBUS,
                        DBUS_PATH_DBUS,
                        DBUS_INTERFACE_DBUS,
                        "GetConnectionUnixProcessID");
        if (!m) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return 0;
        }

        if (!dbus_message_append_args(
                            m,
                            DBUS_TYPE_STRING, &name,
                            DBUS_TYPE_INVALID)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, NULL);
                return 0;
        }

        reply = dbus_connection_send_with_reply_and_block(connection, m, -1, error);
        if (!reply)
                return 0;

        if (dbus_set_error_from_message(error, reply))
                return 0;

        if (!dbus_message_get_args(
                            reply, error,
                            DBUS_TYPE_UINT32, &pid,
                            DBUS_TYPE_INVALID))
                return 0;

        return (pid_t) pid;
}

bool bus_error_is_no_service(const DBusError *error) {
        assert(error);

        if (!dbus_error_is_set(error))
                return false;

        if (dbus_error_has_name(error, DBUS_ERROR_NAME_HAS_NO_OWNER))
                return true;

        if (dbus_error_has_name(error, DBUS_ERROR_SERVICE_UNKNOWN))
                return true;

        return startswith(error->name, "org.freedesktop.DBus.Error.Spawn.");
}

int bus_method_call_with_reply(
                DBusConnection *bus,
                const char *destination,
                const char *path,
                const char *interface,
                const char *method,
                DBusMessage **return_reply,
                DBusError *return_error,
                int first_arg_type, ...) {

        DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL;
        DBusMessage *reply;
        va_list ap;
        int r = 0;

        dbus_error_init(&error);
        assert(bus);

        m = dbus_message_new_method_call(destination, path, interface, method);
        if (!m) {
                r = log_oom();
                goto finish;
        }

        va_start(ap, first_arg_type);
        if (!dbus_message_append_args_valist(m, first_arg_type, ap)) {
                va_end(ap);
                r = log_oom();
                goto finish;
        }
        va_end(ap);

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                if (!return_error)
                        log_error("Failed to issue method call: %s", bus_error_message(&error));

                if (bus_error_is_no_service(&error))
                        r = -ENOENT;
                else if (dbus_error_has_name(&error, DBUS_ERROR_ACCESS_DENIED))
                        r = -EACCES;
                else if (dbus_error_has_name(&error, DBUS_ERROR_NO_REPLY))
                        r = -ETIMEDOUT;
                else if (dbus_error_has_name(&error, DBUS_ERROR_DISCONNECTED))
                        r = -ECONNRESET;
                else
                        r = -EIO;
                goto finish;
        }

        if (return_reply)
                *return_reply = reply;
        else
                dbus_message_unref(reply);

finish:
        if (return_error)
                *return_error = error;
        else
                dbus_error_free(&error);

        return r;
}

void bus_message_unrefp(DBusMessage **reply) {
        if (!reply)
                return;

        if (!*reply)
                return;

        dbus_message_unref(*reply);
}

const char *bus_message_get_sender_with_fallback(DBusMessage *m) {
        const char *s;

        assert(m);

        s = dbus_message_get_sender(m);
        if (s)
                return s;

        /* When the message came in from a direct connection the
         * message will have no sender. We fix that here. */

        return ":no-sender";
}
