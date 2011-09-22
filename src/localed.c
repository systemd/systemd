/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "strv.h"
#include "dbus-common.h"
#include "polkit.h"
#include "def.h"

#define INTERFACE                                                       \
        " <interface name=\"org.freedesktop.locale1\">\n"               \
        "  <property name=\"Locale\" type=\"as\" access=\"read\"/>\n"   \
        "  <method name=\"SetLocale\">\n"                               \
        "   <arg name=\"locale\" type=\"as\" direction=\"in\"/>\n"      \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        " </interface>\n"

#define INTROSPECTION                                                   \
        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE                       \
        "<node>\n"                                                      \
        INTERFACE                                                       \
        BUS_PROPERTIES_INTERFACE                                        \
        BUS_INTROSPECTABLE_INTERFACE                                    \
        BUS_PEER_INTERFACE                                              \
        "</node>\n"

#define INTERFACES_LIST                         \
        BUS_GENERIC_INTERFACES_LIST             \
        "org.freedesktop.locale1\0"

const char locale_interface[] _introspect_("locale1") = INTERFACE;

enum {
        /* We don't list LC_ALL here on purpose. People should be
         * using LANG instead. */

        PROP_LANG,
        PROP_LANGUAGE,
        PROP_LC_CTYPE,
        PROP_LC_NUMERIC,
        PROP_LC_TIME,
        PROP_LC_COLLATE,
        PROP_LC_MONETARY,
        PROP_LC_MESSAGES,
        PROP_LC_PAPER,
        PROP_LC_NAME,
        PROP_LC_ADDRESS,
        PROP_LC_TELEPHONE,
        PROP_LC_MEASUREMENT,
        PROP_LC_IDENTIFICATION,
        _PROP_MAX
};

static const char * const names[_PROP_MAX] = {
        [PROP_LANG] = "LANG",
        [PROP_LANGUAGE] = "LANGUAGE",
        [PROP_LC_CTYPE] = "LC_CTYPE",
        [PROP_LC_NUMERIC] = "LC_NUMERIC",
        [PROP_LC_TIME] = "LC_TIME",
        [PROP_LC_COLLATE] = "LC_COLLATE",
        [PROP_LC_MONETARY] = "LC_MONETARY",
        [PROP_LC_MESSAGES] = "LC_MESSAGES",
        [PROP_LC_PAPER] = "LC_PAPER",
        [PROP_LC_NAME] = "LC_NAME",
        [PROP_LC_ADDRESS] = "LC_ADDRESS",
        [PROP_LC_TELEPHONE] = "LC_TELEPHONE",
        [PROP_LC_MEASUREMENT] = "LC_MEASUREMENT",
        [PROP_LC_IDENTIFICATION] = "LC_IDENTIFICATION"
};

static char *data[_PROP_MAX] = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};

static usec_t remain_until = 0;

static void free_data(void) {
        int p;

        for (p = 0; p < _PROP_MAX; p++) {
                free(data[p]);
                data[p] = NULL;
        }
}

static void simplify(void) {
        int p;

        for (p = 1; p < _PROP_MAX; p++)
                if (isempty(data[p]) || streq_ptr(data[PROP_LANG], data[p])) {
                        free(data[p]);
                        data[p] = NULL;
                }
}

static int read_data(void) {
        int r;

        free_data();

        r = parse_env_file("/etc/locale.conf", NEWLINE,
                           "LANG",              &data[PROP_LANG],
                           "LANGUAGE",          &data[PROP_LANGUAGE],
                           "LC_CTYPE",          &data[PROP_LC_CTYPE],
                           "LC_NUMERIC",        &data[PROP_LC_NUMERIC],
                           "LC_TIME",           &data[PROP_LC_TIME],
                           "LC_COLLATE",        &data[PROP_LC_COLLATE],
                           "LC_MONETARY",       &data[PROP_LC_MONETARY],
                           "LC_MESSAGES",       &data[PROP_LC_MESSAGES],
                           "LC_PAPER",          &data[PROP_LC_PAPER],
                           "LC_NAME",           &data[PROP_LC_NAME],
                           "LC_ADDRESS",        &data[PROP_LC_ADDRESS],
                           "LC_TELEPHONE",      &data[PROP_LC_TELEPHONE],
                           "LC_MEASUREMENT",    &data[PROP_LC_MEASUREMENT],
                           "LC_IDENTIFICATION", &data[PROP_LC_IDENTIFICATION],
                           NULL);

        if (r == -ENOENT) {
                int p;

                /* Fill in what we got passed from systemd. */

                for (p = 0; p < _PROP_MAX; p++) {
                        char *e, *d;

                        assert(names[p]);

                        e = getenv(names[p]);
                        if (e) {
                                d = strdup(e);
                                if (!d)
                                        return -ENOMEM;
                        } else
                                d = NULL;

                        free(data[p]);
                        data[p] = d;
                }

                r = 0;
        }

        simplify();
        return r;
}

static int write_data(void) {
        int r, p;
        char **l = NULL;

        r = load_env_file("/etc/locale.conf", &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 0; p < _PROP_MAX; p++) {
                char *t, **u;

                assert(names[p]);

                if (isempty(data[p])) {
                        l = strv_env_unset(l, names[p]);
                        continue;
                }

                if (asprintf(&t, "%s=%s", names[p], data[p]) < 0) {
                        strv_free(l);
                        return -ENOMEM;
                }

                u = strv_env_set(l, t);
                free(t);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (strv_isempty(l)) {
                strv_free(l);

                if (unlink("/etc/locale.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file("/etc/locale.conf", l);
        strv_free(l);

        return r;
}

static void push_data(DBusConnection *bus) {
        char **l_set = NULL, **l_unset = NULL, **t;
        int c_set = 0, c_unset = 0, p;
        DBusError error;
        DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub;

        dbus_error_init(&error);

        assert(bus);

        l_set = new0(char*, _PROP_MAX);
        l_unset = new0(char*, _PROP_MAX);
        if (!l_set || !l_unset) {
                log_error("Out of memory");
                goto finish;
        }

        for (p = 0; p < _PROP_MAX; p++) {
                assert(names[p]);

                if (isempty(data[p]))
                        l_unset[c_set++] = (char*) names[p];
                else {
                        char *s;

                        if (asprintf(&s, "%s=%s", names[p], data[p]) < 0) {
                                log_error("Out of memory");
                                goto finish;
                        }

                        l_set[c_unset++] = s;
                }
        }

        assert(c_set + c_unset == _PROP_MAX);
        m = dbus_message_new_method_call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "UnsetAndSetEnvironment");
        if (!m) {
                log_error("Could not allocate message.");
                goto finish;
        }

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
                log_error("Out of memory.");
                goto finish;
        }

        STRV_FOREACH(t, l_unset)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, t)) {
                        log_error("Out of memory.");
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
                log_error("Out of memory.");
                goto finish;
        }

        STRV_FOREACH(t, l_set)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, t)) {
                        log_error("Out of memory.");
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub)) {
                log_error("Out of memory.");
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to set locale information: %s", bus_error_message(&error));
                goto finish;
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);

        strv_free(l_set);
        free(l_unset);
}

static int append_locale(DBusMessageIter *i, const char *property, void *userdata) {
        int r, c = 0, p;
        char **l;

        l = new0(char*, _PROP_MAX+1);
        if (!l)
                return -ENOMEM;

        for (p = 0; p < _PROP_MAX; p++) {
                char *t;

                if (isempty(data[p]))
                        continue;

                if (asprintf(&t, "%s=%s", names[p], data[p]) < 0) {
                        strv_free(l);
                        return -ENOMEM;
                }

                l[c++] = t;
        }

        r = bus_property_append_strv(i, property, (void*) l);
        strv_free(l);

        return r;
}

static DBusHandlerResult locale_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        const BusProperty properties[] = {
                { "org.freedesktop.locale1", "Locale", append_locale, "as", NULL},
                { NULL, NULL, NULL, NULL, NULL }
        };

        DBusMessage *reply = NULL, *changed = NULL;
        DBusError error;
        int r;

        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.locale1", "SetLocale")) {
                char **l = NULL, **i;
                dbus_bool_t interactive;
                DBusMessageIter iter;
                bool modified = false;
                bool passed[_PROP_MAX];
                int p;

                if (!dbus_message_iter_init(message, &iter))
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                r = bus_parse_strv_iter(&iter, &l);
                if (r < 0) {
                        if (r == -ENOMEM)
                                goto oom;

                        return bus_send_error_reply(connection, message, NULL, r);
                }

                if (!dbus_message_iter_next(&iter) ||
                    dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)  {
                        strv_free(l);
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);
                }

                dbus_message_iter_get_basic(&iter, &interactive);

                zero(passed);

                /* Check whether a variable changed and if so valid */
                STRV_FOREACH(i, l) {
                        bool valid = false;

                        for (p = 0; p < _PROP_MAX; p++) {
                                size_t k;

                                k = strlen(names[p]);
                                if (startswith(*i, names[p]) && (*i)[k] == '=') {
                                        valid = true;
                                        passed[p] = true;

                                        if (!streq_ptr(*i + k + 1, data[p]))
                                                modified = true;

                                        break;
                                }
                        }

                        if (!valid) {
                                strv_free(l);
                                return bus_send_error_reply(connection, message, NULL, -EINVAL);
                        }
                }

                /* Check whether a variable is unset */
                if (!modified)  {
                        for (p = 0; p < _PROP_MAX; p++)
                                if (!isempty(data[p]) && !passed[p]) {
                                        modified = true;
                                        break;
                                }
                }

                if (modified) {

                        r = verify_polkit(connection, message, "org.freedesktop.locale1.set-locale", interactive, &error);
                        if (r < 0) {
                                strv_free(l);
                                return bus_send_error_reply(connection, message, &error, r);
                        }

                        STRV_FOREACH(i, l) {
                                for (p = 0; p < _PROP_MAX; p++) {
                                        size_t k;

                                        k = strlen(names[p]);
                                        if (startswith(*i, names[p]) && (*i)[k] == '=') {
                                                char *t;

                                                t = strdup(*i + k + 1);
                                                if (!t) {
                                                        strv_free(l);
                                                        goto oom;
                                                }

                                                free(data[p]);
                                                data[p] = t;

                                                break;
                                        }
                                }
                        }

                        strv_free(l);

                        for (p = 0; p < _PROP_MAX; p++) {
                                if (passed[p])
                                        continue;

                                free(data[p]);
                                data[p] = NULL;
                        }

                        simplify();

                        r = write_data();
                        if (r < 0) {
                                log_error("Failed to set locale: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        push_data(connection);

                        log_info("Changed locale information.");

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/locale1",
                                        "org.freedesktop.locale1",
                                        "Locale\0");
                        if (!changed)
                                goto oom;
                }

        } else
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, properties);

        if (!(reply = dbus_message_new_method_return(message)))
                goto oom;

        if (!dbus_connection_send(connection, reply, NULL))
                goto oom;

        dbus_message_unref(reply);
        reply = NULL;

        if (changed) {

                if (!dbus_connection_send(connection, changed, NULL))
                        goto oom;

                dbus_message_unref(changed);
        }

        return DBUS_HANDLER_RESULT_HANDLED;

oom:
        if (reply)
                dbus_message_unref(reply);

        if (changed)
                dbus_message_unref(changed);

        dbus_error_free(&error);

        return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static int connect_bus(DBusConnection **_bus) {
        static const DBusObjectPathVTable locale_vtable = {
                .message_function = locale_message_handler
        };
        DBusError error;
        DBusConnection *bus = NULL;
        int r;

        assert(_bus);

        dbus_error_init(&error);

        bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        if (!bus) {
                log_error("Failed to get system D-Bus connection: %s", bus_error_message(&error));
                r = -ECONNREFUSED;
                goto fail;
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (!dbus_connection_register_object_path(bus, "/org/freedesktop/locale1", &locale_vtable, NULL) ||
            !dbus_connection_add_filter(bus, bus_exit_idle_filter, &remain_until, NULL)) {
                log_error("Not enough memory");
                r = -ENOMEM;
                goto fail;
        }

        r = dbus_bus_request_name(bus, "org.freedesktop.locale1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EEXIST;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
                log_error("Failed to acquire name.");
                r = -EEXIST;
                goto fail;
        }

        if (_bus)
                *_bus = bus;

        return 0;

fail:
        dbus_connection_close(bus);
        dbus_connection_unref(bus);

        dbus_error_free(&error);

        return r;
}

int main(int argc, char *argv[]) {
        int r;
        DBusConnection *bus = NULL;
        bool exiting = false;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc == 2 && streq(argv[1], "--introspect")) {
                fputs(DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
                      "<node>\n", stdout);
                fputs(locale_interface, stdout);
                fputs("</node>\n", stdout);
                return 0;
        }

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = read_data();
        if (r < 0) {
                log_error("Failed to read locale data: %s", strerror(-r));
                goto finish;
        }

        r = connect_bus(&bus);
        if (r < 0)
                goto finish;

        remain_until = now(CLOCK_MONOTONIC) + DEFAULT_EXIT_USEC;
        for (;;) {

                if (!dbus_connection_read_write_dispatch(bus, exiting ? -1 : (int) (DEFAULT_EXIT_USEC/USEC_PER_MSEC)))
                        break;

                if (!exiting && remain_until < now(CLOCK_MONOTONIC)) {
                        exiting = true;
                        bus_async_unregister_and_exit(bus, "org.freedesktop.locale1");
                }
        }

        r = 0;

finish:
        free_data();

        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
