/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <dbus/dbus.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "mkdir.h"
#include "strv.h"
#include "dbus-common.h"
#include "polkit.h"
#include "def.h"
#include "env-util.h"
#include "fileio.h"
#include "fileio-label.h"
#include "label.h"

#define INTERFACE                                                       \
        " <interface name=\"org.freedesktop.locale1\">\n"               \
        "  <property name=\"Locale\" type=\"as\" access=\"read\"/>\n"   \
        "  <property name=\"VConsoleKeymap\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"VConsoleKeymapToggle\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"X11Layout\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"X11Model\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"X11Variant\" type=\"s\" access=\"read\"/>\n" \
        "  <property name=\"X11Options\" type=\"s\" access=\"read\"/>\n" \
        "  <method name=\"SetLocale\">\n"                               \
        "   <arg name=\"locale\" type=\"as\" direction=\"in\"/>\n"      \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetVConsoleKeyboard\">\n"                      \
        "   <arg name=\"keymap\" type=\"s\" direction=\"in\"/>\n"       \
        "   <arg name=\"keymap_toggle\" type=\"s\" direction=\"in\"/>\n" \
        "   <arg name=\"convert\" type=\"b\" direction=\"in\"/>\n"      \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetX11Keyboard\">\n"                          \
        "   <arg name=\"layout\" type=\"s\" direction=\"in\"/>\n"       \
        "   <arg name=\"model\" type=\"s\" direction=\"in\"/>\n"        \
        "   <arg name=\"variant\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"options\" type=\"s\" direction=\"in\"/>\n"      \
        "   <arg name=\"convert\" type=\"b\" direction=\"in\"/>\n"      \
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

static char *data[_PROP_MAX] = {};

typedef struct State {
        char *x11_layout, *x11_model, *x11_variant, *x11_options;
        char *vc_keymap, *vc_keymap_toggle;
} State;

static State state;

static usec_t remain_until = 0;

static int free_and_set(char **s, const char *v) {
        int r;
        char *t;

        assert(s);

        r = strdup_or_null(isempty(v) ? NULL : v, &t);
        if (r < 0)
                return r;

        free(*s);
        *s = t;

        return 0;
}

static void free_data_locale(void) {
        int p;

        for (p = 0; p < _PROP_MAX; p++) {
                free(data[p]);
                data[p] = NULL;
        }
}

static void free_data_x11(void) {
        free(state.x11_layout);
        free(state.x11_model);
        free(state.x11_variant);
        free(state.x11_options);

        state.x11_layout = state.x11_model = state.x11_variant = state.x11_options = NULL;
}

static void free_data_vconsole(void) {
        free(state.vc_keymap);
        free(state.vc_keymap_toggle);

        state.vc_keymap = state.vc_keymap_toggle = NULL;
}

static void simplify(void) {
        int p;

        for (p = 1; p < _PROP_MAX; p++)
                if (isempty(data[p]) || streq_ptr(data[PROP_LANG], data[p])) {
                        free(data[p]);
                        data[p] = NULL;
                }
}

static int read_data_locale(void) {
        int r;

        free_data_locale();

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

static void free_data(void) {
        free_data_locale();
        free_data_vconsole();
        free_data_x11();
}

static int read_data_vconsole(void) {
        int r;

        free_data_vconsole();

        r = parse_env_file("/etc/vconsole.conf", NEWLINE,
                           "KEYMAP",        &state.vc_keymap,
                           "KEYMAP_TOGGLE", &state.vc_keymap_toggle,
                           NULL);

        if (r < 0 && r != -ENOENT)
                return r;

        return 0;
}

static int read_data_x11(void) {
        FILE *f;
        char line[LINE_MAX];
        bool in_section = false;

        free_data_x11();

        f = fopen("/etc/X11/xorg.conf.d/00-keyboard.conf", "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        while (fgets(line, sizeof(line), f)) {
                char *l;

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0 || l[0] == '#')
                        continue;

                if (in_section && first_word(l, "Option")) {
                        char **a;

                        a = strv_split_quoted(l);
                        if (!a) {
                                fclose(f);
                                return -ENOMEM;
                        }

                        if (strv_length(a) == 3) {

                                if (streq(a[1], "XkbLayout")) {
                                        free(state.x11_layout);
                                        state.x11_layout = a[2];
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbModel")) {
                                        free(state.x11_model);
                                        state.x11_model = a[2];
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbVariant")) {
                                        free(state.x11_variant);
                                        state.x11_variant = a[2];
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbOptions")) {
                                        free(state.x11_options);
                                        state.x11_options = a[2];
                                        a[2] = NULL;
                                }
                        }

                        strv_free(a);

                } else if (!in_section && first_word(l, "Section")) {
                        char **a;

                        a = strv_split_quoted(l);
                        if (!a) {
                                fclose(f);
                                return -ENOMEM;
                        }

                        if (strv_length(a) == 2 && streq(a[1], "InputClass"))
                                in_section = true;

                        strv_free(a);
                } else if (in_section && first_word(l, "EndSection"))
                        in_section = false;
        }

        fclose(f);

        return 0;
}

static int read_data(void) {
        int r, q, p;

        r = read_data_locale();
        q = read_data_vconsole();
        p = read_data_x11();

        return r < 0 ? r : q < 0 ? q : p;
}

static int write_data_locale(void) {
        int r, p;
        char **l = NULL;

        r = load_env_file("/etc/locale.conf", NULL, &l);
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

        r = write_env_file_label("/etc/locale.conf", l);
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
                log_oom();
                goto finish;
        }

        for (p = 0; p < _PROP_MAX; p++) {
                assert(names[p]);

                if (isempty(data[p]))
                        l_unset[c_set++] = (char*) names[p];
                else {
                        char *s;

                        if (asprintf(&s, "%s=%s", names[p], data[p]) < 0) {
                                log_oom();
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
                log_oom();
                goto finish;
        }

        STRV_FOREACH(t, l_unset)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, t)) {
                        log_oom();
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
                log_oom();
                goto finish;
        }

        STRV_FOREACH(t, l_set)
                if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, t)) {
                        log_oom();
                        goto finish;
                }

        if (!dbus_message_iter_close_container(&iter, &sub)) {
                log_oom();
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

static int write_data_vconsole(void) {
        int r;
        char **l = NULL;

        r = load_env_file("/etc/vconsole.conf", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        if (isempty(state.vc_keymap))
                l = strv_env_unset(l, "KEYMAP");
        else {
                char *s, **u;

                s = strappend("KEYMAP=", state.vc_keymap);
                if (!s) {
                        strv_free(l);
                        return -ENOMEM;
                }

                u = strv_env_set(l, s);
                free(s);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (isempty(state.vc_keymap_toggle))
                l = strv_env_unset(l, "KEYMAP_TOGGLE");
        else  {
                char *s, **u;

                s = strappend("KEYMAP_TOGGLE=", state.vc_keymap_toggle);
                if (!s) {
                        strv_free(l);
                        return -ENOMEM;
                }

                u = strv_env_set(l, s);
                free(s);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (strv_isempty(l)) {
                strv_free(l);

                if (unlink("/etc/vconsole.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file_label("/etc/vconsole.conf", l);
        strv_free(l);

        return r;
}

static int write_data_x11(void) {
        FILE *f;
        char *temp_path;
        int r;

        if (isempty(state.x11_layout) &&
            isempty(state.x11_model) &&
            isempty(state.x11_variant) &&
            isempty(state.x11_options)) {

                if (unlink("/etc/X11/xorg.conf.d/00-keyboard.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        mkdir_p_label("/etc/X11/xorg.conf.d", 0755);

        r = fopen_temporary("/etc/X11/xorg.conf.d/00-keyboard.conf", &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        fputs("# Read and parsed by systemd-localed. It's probably wise not to edit this file\n"
              "# manually too freely.\n"
              "Section \"InputClass\"\n"
              "        Identifier \"system-keyboard\"\n"
              "        MatchIsKeyboard \"on\"\n", f);

        if (!isempty(state.x11_layout))
                fprintf(f, "        Option \"XkbLayout\" \"%s\"\n", state.x11_layout);

        if (!isempty(state.x11_model))
                fprintf(f, "        Option \"XkbModel\" \"%s\"\n", state.x11_model);

        if (!isempty(state.x11_variant))
                fprintf(f, "        Option \"XkbVariant\" \"%s\"\n", state.x11_variant);

        if (!isempty(state.x11_options))
                fprintf(f, "        Option \"XkbOptions\" \"%s\"\n", state.x11_options);

        fputs("EndSection\n", f);
        fflush(f);

        if (ferror(f) || rename(temp_path, "/etc/X11/xorg.conf.d/00-keyboard.conf") < 0) {
                r = -errno;
                unlink("/etc/X11/xorg.conf.d/00-keyboard.conf");
                unlink(temp_path);
        } else
                r = 0;

        fclose(f);
        free(temp_path);

        return r;
}

static int load_vconsole_keymap(DBusConnection *bus, DBusError *error) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *name = "systemd-vconsole-setup.service", *mode = "replace";
        int r;
        DBusError _error;

        assert(bus);

        if (!error) {
                dbus_error_init(&_error);
                error = &_error;
        }

        m = dbus_message_new_method_call(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "RestartUnit");
        if (!m) {
                log_error("Could not allocate message.");
                r = -ENOMEM;
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &name,
                                      DBUS_TYPE_STRING, &mode,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not append arguments to message.");
                r = -ENOMEM;
                goto finish;
        }

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(error));
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        if (error == &_error)
                dbus_error_free(error);

        return r;
}

static char *strnulldash(const char *s) {
        return s == NULL || *s == 0 || (s[0] == '-' && s[1] == 0) ? NULL : (char*) s;
}

static int read_next_mapping(FILE *f, unsigned *n, char ***a) {
        assert(f);
        assert(n);
        assert(a);

        for (;;) {
                char line[LINE_MAX];
                char *l, **b;

                errno = 0;
                if (!fgets(line, sizeof(line), f)) {

                        if (ferror(f))
                                return errno ? -errno : -EIO;

                        return 0;
                }

                (*n) ++;

                l = strstrip(line);
                if (l[0] == 0 || l[0] == '#')
                        continue;

                b = strv_split_quoted(l);
                if (!b)
                        return -ENOMEM;

                if (strv_length(b) < 5) {
                        log_error("Invalid line "SYSTEMD_KBD_MODEL_MAP":%u, ignoring.", *n);
                        strv_free(b);
                        continue;

                }

                *a = b;
                return 1;
        }
}

static int convert_vconsole_to_x11(DBusConnection *connection) {
        bool modified = false;

        assert(connection);

        if (isempty(state.vc_keymap)) {

                modified =
                        !isempty(state.x11_layout) ||
                        !isempty(state.x11_model) ||
                        !isempty(state.x11_variant) ||
                        !isempty(state.x11_options);

                free_data_x11();
        } else {
                FILE *f;
                unsigned n = 0;

                f = fopen(SYSTEMD_KBD_MODEL_MAP, "re");
                if (!f)
                        return -errno;

                for (;;) {
                        char **a;
                        int r;

                        r = read_next_mapping(f, &n, &a);
                        if (r < 0) {
                                fclose(f);
                                return r;
                        }

                        if (r == 0)
                                break;

                        if (!streq(state.vc_keymap, a[0])) {
                                strv_free(a);
                                continue;
                        }

                        if (!streq_ptr(state.x11_layout, strnulldash(a[1])) ||
                            !streq_ptr(state.x11_model, strnulldash(a[2])) ||
                            !streq_ptr(state.x11_variant, strnulldash(a[3])) ||
                            !streq_ptr(state.x11_options, strnulldash(a[4]))) {

                                if (free_and_set(&state.x11_layout, strnulldash(a[1])) < 0 ||
                                    free_and_set(&state.x11_model, strnulldash(a[2])) < 0 ||
                                    free_and_set(&state.x11_variant, strnulldash(a[3])) < 0 ||
                                    free_and_set(&state.x11_options, strnulldash(a[4])) < 0) {
                                        strv_free(a);
                                        fclose(f);
                                        return -ENOMEM;
                                }

                                modified = true;
                        }

                        strv_free(a);
                        break;
                }

                fclose(f);
        }

        if (modified) {
                dbus_bool_t b;
                DBusMessage *changed;
                int r;

                r = write_data_x11();
                if (r < 0)
                        log_error("Failed to set X11 keyboard layout: %s", strerror(-r));

                changed = bus_properties_changed_new(
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "X11Layout\0"
                                "X11Model\0"
                                "X11Variant\0"
                                "X11Options\0");

                if (!changed)
                        return -ENOMEM;

                b = dbus_connection_send(connection, changed, NULL);
                dbus_message_unref(changed);

                if (!b)
                        return -ENOMEM;
        }

        return 0;
}

static int convert_x11_to_vconsole(DBusConnection *connection) {
        bool modified = false;

        assert(connection);

        if (isempty(state.x11_layout)) {

                modified =
                        !isempty(state.vc_keymap) ||
                        !isempty(state.vc_keymap_toggle);

                free_data_x11();
        } else {
                FILE *f;
                unsigned n = 0;
                unsigned best_matching = 0;
                char *new_keymap = NULL;

                f = fopen(SYSTEMD_KBD_MODEL_MAP, "re");
                if (!f)
                        return -errno;

                for (;;) {
                        char **a;
                        unsigned matching = 0;
                        int r;

                        r = read_next_mapping(f, &n, &a);
                        if (r < 0) {
                                fclose(f);
                                return r;
                        }

                        if (r == 0)
                                break;

                        /* Determine how well matching this entry is */
                        if (streq_ptr(state.x11_layout, a[1]))
                                /* If we got an exact match, this is best */
                                matching = 10;
                        else {
                                size_t x;

                                x = strcspn(state.x11_layout, ",");

                                /* We have multiple X layouts, look
                                 * for an entry that matches our key
                                 * with the everything but the first
                                 * layout stripped off. */
                                if (x > 0 &&
                                    strlen(a[1]) == x &&
                                    strneq(state.x11_layout, a[1], x))
                                        matching = 5;
                                else  {
                                        size_t w;

                                        /* If that didn't work, strip
                                         * off the other layouts from
                                         * the entry, too */

                                        w = strcspn(a[1], ",");

                                        if (x > 0 && x == w &&
                                            memcmp(state.x11_layout, a[1], x) == 0)
                                                matching = 1;
                                }
                        }

                        if (matching > 0 &&
                            streq_ptr(state.x11_model, a[2])) {
                                matching++;

                                if (streq_ptr(state.x11_variant, a[3])) {
                                        matching++;

                                        if (streq_ptr(state.x11_options, a[4]))
                                                matching++;
                                }
                        }

                        /* The best matching entry so far, then let's
                         * save that */
                        if (matching > best_matching) {
                                best_matching = matching;

                                free(new_keymap);
                                new_keymap = strdup(a[0]);

                                if (!new_keymap) {
                                        strv_free(a);
                                        fclose(f);
                                        return -ENOMEM;
                                }
                        }

                        strv_free(a);
                }

                fclose(f);

                if (!streq_ptr(state.vc_keymap, new_keymap)) {
                        free(state.vc_keymap);
                        state.vc_keymap = new_keymap;

                        free(state.vc_keymap_toggle);
                        state.vc_keymap_toggle = NULL;

                        modified = true;
                } else
                        free(new_keymap);
        }

        if (modified) {
                dbus_bool_t b;
                DBusMessage *changed;
                int r;

                r = write_data_vconsole();
                if (r < 0)
                        log_error("Failed to set virtual console keymap: %s", strerror(-r));

                changed = bus_properties_changed_new(
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "VConsoleKeymap\0"
                                "VConsoleKeymapToggle\0");

                if (!changed)
                        return -ENOMEM;

                b = dbus_connection_send(connection, changed, NULL);
                dbus_message_unref(changed);

                if (!b)
                        return -ENOMEM;

                return load_vconsole_keymap(connection, NULL);
        }

        return 0;
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

static const BusProperty bus_locale_properties[] = {
        { "Locale",               append_locale,             "as", 0 },
        { "X11Layout",            bus_property_append_string, "s", offsetof(State, x11_layout),       true },
        { "X11Model",             bus_property_append_string, "s", offsetof(State, x11_model),        true },
        { "X11Variant",           bus_property_append_string, "s", offsetof(State, x11_variant),      true },
        { "X11Options",           bus_property_append_string, "s", offsetof(State, x11_options),      true },
        { "VConsoleKeymap",       bus_property_append_string, "s", offsetof(State, vc_keymap),        true },
        { "VConsoleKeymapToggle", bus_property_append_string, "s", offsetof(State, vc_keymap_toggle), true },
        { NULL, }
};

static const BusBoundProperties bps[] = {
        { "org.freedesktop.locale1", bus_locale_properties, &state },
        { NULL, }
};

static DBusHandlerResult locale_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

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
                bool passed[_PROP_MAX] = {};
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

                /* Check whether a variable changed and if so valid */
                STRV_FOREACH(i, l) {
                        bool valid = false;

                        for (p = 0; p < _PROP_MAX; p++) {
                                size_t k;

                                k = strlen(names[p]);
                                if (startswith(*i, names[p]) &&
                                    (*i)[k] == '=' &&
                                    string_is_safe((*i) + k + 1)) {
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

                        r = verify_polkit(connection, message, "org.freedesktop.locale1.set-locale", interactive, NULL, &error);
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

                        r = write_data_locale();
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
                } else
                        strv_free(l);

        } else if (dbus_message_is_method_call(message, "org.freedesktop.locale1", "SetVConsoleKeyboard")) {

                const char *keymap, *keymap_toggle;
                dbus_bool_t convert, interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &keymap,
                                    DBUS_TYPE_STRING, &keymap_toggle,
                                    DBUS_TYPE_BOOLEAN, &convert,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(keymap))
                        keymap = NULL;

                if (isempty(keymap_toggle))
                        keymap_toggle = NULL;

                if (!streq_ptr(keymap, state.vc_keymap) ||
                    !streq_ptr(keymap_toggle, state.vc_keymap_toggle)) {

                        if ((keymap && (!filename_is_safe(keymap) || !string_is_safe(keymap))) ||
                            (keymap_toggle && (!filename_is_safe(keymap_toggle) || !string_is_safe(keymap_toggle))))
                                return bus_send_error_reply(connection, message, NULL, -EINVAL);

                        r = verify_polkit(connection, message, "org.freedesktop.locale1.set-keyboard", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (free_and_set(&state.vc_keymap, keymap) < 0 ||
                            free_and_set(&state.vc_keymap_toggle, keymap_toggle) < 0)
                                goto oom;

                        r = write_data_vconsole();
                        if (r < 0) {
                                log_error("Failed to set virtual console keymap: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        log_info("Changed virtual console keymap to '%s'", strempty(state.vc_keymap));

                        r = load_vconsole_keymap(connection, NULL);
                        if (r < 0)
                                log_error("Failed to request keymap reload: %s", strerror(-r));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/locale1",
                                        "org.freedesktop.locale1",
                                        "VConsoleKeymap\0"
                                        "VConsoleKeymapToggle\0");
                        if (!changed)
                                goto oom;

                        if (convert) {
                                r = convert_vconsole_to_x11(connection);

                                if (r < 0)
                                        log_error("Failed to convert keymap data: %s", strerror(-r));
                        }
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.locale1", "SetX11Keyboard")) {

                const char *layout, *model, *variant, *options;
                dbus_bool_t convert, interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &layout,
                                    DBUS_TYPE_STRING, &model,
                                    DBUS_TYPE_STRING, &variant,
                                    DBUS_TYPE_STRING, &options,
                                    DBUS_TYPE_BOOLEAN, &convert,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (isempty(layout))
                        layout = NULL;

                if (isempty(model))
                        model = NULL;

                if (isempty(variant))
                        variant = NULL;

                if (isempty(options))
                        options = NULL;

                if (!streq_ptr(layout, state.x11_layout) ||
                    !streq_ptr(model, state.x11_model) ||
                    !streq_ptr(variant, state.x11_variant) ||
                    !streq_ptr(options, state.x11_options)) {

                        if ((layout && !string_is_safe(layout)) ||
                            (model && !string_is_safe(model)) ||
                            (variant && !string_is_safe(variant)) ||
                            (options && !string_is_safe(options)))
                                return bus_send_error_reply(connection, message, NULL, -EINVAL);

                        r = verify_polkit(connection, message, "org.freedesktop.locale1.set-keyboard", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        if (free_and_set(&state.x11_layout, layout) < 0 ||
                            free_and_set(&state.x11_model, model) < 0 ||
                            free_and_set(&state.x11_variant, variant) < 0 ||
                            free_and_set(&state.x11_options, options) < 0)
                                goto oom;

                        r = write_data_x11();
                        if (r < 0) {
                                log_error("Failed to set X11 keyboard layout: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        log_info("Changed X11 keyboard layout to '%s'", strempty(state.x11_layout));

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/locale1",
                                        "org.freedesktop.locale1",
                                        "X11Layout\0"
                                        "X11Model\0"
                                        "X11Variant\0"
                                        "X11Options\0");
                        if (!changed)
                                goto oom;

                        if (convert) {
                                r = convert_x11_to_vconsole(connection);

                                if (r < 0)
                                        log_error("Failed to convert keymap data: %s", strerror(-r));
                        }
                }
        } else
                return bus_default_message_handler(connection, message, INTROSPECTION, INTERFACES_LIST, bps);

        if (!(reply = dbus_message_new_method_return(message)))
                goto oom;

        if (!bus_maybe_send_reply(connection, message, reply))
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
                r = log_oom();
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
        label_init("/etc");
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
