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

#include "systemd/sd-id128.h"
#include "systemd/sd-messages.h"
#include "util.h"
#include "strv.h"
#include "dbus-common.h"
#include "polkit.h"
#include "def.h"
#include "hwclock.h"
#include "conf-files.h"
#include "path-util.h"
#include "fileio-label.h"
#include "label.h"

#define NULL_ADJTIME_UTC "0.0 0 0\n0\nUTC\n"
#define NULL_ADJTIME_LOCAL "0.0 0 0\n0\nLOCAL\n"

#define INTERFACE                                                       \
        " <interface name=\"org.freedesktop.timedate1\">\n"             \
        "  <property name=\"Timezone\" type=\"s\" access=\"read\"/>\n"  \
        "  <property name=\"LocalRTC\" type=\"b\" access=\"read\"/>\n"  \
        "  <property name=\"CanNTP\" type=\"b\" access=\"read\"/>\n"    \
        "  <property name=\"NTP\" type=\"b\" access=\"read\"/>\n"       \
        "  <method name=\"SetTime\">\n"                                 \
        "   <arg name=\"usec_utc\" type=\"x\" direction=\"in\"/>\n"     \
        "   <arg name=\"relative\" type=\"b\" direction=\"in\"/>\n"     \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetTimezone\">\n"                             \
        "   <arg name=\"timezone\" type=\"s\" direction=\"in\"/>\n"     \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetLocalRTC\">\n"                             \
        "   <arg name=\"local_rtc\" type=\"b\" direction=\"in\"/>\n"    \
        "   <arg name=\"fix_system\" type=\"b\" direction=\"in\"/>\n"   \
        "   <arg name=\"user_interaction\" type=\"b\" direction=\"in\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"SetNTP\">\n"                                  \
        "   <arg name=\"use_ntp\" type=\"b\" direction=\"in\"/>\n"      \
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
        "org.freedesktop.timedate1\0"

const char timedate_interface[] _introspect_("timedate1") = INTERFACE;

typedef struct TZ {
        char *zone;
        bool local_rtc;
        int can_ntp;
        int use_ntp;
} TZ;

static TZ tz = {
        .zone = NULL,
        .local_rtc = false,
        .can_ntp = -1,
        .use_ntp = -1,
};

static usec_t remain_until;

static void free_data(void) {
        free(tz.zone);
        tz.zone = NULL;

        tz.local_rtc = false;
}

static bool valid_timezone(const char *name) {
        const char *p;
        char *t;
        bool slash = false;
        int r;
        struct stat st;

        assert(name);

        if (*name == '/' || *name == 0)
                return false;

        for (p = name; *p; p++) {
                if (!(*p >= '0' && *p <= '9') &&
                    !(*p >= 'a' && *p <= 'z') &&
                    !(*p >= 'A' && *p <= 'Z') &&
                    !(*p == '-' || *p == '_' || *p == '+' || *p == '/'))
                        return false;

                if (*p == '/') {

                        if (slash)
                                return false;

                        slash = true;
                } else
                        slash = false;
        }

        if (slash)
                return false;

        t = strappend("/usr/share/zoneinfo/", name);
        if (!t)
                return false;

        r = stat(t, &st);
        free(t);

        if (r < 0)
                return false;

        if (!S_ISREG(st.st_mode))
                return false;

        return true;
}

static int read_data(void) {
        int r;
        _cleanup_free_ char *t = NULL;

        free_data();

        r = readlink_malloc("/etc/localtime", &t);
        if (r < 0) {
                if (r == -EINVAL)
                        log_warning("/etc/localtime should be a symbolic link to a timezone data file in /usr/share/zoneinfo/.");
                else
                        log_warning("Failed to get target of /etc/localtime: %s", strerror(-r));
        } else {
                const char *e;

                e = path_startswith(t, "/usr/share/zoneinfo/");
                if (!e)
                        e = path_startswith(t, "../usr/share/zoneinfo/");

                if (!e)
                        log_warning("/etc/localtime should be a symbolic link to a timezone data file in /usr/share/zoneinfo/.");
                else {
                        tz.zone = strdup(e);
                        if (!tz.zone)
                                return log_oom();

                        goto have_timezone;
                }
        }

have_timezone:
        if (isempty(tz.zone)) {
                free(tz.zone);
                tz.zone = NULL;
        }

        tz.local_rtc = hwclock_is_localtime() > 0;

        return 0;
}

static int write_data_timezone(void) {
        int r = 0;
        _cleanup_free_ char *p = NULL;

        if (!tz.zone) {
                if (unlink("/etc/localtime") < 0 && errno != ENOENT)
                        r = -errno;

                return r;
        }

        p = strappend("../usr/share/zoneinfo/", tz.zone);
        if (!p)
                return log_oom();

        r = symlink_atomic(p, "/etc/localtime");
        if (r < 0)
                return r;

        return 0;
}

static int write_data_local_rtc(void) {
        int r;
        _cleanup_free_ char *s = NULL, *w = NULL;

        r = read_full_file("/etc/adjtime", &s, NULL);
        if (r < 0) {
                if (r != -ENOENT)
                        return r;

                if (!tz.local_rtc)
                        return 0;

                w = strdup(NULL_ADJTIME_LOCAL);
                if (!w)
                        return -ENOMEM;
        } else {
                char *p, *e;
                size_t a, b;

                p = strchr(s, '\n');
                if (!p)
                        return -EIO;

                p = strchr(p+1, '\n');
                if (!p)
                        return -EIO;

                p++;
                e = strchr(p, '\n');
                if (!e)
                        return -EIO;

                a = p - s;
                b = strlen(e);

                w = new(char, a + (tz.local_rtc ? 5 : 3) + b + 1);
                if (!w)
                        return -ENOMEM;

                *(char*) mempcpy(stpcpy(mempcpy(w, s, a), tz.local_rtc ? "LOCAL" : "UTC"), e, b) = 0;

                if (streq(w, NULL_ADJTIME_UTC)) {
                        if (unlink("/etc/adjtime") < 0)
                                if (errno != ENOENT)
                                        return -errno;

                        return 0;
                }
        }
        label_init("/etc");
        return write_string_file_atomic_label("/etc/adjtime", w);
}

static char** get_ntp_services(void) {
        _cleanup_strv_free_ char **r = NULL, **files;
        char **i;
        int k;

        k = conf_files_list(&files, ".list", NULL,
                            "/etc/systemd/ntp-units.d",
                            "/run/systemd/ntp-units.d",
                            "/usr/local/lib/systemd/ntp-units.d",
                            "/usr/lib/systemd/ntp-units.d",
                            NULL);
        if (k < 0)
                return NULL;

        STRV_FOREACH(i, files) {
                _cleanup_fclose_ FILE *f;

                f = fopen(*i, "re");
                if (!f)
                        continue;

                for (;;) {
                        char line[PATH_MAX], *l;

                        if (!fgets(line, sizeof(line), f)) {

                                if (ferror(f))
                                        log_error("Failed to read NTP units file: %m");

                                break;
                        }

                        l = strstrip(line);
                        if (l[0] == 0 || l[0] == '#')
                                continue;

                        if (strv_extend(&r, l) < 0) {
                                log_oom();
                                return NULL;
                        }
                }
        }

        i = r;
        r = NULL; /* avoid cleanup */

        return strv_uniq(i);
}

static int read_ntp(DBusConnection *bus) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        int r;
        char **i, **l;

        assert(bus);

        dbus_error_init(&error);

        l = get_ntp_services();
        STRV_FOREACH(i, l) {
                const char *s;

                if (m)
                        dbus_message_unref(m);
                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "GetUnitFileState");
                if (!m) {
                        r = log_oom();
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, i,
                                              DBUS_TYPE_INVALID)) {
                        r = log_oom();
                        goto finish;
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
                if (!reply) {
                        if (streq(error.name, "org.freedesktop.DBus.Error.FileNotFound")) {
                                /* This implementation does not exist, try next one */
                                dbus_error_free(&error);
                                continue;
                        }

                        log_error("Failed to issue method call: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                if (!dbus_message_get_args(reply, &error,
                                           DBUS_TYPE_STRING, &s,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse reply: %s", bus_error_message(&error));
                        r = -EIO;
                        goto finish;
                }

                tz.can_ntp = 1;
                tz.use_ntp =
                        streq(s, "enabled") ||
                        streq(s, "enabled-runtime");
                r = 0;
                goto finish;
        }

        /* NTP is not installed. */
        tz.can_ntp = 0;
        tz.use_ntp = 0;
        r = 0;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        strv_free(l);

        dbus_error_free(&error);

        return r;
}

static int start_ntp(DBusConnection *bus, DBusError *error) {
        DBusMessage *m = NULL, *reply = NULL;
        const char *mode = "replace";
        char **i, **l;
        int r;

        assert(bus);
        assert(error);

        l = get_ntp_services();
        STRV_FOREACH(i, l) {
                if (m)
                        dbus_message_unref(m);
                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                tz.use_ntp ? "StartUnit" : "StopUnit");
                if (!m) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (!dbus_message_append_args(m,
                                              DBUS_TYPE_STRING, i,
                                              DBUS_TYPE_STRING, &mode,
                                              DBUS_TYPE_INVALID)) {
                        log_error("Could not append arguments to message.");
                        r = -ENOMEM;
                        goto finish;
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, error);
                if (!reply) {
                        if (streq(error->name, "org.freedesktop.DBus.Error.FileNotFound") ||
                            streq(error->name, "org.freedesktop.systemd1.LoadFailed") ||
                            streq(error->name, "org.freedesktop.systemd1.NoSuchUnit")) {
                                /* This implementation does not exist, try next one */
                                dbus_error_free(error);
                                continue;
                        }

                        log_error("Failed to issue method call: %s", bus_error_message(error));
                        r = -EIO;
                        goto finish;
                }

                r = 0;
                goto finish;
        }

        /* No implementaiton available... */
        r = -ENOENT;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        strv_free(l);

        return r;
}

static int enable_ntp(DBusConnection *bus, DBusError *error) {
        DBusMessage *m = NULL, *reply = NULL;
        int r;
        DBusMessageIter iter;
        dbus_bool_t f = FALSE, t = TRUE;
        char **i, **l;

        assert(bus);
        assert(error);

        l = get_ntp_services();
        STRV_FOREACH(i, l) {
                char* k[2];

                if (m)
                        dbus_message_unref(m);
                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                tz.use_ntp ? "EnableUnitFiles" : "DisableUnitFiles");
                if (!m) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_iter_init_append(m, &iter);

                k[0] = *i;
                k[1] = NULL;

                r = bus_append_strv_iter(&iter, k);
                if (r < 0) {
                        log_error("Failed to append unit files.");
                        goto finish;
                }

                /* send runtime bool */
                if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &f)) {
                        log_error("Failed to append runtime boolean.");
                        r = -ENOMEM;
                        goto finish;
                }

                if (tz.use_ntp) {
                        /* send force bool */
                        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &t)) {
                                log_error("Failed to append force boolean.");
                                r = -ENOMEM;
                                goto finish;
                        }
                }

                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, error);
                if (!reply) {
                        if (streq(error->name, "org.freedesktop.DBus.Error.FileNotFound")) {
                                /* This implementation does not exist, try next one */
                                dbus_error_free(error);
                                continue;
                        }

                        log_error("Failed to issue method call: %s", bus_error_message(error));
                        r = -EIO;
                        goto finish;
                }

                dbus_message_unref(m);
                m = dbus_message_new_method_call(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "Reload");
                if (!m) {
                        log_error("Could not allocate message.");
                        r = -ENOMEM;
                        goto finish;
                }

                dbus_message_unref(reply);
                reply = dbus_connection_send_with_reply_and_block(bus, m, -1, error);
                if (!reply) {
                        log_error("Failed to issue method call: %s", bus_error_message(error));
                        r = -EIO;
                        goto finish;
                }

                r = 0;
                goto finish;
        }

        r = -ENOENT;

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        strv_free(l);

        return r;
}

static int property_append_can_ntp(DBusMessageIter *i, const char *property, void *data) {
        dbus_bool_t db;

        assert(i);
        assert(property);

        db = tz.can_ntp > 0;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &db))
                return -ENOMEM;

        return 0;
}

static int property_append_ntp(DBusMessageIter *i, const char *property, void *data) {
        dbus_bool_t db;

        assert(i);
        assert(property);

        db = tz.use_ntp > 0;

        if (!dbus_message_iter_append_basic(i, DBUS_TYPE_BOOLEAN, &db))
                return -ENOMEM;

        return 0;
}

static const BusProperty bus_timedate_properties[] = {
        { "Timezone", bus_property_append_string, "s", offsetof(TZ, zone),     true },
        { "LocalRTC", bus_property_append_bool,   "b", offsetof(TZ, local_rtc) },
        { "CanNTP",   property_append_can_ntp,    "b", offsetof(TZ, can_ntp)   },
        { "NTP",      property_append_ntp,        "b", offsetof(TZ, use_ntp)   },
        { NULL, }
};

static const BusBoundProperties bps[] = {
        { "org.freedesktop.timedate1", bus_timedate_properties, &tz },
        { NULL, }
};

static DBusHandlerResult timedate_message_handler(
                DBusConnection *connection,
                DBusMessage *message,
                void *userdata) {

        DBusMessage *reply = NULL, *changed = NULL;
        DBusError error;
        int r;

        assert(connection);
        assert(message);

        dbus_error_init(&error);

        if (dbus_message_is_method_call(message, "org.freedesktop.timedate1", "SetTimezone")) {
                const char *z;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_STRING, &z,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!valid_timezone(z))
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                if (!streq_ptr(z, tz.zone)) {
                        char *t;

                        r = verify_polkit(connection, message, "org.freedesktop.timedate1.set-timezone", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        t = strdup(z);
                        if (!t)
                                goto oom;

                        free(tz.zone);
                        tz.zone = t;

                        /* 1. Write new configuration file */
                        r = write_data_timezone();
                        if (r < 0) {
                                log_error("Failed to set timezone: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        /* 2. Tell the kernel our time zone */
                        hwclock_set_timezone(NULL);

                        if (tz.local_rtc) {
                                struct timespec ts;
                                struct tm *tm;

                                /* 3. Sync RTC from system clock, with the new delta */
                                assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
                                assert_se(tm = localtime(&ts.tv_sec));
                                hwclock_set_time(tm);
                        }

                        log_struct(LOG_INFO,
                                   MESSAGE_ID(SD_MESSAGE_TIMEZONE_CHANGE),
                                   "TIMEZONE=%s", tz.zone,
                                   "MESSAGE=Changed timezone to '%s'.", tz.zone,
                                   NULL);

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/timedate1",
                                        "org.freedesktop.timedate1",
                                        "Timezone\0");
                        if (!changed)
                                goto oom;
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.timedate1", "SetLocalRTC")) {
                dbus_bool_t lrtc;
                dbus_bool_t fix_system;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_BOOLEAN, &lrtc,
                                    DBUS_TYPE_BOOLEAN, &fix_system,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (lrtc != tz.local_rtc) {
                        struct timespec ts;

                        r = verify_polkit(connection, message, "org.freedesktop.timedate1.set-local-rtc", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        tz.local_rtc = lrtc;

                        /* 1. Write new configuration file */
                        r = write_data_local_rtc();
                        if (r < 0) {
                                log_error("Failed to set RTC to local/UTC: %s", strerror(-r));
                                return bus_send_error_reply(connection, message, NULL, r);
                        }

                        /* 2. Tell the kernel our time zone */
                        hwclock_set_timezone(NULL);

                        /* 3. Synchronize clocks */
                        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);

                        if (fix_system) {
                                struct tm tm;

                                /* Sync system clock from RTC; first,
                                 * initialize the timezone fields of
                                 * struct tm. */
                                if (tz.local_rtc)
                                        tm = *localtime(&ts.tv_sec);
                                else
                                        tm = *gmtime(&ts.tv_sec);

                                /* Override the main fields of
                                 * struct tm, but not the timezone
                                 * fields */
                                if (hwclock_get_time(&tm) >= 0) {

                                        /* And set the system clock
                                         * with this */
                                        if (tz.local_rtc)
                                                ts.tv_sec = mktime(&tm);
                                        else
                                                ts.tv_sec = timegm(&tm);

                                        clock_settime(CLOCK_REALTIME, &ts);
                                }

                        } else {
                                struct tm *tm;

                                /* Sync RTC from system clock */
                                if (tz.local_rtc)
                                        tm = localtime(&ts.tv_sec);
                                else
                                        tm = gmtime(&ts.tv_sec);

                                hwclock_set_time(tm);
                        }

                        log_info("RTC configured to %s time.", tz.local_rtc ? "local" : "UTC");

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/timedate1",
                                        "org.freedesktop.timedate1",
                                        "LocalRTC\0");
                        if (!changed)
                                goto oom;
                }

        } else if (dbus_message_is_method_call(message, "org.freedesktop.timedate1", "SetTime")) {
                int64_t utc;
                dbus_bool_t relative;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_INT64, &utc,
                                    DBUS_TYPE_BOOLEAN, &relative,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (!relative && utc <= 0)
                        return bus_send_error_reply(connection, message, NULL, -EINVAL);

                if (!relative || utc != 0) {
                        struct timespec ts;
                        struct tm* tm;

                        if (relative) {
                                usec_t n, x;

                                n = now(CLOCK_REALTIME);
                                x = n + utc;

                                if ((utc > 0 && x < n) ||
                                    (utc < 0 && x > n))
                                        return bus_send_error_reply(connection, message, NULL, -EOVERFLOW);

                                timespec_store(&ts, x);
                        } else
                                timespec_store(&ts, (usec_t) utc);

                        r = verify_polkit(connection, message, "org.freedesktop.timedate1.set-time", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        /* Set system clock */
                        if (clock_settime(CLOCK_REALTIME, &ts) < 0) {
                                log_error("Failed to set local time: %m");
                                return bus_send_error_reply(connection, message, NULL, -errno);
                        }

                        /* Sync down to RTC */
                        if (tz.local_rtc)
                                tm = localtime(&ts.tv_sec);
                        else
                                tm = gmtime(&ts.tv_sec);

                        hwclock_set_time(tm);

                        log_struct(LOG_INFO,
                                   MESSAGE_ID(SD_MESSAGE_TIME_CHANGE),
                                   "REALTIME=%llu", (unsigned long long) timespec_load(&ts),
                                   "MESSAGE=Changed local time to %s", ctime(&ts.tv_sec),
                                   NULL);
                }
        } else if (dbus_message_is_method_call(message, "org.freedesktop.timedate1", "SetNTP")) {
                dbus_bool_t ntp;
                dbus_bool_t interactive;

                if (!dbus_message_get_args(
                                    message,
                                    &error,
                                    DBUS_TYPE_BOOLEAN, &ntp,
                                    DBUS_TYPE_BOOLEAN, &interactive,
                                    DBUS_TYPE_INVALID))
                        return bus_send_error_reply(connection, message, &error, -EINVAL);

                if (ntp != !!tz.use_ntp) {

                        r = verify_polkit(connection, message, "org.freedesktop.timedate1.set-ntp", interactive, NULL, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        tz.use_ntp = !!ntp;

                        r = enable_ntp(connection, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        r = start_ntp(connection, &error);
                        if (r < 0)
                                return bus_send_error_reply(connection, message, &error, r);

                        log_info("Set NTP to %s", tz.use_ntp ? "enabled" : "disabled");

                        changed = bus_properties_changed_new(
                                        "/org/freedesktop/timedate1",
                                        "org.freedesktop.timedate1",
                                        "NTP\0");
                        if (!changed)
                                goto oom;
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
        static const DBusObjectPathVTable timedate_vtable = {
                .message_function = timedate_message_handler
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
                goto fail2;
        }

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (!dbus_connection_register_object_path(bus, "/org/freedesktop/timedate1", &timedate_vtable, NULL) ||
            !dbus_connection_add_filter(bus, bus_exit_idle_filter, &remain_until, NULL)) {
                r = log_oom();
                goto fail;
        }

        r = dbus_bus_request_name(bus, "org.freedesktop.timedate1", DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
        if (dbus_error_is_set(&error)) {
                log_error("Failed to register name on bus: %s", bus_error_message(&error));
                r = -EEXIST;
                goto fail;
        }

        if (r != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)  {
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
fail2:
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
                fputs(timedate_interface, stdout);
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
                log_error("Failed to read timezone data: %s", strerror(-r));
                goto finish;
        }

        r = connect_bus(&bus);
        if (r < 0)
                goto finish;

        r = read_ntp(bus);
        if (r < 0) {
                log_error("Failed to determine whether NTP is enabled: %s", strerror(-r));
                goto finish;
        }

        remain_until = now(CLOCK_MONOTONIC) + DEFAULT_EXIT_USEC;
        for (;;) {

                if (!dbus_connection_read_write_dispatch(bus, exiting ? -1 : (int) (DEFAULT_EXIT_USEC/USEC_PER_MSEC)))
                        break;

                if (!exiting && remain_until < now(CLOCK_MONOTONIC)) {
                        exiting = true;
                        bus_async_unregister_and_exit(bus, "org.freedesktop.timedated1");
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
