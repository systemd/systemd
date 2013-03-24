/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <sys/timex.h>

#include "dbus-common.h"
#include "util.h"
#include "spawn-polkit-agent.h"
#include "build.h"
#include "hwclock.h"
#include "strv.h"
#include "pager.h"
#include "time-dst.h"

static bool arg_adjust_system_clock = false;
static bool arg_no_pager = false;
static enum transport {
        TRANSPORT_NORMAL,
        TRANSPORT_SSH,
        TRANSPORT_POLKIT
} arg_transport = TRANSPORT_NORMAL;
static bool arg_ask_password = true;
static const char *arg_host = NULL;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        polkit_agent_open();
}

typedef struct StatusInfo {
        const char *timezone;
        bool local_rtc;
        bool ntp;
        bool can_ntp;
} StatusInfo;

static bool ntp_synced(void) {
        struct timex txc = {};

        if (adjtimex(&txc) < 0)
                return false;

        if (txc.status & STA_UNSYNC)
                return false;

        return true;
}

static const char *jump_str(int delta_minutes, char *s, size_t size) {
        if (delta_minutes == 60)
                return "one hour forward";
        if (delta_minutes == -60)
                return "one hour backwards";
        if (delta_minutes < 0) {
                snprintf(s, size, "%i minutes backwards", -delta_minutes);
                return s;
        }
        if (delta_minutes > 0) {
                snprintf(s, size, "%i minutes forward", delta_minutes);
                return s;
        }
        return "";
}

static void print_status_info(StatusInfo *i) {
        usec_t n;
        char a[FORMAT_TIMESTAMP_MAX];
        char b[FORMAT_TIMESTAMP_MAX];
        char s[32];
        struct tm tm;
        time_t sec;
        char *zc, *zn;
        time_t t, tc, tn;
        int dn;
        bool is_dstc, is_dstn;
        int r;

        assert(i);

        /* enforce the values of /etc/localtime */
        if (getenv("TZ")) {
                fprintf(stderr, "Warning: ignoring the TZ variable, reading the system's timezone setting only.\n\n");
                unsetenv("TZ");
        }

        n = now(CLOCK_REALTIME);
        sec = (time_t) (n / USEC_PER_SEC);

        zero(tm);
        assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&sec, &tm)) > 0);
        char_array_0(a);
        printf("      Local time: %s\n", a);

        zero(tm);
        assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S UTC", gmtime_r(&sec, &tm)) > 0);
        char_array_0(a);
        printf("  Universal time: %s\n", a);

        zero(tm);
        r = hwclock_get_time(&tm);
        if (r >= 0) {
                /* Calculcate the week-day */
                mktime(&tm);

                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S", &tm) > 0);
                char_array_0(a);
                printf("        RTC time: %s\n", a);
        }

        zero(tm);
        assert_se(strftime(a, sizeof(a), "%Z, %z", localtime_r(&sec, &tm)) > 0);
        char_array_0(a);
        printf("        Timezone: %s (%s)\n"
               "     NTP enabled: %s\n"
               "NTP synchronized: %s\n"
               " RTC in local TZ: %s\n",
               strna(i->timezone),
               a,
               i->can_ntp ? yes_no(i->ntp) : "n/a",
               yes_no(ntp_synced()),
               yes_no(i->local_rtc));

        r = time_get_dst(sec, "/etc/localtime",
                         &tc, &zc, &is_dstc,
                         &tn, &dn, &zn, &is_dstn);
        if (r < 0)
                printf("      DST active: n/a\n");
        else {
                printf("      DST active: %s\n", yes_no(is_dstc));

                t = tc - 1;
                zero(tm);
                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&t, &tm)) > 0);
                char_array_0(a);

                zero(tm);
                assert_se(strftime(b, sizeof(b), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&tc, &tm)) > 0);
                char_array_0(b);
                printf(" Last DST change: DST %s at\n"
                       "                  %s\n"
                       "                  %s\n",
                       is_dstc ? "began" : "ended", a, b);

                t = tn - 1;
                zero(tm);
                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&t, &tm)) > 0);
                char_array_0(a);

                zero(tm);
                assert_se(strftime(b, sizeof(b), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&tn, &tm)) > 0);
                char_array_0(b);
                printf(" Next DST change: DST %s (the clock jumps %s) at\n"
                       "                  %s\n"
                       "                  %s\n",
                       is_dstn ? "begins" : "ends", jump_str(dn, s, sizeof(s)), a, b);

                free(zc);
                free(zn);
        }

        if (i->local_rtc)
                fputs("\n" ANSI_HIGHLIGHT_ON
                      "Warning: The RTC is configured to maintain time in the local time zone. This\n"
                      "         mode is not fully supported and will create various problems with time\n"
                      "         zone changes and daylight saving adjustments. If at all possible use\n"
                      "         RTC in UTC, by calling 'timedatectl set-local-rtc 0'" ANSI_HIGHLIGHT_OFF ".\n", stdout);
}

static int status_property(const char *name, DBusMessageIter *iter, StatusInfo *i) {
        assert(name);
        assert(iter);

        switch (dbus_message_iter_get_arg_type(iter)) {

        case DBUS_TYPE_STRING: {
                const char *s;

                dbus_message_iter_get_basic(iter, &s);
                if (!isempty(s)) {
                        if (streq(name, "Timezone"))
                                i->timezone = s;
                }
                break;
        }

        case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;

                dbus_message_iter_get_basic(iter, &b);
                if (streq(name, "LocalRTC"))
                        i->local_rtc = b;
                else if (streq(name, "NTP"))
                        i->ntp = b;
                else if (streq(name, "CanNTP"))
                        i->can_ntp = b;
        }
        }

        return 0;
}

static int show_status(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;
        StatusInfo info = {};

        assert(args);

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *name;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_DICT_ENTRY) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &name, true) < 0) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT)  {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub2, &sub3);

                r = status_property(name, &sub3, &info);
                if (r < 0) {
                        log_error("Failed to parse reply.");
                        return r;
                }

                dbus_message_iter_next(&sub);
        }

        print_status_info(&info);
        return 0;
}

static int set_time(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t relative = false, interactive = true;
        usec_t t;
        dbus_int64_t u;
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        r = parse_timestamp(args[1], &t);
        if (r < 0) {
                log_error("Failed to parse time specification: %s", args[1]);
                return r;
        }

        u = (dbus_uint64_t) t;

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetTime",
                        &reply,
                        NULL,
                        DBUS_TYPE_INT64, &u,
                        DBUS_TYPE_BOOLEAN, &relative,
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int set_timezone(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = true;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetTimezone",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &args[1],
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int set_local_rtc(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = true, b, q;
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        r = parse_boolean(args[1]);
        if (r < 0) {
                log_error("Failed to parse local RTC setting: %s", args[1]);
                return r;
        }

        b = r;
        q = arg_adjust_system_clock;

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetLocalRTC",
                        &reply,
                        NULL,
                        DBUS_TYPE_BOOLEAN, &b,
                        DBUS_TYPE_BOOLEAN, &q,
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int set_ntp(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        dbus_bool_t interactive = true, b;
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        r = parse_boolean(args[1]);
        if (r < 0) {
                log_error("Failed to parse NTP setting: %s", args[1]);
                return r;
        }

        b = r;

        return bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.timedate1",
                        "/org/freedesktop/timedate1",
                        "org.freedesktop.timedate1",
                        "SetNTP",
                        &reply,
                        NULL,
                        DBUS_TYPE_BOOLEAN, &b,
                        DBUS_TYPE_BOOLEAN, &interactive,
                        DBUS_TYPE_INVALID);
}

static int list_timezones(DBusConnection *bus, char **args, unsigned n) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **zones = NULL;
        size_t n_zones = 0;

        assert(args);
        assert(n == 1);

        f = fopen("/usr/share/zoneinfo/zone.tab", "re");
        if (!f) {
                log_error("Failed to open timezone database: %m");
                return -errno;
        }

        for (;;) {
                char l[LINE_MAX], *p, **z, *w;
                size_t k;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        log_error("Failed to read timezone database: %m");
                        return -errno;
                }

                p = strstrip(l);

                if (isempty(p) || *p == '#')
                        continue;


                /* Skip over country code */
                p += strcspn(p, WHITESPACE);
                p += strspn(p, WHITESPACE);

                /* Skip over coordinates */
                p += strcspn(p, WHITESPACE);
                p += strspn(p, WHITESPACE);

                /* Found timezone name */
                k = strcspn(p, WHITESPACE);
                if (k <= 0)
                        continue;

                w = strndup(p, k);
                if (!w)
                        return log_oom();

                z = realloc(zones, sizeof(char*) * (n_zones + 2));
                if (!z) {
                        free(w);
                        return log_oom();
                }

                zones = z;
                zones[n_zones++] = w;
        }

        if (zones)
                zones[n_zones] = NULL;

        pager_open_if_enabled();

        strv_sort(zones);
        strv_print(zones);

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change system time and date settings.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --adjust-system-clock\n"
               "                         Adjust system clock when changing local RTC mode\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-ask-password   Do not prompt for password\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n\n"
               "Commands:\n"
               "  status                 Show current time settings\n"
               "  set-time TIME          Set system time\n"
               "  set-timezone ZONE      Set system timezone\n"
               "  list-timezones         Show known timezones\n"
               "  set-local-rtc BOOL     Control whether RTC is in local time\n"
               "  set-ntp BOOL           Control whether NTP is enabled\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_ADJUST_SYSTEM_CLOCK,
                ARG_NO_ASK_PASSWORD
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                { "no-pager",            no_argument,       NULL, ARG_NO_PAGER            },
                { "host",                required_argument, NULL, 'H'                     },
                { "privileged",          no_argument,       NULL, 'P'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "adjust-system-clock", no_argument,       NULL, ARG_ADJUST_SYSTEM_CLOCK },
                { NULL,                  0,                 NULL, 0                       }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hH:P", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'P':
                        arg_transport = TRANSPORT_POLKIT;
                        break;

                case 'H':
                        arg_transport = TRANSPORT_SSH;
                        arg_host = optarg;
                        break;

                case ARG_ADJUST_SYSTEM_CLOCK:
                        arg_adjust_system_clock = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

static int timedatectl_main(DBusConnection *bus, int argc, char *argv[], DBusError *error) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(DBusConnection *bus, char **args, unsigned n);
        } verbs[] = {
                { "status",                LESS,   1, show_status      },
                { "set-time",              EQUAL,  2, set_time         },
                { "set-timezone",          EQUAL,  2, set_timezone     },
                { "list-timezones",        EQUAL,  1, list_timezones   },
                { "set-local-rtc",         EQUAL,  2, set_local_rtc    },
                { "set-ntp",               EQUAL,  2, set_ntp,         },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);
        assert(error);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "status" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        if (!bus) {
                log_error("Failed to get D-Bus connection: %s", error->message);
                return -EIO;
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char *argv[]) {
        int r, retval = EXIT_FAILURE;
        DBusConnection *bus = NULL;
        DBusError error;

        dbus_error_init(&error);

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (arg_transport == TRANSPORT_NORMAL)
                bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
        else if (arg_transport == TRANSPORT_POLKIT)
                bus_connect_system_polkit(&bus, &error);
        else if (arg_transport == TRANSPORT_SSH)
                bus_connect_system_ssh(NULL, arg_host, &bus, &error);
        else
                assert_not_reached("Uh, invalid transport...");

        r = timedatectl_main(bus, argc, argv, &error);
        retval = r < 0 ? EXIT_FAILURE : r;

finish:
        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
        dbus_shutdown();

        pager_close();

        return retval;
}
