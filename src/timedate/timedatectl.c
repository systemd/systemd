/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Kay Sievers

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

#include <getopt.h>
#include <locale.h>
#include <stdbool.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-util.h"
#include "pager.h"
#include "parse-util.h"
#include "spawn-polkit-agent.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"
#include "verbs.h"

static bool arg_no_pager = false;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_adjust_system_clock = false;

typedef struct StatusInfo {
        usec_t time;
        const char *timezone;

        usec_t rtc_time;
        bool rtc_local;

        bool ntp_enabled;
        bool ntp_capable;
        bool ntp_synced;
} StatusInfo;

static void print_status_info(const StatusInfo *i) {
        char a[LINE_MAX];
        struct tm tm;
        time_t sec;
        bool have_time = false;
        const char *old_tz = NULL, *tz;
        int r;
        size_t n;

        assert(i);

        /* Save the old $TZ */
        tz = getenv("TZ");
        if (tz)
                old_tz = strdupa(tz);

        /* Set the new $TZ */
        if (setenv("TZ", isempty(i->timezone) ? "UTC" : i->timezone, true) < 0)
                log_warning_errno(errno, "Failed to set TZ environment variable, ignoring: %m");
        else
                tzset();

        if (i->time != 0) {
                sec = (time_t) (i->time / USEC_PER_SEC);
                have_time = true;
        } else if (IN_SET(arg_transport, BUS_TRANSPORT_LOCAL, BUS_TRANSPORT_MACHINE)) {
                sec = time(NULL);
                have_time = true;
        } else
                log_warning("Could not get time from timedated and not operating locally, ignoring.");

        if (have_time) {
                n = strftime(a, sizeof a, "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&sec, &tm));
                printf("                      Local time: %s\n", n > 0 ? a : "n/a");

                n = strftime(a, sizeof a, "%a %Y-%m-%d %H:%M:%S UTC", gmtime_r(&sec, &tm));
                printf("                  Universal time: %s\n", n > 0 ? a : "n/a");
        } else {
                printf("                      Local time: %s\n", "n/a");
                printf("                  Universal time: %s\n", "n/a");
        }

        if (i->rtc_time > 0) {
                time_t rtc_sec;

                rtc_sec = (time_t) (i->rtc_time / USEC_PER_SEC);
                n = strftime(a, sizeof a, "%a %Y-%m-%d %H:%M:%S", gmtime_r(&rtc_sec, &tm));
                printf("                        RTC time: %s\n", n > 0 ? a : "n/a");
        } else
                printf("                        RTC time: %s\n", "n/a");

        if (have_time)
                n = strftime(a, sizeof a, "%Z, %z", localtime_r(&sec, &tm));

        /* Restore the $TZ */
        if (old_tz)
                r = setenv("TZ", old_tz, true);
        else
                r = unsetenv("TZ");
        if (r < 0)
                log_warning_errno(errno, "Failed to set TZ environment variable, ignoring: %m");
        else
                tzset();

        printf("                       Time zone: %s (%s)\n"
               "       System clock synchronized: %s\n"
               "systemd-timesyncd.service active: %s\n"
               "                 RTC in local TZ: %s\n",
               strna(i->timezone), have_time && n > 0 ? a : "n/a",
               yes_no(i->ntp_synced),
               i->ntp_capable ? yes_no(i->ntp_enabled) : "n/a",
               yes_no(i->rtc_local));

        if (i->rtc_local)
                printf("\n%s"
                       "Warning: The system is configured to read the RTC time in the local time zone.\n"
                       "         This mode cannot be fully supported. It will create various problems\n"
                       "         with time zone changes and daylight saving time adjustments. The RTC\n"
                       "         time is never updated, it relies on external facilities to maintain it.\n"
                       "         If at all possible, use RTC in UTC by calling\n"
                       "         'timedatectl set-local-rtc 0'.%s\n", ansi_highlight(), ansi_normal());
}

static int show_status(int argc, char **argv, void *userdata) {
        StatusInfo info = {};
        static const struct bus_properties_map map[]  = {
                { "Timezone",        "s", NULL, offsetof(StatusInfo, timezone) },
                { "LocalRTC",        "b", NULL, offsetof(StatusInfo, rtc_local) },
                { "NTP",             "b", NULL, offsetof(StatusInfo, ntp_enabled) },
                { "CanNTP",          "b", NULL, offsetof(StatusInfo, ntp_capable) },
                { "NTPSynchronized", "b", NULL, offsetof(StatusInfo, ntp_synced) },
                { "TimeUSec",        "t", NULL, offsetof(StatusInfo, time) },
                { "RTCTimeUSec",     "t", NULL, offsetof(StatusInfo, rtc_time) },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.timedate1",
                                   "/org/freedesktop/timedate1",
                                   map,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Failed to query server: %s", bus_error_message(&error, r));

        print_status_info(&info);

        return r;
}

static int set_time(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool relative = false, interactive = arg_ask_password;
        sd_bus *bus = userdata;
        usec_t t;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = parse_timestamp(argv[1], &t);
        if (r < 0)
                return log_error_errno(r, "Failed to parse time specification '%s': %m", argv[1]);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetTime",
                               &error,
                               NULL,
                               "xbb", (int64_t) t, relative, interactive);
        if (r < 0)
                log_error("Failed to set time: %s", bus_error_message(&error, r));

        return r;
}

static int set_timezone(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetTimezone",
                               &error,
                               NULL,
                               "sb", argv[1], arg_ask_password);
        if (r < 0)
                log_error("Failed to set time zone: %s", bus_error_message(&error, r));

        return r;
}

static int set_local_rtc(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r, b;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        b = parse_boolean(argv[1]);
        if (b < 0)
                return log_error_errno(b, "Failed to parse local RTC setting '%s': %m", argv[1]);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetLocalRTC",
                               &error,
                               NULL,
                               "bbb", b, arg_adjust_system_clock, arg_ask_password);
        if (r < 0)
                log_error("Failed to set local RTC: %s", bus_error_message(&error, r));

        return r;
}

static int set_ntp(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int b, r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        b = parse_boolean(argv[1]);
        if (b < 0)
                return log_error_errno(b, "Failed to parse NTP setting '%s': %m", argv[1]);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetNTP",
                               &error,
                               NULL,
                               "bb", b, arg_ask_password);
        if (r < 0)
                log_error("Failed to set ntp: %s", bus_error_message(&error, r));

        return r;
}

static int list_timezones(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        r = get_timezones(&zones);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of time zones: %m");

        (void) pager_open(arg_no_pager, false);
        strv_print(zones);

        return 0;
}

static int help(void) {
        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change system time and date settings.\n\n"
               "  -h --help                Show this help message\n"
               "     --version             Show package version\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-ask-password     Do not prompt for password\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --adjust-system-clock Adjust system clock when changing local RTC mode\n\n"
               "Commands:\n"
               "  status                   Show current time settings\n"
               "  set-time TIME            Set system time\n"
               "  set-timezone ZONE        Set system time zone\n"
               "  list-timezones           Show known time zones\n"
               "  set-local-rtc BOOL       Control whether RTC is in local time\n"
               "  set-ntp BOOL             Enable or disable network time synchronization\n",
               program_invocation_short_name);

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
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
                { "machine",             required_argument, NULL, 'M'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "adjust-system-clock", no_argument,       NULL, ARG_ADJUST_SYSTEM_CLOCK },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
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
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int timedatectl_main(sd_bus *bus, int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "status",         VERB_ANY, 1,        VERB_DEFAULT, show_status    },
                { "set-time",       2,        2,        0,            set_time       },
                { "set-timezone",   2,        2,        0,            set_timezone   },
                { "list-timezones", VERB_ANY, 1,        0,            list_timezones },
                { "set-local-rtc",  2,        2,        0,            set_local_rtc  },
                { "set-ntp",        2,        2,        0,            set_ntp        },
                { "help",           VERB_ANY, VERB_ANY, 0,            verb_help      }, /* Not documented, but supported since it is created. */
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

int main(int argc, char *argv[]) {
        sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bus_connect_transport(arg_transport, arg_host, false, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

        r = timedatectl_main(bus, argc, argv);

finish:
        /* make sure we terminate the bus connection first, and then close the
         * pager, see issue #3543 for the details. */
        sd_bus_flush_close_unref(bus);
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
