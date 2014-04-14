/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <locale.h>
#include <string.h>
#include <sys/timex.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "util.h"
#include "spawn-polkit-agent.h"
#include "build.h"
#include "strv.h"
#include "pager.h"
#include "time-dst.h"

static bool arg_no_pager = false;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_adjust_system_clock = false;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */
        if (!arg_ask_password)
                return;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return;

        polkit_agent_open();
}

typedef struct StatusInfo {
        usec_t time;
        char *timezone;

        usec_t rtc_time;
        bool rtc_local;

        bool ntp_enabled;
        bool ntp_capable;
        bool ntp_synced;
} StatusInfo;

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

static void print_status_info(const StatusInfo *i) {
        char a[FORMAT_TIMESTAMP_MAX];
        char b[FORMAT_TIMESTAMP_MAX];
        char s[32];
        struct tm tm;
        time_t sec;
        bool have_time = false;
        _cleanup_free_ char *zc = NULL, *zn = NULL;
        time_t t, tc, tn;
        int dn = 0;
        bool is_dstc = false, is_dstn = false;
        int r;

        assert(i);

        /* Enforce the values of /etc/localtime */
        if (getenv("TZ")) {
                fprintf(stderr, "Warning: Ignoring the TZ variable. Reading the system's time zone setting only.\n\n");
                unsetenv("TZ");
        }

        if (i->time != 0) {
                sec = (time_t) (i->time / USEC_PER_SEC);
                have_time = true;
        } else if (arg_transport == BUS_TRANSPORT_LOCAL) {
                sec = time(NULL);
                have_time = true;
        } else
                fprintf(stderr, "Warning: Could not get time from timedated and not operating locally.\n\n");

        if (have_time) {
                zero(tm);
                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S %Z", localtime_r(&sec, &tm)) > 0);
                char_array_0(a);
                printf("      Local time: %s\n", a);

                zero(tm);
                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S UTC", gmtime_r(&sec, &tm)) > 0);
                char_array_0(a);
                printf("  Universal time: %s\n", a);
        } else {
                printf("      Local time: %s\n", "n/a");
                printf("  Universal time: %s\n", "n/a");
        }

        if (i->rtc_time > 0) {
                time_t rtc_sec;

                rtc_sec = (time_t)(i->rtc_time / USEC_PER_SEC);
                zero(tm);
                assert_se(strftime(a, sizeof(a), "%a %Y-%m-%d %H:%M:%S", gmtime_r(&rtc_sec, &tm)) > 0);
                char_array_0(a);
                printf("        RTC time: %s\n", a);
        } else
                printf("        RTC time: %s\n", "n/a");

        if (have_time) {
                zero(tm);
                assert_se(strftime(a, sizeof(a), "%Z, %z", localtime_r(&sec, &tm)) > 0);
                char_array_0(a);
        }

        printf("       Time zone: %s (%s)\n"
               "     NTP enabled: %s\n"
               "NTP synchronized: %s\n"
               " RTC in local TZ: %s\n",
               strna(i->timezone), have_time ? a : "n/a",
               i->ntp_capable ? yes_no(i->ntp_enabled) : "n/a",
               yes_no(i->ntp_synced),
               yes_no(i->rtc_local));

        if (have_time) {
                r = time_get_dst(sec, "/etc/localtime",
                                 &tc, &zc, &is_dstc,
                                 &tn, &dn, &zn, &is_dstn);
                if (r < 0)
                        printf("      DST active: %s\n", "n/a");
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
                }
        } else
                printf("      DST active: %s\n", yes_no(is_dstc));

        if (i->rtc_local)
                fputs("\n" ANSI_HIGHLIGHT_ON
                      "Warning: The RTC is configured to maintain time in the local time zone. This\n"
                      "         mode is not fully supported and will create various problems with time\n"
                      "         zone changes and daylight saving time adjustments. If at all possible, use\n"
                      "         RTC in UTC by calling 'timedatectl set-local-rtc 0'" ANSI_HIGHLIGHT_OFF ".\n", stdout);
}

static int show_status(sd_bus *bus, char **args, unsigned n) {
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
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.timedate1",
                                   "/org/freedesktop/timedate1",
                                   map,
                                   &info);
        if (r < 0) {
                log_error("Failed to query server: %s", strerror(-r));
                goto fail;
        }

        print_status_info(&info);

fail:
        free(info.timezone);
        return r;
}

static int set_time(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        bool relative = false, interactive = arg_ask_password;
        usec_t t;
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        r = parse_timestamp(args[1], &t);
        if (r < 0) {
                log_error("Failed to parse time specification: %s", args[1]);
                return r;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetTime",
                               &error,
                               NULL,
                               "xbb", (int64_t)t, relative, interactive);
        if (r < 0)
                log_error("Failed to set time: %s", bus_error_message(&error, -r));

        return r;
}

static int set_timezone(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetTimezone",
                               &error,
                               NULL,
                               "sb", args[1], arg_ask_password);
        if (r < 0)
                log_error("Failed to set time zone: %s", bus_error_message(&error, -r));

        return r;
}

static int set_local_rtc(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, b;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        b = parse_boolean(args[1]);
        if (b < 0) {
                log_error("Failed to parse local RTC setting: %s", args[1]);
                return b;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetLocalRTC",
                               &error,
                               NULL,
                               "bbb", b, arg_adjust_system_clock, arg_ask_password);
        if (r < 0)
                log_error("Failed to set local RTC: %s", bus_error_message(&error, -r));

        return r;
}

static int set_ntp(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int b, r;

        assert(args);
        assert(n == 2);

        polkit_agent_open_if_enabled();

        b = parse_boolean(args[1]);
        if (b < 0) {
                log_error("Failed to parse NTP setting: %s", args[1]);
                return b;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "SetNTP",
                               &error,
                               NULL,
                               "bb", b, arg_ask_password);
        if (r < 0)
                log_error("Failed to set ntp: %s", bus_error_message(&error, -r));

        return r;
}

static int list_timezones(sd_bus *bus, char **args, unsigned n) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **zones = NULL;
        size_t n_zones = 0;

        assert(args);
        assert(n == 1);

        f = fopen("/usr/share/zoneinfo/zone.tab", "re");
        if (!f) {
                log_error("Failed to open time zone database: %m");
                return -errno;
        }

        for (;;) {
                char l[LINE_MAX], *p, **z, *w;
                size_t k;

                if (!fgets(l, sizeof(l), f)) {
                        if (feof(f))
                                break;

                        log_error("Failed to read time zone database: %m");
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
               "  set-ntp BOOL             Control whether NTP is enabled\n",
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
                { "machine",             required_argument, NULL, 'M'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "adjust-system-clock", no_argument,       NULL, ARG_ADJUST_SYSTEM_CLOCK },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_CONTAINER;
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
        }

        return 1;
}

static int timedatectl_main(sd_bus *bus, int argc, char *argv[]) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(sd_bus *bus, char **args, unsigned n);
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

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char *argv[]) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bus_open_transport(arg_transport, arg_host, false, &bus);
        if (r < 0) {
                log_error("Failed to create bus connection: %s", strerror(-r));
                goto finish;
        }

        r = timedatectl_main(bus, argc, argv);

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
