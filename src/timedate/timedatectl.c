/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>
#include <locale.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-util.h"
#include "in-addr-util.h"
#include "main-func.h"
#include "pager.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "spawn-polkit-agent.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static bool arg_ask_password = true;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_adjust_system_clock = false;
static bool arg_monitor = false;
static char **arg_property = NULL;
static bool arg_value = false;
static bool arg_all = false;

typedef struct StatusInfo {
        usec_t time;
        const char *timezone;

        usec_t rtc_time;
        bool rtc_local;

        bool ntp_capable;
        bool ntp_active;
        bool ntp_synced;
} StatusInfo;

static void print_status_info(const StatusInfo *i) {
        const char *old_tz = NULL, *tz;
        bool have_time = false;
        char a[LINE_MAX];
        struct tm tm;
        time_t sec;
        size_t n;
        int r;

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
                printf("               Local time: %s\n", n > 0 ? a : "n/a");

                n = strftime(a, sizeof a, "%a %Y-%m-%d %H:%M:%S UTC", gmtime_r(&sec, &tm));
                printf("           Universal time: %s\n", n > 0 ? a : "n/a");
        } else {
                printf("               Local time: %s\n", "n/a");
                printf("           Universal time: %s\n", "n/a");
        }

        if (i->rtc_time > 0) {
                time_t rtc_sec;

                rtc_sec = (time_t) (i->rtc_time / USEC_PER_SEC);
                n = strftime(a, sizeof a, "%a %Y-%m-%d %H:%M:%S", gmtime_r(&rtc_sec, &tm));
                printf("                 RTC time: %s\n", n > 0 ? a : "n/a");
        } else
                printf("                 RTC time: %s\n", "n/a");

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

        printf("                Time zone: %s (%s)\n"
               "System clock synchronized: %s\n"
               "              NTP service: %s\n"
               "          RTC in local TZ: %s\n",
               strna(i->timezone), have_time && n > 0 ? a : "n/a",
               yes_no(i->ntp_synced),
               i->ntp_capable ? (i->ntp_active ? "active" : "inactive") : "n/a",
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
                { "Timezone",        "s", NULL, offsetof(StatusInfo, timezone)    },
                { "LocalRTC",        "b", NULL, offsetof(StatusInfo, rtc_local)   },
                { "NTP",             "b", NULL, offsetof(StatusInfo, ntp_active)  },
                { "CanNTP",          "b", NULL, offsetof(StatusInfo, ntp_capable) },
                { "NTPSynchronized", "b", NULL, offsetof(StatusInfo, ntp_synced)  },
                { "TimeUSec",        "t", NULL, offsetof(StatusInfo, time)        },
                { "RTCTimeUSec",     "t", NULL, offsetof(StatusInfo, rtc_time)    },
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
                                   BUS_MAP_BOOLEAN_AS_BOOL,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Failed to query server: %s", bus_error_message(&error, r));

        print_status_info(&info);

        return r;
}

static int show_properties(int argc, char **argv, void *userdata) {
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = bus_print_all_properties(bus,
                                     "org.freedesktop.timedate1",
                                     "/org/freedesktop/timedate1",
                                     NULL,
                                     arg_property,
                                     arg_value,
                                     arg_all,
                                     NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
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
                return log_error_errno(r, "Failed to set time: %s", bus_error_message(&error, r));

        return 0;
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
                return log_error_errno(r, "Failed to set time zone: %s", bus_error_message(&error, r));

        return 0;
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
                return log_error_errno(r, "Failed to set local RTC: %s", bus_error_message(&error, r));

        return 0;
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
                return log_error_errno(r, "Failed to set ntp: %s", bus_error_message(&error, r));

        return 0;
}

static int list_timezones(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;
        char** zones;

        r = sd_bus_call_method(bus,
                               "org.freedesktop.timedate1",
                               "/org/freedesktop/timedate1",
                               "org.freedesktop.timedate1",
                               "ListTimezones",
                               &error,
                               &reply,
                               NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request list of time zones: %s",
                                       bus_error_message(&error, r));

        r = sd_bus_message_read_strv(reply, &zones);
        if (r < 0)
                return bus_log_parse_error(r);

        (void) pager_open(arg_pager_flags);
        strv_print(zones);

        return 0;
}

typedef struct NTPStatusInfo {
        const char *server_name;
        char *server_address;
        usec_t poll_interval, poll_max, poll_min;
        usec_t root_distance_max;

        uint32_t leap, version, mode, stratum;
        int32_t precision;
        usec_t root_delay, root_dispersion;
        union {
                char str[5];
                uint32_t val;
        } reference;
        usec_t origin, recv, trans, dest;

        bool spike;
        uint64_t packet_count;
        usec_t jitter;

        int64_t freq;
} NTPStatusInfo;

static void ntp_status_info_clear(NTPStatusInfo *p) {
        p->server_address = mfree(p->server_address);
}

static const char * const ntp_leap_table[4] = {
        [0] = "normal",
        [1] = "last minute of the day has 61 seconds",
        [2] = "last minute of the day has 59 seconds",
        [3] = "not synchronized",
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(ntp_leap, uint32_t);
#pragma GCC diagnostic pop

static void print_ntp_status_info(NTPStatusInfo *i) {
        char ts[FORMAT_TIMESPAN_MAX], tmin[FORMAT_TIMESPAN_MAX], tmax[FORMAT_TIMESPAN_MAX];
        usec_t delay, t14, t23, offset, root_distance;
        bool offset_sign;

        assert(i);

        /*
         * "Timestamp Name          ID   When Generated
         *  ------------------------------------------------------------
         *  Originate Timestamp     T1   time request sent by client
         *  Receive Timestamp       T2   time request received by server
         *  Transmit Timestamp      T3   time reply sent by server
         *  Destination Timestamp   T4   time reply received by client
         *
         *  The round-trip delay, d, and system clock offset, t, are defined as:
         *  d = (T4 - T1) - (T3 - T2)     t = ((T2 - T1) + (T3 - T4)) / 2"
         */

        printf("       Server: %s (%s)\n",
               i->server_address, i->server_name);
        printf("Poll interval: %s (min: %s; max %s)\n",
               format_timespan(ts, sizeof(ts), i->poll_interval, 0),
               format_timespan(tmin, sizeof(tmin), i->poll_min, 0),
               format_timespan(tmax, sizeof(tmax), i->poll_max, 0));

        if (i->packet_count == 0) {
                printf(" Packet count: 0\n");
                return;
        }

        if (i->dest < i->origin || i->trans < i->recv || i->dest - i->origin < i->trans - i->recv) {
                log_error("Invalid NTP response");
                return;
        }

        delay = (i->dest - i->origin) - (i->trans - i->recv);

        t14 = i->origin + i->dest;
        t23 = i->recv + i->trans;
        offset_sign = t14 < t23;
        offset = (offset_sign ? t23 - t14 : t14 - t23) / 2;

        root_distance = i->root_delay / 2 + i->root_dispersion;

        printf("         Leap: %s\n"
               "      Version: %" PRIu32 "\n"
               "      Stratum: %" PRIu32 "\n",
               ntp_leap_to_string(i->leap),
               i->version,
               i->stratum);
        if (i->stratum <= 1)
                printf("    Reference: %s\n", i->reference.str);
        else
                printf("    Reference: %" PRIX32 "\n", be32toh(i->reference.val));
        printf("    Precision: %s (%" PRIi32 ")\n",
               format_timespan(ts, sizeof(ts), DIV_ROUND_UP((nsec_t) (exp2(i->precision) * NSEC_PER_SEC), NSEC_PER_USEC), 0),
               i->precision);
        printf("Root distance: %s (max: %s)\n",
               format_timespan(ts, sizeof(ts), root_distance, 0),
               format_timespan(tmax, sizeof(tmax), i->root_distance_max, 0));
        printf("       Offset: %s%s\n",
               offset_sign ? "+" : "-",
               format_timespan(ts, sizeof(ts), offset, 0));
        printf("        Delay: %s\n",
               format_timespan(ts, sizeof(ts), delay, 0));
        printf("       Jitter: %s\n",
               format_timespan(ts, sizeof(ts), i->jitter, 0));
        printf(" Packet count: %" PRIu64 "\n", i->packet_count);

        if (!i->spike)
                printf("    Frequency: %+.3fppm\n",
                       (double) i->freq / 0x10000);
}

static int map_server_address(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        char **p = (char **) userdata;
        const void *d;
        int family, r;
        size_t sz;

        assert(p);

        r = sd_bus_message_enter_container(m, 'r', "iay");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "i", &family);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(m, 'y', &d, &sz);
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        if (sz == 0 && family == AF_UNSPEC) {
                *p = mfree(*p);
                return 0;
        }

        if (!IN_SET(family, AF_INET, AF_INET6))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown address family %i", family);

        if (sz != FAMILY_ADDRESS_SIZE(family))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid address size");

        r = in_addr_to_string(family, d, p);
        if (r < 0)
                return r;

        return 0;
}

static int map_ntp_message(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        NTPStatusInfo *p = userdata;
        const void *d;
        size_t sz;
        int32_t b;
        int r;

        assert(p);

        r = sd_bus_message_enter_container(m, 'r', "uuuuittayttttbtt");
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "uuuuitt",
                                &p->leap, &p->version, &p->mode, &p->stratum, &p->precision,
                                &p->root_delay, &p->root_dispersion);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(m, 'y', &d, &sz);
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "ttttbtt",
                                &p->origin, &p->recv, &p->trans, &p->dest,
                                &b, &p->packet_count, &p->jitter);
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        if (sz != 4)
                return -EINVAL;

        memcpy(p->reference.str, d, sz);

        p->spike = b;

        return 0;
}

static int show_timesync_status_once(sd_bus *bus) {
        static const struct bus_properties_map map_timesync[]  = {
                { "ServerName",           "s",                  NULL,               offsetof(NTPStatusInfo, server_name)       },
                { "ServerAddress",        "(iay)",              map_server_address, offsetof(NTPStatusInfo, server_address)    },
                { "PollIntervalUSec",     "t",                  NULL,               offsetof(NTPStatusInfo, poll_interval)     },
                { "PollIntervalMinUSec",  "t",                  NULL,               offsetof(NTPStatusInfo, poll_min)          },
                { "PollIntervalMaxUSec",  "t",                  NULL,               offsetof(NTPStatusInfo, poll_max)          },
                { "RootDistanceMaxUSec",  "t",                  NULL,               offsetof(NTPStatusInfo, root_distance_max) },
                { "NTPMessage",           "(uuuuittayttttbtt)", map_ntp_message,    0                                          },
                { "Frequency",            "x",                  NULL,               offsetof(NTPStatusInfo, freq)              },
                {}
        };
        _cleanup_(ntp_status_info_clear) NTPStatusInfo info = {};
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.timesync1",
                                   "/org/freedesktop/timesync1",
                                   map_timesync,
                                   BUS_MAP_BOOLEAN_AS_BOOL,
                                   &error,
                                   &m,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Failed to query server: %s", bus_error_message(&error, r));

        if (arg_monitor && !terminal_is_dumb())
                fputs(ANSI_HOME_CLEAR, stdout);

        print_ntp_status_info(&info);

        return 0;
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *name;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to read interface name: %m");

        if (!streq_ptr(name, "org.freedesktop.timesync1.Manager"))
                return 0;

        return show_timesync_status_once(sd_bus_message_get_bus(m));
}

static int show_timesync_status(int argc, char **argv, void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = show_timesync_status_once(bus);
        if (r < 0)
                return r;

        if (!arg_monitor)
                return 0;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_match_signal(bus,
                                NULL,
                                "org.freedesktop.timesync1",
                                "/org/freedesktop/timesync1",
                                "org.freedesktop.DBus.Properties",
                                "PropertiesChanged",
                                on_properties_changed, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PropertiesChanged signal: %m");

        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

static int print_timesync_property(const char *name, const char *expected_value, sd_bus_message *m, bool value, bool all) {
        char type;
        const char *contents;
        int r;

        assert(name);
        assert(m);

        r = sd_bus_message_peek_type(m, &type, &contents);
        if (r < 0)
                return r;

        switch (type) {

        case SD_BUS_TYPE_STRUCT:
                if (streq(name, "NTPMessage")) {
                        _cleanup_(ntp_status_info_clear) NTPStatusInfo i = {};
                        char ts[FORMAT_TIMESPAN_MAX], stamp[FORMAT_TIMESTAMP_MAX];

                        r = map_ntp_message(NULL, NULL, m, NULL, &i);
                        if (r < 0)
                                return r;

                        if (i.packet_count == 0)
                                return 1;

                        if (!value) {
                                fputs(name, stdout);
                                fputc('=', stdout);
                        }

                        printf("{ Leap=%u, Version=%u, Mode=%u, Stratum=%u, Precision=%i,",
                               i.leap, i.version, i.mode, i.stratum, i.precision);
                        printf(" RootDelay=%s,",
                               format_timespan(ts, sizeof(ts), i.root_delay, 0));
                        printf(" RootDispersion=%s,",
                               format_timespan(ts, sizeof(ts), i.root_dispersion, 0));

                        if (i.stratum == 1)
                                printf(" Reference=%s,", i.reference.str);
                        else
                                printf(" Reference=%" PRIX32 ",", be32toh(i.reference.val));

                        printf(" OriginateTimestamp=%s,",
                               format_timestamp(stamp, sizeof(stamp), i.origin));
                        printf(" ReceiveTimestamp=%s,",
                               format_timestamp(stamp, sizeof(stamp), i.recv));
                        printf(" TransmitTimestamp=%s,",
                               format_timestamp(stamp, sizeof(stamp), i.trans));
                        printf(" DestinationTimestamp=%s,",
                               format_timestamp(stamp, sizeof(stamp), i.dest));
                        printf(" Ignored=%s PacketCount=%" PRIu64 ",",
                               yes_no(i.spike), i.packet_count);
                        printf(" Jitter=%s }\n",
                               format_timespan(ts, sizeof(ts), i.jitter, 0));

                        return 1;

                } else if (streq(name, "ServerAddress")) {
                        _cleanup_free_ char *str = NULL;

                        r = map_server_address(NULL, NULL, m, NULL, &str);
                        if (r < 0)
                                return r;

                        if (arg_all || !isempty(str))
                                bus_print_property_value(name, expected_value, value, str);

                        return 1;
                }
                break;
        }

        return 0;
}

static int show_timesync(int argc, char **argv, void *userdata) {
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = bus_print_all_properties(bus,
                                     "org.freedesktop.timesync1",
                                     "/org/freedesktop/timesync1",
                                     print_timesync_property,
                                     arg_property,
                                     arg_value,
                                     arg_all,
                                     NULL);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int parse_ifindex_bus(sd_bus *bus, const char *str, int *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int32_t i;
        int r;

        assert(bus);
        assert(str);
        assert(ret);

        r = parse_ifindex(str, ret);
        if (r >= 0)
                return 0;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.network1",
                        "/org/freedesktop/network1",
                        "org.freedesktop.network1.Manager",
                        "GetLinkByName",
                        &error,
                        &reply,
                        "s", str);
        if (r < 0)
                return log_error_errno(r, "Failed to get ifindex of interfaces %s: %s", str, bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "io", &i, NULL);
        if (r < 0)
                return bus_log_create_error(r);

        *ret = i;
        return 0;
}

static int verb_ntp_servers(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *req = NULL;
        sd_bus *bus = userdata;
        int ifindex, r;

        assert(bus);

        r = parse_ifindex_bus(bus, argv[1], &ifindex);
        if (r < 0)
                return r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_message_new_method_call(
                        bus,
                        &req,
                        "org.freedesktop.network1",
                        "/org/freedesktop/network1",
                        "org.freedesktop.network1.Manager",
                        "SetLinkNTP");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(req, "i", ifindex);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(req, argv + 2);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, req, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set NTP servers: %s", bus_error_message(&error, r));

        return 0;
}

static int verb_revert(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int ifindex, r;

        assert(bus);

        r = parse_ifindex_bus(bus, argv[1], &ifindex);
        if (r < 0)
                return r;

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.network1",
                        "/org/freedesktop/network1",
                        "org.freedesktop.network1.Manager",
                        "RevertLinkNTP",
                        &error,
                        NULL,
                        "i", ifindex);
        if (r < 0)
                return log_error_errno(r, "Failed to revert interface configuration: %s", bus_error_message(&error, r));

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("timedatectl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "Query or change system time and date settings.\n\n"
               "  -h --help                Show this help message\n"
               "     --version             Show package version\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-ask-password     Do not prompt for password\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --adjust-system-clock Adjust system clock when changing local RTC mode\n"
               "     --monitor             Monitor status of systemd-timesyncd\n"
               "  -p --property=NAME       Show only properties by this name\n"
               "  -a --all                 Show all properties, including empty ones\n"
               "     --value               When showing properties, only print the value\n"
               "\n"
               "Commands:\n"
               "  status                   Show current time settings\n"
               "  show                     Show properties of systemd-timedated\n"
               "  set-time TIME            Set system time\n"
               "  set-timezone ZONE        Set system time zone\n"
               "  list-timezones           Show known time zones\n"
               "  set-local-rtc BOOL       Control whether RTC is in local time\n"
               "  set-ntp BOOL             Enable or disable network time synchronization\n"
               "\n"
               "systemd-timesyncd Commands:\n"
               "  timesync-status          Show status of systemd-timesyncd\n"
               "  show-timesync            Show properties of systemd-timesyncd\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

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
                ARG_NO_ASK_PASSWORD,
                ARG_MONITOR,
                ARG_VALUE,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                { "no-pager",            no_argument,       NULL, ARG_NO_PAGER            },
                { "host",                required_argument, NULL, 'H'                     },
                { "machine",             required_argument, NULL, 'M'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "adjust-system-clock", no_argument,       NULL, ARG_ADJUST_SYSTEM_CLOCK },
                { "monitor",             no_argument,       NULL, ARG_MONITOR             },
                { "property",            required_argument, NULL, 'p'                     },
                { "all",                 no_argument,       NULL, 'a'                     },
                { "value",               no_argument,       NULL, ARG_VALUE               },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:p:a", options, NULL)) >= 0)

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
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_MONITOR:
                        arg_monitor = true;
                        break;

                case 'p': {
                        r = strv_extend(&arg_property, optarg);
                        if (r < 0)
                                return log_oom();

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
                        break;
                }

                case 'a':
                        arg_all = true;
                        break;

                case ARG_VALUE:
                        arg_value = true;
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
                { "status",          VERB_ANY, 1,        VERB_DEFAULT, show_status          },
                { "show",            VERB_ANY, 1,        0,            show_properties      },
                { "set-time",        2,        2,        0,            set_time             },
                { "set-timezone",    2,        2,        0,            set_timezone         },
                { "list-timezones",  VERB_ANY, 1,        0,            list_timezones       },
                { "set-local-rtc",   2,        2,        0,            set_local_rtc        },
                { "set-ntp",         2,        2,        0,            set_ntp              },
                { "timesync-status", VERB_ANY, 1,        0,            show_timesync_status },
                { "show-timesync",   VERB_ANY, 1,        0,            show_timesync        },
                { "ntp-servers",     3,        VERB_ANY, 0,            verb_ntp_servers     },
                { "revert",          2,        2,        0,            verb_revert          },
                { "help",            VERB_ANY, VERB_ANY, 0,            verb_help            }, /* Not documented, but supported since it is created. */
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = bus_connect_transport(arg_transport, arg_host, false, &bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        return timedatectl_main(bus, argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
