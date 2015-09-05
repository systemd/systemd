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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sd-messages.h"
#include "sd-event.h"
#include "sd-bus.h"

#include "util.h"
#include "strv.h"
#include "def.h"
#include "clock-util.h"
#include "path-util.h"
#include "fileio-label.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-common-errors.h"
#include "event-util.h"
#include "selinux-util.h"

#define NULL_ADJTIME_UTC "0.0 0 0\n0\nUTC\n"
#define NULL_ADJTIME_LOCAL "0.0 0 0\n0\nLOCAL\n"

static BUS_ERROR_MAP_ELF_REGISTER const sd_bus_error_map timedated_errors[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.timedate1.NoNTPSupport", EOPNOTSUPP),
        SD_BUS_ERROR_MAP_END
};

typedef struct Context {
        char *zone;
        bool local_rtc;
        bool can_ntp;
        bool use_ntp;
        Hashmap *polkit_registry;
} Context;

static void context_free(Context *c) {
        assert(c);

        free(c->zone);
        bus_verify_polkit_async_registry_free(c->polkit_registry);
}

static int context_read_data(Context *c) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(c);

        r = get_timezone(&t);
        if (r == -EINVAL)
                log_warning_errno(r, "/etc/localtime should be a symbolic link to a time zone data file in /usr/share/zoneinfo/.");
        else if (r < 0)
                log_warning_errno(r, "Failed to get target of /etc/localtime: %m");

        free(c->zone);
        c->zone = t;
        t = NULL;

        c->local_rtc = clock_is_localtime() > 0;

        return 0;
}

static int context_write_data_timezone(Context *c) {
        _cleanup_free_ char *p = NULL;
        int r = 0;

        assert(c);

        if (isempty(c->zone)) {
                if (unlink("/etc/localtime") < 0 && errno != ENOENT)
                        r = -errno;

                return r;
        }

        p = strappend("../usr/share/zoneinfo/", c->zone);
        if (!p)
                return log_oom();

        r = symlink_atomic(p, "/etc/localtime");
        if (r < 0)
                return r;

        return 0;
}

static int context_write_data_local_rtc(Context *c) {
        int r;
        _cleanup_free_ char *s = NULL, *w = NULL;

        assert(c);

        r = read_full_file("/etc/adjtime", &s, NULL);
        if (r < 0) {
                if (r != -ENOENT)
                        return r;

                if (!c->local_rtc)
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

                w = new(char, a + (c->local_rtc ? 5 : 3) + b + 1);
                if (!w)
                        return -ENOMEM;

                *(char*) mempcpy(stpcpy(mempcpy(w, s, a), c->local_rtc ? "LOCAL" : "UTC"), e, b) = 0;

                if (streq(w, NULL_ADJTIME_UTC)) {
                        if (unlink("/etc/adjtime") < 0)
                                if (errno != ENOENT)
                                        return -errno;

                        return 0;
                }
        }

        mac_selinux_init("/etc");
        return write_string_file_atomic_label("/etc/adjtime", w);
}

static int context_read_ntp(Context *c, sd_bus *bus) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *s;
        int r;

        assert(c);
        assert(bus);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "GetUnitFileState",
                        &error,
                        &reply,
                        "s",
                        "systemd-timesyncd.service");

        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_FILE_NOT_FOUND) ||
                    sd_bus_error_has_name(&error, "org.freedesktop.systemd1.LoadFailed") ||
                    sd_bus_error_has_name(&error, "org.freedesktop.systemd1.NoSuchUnit"))
                        return 0;

                return r;
        }

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return r;

        c->can_ntp = true;
        c->use_ntp = STR_IN_SET(s, "enabled", "enabled-runtime");

        return 0;
}

static int context_start_ntp(sd_bus *bus, sd_bus_error *error, bool enabled) {
        int r;

        assert(bus);
        assert(error);

        r = sd_bus_call_method(
                bus,
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                enabled ? "StartUnit" : "StopUnit",
                error,
                NULL,
                "ss",
                "systemd-timesyncd.service",
                "replace");
        if (r < 0) {
                if (sd_bus_error_has_name(error, SD_BUS_ERROR_FILE_NOT_FOUND) ||
                    sd_bus_error_has_name(error, "org.freedesktop.systemd1.LoadFailed") ||
                    sd_bus_error_has_name(error, "org.freedesktop.systemd1.NoSuchUnit"))
                        return sd_bus_error_set_const(error, "org.freedesktop.timedate1.NoNTPSupport", "NTP not supported.");

                return r;
        }

        return 0;
}

static int context_enable_ntp(sd_bus *bus, sd_bus_error *error, bool enabled) {
        int r;

        assert(bus);
        assert(error);

        if (enabled)
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "EnableUnitFiles",
                                error,
                                NULL,
                                "asbb", 1,
                                "systemd-timesyncd.service",
                                false, true);
        else
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "DisableUnitFiles",
                                error,
                                NULL,
                                "asb", 1,
                                "systemd-timesyncd.service",
                                false);

        if (r < 0) {
                if (sd_bus_error_has_name(error, SD_BUS_ERROR_FILE_NOT_FOUND))
                        return sd_bus_error_set_const(error, "org.freedesktop.timedate1.NoNTPSupport", "NTP not supported.");

                return r;
        }

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Reload",
                        error,
                        NULL,
                        NULL);
        if (r < 0)
                return r;

        return 0;
}

static int property_get_rtc_time(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        struct tm tm;
        usec_t t;
        int r;

        zero(tm);
        r = clock_get_hwclock(&tm);
        if (r == -EBUSY) {
                log_warning("/dev/rtc is busy. Is somebody keeping it open continuously? That's not a good idea... Returning a bogus RTC timestamp.");
                t = 0;
        } else if (r == -ENOENT) {
                log_debug("/dev/rtc not found.");
                t = 0; /* no RTC found */
        } else if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to read RTC: %m");
        else
                t = (usec_t) timegm(&tm) * USEC_PER_SEC;

        return sd_bus_message_append(reply, "t", t);
}

static int property_get_time(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        return sd_bus_message_append(reply, "t", now(CLOCK_REALTIME));
}

static int property_get_ntp_sync(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        return sd_bus_message_append(reply, "b", ntp_synced());
}

static int method_set_timezone(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *z;
        int interactive;
        char *t;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "sb", &z, &interactive);
        if (r < 0)
                return r;

        if (!timezone_is_valid(z))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid time zone '%s'", z);

        if (streq_ptr(z, c->zone))
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_TIME,
                        "org.freedesktop.timedate1.set-timezone",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        t = strdup(z);
        if (!t)
                return -ENOMEM;

        free(c->zone);
        c->zone = t;

        /* 1. Write new configuration file */
        r = context_write_data_timezone(c);
        if (r < 0) {
                log_error_errno(r, "Failed to set time zone: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set time zone: %m");
        }

        /* 2. Tell the kernel our timezone */
        clock_set_timezone(NULL);

        if (c->local_rtc) {
                struct timespec ts;
                struct tm *tm;

                /* 3. Sync RTC from system clock, with the new delta */
                assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
                assert_se(tm = localtime(&ts.tv_sec));
                clock_set_hwclock(tm);
        }

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_TIMEZONE_CHANGE),
                   "TIMEZONE=%s", c->zone,
                   LOG_MESSAGE("Changed time zone to '%s'.", c->zone),
                   NULL);

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "Timezone", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_local_rtc(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int lrtc, fix_system, interactive;
        Context *c = userdata;
        struct timespec ts;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "bbb", &lrtc, &fix_system, &interactive);
        if (r < 0)
                return r;

        if (lrtc == c->local_rtc)
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_TIME,
                        "org.freedesktop.timedate1.set-local-rtc",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        c->local_rtc = lrtc;

        /* 1. Write new configuration file */
        r = context_write_data_local_rtc(c);
        if (r < 0) {
                log_error_errno(r, "Failed to set RTC to local/UTC: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set RTC to local/UTC: %m");
        }

        /* 2. Tell the kernel our timezone */
        clock_set_timezone(NULL);

        /* 3. Synchronize clocks */
        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);

        if (fix_system) {
                struct tm tm;

                /* Sync system clock from RTC; first,
                 * initialize the timezone fields of
                 * struct tm. */
                if (c->local_rtc)
                        tm = *localtime(&ts.tv_sec);
                else
                        tm = *gmtime(&ts.tv_sec);

                /* Override the main fields of
                 * struct tm, but not the timezone
                 * fields */
                if (clock_get_hwclock(&tm) >= 0) {

                        /* And set the system clock
                         * with this */
                        if (c->local_rtc)
                                ts.tv_sec = mktime(&tm);
                        else
                                ts.tv_sec = timegm(&tm);

                        clock_settime(CLOCK_REALTIME, &ts);
                }

        } else {
                struct tm *tm;

                /* Sync RTC from system clock */
                if (c->local_rtc)
                        tm = localtime(&ts.tv_sec);
                else
                        tm = gmtime(&ts.tv_sec);

                clock_set_hwclock(tm);
        }

        log_info("RTC configured to %s time.", c->local_rtc ? "local" : "UTC");

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "LocalRTC", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_time(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int relative, interactive;
        Context *c = userdata;
        int64_t utc;
        struct timespec ts;
        usec_t start;
        struct tm* tm;
        int r;

        assert(m);
        assert(c);

        if (c->use_ntp)
                return sd_bus_error_setf(error, BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED, "Automatic time synchronization is enabled");

        /* this only gets used if dbus does not provide a timestamp */
        start = now(CLOCK_MONOTONIC);

        r = sd_bus_message_read(m, "xbb", &utc, &relative, &interactive);
        if (r < 0)
                return r;

        if (!relative && utc <= 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid absolute time");

        if (relative && utc == 0)
                return sd_bus_reply_method_return(m, NULL);

        if (relative) {
                usec_t n, x;

                n = now(CLOCK_REALTIME);
                x = n + utc;

                if ((utc > 0 && x < n) ||
                    (utc < 0 && x > n))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Time value overflow");

                timespec_store(&ts, x);
        } else
                timespec_store(&ts, (usec_t) utc);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_TIME,
                        "org.freedesktop.timedate1.set-time",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        /* adjust ts for time spent in program */
        r = sd_bus_message_get_monotonic_usec(m, &start);
        /* when sd_bus_message_get_monotonic_usec() returns -ENODATA it does not modify &start */
        if (r < 0 && r != -ENODATA)
                return r;

        timespec_store(&ts, timespec_load(&ts) + (now(CLOCK_MONOTONIC) - start));

        /* Set system clock */
        if (clock_settime(CLOCK_REALTIME, &ts) < 0) {
                log_error_errno(errno, "Failed to set local time: %m");
                return sd_bus_error_set_errnof(error, errno, "Failed to set local time: %m");
        }

        /* Sync down to RTC */
        if (c->local_rtc)
                tm = localtime(&ts.tv_sec);
        else
                tm = gmtime(&ts.tv_sec);
        clock_set_hwclock(tm);

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_TIME_CHANGE),
                   "REALTIME="USEC_FMT, timespec_load(&ts),
                   LOG_MESSAGE("Changed local time to %s", ctime(&ts.tv_sec)),
                   NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_ntp(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int enabled, interactive;
        Context *c = userdata;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "bb", &enabled, &interactive);
        if (r < 0)
                return r;

        if ((bool)enabled == c->use_ntp)
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async(
                        m,
                        CAP_SYS_TIME,
                        "org.freedesktop.timedate1.set-ntp",
                        NULL,
                        interactive,
                        UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        r = context_enable_ntp(sd_bus_message_get_bus(m), error, enabled);
        if (r < 0)
                return r;

        r = context_start_ntp(sd_bus_message_get_bus(m), error, enabled);
        if (r < 0)
                return r;

        c->use_ntp = enabled;
        log_info("Set NTP to %s", enabled ? "enabled" : "disabled");

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m), "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "NTP", NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable timedate_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Timezone", "s", NULL, offsetof(Context, zone), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("LocalRTC", "b", bus_property_get_bool, offsetof(Context, local_rtc), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanNTP", "b", bus_property_get_bool, offsetof(Context, can_ntp), 0),
        SD_BUS_PROPERTY("NTP", "b", bus_property_get_bool, offsetof(Context, use_ntp), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NTPSynchronized", "b", property_get_ntp_sync, 0, 0),
        SD_BUS_PROPERTY("TimeUSec", "t", property_get_time, 0, 0),
        SD_BUS_PROPERTY("RTCTimeUSec", "t", property_get_rtc_time, 0, 0),
        SD_BUS_METHOD("SetTime", "xbb", NULL, method_set_time, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetTimezone", "sb", NULL, method_set_timezone, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetLocalRTC", "bbb", NULL, method_set_local_rtc, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetNTP", "bb", NULL, method_set_ntp, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static int connect_bus(Context *c, sd_event *event, sd_bus **_bus) {
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/timedate1", "org.freedesktop.timedate1", timedate_vtable, c);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_request_name(bus, "org.freedesktop.timedate1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to register name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *_bus = bus;
        bus = NULL;

        return 0;
}

int main(int argc, char *argv[]) {
        Context context = {};
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = sd_event_default(&event);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate event loop: %m");
                goto finish;
        }

        sd_event_set_watchdog(event, true);

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                goto finish;

        (void) sd_bus_negotiate_timestamp(bus, true);

        r = context_read_data(&context);
        if (r < 0) {
                log_error_errno(r, "Failed to read time zone data: %m");
                goto finish;
        }

        r = context_read_ntp(&context, bus);
        if (r < 0) {
                log_error_errno(r, "Failed to determine whether NTP is enabled: %m");
                goto finish;
        }

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.timedate1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to run event loop: %m");
                goto finish;
        }

finish:
        context_free(&context);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
