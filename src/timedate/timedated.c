/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-get-properties.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-map-properties.h"
#include "bus-polkit.h"
#include "bus-unit-util.h"
#include "clock-util.h"
#include "conf-files.h"
#include "constants.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "list.h"
#include "main-func.h"
#include "memory-util.h"
#include "missing_capability.h"
#include "path-util.h"
#include "selinux-util.h"
#include "service-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-def.h"
#include "unit-name.h"
#include "user-util.h"

#define NULL_ADJTIME_UTC "0.0 0 0\n0\nUTC\n"
#define NULL_ADJTIME_LOCAL "0.0 0 0\n0\nLOCAL\n"

#define UNIT_LIST_DIRS (const char* const*) CONF_PATHS_STRV("systemd/ntp-units.d")

typedef struct UnitStatusInfo {
        char *name;
        char *load_state;
        char *unit_file_state;
        char *active_state;
        char *path;

        LIST_FIELDS(struct UnitStatusInfo, units);
} UnitStatusInfo;

typedef struct Context {
        char *zone;
        bool local_rtc;
        Hashmap *polkit_registry;
        sd_bus_message *cache;

        sd_bus_slot *slot_job_removed;

        LIST_HEAD(UnitStatusInfo, units);
} Context;

#define log_unit_full_errno_zerook(unit, level, error, ...)             \
        ({                                                              \
                const UnitStatusInfo *_u = (unit);                      \
                _u ? log_object_internal(level, error, PROJECT_FILE, __LINE__, __func__, "UNIT=", _u->name, NULL, NULL, ##__VA_ARGS__) : \
                        log_internal(level, error, PROJECT_FILE, __LINE__, __func__, ##__VA_ARGS__); \
        })

#define log_unit_full_errno(unit, level, error, ...) \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_unit_full_errno_zerook(unit, level, _error, ##__VA_ARGS__); \
        })

#define log_unit_full(unit, level, ...) (void) log_unit_full_errno_zerook(unit, level, 0, ##__VA_ARGS__)

#define log_unit_debug(unit, ...)   log_unit_full(unit, LOG_DEBUG, ##__VA_ARGS__)
#define log_unit_info(unit, ...)    log_unit_full(unit, LOG_INFO, ##__VA_ARGS__)
#define log_unit_notice(unit, ...)  log_unit_full(unit, LOG_NOTICE, ##__VA_ARGS__)
#define log_unit_warning(unit, ...) log_unit_full(unit, LOG_WARNING, ##__VA_ARGS__)
#define log_unit_error(unit, ...)   log_unit_full(unit, LOG_ERR, ##__VA_ARGS__)

#define log_unit_debug_errno(unit, error, ...)   log_unit_full_errno(unit, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_unit_info_errno(unit, error, ...)    log_unit_full_errno(unit, LOG_INFO, error, ##__VA_ARGS__)
#define log_unit_notice_errno(unit, error, ...)  log_unit_full_errno(unit, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_unit_warning_errno(unit, error, ...) log_unit_full_errno(unit, LOG_WARNING, error, ##__VA_ARGS__)
#define log_unit_error_errno(unit, error, ...)   log_unit_full_errno(unit, LOG_ERR, error, ##__VA_ARGS__)

static void unit_status_info_clear(UnitStatusInfo *p) {
        assert(p);

        p->load_state = mfree(p->load_state);
        p->unit_file_state = mfree(p->unit_file_state);
        p->active_state = mfree(p->active_state);
}

static UnitStatusInfo *unit_status_info_free(UnitStatusInfo *p) {
        if (!p)
                return NULL;

        unit_status_info_clear(p);
        free(p->name);
        free(p->path);
        return mfree(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UnitStatusInfo*, unit_status_info_free);

static void context_clear(Context *c) {
        assert(c);

        free(c->zone);
        bus_verify_polkit_async_registry_free(c->polkit_registry);
        sd_bus_message_unref(c->cache);

        sd_bus_slot_unref(c->slot_job_removed);

        LIST_CLEAR(units, c->units, unit_status_info_free);
}

static int context_add_ntp_service(Context *c, const char *s, const char *source) {
        _cleanup_(unit_status_info_freep) UnitStatusInfo *unit = NULL;

        assert(c);
        assert(s);
        assert(source);

        if (!unit_name_is_valid(s, UNIT_NAME_PLAIN))
                return -EINVAL;

        /* Do not add this if it is already listed */
        LIST_FOREACH(units, u, c->units)
                if (streq(u->name, s))
                        return 0;

        unit = new0(UnitStatusInfo, 1);
        if (!unit)
                return -ENOMEM;

        unit->name = strdup(s);
        if (!unit->name)
                return -ENOMEM;

        LIST_APPEND(units, c->units, unit);
        log_unit_debug(unit, "added from %s.", source);
        TAKE_PTR(unit);

        return 0;
}

static int context_parse_ntp_services_from_environment(Context *c) {
        const char *env, *p;
        int r;

        assert(c);

        env = getenv("SYSTEMD_TIMEDATED_NTP_SERVICES");
        if (!env)
                return 0;

        log_debug("Using list of ntp services from environment variable $SYSTEMD_TIMEDATED_NTP_SERVICES=%s.", env);

        for (p = env;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ":", 0);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_error("Invalid syntax, ignoring: %s", env);
                        break;
                }

                r = context_add_ntp_service(c, word, "$SYSTEMD_TIMEDATED_NTP_SERVICES");
                if (r < 0)
                        log_warning_errno(r, "Failed to add NTP service \"%s\", ignoring: %m", word);
        }

        return 1;
}

static int context_parse_ntp_services_from_disk(Context *c) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = conf_files_list_strv(&files, ".list", NULL, CONF_FILES_FILTER_MASKED, UNIT_LIST_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .list files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_fclose_ FILE *file = NULL;

                log_debug("Reading file '%s'", *f);

                r = fopen_unlocked(*f, "re", &file);
                if (r < 0) {
                        log_error_errno(r, "Failed to open %s, ignoring: %m", *f);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;

                        r = read_stripped_line(file, LINE_MAX, &line);
                        if (r < 0) {
                                log_error_errno(r, "Failed to read %s, ignoring: %m", *f);
                                continue;
                        }
                        if (r == 0)
                                break;

                        if (isempty(line) || startswith(line, "#"))
                                continue;

                        r = context_add_ntp_service(c, line, *f);
                        if (r < 0)
                                log_warning_errno(r, "Failed to add NTP service \"%s\", ignoring: %m", line);
                }
        }

        return 1;
}

static int context_parse_ntp_services(Context *c) {
        int r;

        r = context_parse_ntp_services_from_environment(c);
        if (r != 0)
                return r;

        return context_parse_ntp_services_from_disk(c);
}

static int context_ntp_service_is_active(Context *c) {
        int count = 0;

        assert(c);

        /* Call context_update_ntp_status() to update UnitStatusInfo before calling this. */

        LIST_FOREACH(units, info, c->units)
                count += !STRPTR_IN_SET(info->active_state, "inactive", "failed");

        return count;
}

static int context_ntp_service_exists(Context *c) {
        int count = 0;

        assert(c);

        /* Call context_update_ntp_status() to update UnitStatusInfo before calling this. */

        LIST_FOREACH(units, info, c->units)
                count += streq_ptr(info->load_state, "loaded");

        return count;
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

        free_and_replace(c->zone, t);

        c->local_rtc = clock_is_localtime(NULL) > 0;

        return 0;
}

static int context_write_data_timezone(Context *c) {
        _cleanup_free_ char *p = NULL;
        const char *source;

        assert(c);

        /* No timezone is very similar to UTC. Hence in either of these cases link the UTC file in. Except if
         * it isn't installed, in which case we remove the symlink altogether. Since glibc defaults to an
         * internal version of UTC in that case behaviour is mostly equivalent. We still prefer creating the
         * symlink though, since things are more self explanatory then. */

        if (isempty(c->zone) || streq(c->zone, "UTC")) {

                if (access("/usr/share/zoneinfo/UTC", F_OK) < 0) {

                        if (unlink("/etc/localtime") < 0 && errno != ENOENT)
                                return -errno;

                        return 0;
                }

                source = "../usr/share/zoneinfo/UTC";
        } else {
                p = path_join("../usr/share/zoneinfo", c->zone);
                if (!p)
                        return -ENOMEM;

                source = p;
        }

        return symlink_atomic(source, "/etc/localtime");
}

static int context_write_data_local_rtc(Context *c) {
        _cleanup_free_ char *s = NULL, *w = NULL;
        int r;

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
                char *p;
                const char *e = "\n"; /* default if there is less than 3 lines */
                const char *prepend = "";
                size_t a, b;

                p = strchrnul(s, '\n');
                if (*p == '\0')
                        /* only one line, no \n terminator */
                        prepend = "\n0\n";
                else if (p[1] == '\0') {
                        /* only one line, with \n terminator */
                        ++p;
                        prepend = "0\n";
                } else {
                        p = strchr(p+1, '\n');
                        if (!p) {
                                /* only two lines, no \n terminator */
                                prepend = "\n";
                                p = s + strlen(s);
                        } else {
                                char *end;
                                /* third line might have a \n terminator or not */
                                p++;
                                end = strchr(p, '\n');
                                /* if we actually have a fourth line, use that as suffix "e", otherwise the default \n */
                                if (end)
                                        e = end;
                        }
                }

                a = p - s;
                b = strlen(e);

                w = new(char, a + (c->local_rtc ? 5 : 3) + strlen(prepend) + b + 1);
                if (!w)
                        return -ENOMEM;

                *(char*) mempcpy(stpcpy(stpcpy(mempcpy(w, s, a), prepend), c->local_rtc ? "LOCAL" : "UTC"), e, b) = 0;

                if (streq(w, NULL_ADJTIME_UTC)) {
                        if (unlink("/etc/adjtime") < 0)
                                if (errno != ENOENT)
                                        return -errno;

                        return 0;
                }
        }

        r = mac_init();
        if (r < 0)
                return r;

        return write_string_file_atomic_label("/etc/adjtime", w);
}

static int context_update_ntp_status(Context *c, sd_bus *bus, sd_bus_message *m) {
        static const struct bus_properties_map map[] = {
                { "LoadState",     "s", NULL, offsetof(UnitStatusInfo, load_state)      },
                { "ActiveState",   "s", NULL, offsetof(UnitStatusInfo, active_state)    },
                { "UnitFileState", "s", NULL, offsetof(UnitStatusInfo, unit_file_state) },
                {}
        };
        int r;

        assert(c);
        assert(bus);

        /* Suppress calling context_update_ntp_status() multiple times within single DBus transaction. */
        if (m) {
                if (m == c->cache)
                        return 0;

                sd_bus_message_unref(c->cache);
                c->cache = sd_bus_message_ref(m);
        }

        LIST_FOREACH(units, u, c->units) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *path = NULL;

                unit_status_info_clear(u);

                path = unit_dbus_path_from_name(u->name);
                if (!path)
                        return -ENOMEM;

                r = bus_map_all_properties(
                                bus,
                                "org.freedesktop.systemd1",
                                path,
                                map,
                                BUS_MAP_STRDUP,
                                &error,
                                NULL,
                                u);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to get properties: %s", bus_error_message(&error, r));
        }

        return 0;
}

static int match_job_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        const char *path;
        unsigned n = 0;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "uoss", NULL, &path, NULL, NULL);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        LIST_FOREACH(units, u, c->units)
                if (streq_ptr(path, u->path))
                        u->path = mfree(u->path);
                else
                        n += !!u->path;

        if (n == 0) {
                c->slot_job_removed = sd_bus_slot_unref(c->slot_job_removed);

                (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                                      "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "NTP",
                                                      NULL);
        }

        return 0;
}

static int unit_start_or_stop(UnitStatusInfo *u, sd_bus *bus, sd_bus_error *error, bool start) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        int r;

        assert(u);
        assert(bus);
        assert(error);

        r = bus_call_method(
                bus,
                bus_systemd_mgr,
                start ? "StartUnit" : "StopUnit",
                error,
                &reply,
                "ss",
                u->name,
                "replace");
        log_unit_full_errno_zerook(u, r < 0 ? LOG_WARNING : LOG_DEBUG, r,
                                   "%s unit: %m", start ? "Starting" : "Stopping");
        if (r < 0)
                return r;

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = free_and_strdup(&u->path, path);
        if (r < 0)
                return log_oom();

        return 0;
}

static int unit_enable_or_disable(UnitStatusInfo *u, sd_bus *bus, sd_bus_error *error, bool enable) {
        int r;

        assert(u);
        assert(bus);
        assert(error);

        /* Call context_update_ntp_status() to update UnitStatusInfo before calling this. */

        if (streq(u->unit_file_state, "enabled") == enable) {
                log_unit_debug(u, "already %sd.", enable_disable(enable));
                return 0;
        }

        log_unit_info(u, "%s unit.", enable ? "Enabling" : "Disabling");

        if (enable)
                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "EnableUnitFiles",
                                error,
                                NULL,
                                "asbb", 1,
                                u->name,
                                false, true);
        else
                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "DisableUnitFiles",
                                error,
                                NULL,
                                "asb", 1,
                                u->name,
                                false);
        if (r < 0)
                return r;

        r = bus_service_manager_reload(bus);
        if (r < 0)
                return r;

        return 0;
}

static bool ntp_synced(void) {
        struct timex txc = {};

        if (adjtimex(&txc) < 0)
                return false;

        /* Consider the system clock synchronized if the reported maximum error is smaller than the maximum
         * value (16 seconds). Ignore the STA_UNSYNC flag as it may have been set to prevent the kernel from
         * touching the RTC. */
        return txc.maxerror < 16000000;
}

static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_time, "t", now(CLOCK_REALTIME));
static BUS_DEFINE_PROPERTY_GET_GLOBAL(property_get_ntp_sync, "b", ntp_synced());

static int property_get_rtc_time(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        struct tm tm = {};
        usec_t t = 0;
        int r;

        r = clock_get_hwclock(&tm);
        if (r == -EBUSY)
                log_warning("/dev/rtc is busy. Is somebody keeping it open continuously? That's not a good idea... Returning a bogus RTC timestamp.");
        else if (r == -ENOENT)
                log_debug("/dev/rtc not found.");
        else if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to read RTC: %m");
        else
                t = (usec_t) timegm(&tm) * USEC_PER_SEC;

        return sd_bus_message_append(reply, "t", t);
}

static int property_get_can_ntp(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(property);
        assert(reply);
        assert(error);

        if (c->slot_job_removed)
                /* When the previous request is not finished, then assume NTP is enabled. */
                return sd_bus_message_append(reply, "b", true);

        r = context_update_ntp_status(c, bus, reply);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "b", context_ntp_service_exists(c) > 0);
}

static int property_get_ntp(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(bus);
        assert(property);
        assert(reply);
        assert(error);

        if (c->slot_job_removed)
                /* When the previous request is not finished, then assume NTP is active. */
                return sd_bus_message_append(reply, "b", true);

        r = context_update_ntp_status(c, bus, reply);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "b", context_ntp_service_is_active(c) > 0);
}

static int method_set_timezone(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        int interactive, r;
        const char *z;

        assert(m);

        r = sd_bus_message_read(m, "sb", &z, &interactive);
        if (r < 0)
                return r;

        if (!timezone_is_valid(z, LOG_DEBUG))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid or not installed time zone '%s'", z);

        if (streq_ptr(z, c->zone))
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-timezone",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = free_and_strdup(&c->zone, z);
        if (r < 0)
                return r;

        /* 1. Write new configuration file */
        r = context_write_data_timezone(c);
        if (r < 0) {
                log_error_errno(r, "Failed to set time zone: %m");
                return sd_bus_error_set_errnof(error, r, "Failed to set time zone: %m");
        }

        /* 2. Make glibc notice the new timezone */
        tzset();

        /* 3. Tell the kernel our timezone */
        r = clock_set_timezone(NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to tell kernel about timezone, ignoring: %m");

        if (c->local_rtc) {
                struct timespec ts;
                struct tm tm;

                /* 4. Sync RTC from system clock, with the new delta */
                assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
                assert_se(localtime_r(&ts.tv_sec, &tm));

                r = clock_set_hwclock(&tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to sync time to hardware clock, ignoring: %m");
        }

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TIMEZONE_CHANGE_STR,
                   "TIMEZONE=%s", c->zone,
                   "TIMEZONE_SHORTNAME=%s", tzname[daylight],
                   "DAYLIGHT=%i", daylight,
                   LOG_MESSAGE("Changed time zone to '%s' (%s).", c->zone, tzname[daylight]));

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                              "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "Timezone",
                                              NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_local_rtc(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int lrtc, fix_system, interactive;
        Context *c = ASSERT_PTR(userdata);
        struct timespec ts;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "bbb", &lrtc, &fix_system, &interactive);
        if (r < 0)
                return r;

        if (lrtc == c->local_rtc && !fix_system)
                return sd_bus_reply_method_return(m, NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-local-rtc",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        if (lrtc != c->local_rtc) {
                c->local_rtc = lrtc;

                /* 1. Write new configuration file */
                r = context_write_data_local_rtc(c);
                if (r < 0) {
                        log_error_errno(r, "Failed to set RTC to %s: %m", lrtc ? "local" : "UTC");
                        return sd_bus_error_set_errnof(error, r, "Failed to set RTC to %s: %m", lrtc ? "local" : "UTC");
                }
        }

        /* 2. Tell the kernel our timezone */
        r = clock_set_timezone(NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to tell kernel about timezone, ignoring: %m");

        /* 3. Synchronize clocks */
        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);

        if (fix_system) {
                struct tm tm;

                /* Sync system clock from RTC; first, initialize the timezone fields of struct tm. */
                localtime_or_gmtime_r(&ts.tv_sec, &tm, !c->local_rtc);

                /* Override the main fields of struct tm, but not the timezone fields */
                r = clock_get_hwclock(&tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to get hardware clock, ignoring: %m");
                else {
                        /* And set the system clock with this */
                        ts.tv_sec = mktime_or_timegm(&tm, !c->local_rtc);

                        if (clock_settime(CLOCK_REALTIME, &ts) < 0)
                                log_debug_errno(errno, "Failed to update system clock, ignoring: %m");
                }

        } else {
                struct tm tm;

                /* Sync RTC from system clock */
                localtime_or_gmtime_r(&ts.tv_sec, &tm, !c->local_rtc);

                r = clock_set_hwclock(&tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to sync time to hardware clock, ignoring: %m");
        }

        log_info("RTC configured to %s time.", c->local_rtc ? "local" : "UTC");

        (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                              "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "LocalRTC",
                                              NULL);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_time(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        sd_bus *bus = sd_bus_message_get_bus(m);
        char buf[FORMAT_TIMESTAMP_MAX];
        int relative, interactive, r;
        Context *c = ASSERT_PTR(userdata);
        int64_t utc;
        struct timespec ts;
        usec_t start;
        struct tm tm;

        assert(m);

        if (c->slot_job_removed)
                return sd_bus_error_set(error, BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED, "Previous request is not finished, refusing.");

        r = context_update_ntp_status(c, bus, m);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to update context: %m");

        if (context_ntp_service_is_active(c) > 0)
                return sd_bus_error_set(error, BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED, "Automatic time synchronization is enabled");

        /* this only gets used if dbus does not provide a timestamp */
        start = now(CLOCK_MONOTONIC);

        r = sd_bus_message_read(m, "xbb", &utc, &relative, &interactive);
        if (r < 0)
                return r;

        if (!relative && utc <= 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid absolute time");

        if (relative && utc == 0)
                return sd_bus_reply_method_return(m, NULL);

        if (relative) {
                usec_t n, x;

                n = now(CLOCK_REALTIME);
                x = n + utc;

                if ((utc > 0 && x < n) ||
                    (utc < 0 && x > n))
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Time value overflow");

                timespec_store(&ts, x);
        } else
                timespec_store(&ts, (usec_t) utc);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-time",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
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
        localtime_or_gmtime_r(&ts.tv_sec, &tm, !c->local_rtc);

        r = clock_set_hwclock(&tm);
        if (r < 0)
                log_debug_errno(r, "Failed to update hardware clock, ignoring: %m");

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TIME_CHANGE_STR,
                   "REALTIME="USEC_FMT, timespec_load(&ts),
                   LOG_MESSAGE("Changed local time to %s", strnull(format_timestamp(buf, sizeof(buf), timespec_load(&ts)))));

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_ntp(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        sd_bus *bus = sd_bus_message_get_bus(m);
        Context *c = ASSERT_PTR(userdata);
        const UnitStatusInfo *selected = NULL;
        int enable, interactive, q, r;

        assert(m);
        assert(bus);

        r = sd_bus_message_read(m, "bb", &enable, &interactive);
        if (r < 0)
                return r;

        r = context_update_ntp_status(c, bus, m);
        if (r < 0)
                return r;

        if (context_ntp_service_exists(c) <= 0)
                return sd_bus_error_set(error, BUS_ERROR_NO_NTP_SUPPORT, "NTP not supported");

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-ntp",
                        /* details= */ NULL,
                        interactive,
                        /* good_user= */ UID_INVALID,
                        &c->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        /* This method may be called frequently. Forget the previous job if it has not completed yet. */
        LIST_FOREACH(units, u, c->units)
                u->path = mfree(u->path);

        if (!c->slot_job_removed) {
                r = bus_match_signal_async(
                                bus,
                                &slot,
                                bus_systemd_mgr,
                                "JobRemoved",
                                match_job_removed, NULL, c);
                if (r < 0)
                        return r;
        }

        if (enable)
                LIST_FOREACH(units, u, c->units) {
                        bool enable_this_one = !selected;

                        if (!streq(u->load_state, "loaded"))
                                continue;

                        r = unit_enable_or_disable(u, bus, error, enable_this_one);
                        if (r < 0)
                                /* If enablement failed, don't start this unit. */
                                enable_this_one = false;

                        r = unit_start_or_stop(u, bus, error, enable_this_one);
                        if (r < 0)
                                log_unit_warning_errno(u, r, "Failed to %s %sd NTP unit, ignoring: %m",
                                                       enable_this_one ? "start" : "stop",
                                                       enable_disable(enable_this_one));
                        if (enable_this_one)
                                selected = u;
                }
        else
                LIST_FOREACH(units, u, c->units) {
                        if (!streq(u->load_state, "loaded"))
                                continue;

                        q = unit_enable_or_disable(u, bus, error, false);
                        if (q < 0)
                                r = q;

                        q = unit_start_or_stop(u, bus, error, false);
                        if (q < 0)
                                r = q;
                }

        if (r < 0)
                return r;
        if (enable && !selected)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No NTP service found to enable.");

        if (slot)
                c->slot_job_removed = TAKE_PTR(slot);

        if (selected)
                log_info("Set NTP to enabled (%s).", selected->name);
        else
                log_info("Set NTP to disabled.");

        return sd_bus_reply_method_return(m, NULL);
}

static int method_list_timezones(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        assert(m);

        r = get_timezones(&zones);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to read list of time zones: %m");

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(reply, zones);
        if (r < 0)
                return r;

        return sd_bus_send(NULL, reply, NULL);
}

static const sd_bus_vtable timedate_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("Timezone", "s", NULL, offsetof(Context, zone), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("LocalRTC", "b", bus_property_get_bool, offsetof(Context, local_rtc), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("CanNTP", "b", property_get_can_ntp, 0, 0),
        SD_BUS_PROPERTY("NTP", "b", property_get_ntp, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("NTPSynchronized", "b", property_get_ntp_sync, 0, 0),
        SD_BUS_PROPERTY("TimeUSec", "t", property_get_time, 0, 0),
        SD_BUS_PROPERTY("RTCTimeUSec", "t", property_get_rtc_time, 0, 0),

        SD_BUS_METHOD_WITH_ARGS("SetTime",
                                SD_BUS_ARGS("x", usec_utc, "b", relative, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_time,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetTimezone",
                                SD_BUS_ARGS("s", timezone, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_timezone,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetLocalRTC",
                                SD_BUS_ARGS("b", local_rtc, "b", fix_system, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_local_rtc,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("SetNTP",
                                SD_BUS_ARGS("b", use_ntp, "b", interactive),
                                SD_BUS_NO_RESULT,
                                method_set_ntp,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("ListTimezones",
                                SD_BUS_NO_ARGS,
                                SD_BUS_RESULT("as", timezones),
                                method_list_timezones,
                                SD_BUS_VTABLE_UNPRIVILEGED),

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation manager_object = {
        "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1",
        .vtables = BUS_VTABLES(timedate_vtable),
};

static int connect_bus(Context *c, sd_event *event, sd_bus **_bus) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(bus, &manager_object, c);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(bus, NULL, "org.freedesktop.timedate1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *_bus = TAKE_PTR(bus);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_clear) Context context = {};
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-timedated.service",
                               "Manage the system clock and timezone and NTP enablement.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(event, true);

        r = sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT handler: %m");

        r = sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGTERM handler: %m");

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                return r;

        (void) sd_bus_negotiate_timestamp(bus, true);

        r = context_read_data(&context);
        if (r < 0)
                return log_error_errno(r, "Failed to read time zone data: %m");

        r = context_parse_ntp_services(&context);
        if (r < 0)
                return r;

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.timedate1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
