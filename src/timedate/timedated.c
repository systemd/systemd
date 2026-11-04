/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-json.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-get-properties.h"
#include "bus-internal.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-map-properties.h"
#include "bus-message-util.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "clock-util.h"
#include "conf-files.h"
#include "constants.h"
#include "daemon-util.h"
#include "dlopen-note.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hwclock-util.h"
#include "json-util.h"
#include "label-util.h"
#include "list.h"
#include "log.h"
#include "log-context.h"
#include "main-func.h"
#include "memory-util.h"
#include "path-util.h"
#include "service-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "varlink-io.systemd.Timedate.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"
#include "verbs.h"

#define NULL_ADJTIME_UTC "0.0 0 0\n0\nUTC\n"
#define NULL_ADJTIME_LOCAL "0.0 0 0\n0\nLOCAL\n"

#define UNIT_LIST_DIRS (const char* const*) CONF_PATHS_STRV("systemd/ntp-units.d")
#define SET_NTP_IN_FLIGHT_MAX 16

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
        Set *set_ntp_calls;
        Set *set_ntp_links;

        sd_bus_slot *slot_job_removed;

        sd_event *event;
        sd_bus *bus;
        sd_varlink_server *varlink_server;

        LIST_HEAD(UnitStatusInfo, units);
} Context;

#define _LOG_CONTEXT_PUSH_UNIT(unit, u)               \
        const UnitStatusInfo *u = (unit);             \
        LOG_CONTEXT_PUSH_KEY_VALUE("UNIT=", u->name); \
        LOG_SET_PREFIX(u->name)

#define LOG_CONTEXT_PUSH_UNIT(unit) \
        _LOG_CONTEXT_PUSH_UNIT(unit, UNIQ_T(u, UNIQ))

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

static void context_done(Context *c) {
        assert(c);

        free(c->zone);
        hashmap_free(c->polkit_registry);
        sd_bus_message_unref(c->cache);
        set_free(c->set_ntp_calls);
        set_free(c->set_ntp_links);

        sd_bus_slot_unref(c->slot_job_removed);

        sd_varlink_server_unref(c->varlink_server);
        sd_bus_flush_close_unref(c->bus);
        sd_event_unref(c->event);

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

        LOG_CONTEXT_PUSH_UNIT(unit);

        LIST_APPEND(units, c->units, unit);
        log_debug("added from %s.", source);
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

                r = extract_first_word(&p, &word, ":", /* flags= */ 0);
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

        r = conf_files_list_strv(&files, ".list", /* root= */ NULL,
                                 CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
                                 UNIT_LIST_DIRS);
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

        c->local_rtc = clock_is_localtime(/* adjtime_path= */ NULL) > 0;

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

                        if (unlink(etc_localtime()) < 0 && errno != ENOENT)
                                return -errno;

                        return 0;
                }

                source = "/usr/share/zoneinfo/UTC";
        } else {
                p = path_join("/usr/share/zoneinfo", c->zone);
                if (!p)
                        return -ENOMEM;

                source = p;
        }

        return symlinkat_atomic_full(source, AT_FDCWD, etc_localtime(),
                                     !secure_getenv("SYSTEMD_ETC_LOCALTIME") ? SYMLINK_MAKE_RELATIVE : 0);
}

static const char* etc_adjtime(void) {
        static const char *cached = NULL;

        if (!cached)
                cached = secure_getenv("SYSTEMD_ETC_ADJTIME") ?: "/etc/adjtime";

        return cached;
}

static int context_write_data_local_rtc(Context *c) {
        _cleanup_free_ char *s = NULL, *w = NULL;
        int r;

        assert(c);

        r = read_full_file(etc_adjtime(), &s, /* ret_size= */ NULL);
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

                *mempcpy_typesafe(stpcpy(stpcpy(mempcpy(w, s, a), prepend), c->local_rtc ? "LOCAL" : "UTC"), e, b) = 0;

                if (streq(w, NULL_ADJTIME_UTC)) {
                        if (unlink(etc_adjtime()) < 0)
                                if (errno != ENOENT)
                                        return -errno;

                        return 0;
                }
        }

        r = mac_init();
        if (r < 0)
                return r;

        return write_string_file(etc_adjtime(), w, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_LABEL);
}

static int bus_verify_available(sd_bus *bus) {
        int r;

        assert(bus);

        r = sd_bus_is_open(bus);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTCONN;

        if (bus->state == BUS_WATCH_BIND)
                return -EAGAIN;

        return 0;
}

static int context_update_ntp_status(Context *c, sd_bus_message *m) {
        static const struct bus_properties_map map[] = {
                { "LoadState",     "s", NULL, offsetof(UnitStatusInfo, load_state)      },
                { "ActiveState",   "s", NULL, offsetof(UnitStatusInfo, active_state)    },
                { "UnitFileState", "s", NULL, offsetof(UnitStatusInfo, unit_file_state) },
                {}
        };
        int r;

        assert(c);
        assert(c->bus);

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

                LOG_CONTEXT_PUSH_UNIT(u);

                unit_status_info_clear(u);

                path = unit_dbus_path_from_name(u->name);
                if (!path)
                        return -ENOMEM;

                r = bus_map_all_properties(
                                c->bus,
                                "org.freedesktop.systemd1",
                                path,
                                map,
                                BUS_MAP_STRDUP,
                                &error,
                                /* ret_reply= */ NULL,
                                u);
                if (r < 0)
                        return log_error_errno(r, "Failed to get properties: %s", bus_error_message(&error, r));
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
                sd_bus_message *cm;

                c->slot_job_removed = sd_bus_slot_unref(c->slot_job_removed);

                (void) sd_bus_emit_properties_changed(sd_bus_message_get_bus(m),
                                                      "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "NTP",
                                                      NULL);
                while ((cm = set_steal_first(c->set_ntp_calls))) {
                        r = sd_bus_reply_method_return(cm, /* types= */ NULL);
                        if (r < 0)
                                log_debug_errno(r, "Failed to reply to SetNTP method call, ignoring: %m");
                        sd_bus_message_unref(cm);
                }

                r = varlink_many_reply(c->set_ntp_links, /* parameters= */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to reply to SetNTP Varlink call, ignoring: %m");
                c->set_ntp_links = set_free(c->set_ntp_links);
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

        LOG_CONTEXT_PUSH_UNIT(u);

        r = bus_call_method(
                bus,
                bus_systemd_mgr,
                start ? "StartUnit" : "StopUnit",
                error,
                &reply,
                "ss",
                u->name,
                "replace");
        log_full_errno_zerook(r < 0 ? LOG_WARNING : LOG_DEBUG, r,
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

        LOG_CONTEXT_PUSH_UNIT(u);

        if (streq(u->unit_file_state, "enabled") == enable) {
                log_debug("already %sd.", enable_disable(enable));
                return 0;
        }

        log_info("%s unit.", enable ? "Enabling" : "Disabling");

        if (enable)
                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "EnableUnitFiles",
                                error,
                                /* ret_reply= */ NULL,
                                "asbb", 1,
                                u->name,
                                false, true);
        else
                r = bus_call_method(
                                bus,
                                bus_systemd_mgr,
                                "DisableUnitFiles",
                                error,
                                /* ret_reply= */ NULL,
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

static int get_rtc_time(usec_t *ret) {
        struct tm tm = {};
        usec_t t = 0;
        int r;

        assert(ret);

        r = hwclock_get(&tm);
        if (r == -EBUSY)
                log_warning("/dev/rtc is busy. Is somebody keeping it open continuously? That's not a good idea... Returning a bogus RTC timestamp.");
        else if (r == -ENOENT)
                log_debug("/dev/rtc not found.");
        else if (r == -ENODATA)
                log_debug("/dev/rtc has no valid time, power loss probably occurred?");
        else if (r < 0)
                return r;
        else {
                r = mktime_or_timegm_usec(&tm, /* utc= */ true, &t);
                if (r < 0)
                        log_warning_errno(r, "Failed to convert RTC time to UNIX time, ignoring: %m");
        }

        *ret = t;
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

        usec_t t = 0;
        int r;

        r = get_rtc_time(&t);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to read RTC: %m");

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

        r = context_update_ntp_status(c, reply);
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

        r = context_update_ntp_status(c, reply);
        if (r < 0)
                return r;

        return sd_bus_message_append(reply, "b", context_ntp_service_is_active(c) > 0);
}

static int context_build_json(Context *c, sd_json_variant **ret) {
        bool can_ntp, ntp;
        int r;

        assert(c);
        assert(ret);

        if (c->slot_job_removed)
                /* When the previous request is not finished, then assume NTP is enabled and active. */
                can_ntp = ntp = true;
        else {
                r = context_update_ntp_status(c, /* m= */ NULL);
                if (r < 0)
                        return r;

                can_ntp = context_ntp_service_exists(c) > 0;
                ntp = context_ntp_service_is_active(c) > 0;
        }

        usec_t rtc = 0;
        r = get_rtc_time(&rtc);
        if (r < 0)
                log_warning_errno(r, "Failed to read RTC, ignoring: %m");

        return sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Timezone", c->zone),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LocalRTC", c->local_rtc),
                        SD_JSON_BUILD_PAIR_BOOLEAN("CanNTP", can_ntp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NTP", ntp),
                        SD_JSON_BUILD_PAIR_BOOLEAN("NTPSynchronized", ntp_synced()),
                        SD_JSON_BUILD_PAIR_UNSIGNED("TimeUSec", now(CLOCK_REALTIME)),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("RTCTimeUSec", rtc));
}

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* Determining the NTP status makes synchronous calls on the (possibly watch-bound) system bus,
         * which would block the event loop until D-Bus is up. Fail fast instead if it is not connected
         * yet. */
        r = bus_verify_available(c->bus);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = context_build_json(c, &v);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, v);
}

static int context_set_timezone(Context *c, const char *z) {
        _cleanup_free_ char *old_zone = NULL, *zone = NULL;
        int r;

        assert(c);
        assert(z);

        if (streq_ptr(z, c->zone))
                return 0;

        zone = strdup(z);
        if (!zone)
                return -ENOMEM;

        old_zone = TAKE_PTR(c->zone);
        c->zone = TAKE_PTR(zone);

        /* 1. Write new configuration file */
        r = context_write_data_timezone(c);
        if (r < 0) {
                free_and_replace(c->zone, old_zone);
                return log_error_errno(r, "Failed to set time zone: %m");
        }

        /* 2. Make glibc notice the new timezone */
        tzset();

        /* 3. Tell the kernel our timezone */
        r = clock_set_timezone(/* ret_minutesdelta= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to tell kernel about timezone, ignoring: %m");

        if (c->local_rtc) {
                struct tm tm;

                /* 4. Sync RTC from system clock, with the new delta */
                r = localtime_or_gmtime_usec(now(CLOCK_REALTIME), /* utc= */ false, &tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to convert system time to calendar time, ignoring: %m");
                else {
                        r = hwclock_set(&tm);
                        if (r < 0)
                                log_debug_errno(r, "Failed to sync time to hardware clock, ignoring: %m");
                }
        }

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_TIMEZONE_CHANGE_STR),
                   LOG_ITEM("TIMEZONE=%s", c->zone),
                   LOG_ITEM("TIMEZONE_SHORTNAME=%s", get_tzname(daylight)),
                   LOG_ITEM("DAYLIGHT=%i", daylight),
                   LOG_MESSAGE("Changed time zone to '%s' (%s).", c->zone, get_tzname(daylight)));

        (void) sd_bus_emit_properties_changed(c->bus,
                                              "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "Timezone",
                                              NULL);

        return 1;
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
                return sd_bus_reply_method_return(m, /* types= */ NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-timezone",
                        (const char**) STRV_MAKE("zone", z),
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = context_set_timezone(c, z);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to set time zone: %m");

        return sd_bus_reply_method_return(m, /* types= */ NULL);
}

static int vl_method_set_timezone(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "timezone", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        const char *z = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &z);
        if (r != 0)
                return r;

        if (!timezone_is_valid(z, LOG_DEBUG))
                return sd_varlink_error_invalid_parameter_name(link, "timezone");

        if (streq_ptr(z, c->zone))
                return sd_varlink_reply(link, /* parameters= */ NULL);

        r = varlink_verify_polkit_async(
                        link,
                        c->bus,
                        "org.freedesktop.timedate1.set-timezone",
                        (const char**) STRV_MAKE("zone", z),
                        &c->polkit_registry);
        if (r <= 0)
                return r;

        r = context_set_timezone(c, z);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int context_set_local_rtc(Context *c, bool local_rtc, bool adjust_system_clock) {
        struct timespec ts;
        int r;

        assert(c);

        if (local_rtc == c->local_rtc && !adjust_system_clock)
                return 0;

        if (local_rtc != c->local_rtc) {
                bool old_local_rtc = c->local_rtc;

                c->local_rtc = local_rtc;

                /* 1. Write new configuration file */
                r = context_write_data_local_rtc(c);
                if (r < 0) {
                        c->local_rtc = old_local_rtc;
                        return log_error_errno(r, "Failed to set RTC to %s: %m", local_rtc ? "local" : "UTC");
                }
        }

        /* 2. Tell the kernel our timezone */
        r = clock_set_timezone(/* ret_minutesdelta= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to tell kernel about timezone, ignoring: %m");

        /* 3. Synchronize clocks */
        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);

        if (adjust_system_clock) {
                struct tm tm = {
                        .tm_isdst = -1,
                };

                /* Sync system clock from RTC; first, initialize the timezone fields of struct tm. */
                r = localtime_or_gmtime_usec(timespec_load(&ts), !c->local_rtc, &tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to determine current timezone, ignoring: %m");

                /* Override the main fields of struct tm, but not the timezone fields */
                r = hwclock_get(&tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to get hardware clock, ignoring: %m");
                else {
                        usec_t t;
                        /* And set the system clock with this */

                        r = mktime_or_timegm_usec(&tm, !c->local_rtc, &t);
                        if (r < 0)
                                log_debug_errno(r, "Failed to convert calendar time to system time, ignoring: %m");
                        else {
                                /* We leave the subsecond offset as is! */
                                ts.tv_sec = t / USEC_PER_SEC;

                                if (clock_settime(CLOCK_REALTIME, &ts) < 0)
                                        log_debug_errno(errno, "Failed to update system clock, ignoring: %m");
                        }
                }
        } else {
                struct tm tm;

                /* Sync RTC from system clock */
                r = localtime_or_gmtime_usec(timespec_load(&ts), !c->local_rtc, &tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to convert time to calendar time, ignoring: %m");
                else {
                        r = hwclock_set(&tm);
                        if (r < 0)
                                log_debug_errno(r, "Failed to sync time to hardware clock, ignoring: %m");
                }
        }

        log_info("RTC configured to %s time.", c->local_rtc ? "local" : "UTC");

        (void) sd_bus_emit_properties_changed(c->bus,
                                              "/org/freedesktop/timedate1", "org.freedesktop.timedate1", "LocalRTC",
                                              NULL);

        return 1;
}

static int method_set_local_rtc(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int lrtc, adjust_system_clock, interactive;
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(m);

        r = sd_bus_message_read(m, "bbb", &lrtc, &adjust_system_clock, &interactive);
        if (r < 0)
                return r;

        if (lrtc == c->local_rtc && !adjust_system_clock)
                return sd_bus_reply_method_return(m, /* types= */ NULL);

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-local-rtc",
                        (const char**) STRV_MAKE("local_rtc", one_zero(lrtc)),
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        r = context_set_local_rtc(c, lrtc, adjust_system_clock);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to set RTC to %s: %m", lrtc ? "local" : "UTC");

        return sd_bus_reply_method_return(m, /* types= */ NULL);
}

static int vl_method_set_local_rtc(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        struct params {
                bool local_rtc;
                bool adjust_system_clock;
        };
        static const sd_json_dispatch_field dispatch_table[] = {
                { "localRTC",          SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct params, local_rtc),           SD_JSON_MANDATORY },
                { "adjustSystemClock", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct params, adjust_system_clock), SD_JSON_NULLABLE  },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        struct params p = {};
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.local_rtc == c->local_rtc && !p.adjust_system_clock)
                return sd_varlink_reply(link, /* parameters= */ NULL);

        r = varlink_verify_polkit_async(
                        link,
                        c->bus,
                        "org.freedesktop.timedate1.set-local-rtc",
                        (const char**) STRV_MAKE("local_rtc", one_zero(p.local_rtc)),
                        &c->polkit_registry);
        if (r <= 0)
                return r;

        r = context_set_local_rtc(c, p.local_rtc, p.adjust_system_clock);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int timespec_store_maybe_relative(struct timespec *ts, int64_t signed_usec, bool relative) {
        assert(ts);

        if (relative) {
                usec_t n = now(CLOCK_REALTIME);
                bool valid;
                if (signed_usec > 0)
                        valid = INC_SAFE(&n, (usec_t) signed_usec);
                else if (signed_usec == INT64_MIN)
                        valid = false; /* subtracting 2^63 from any unsigned value is going to underflow */
                else
                        valid = DEC_SAFE(&n, (usec_t) -signed_usec);
                if (!valid)
                        return -EINVAL;

                timespec_store(ts, n);
        } else
                timespec_store(ts, (usec_t) signed_usec);

        return 0;
}

static int context_set_time(Context *c, usec_t t) {
        struct timespec ts;
        struct tm tm;
        int r;

        assert(c);

        timespec_store(&ts, t);

        /* Set system clock */
        if (clock_settime(CLOCK_REALTIME, &ts) < 0)
                return log_error_errno(errno, "Failed to set local time: %m");

        /* Sync down to RTC */
        r = localtime_or_gmtime_usec(timespec_load(&ts), !c->local_rtc, &tm);
        if (r < 0)
                log_debug_errno(r, "Failed to convert timestamp to calendar time, ignoring: %m");
        else {
                r = hwclock_set(&tm);
                if (r < 0)
                        log_debug_errno(r, "Failed to update hardware clock, ignoring: %m");
        }

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_TIME_CHANGE_STR),
                   LOG_ITEM("REALTIME="USEC_FMT, timespec_load(&ts)),
                   LOG_MESSAGE("Changed local time to %s", strnull(FORMAT_TIMESTAMP(timespec_load(&ts)))));

        return 0;
}

static int method_set_time(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        int relative, interactive, r;
        Context *c = ASSERT_PTR(userdata);
        int64_t utc;
        struct timespec ts;

        assert(m);

        if (c->slot_job_removed)
                return sd_bus_error_set(error, BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED, "Previous request is not finished, refusing.");

        r = context_update_ntp_status(c, m);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to update context: %m");

        if (context_ntp_service_is_active(c) > 0)
                return sd_bus_error_set(error, BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED, "Automatic time synchronization is enabled");

        r = sd_bus_message_read(m, "xbb", &utc, &relative, &interactive);
        if (r < 0)
                return r;

        if (!relative && utc <= 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid absolute time");

        if (relative && utc == 0)
                return sd_bus_reply_method_return(m, /* types= */ NULL);

        r = timespec_store_maybe_relative(&ts, utc, relative);
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Time value overflow");

        /* refuse the request when the time is before systemd build date time */
        if (ts.tv_sec < TIME_EPOCH)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Requested to set the clock to time before build time, refusing.");

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-time",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        r = context_set_time(c, timespec_load(&ts));
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to set local time: %m");

        return sd_bus_reply_method_return(m, /* types= */ NULL);
}

static int vl_method_set_time(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        struct params {
                int64_t time_usec;
                bool relative;
        };
        static const sd_json_dispatch_field dispatch_table[] = {
                { "timeUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int64,   offsetof(struct params, time_usec), SD_JSON_MANDATORY },
                { "relative", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool, offsetof(struct params, relative),  SD_JSON_NULLABLE  },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Context *c = ASSERT_PTR(userdata);
        struct timespec ts;
        int r;

        assert(link);
        assert(parameters);

        struct params p = {};
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* Validate the parameters before the more expensive operations below. */
        if (!p.relative && p.time_usec <= 0)
                return sd_varlink_error_invalid_parameter_name(link, "timeUSec");

        if (p.relative && p.time_usec == 0)
                return sd_varlink_reply(link, /* parameters= */ NULL);

        r = timespec_store_maybe_relative(&ts, p.time_usec, p.relative);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "timeUSec");

        /* refuse the request when the time is before systemd build date time */
        if (ts.tv_sec < TIME_EPOCH)
                return sd_varlink_error_invalid_parameter_name(link, "timeUSec");

        if (c->slot_job_removed)
                return sd_varlink_error(link, "io.systemd.Timedate.AutomaticTimeSyncEnabled", /* parameters= */ NULL);

        /* The following makes synchronous calls on the (possibly watch-bound) system bus, which would
         * block the event loop until D-Bus is up. Fail fast instead if it is not connected yet. */
        r = bus_verify_available(c->bus);
        if (r < 0)
                return r;

        r = context_update_ntp_status(c, /* m= */ NULL);
        if (r < 0)
                return r;

        if (context_ntp_service_is_active(c) > 0)
                return sd_varlink_error(link, "io.systemd.Timedate.AutomaticTimeSyncEnabled", /* parameters= */ NULL);

        r = varlink_verify_polkit_async(
                        link,
                        c->bus,
                        "org.freedesktop.timedate1.set-time",
                        /* details= */ NULL,
                        &c->polkit_registry);
        if (r <= 0)
                return r;

        r = context_set_time(c, timespec_load(&ts));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int context_set_ntp(Context *c, bool enable, sd_bus_error *error) {
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        const UnitStatusInfo *selected = NULL;
        int q, r = 0;

        assert(c);

        if (set_size(c->set_ntp_calls) + set_size(c->set_ntp_links) >= SET_NTP_IN_FLIGHT_MAX)
                return -EAGAIN;

        /* This may be called frequently. Forget the previous job if it has not completed yet. */
        LIST_FOREACH(units, u, c->units)
                u->path = mfree(u->path);

        if (!c->slot_job_removed) {
                r = bus_match_signal_async(
                                c->bus,
                                &slot,
                                bus_systemd_mgr,
                                "JobRemoved",
                                match_job_removed, /* install_callback= */ NULL, c);
                if (r < 0)
                        return r;
        }

        if (enable)
                LIST_FOREACH(units, u, c->units) {
                        bool enable_this_one = !selected;

                        if (!streq(u->load_state, "loaded"))
                                continue;

                        LOG_CONTEXT_PUSH_UNIT(u);

                        r = unit_enable_or_disable(u, c->bus, error, enable_this_one);
                        if (r < 0)
                                /* If enablement failed, don't start this unit. */
                                enable_this_one = false;

                        r = unit_start_or_stop(u, c->bus, error, enable_this_one);
                        if (r < 0)
                                log_warning_errno(r, "Failed to %s %sd NTP unit, ignoring: %m",
                                                  enable_this_one ? "start" : "stop",
                                                  enable_disable(enable_this_one));
                        if (enable_this_one)
                                selected = u;
                }
        else
                LIST_FOREACH(units, u, c->units) {
                        if (!streq(u->load_state, "loaded"))
                                continue;

                        q = unit_enable_or_disable(u, c->bus, error, /* enable= */ false);
                        if (q < 0)
                                r = q;

                        q = unit_start_or_stop(u, c->bus, error, /* start= */ false);
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
                log_info("Set NTP to be enabled (%s).", selected->name);
        else
                log_info("Set NTP to be disabled.");

        return 0;
}

static int method_set_ntp(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = ASSERT_PTR(userdata);
        int enable, interactive, r;

        assert(m);

        r = sd_bus_message_read(m, "bb", &enable, &interactive);
        if (r < 0)
                return r;

        r = context_update_ntp_status(c, m);
        if (r < 0)
                return r;

        if (context_ntp_service_exists(c) <= 0)
                return sd_bus_error_set(error, BUS_ERROR_NO_NTP_SUPPORT, "NTP not supported");

        r = bus_verify_polkit_async_full(
                        m,
                        "org.freedesktop.timedate1.set-ntp",
                        (const char**) STRV_MAKE("enable", one_zero(enable)),
                        /* good_user= */ UID_INVALID,
                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1;

        r = context_set_ntp(c, enable, error);
        if (r < 0)
                return r;

        /* Asynchronous reply to m in match_job_removed() */
        return set_ensure_consume(&c->set_ntp_calls, &bus_message_hash_ops, sd_bus_message_ref(m));
}

static int vl_method_set_ntp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "useNTP", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Context *c = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        bool enable = false;
        int r;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &enable);
        if (r != 0)
                return r;

        /* The following makes synchronous calls on the (possibly watch-bound) system bus, which would
         * block the event loop until D-Bus is up. Fail fast instead if it is not connected yet. */
        r = bus_verify_available(c->bus);
        if (r < 0)
                return r;

        r = context_update_ntp_status(c, /* m= */ NULL);
        if (r < 0)
                return r;

        if (context_ntp_service_exists(c) <= 0)
                return sd_varlink_error(link, "io.systemd.Timedate.NoNTPSupport", /* parameters= */ NULL);

        r = varlink_verify_polkit_async(
                        link,
                        c->bus,
                        "org.freedesktop.timedate1.set-ntp",
                        (const char**) STRV_MAKE("enable", one_zero(enable)),
                        &c->polkit_registry);
        if (r <= 0)
                return r;

        r = context_set_ntp(c, enable, &error);
        if (r < 0)
                return r;

        /* A oneway caller doesn't expect a reply, so don't track the link. Otherwise reply
         * asynchronously from match_job_removed() once the units' jobs have completed. */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY)) {
                r = set_ensure_consume(&c->set_ntp_links, &varlink_hash_ops, sd_varlink_ref(link));
                if (r < 0)
                        return r;
        }

        return 0;
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

        return sd_bus_message_send(reply);
}

static int vl_method_list_timezones(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_strv_free_ char **zones = NULL;
        int r;

        assert(link);
        assert(parameters);

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = get_timezones(&zones);
        if (r < 0)
                return log_error_errno(r, "Failed to read list of time zones: %m");

        r = sd_varlink_set_sentinel(link, /* error_id= */ NULL);
        if (r < 0)
                return r;

        STRV_FOREACH(zone, zones) {
                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("timezone", *zone));
                if (r < 0)
                        return r;
        }

        return 0;
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
                                SD_BUS_ARGS("b", local_rtc, "b", adjust_system_clock, "b", interactive),
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

static const BusObjectImplementation manager_object = {
        "/org/freedesktop/timedate1",
        "org.freedesktop.timedate1",
        .vtables = BUS_VTABLES(timedate_vtable),
};

static int connect_bus(Context *c) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(c->event);
        assert(!c->bus);

        r = bus_open_system_watch_bind_with_description(&bus, "bus-api-timedate");
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(bus, &manager_object, c);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(bus, /* ret_slot= */ NULL, "org.freedesktop.timedate1", /* flags= */ 0, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(bus, c->event, /* priority= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        c->bus = TAKE_PTR(bus);
        return 0;
}

static int connect_varlink(Context *c) {
        int r;

        assert(c);
        assert(c->event);
        assert(!c->varlink_server);

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        r = varlink_server_new(
                        &server,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        server,
                        &vl_interface_io_systemd_Timedate,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        server,
                        "io.systemd.Timedate.Describe",      vl_method_describe,
                        "io.systemd.Timedate.ListTimezones", vl_method_list_timezones,
                        "io.systemd.Timedate.SetLocalRTC",   vl_method_set_local_rtc,
                        "io.systemd.Timedate.SetNTP",        vl_method_set_ntp,
                        "io.systemd.Timedate.SetTime",       vl_method_set_time,
                        "io.systemd.Timedate.SetTimezone",   vl_method_set_timezone,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetLogLevel",    varlink_method_get_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method calls: %m");

        r = sd_varlink_server_attach_event(server, c->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        r = sd_varlink_server_listen_auto(server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                r = sd_varlink_server_listen_address(server, "/run/systemd/io.systemd.Timedate", 0666);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to Varlink socket: %m");
        }

        c->varlink_server = TAKE_PTR(server);
        return 0;
}

static bool context_check_idle(void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        return sd_varlink_server_current_connections(c->varlink_server) == 0 &&
                hashmap_isempty(c->polkit_registry);
}

COMMAND(
        "systemd-timedated\0",
        "Manage the system clock and timezone and NTP enablement.",
        .man_pages = "systemd-timedated.service(8)\0",
        .option_namespace = "service",
        .option_groups =
                "Options\0"
                "Bus introspection\0",
);

static int context_init(Context *c) {
        int r;

        assert(c);

        r = sd_event_default(&c->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(c->event, true);

        r = sd_event_set_signal_exit(c->event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        r = connect_bus(c);
        if (r < 0)
                return r;

        r = connect_varlink(c);
        if (r < 0)
                return r;

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_done) Context context = {};
        int r;

        LIBSELINUX_NOTE(recommended);

        log_setup();

        r = service_parse_argv(BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               /* runtime_scope= */ NULL,
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        r = context_init(&context);
        if (r < 0)
                return r;

        r = context_read_data(&context);
        if (r < 0)
                return log_error_errno(r, "Failed to read time zone data: %m");

        r = context_parse_ntp_services(&context);
        if (r < 0)
                return r;

        r = sd_notify(/* unset_environment= */ false, NOTIFY_READY_MESSAGE);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        context.event,
                        context.bus,
                        "org.freedesktop.timedate1",
                        DEFAULT_EXIT_USEC,
                        context_check_idle,
                        &context);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
