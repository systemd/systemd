/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Simon Peeters
***/

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-calendar.h"
#include "analyze-condition.h"
#include "analyze-dot.h"
#include "analyze-dump.h"
#include "analyze-elf.h"
#include "analyze-filesystems.h"
#include "analyze-security.h"
#include "analyze-service-watchdogs.h"
#include "analyze-syscall-filter.h"
#include "analyze-timespan.h"
#include "analyze-timestamp.h"
#include "analyze-verify.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "calendarspec.h"
#include "cap-list.h"
#include "capability-util.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
#include "exit-status.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "format-table.h"
#include "glob-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "log.h"
#include "main-func.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#if HAVE_SECCOMP
#  include "seccomp-util.h"
#endif
#include "sort-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "util.h"
#include "verb-log-control.h"
#include "verbs.h"
#include "version.h"

#define SCALE_X (0.1 / 1000.0) /* pixels per us */
#define SCALE_Y (20.0)

#define svg(...) printf(__VA_ARGS__)

#define svg_bar(class, x1, x2, y)                                       \
        svg("  <rect class=\"%s\" x=\"%.03f\" y=\"%.03f\" width=\"%.03f\" height=\"%.03f\" />\n", \
            (class),                                                    \
            SCALE_X * (x1), SCALE_Y * (y),                              \
            SCALE_X * ((x2) - (x1)), SCALE_Y - 1.0)

#define svg_text(b, x, y, format, ...)                                  \
        do {                                                            \
                svg("  <text class=\"%s\" x=\"%.03f\" y=\"%.03f\">", (b) ? "left" : "right", SCALE_X * (x) + (b ? 5.0 : -5.0), SCALE_Y * (y) + 14.0); \
                svg(format, ## __VA_ARGS__);                            \
                svg("</text>\n");                                       \
        } while (false)

DotMode arg_dot = DEP_ALL;
char **arg_dot_from_patterns = NULL, **arg_dot_to_patterns = NULL;
static usec_t arg_fuzz = 0;
PagerFlags arg_pager_flags = 0;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static RecursiveErrors arg_recursive_errors = RECURSIVE_ERRORS_YES;
static bool arg_man = true;
static bool arg_generators = false;
static char *arg_root = NULL;
static char *arg_image = NULL;
static char *arg_security_policy = NULL;
static bool arg_offline = false;
static unsigned arg_threshold = 100;
unsigned arg_iterations = 1;
usec_t arg_base_time = USEC_INFINITY;
static char *arg_unit = NULL;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
bool arg_quiet = false;
static char *arg_profile = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_dot_from_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_dot_to_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_security_policy, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_profile, freep);

typedef struct BootTimes {
        usec_t firmware_time;
        usec_t loader_time;
        usec_t kernel_time;
        usec_t kernel_done_time;
        usec_t initrd_time;
        usec_t userspace_time;
        usec_t finish_time;
        usec_t security_start_time;
        usec_t security_finish_time;
        usec_t generators_start_time;
        usec_t generators_finish_time;
        usec_t unitsload_start_time;
        usec_t unitsload_finish_time;
        usec_t initrd_security_start_time;
        usec_t initrd_security_finish_time;
        usec_t initrd_generators_start_time;
        usec_t initrd_generators_finish_time;
        usec_t initrd_unitsload_start_time;
        usec_t initrd_unitsload_finish_time;

        /*
         * If we're analyzing the user instance, all timestamps will be offset
         * by its own start-up timestamp, which may be arbitrarily big.
         * With "plot", this causes arbitrarily wide output SVG files which almost
         * completely consist of empty space. Thus we cancel out this offset.
         *
         * This offset is subtracted from times above by acquire_boot_times(),
         * but it still needs to be subtracted from unit-specific timestamps
         * (so it is stored here for reference).
         */
        usec_t reverse_offset;
} BootTimes;

typedef struct UnitTimes {
        bool has_data;
        char *name;
        usec_t activating;
        usec_t activated;
        usec_t deactivated;
        usec_t deactivating;
        usec_t time;
} UnitTimes;

typedef struct HostInfo {
        char *hostname;
        char *kernel_name;
        char *kernel_release;
        char *kernel_version;
        char *os_pretty_name;
        char *virtualization;
        char *architecture;
} HostInfo;

int acquire_bus(sd_bus **bus, bool *use_full_bus) {
        bool user = arg_scope != UNIT_FILE_SYSTEM;
        int r;

        if (use_full_bus && *use_full_bus) {
                r = bus_connect_transport(arg_transport, arg_host, user, bus);
                if (IN_SET(r, 0, -EHOSTDOWN))
                        return r;

                *use_full_bus = false;
        }

        return bus_connect_transport_systemd(arg_transport, arg_host, user, bus);
}

static int bus_get_uint64_property(sd_bus *bus, const char *path, const char *interface, const char *property, uint64_t *val) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(property);
        assert(val);

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        interface,
                        property,
                        &error,
                        't', val);

        if (r < 0)
                return log_error_errno(r, "Failed to parse reply: %s", bus_error_message(&error, r));

        return 0;
}

int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(property);
        assert(strv);

        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        property,
                        &error,
                        strv);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit property %s: %s", property, bus_error_message(&error, r));

        return 0;
}

static int compare_unit_start(const UnitTimes *a, const UnitTimes *b) {
        return CMP(a->activating, b->activating);
}

static int process_aliases(char *argv[], char *tempdir, char ***ret) {
        _cleanup_strv_free_ char **filenames = NULL;
        char **filename;
        int r;

        assert(argv);
        assert(tempdir);
        assert(ret);

        STRV_FOREACH(filename, strv_skip(argv, 1)) {
                _cleanup_free_ char *src = NULL, *dst = NULL, *base = NULL;
                const char *parse_arg;

                parse_arg = *filename;
                r = extract_first_word(&parse_arg, &src, ":", EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;

                if (!parse_arg) {
                        r = strv_consume(&filenames, TAKE_PTR(src));
                        if (r < 0)
                                return r;

                        continue;
                }

                r = path_extract_filename(parse_arg, &base);
                if (r < 0)
                        return r;

                dst = path_join(tempdir, base);
                if (!dst)
                        return -ENOMEM;

                r = copy_file(src, dst, 0, 0644, 0, 0, COPY_REFLINK);
                if (r < 0)
                        return r;

                r = strv_consume(&filenames, TAKE_PTR(dst));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(filenames);
        return 0;
}

static UnitTimes* unit_times_free_array(UnitTimes *t) {
        for (UnitTimes *p = t; p && p->has_data; p++)
                free(p->name);
        return mfree(t);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(UnitTimes*, unit_times_free_array);

static void subtract_timestamp(usec_t *a, usec_t b) {
        assert(a);

        if (*a > 0) {
                assert(*a >= b);
                *a -= b;
        }
}

static int acquire_boot_times(sd_bus *bus, BootTimes **bt) {
        static const struct bus_properties_map property_map[] = {
                { "FirmwareTimestampMonotonic",               "t", NULL, offsetof(BootTimes, firmware_time)                 },
                { "LoaderTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, loader_time)                   },
                { "KernelTimestamp",                          "t", NULL, offsetof(BootTimes, kernel_time)                   },
                { "InitRDTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, initrd_time)                   },
                { "UserspaceTimestampMonotonic",              "t", NULL, offsetof(BootTimes, userspace_time)                },
                { "FinishTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, finish_time)                   },
                { "SecurityStartTimestampMonotonic",          "t", NULL, offsetof(BootTimes, security_start_time)           },
                { "SecurityFinishTimestampMonotonic",         "t", NULL, offsetof(BootTimes, security_finish_time)          },
                { "GeneratorsStartTimestampMonotonic",        "t", NULL, offsetof(BootTimes, generators_start_time)         },
                { "GeneratorsFinishTimestampMonotonic",       "t", NULL, offsetof(BootTimes, generators_finish_time)        },
                { "UnitsLoadStartTimestampMonotonic",         "t", NULL, offsetof(BootTimes, unitsload_start_time)          },
                { "UnitsLoadFinishTimestampMonotonic",        "t", NULL, offsetof(BootTimes, unitsload_finish_time)         },
                { "InitRDSecurityStartTimestampMonotonic",    "t", NULL, offsetof(BootTimes, initrd_security_start_time)    },
                { "InitRDSecurityFinishTimestampMonotonic",   "t", NULL, offsetof(BootTimes, initrd_security_finish_time)   },
                { "InitRDGeneratorsStartTimestampMonotonic",  "t", NULL, offsetof(BootTimes, initrd_generators_start_time)  },
                { "InitRDGeneratorsFinishTimestampMonotonic", "t", NULL, offsetof(BootTimes, initrd_generators_finish_time) },
                { "InitRDUnitsLoadStartTimestampMonotonic",   "t", NULL, offsetof(BootTimes, initrd_unitsload_start_time)   },
                { "InitRDUnitsLoadFinishTimestampMonotonic",  "t", NULL, offsetof(BootTimes, initrd_unitsload_finish_time)  },
                {},
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        static BootTimes times;
        static bool cached = false;
        int r;

        if (cached)
                goto finish;

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        property_map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        &times);
        if (r < 0)
                return log_error_errno(r, "Failed to get timestamp properties: %s", bus_error_message(&error, r));

        if (times.finish_time <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINPROGRESS),
                                       "Bootup is not yet finished (org.freedesktop.systemd1.Manager.FinishTimestampMonotonic=%"PRIu64").\n"
                                       "Please try again later.\n"
                                       "Hint: Use 'systemctl%s list-jobs' to see active jobs",
                                       times.finish_time,
                                       arg_scope == UNIT_FILE_SYSTEM ? "" : " --user");

        if (arg_scope == UNIT_FILE_SYSTEM && times.security_start_time > 0) {
                /* security_start_time is set when systemd is not running under container environment. */
                if (times.initrd_time > 0)
                        times.kernel_done_time = times.initrd_time;
                else
                        times.kernel_done_time = times.userspace_time;
        } else {
                /*
                 * User-instance-specific or container-system-specific timestamps processing
                 * (see comment to reverse_offset in BootTimes).
                 */
                times.reverse_offset = times.userspace_time;

                times.firmware_time = times.loader_time = times.kernel_time = times.initrd_time =
                        times.userspace_time = times.security_start_time = times.security_finish_time = 0;

                subtract_timestamp(&times.finish_time, times.reverse_offset);

                subtract_timestamp(&times.generators_start_time, times.reverse_offset);
                subtract_timestamp(&times.generators_finish_time, times.reverse_offset);

                subtract_timestamp(&times.unitsload_start_time, times.reverse_offset);
                subtract_timestamp(&times.unitsload_finish_time, times.reverse_offset);
        }

        cached = true;

finish:
        *bt = &times;
        return 0;
}

static HostInfo* free_host_info(HostInfo *hi) {
        if (!hi)
                return NULL;

        free(hi->hostname);
        free(hi->kernel_name);
        free(hi->kernel_release);
        free(hi->kernel_version);
        free(hi->os_pretty_name);
        free(hi->virtualization);
        free(hi->architecture);
        return mfree(hi);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(HostInfo *, free_host_info);

static int acquire_time_data(sd_bus *bus, UnitTimes **out) {
        static const struct bus_properties_map property_map[] = {
                { "InactiveExitTimestampMonotonic",  "t", NULL, offsetof(UnitTimes, activating)   },
                { "ActiveEnterTimestampMonotonic",   "t", NULL, offsetof(UnitTimes, activated)    },
                { "ActiveExitTimestampMonotonic",    "t", NULL, offsetof(UnitTimes, deactivating) },
                { "InactiveEnterTimestampMonotonic", "t", NULL, offsetof(UnitTimes, deactivated)  },
                {},
        };
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *unit_times = NULL;
        BootTimes *boot_times = NULL;
        size_t c = 0;
        UnitInfo u;
        int r;

        r = acquire_boot_times(bus, &boot_times);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "ListUnits", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {
                UnitTimes *t;

                if (!GREEDY_REALLOC(unit_times, c + 2))
                        return log_oom();

                unit_times[c + 1].has_data = false;
                t = &unit_times[c];
                t->name = NULL;

                assert_cc(sizeof(usec_t) == sizeof(uint64_t));

                r = bus_map_all_properties(
                                bus,
                                "org.freedesktop.systemd1",
                                u.unit_path,
                                property_map,
                                BUS_MAP_STRDUP,
                                &error,
                                NULL,
                                t);
                if (r < 0)
                        return log_error_errno(r, "Failed to get timestamp properties of unit %s: %s",
                                               u.id, bus_error_message(&error, r));

                subtract_timestamp(&t->activating, boot_times->reverse_offset);
                subtract_timestamp(&t->activated, boot_times->reverse_offset);
                subtract_timestamp(&t->deactivating, boot_times->reverse_offset);
                subtract_timestamp(&t->deactivated, boot_times->reverse_offset);

                if (t->activated >= t->activating)
                        t->time = t->activated - t->activating;
                else if (t->deactivated >= t->activating)
                        t->time = t->deactivated - t->activating;
                else
                        t->time = 0;

                if (t->activating == 0)
                        continue;

                t->name = strdup(u.id);
                if (!t->name)
                        return log_oom();

                t->has_data = true;
                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        *out = TAKE_PTR(unit_times);
        return c;
}

static int acquire_host_info(sd_bus *bus, HostInfo **hi) {
        static const struct bus_properties_map hostname_map[] = {
                { "Hostname",                  "s", NULL, offsetof(HostInfo, hostname)       },
                { "KernelName",                "s", NULL, offsetof(HostInfo, kernel_name)    },
                { "KernelRelease",             "s", NULL, offsetof(HostInfo, kernel_release) },
                { "KernelVersion",             "s", NULL, offsetof(HostInfo, kernel_version) },
                { "OperatingSystemPrettyName", "s", NULL, offsetof(HostInfo, os_pretty_name) },
                {}
        };

        static const struct bus_properties_map manager_map[] = {
                { "Virtualization", "s", NULL, offsetof(HostInfo, virtualization) },
                { "Architecture",   "s", NULL, offsetof(HostInfo, architecture)   },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        _cleanup_(free_host_infop) HostInfo *host = NULL;
        int r;

        host = new0(HostInfo, 1);
        if (!host)
                return log_oom();

        if (arg_scope != UNIT_FILE_SYSTEM) {
                r = bus_connect_transport(arg_transport, arg_host, false, &system_bus);
                if (r < 0) {
                        log_debug_errno(r, "Failed to connect to system bus, ignoring: %m");
                        goto manager;
                }
        }

        r = bus_map_all_properties(
                        system_bus ?: bus,
                        "org.freedesktop.hostname1",
                        "/org/freedesktop/hostname1",
                        hostname_map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        host);
        if (r < 0) {
                log_debug_errno(r, "Failed to get host information from systemd-hostnamed, ignoring: %s",
                                bus_error_message(&error, r));
                sd_bus_error_free(&error);
        }

manager:
        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        manager_map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        host);
        if (r < 0)
                return log_error_errno(r, "Failed to get host information from systemd: %s",
                                       bus_error_message(&error, r));

        *hi = TAKE_PTR(host);
        return 0;
}

static int pretty_boot_time(sd_bus *bus, char **_buf) {
        BootTimes *t;
        static char buf[4096];
        size_t size;
        char *ptr;
        int r;
        usec_t activated_time = USEC_INFINITY;
        _cleanup_free_ char *path = NULL, *unit_id = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

        r = acquire_boot_times(bus, &t);
        if (r < 0)
                return r;

        path = unit_dbus_path_from_name(SPECIAL_DEFAULT_TARGET);
        if (!path)
                return log_oom();

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Id",
                        &error,
                        &unit_id);
        if (r < 0) {
                log_error_errno(r, "default.target doesn't seem to exist: %s", bus_error_message(&error, r));
                unit_id = NULL;
        }

        r = bus_get_uint64_property(bus, path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveEnterTimestampMonotonic",
                        &activated_time);
        if (r < 0) {
                log_info_errno(r, "Could not get time to reach default.target, ignoring: %m");
                activated_time = USEC_INFINITY;
        }

        ptr = buf;
        size = sizeof(buf);

        size = strpcpyf(&ptr, size, "Startup finished in ");
        if (t->firmware_time > 0)
                size = strpcpyf(&ptr, size, "%s (firmware) + ", FORMAT_TIMESPAN(t->firmware_time - t->loader_time, USEC_PER_MSEC));
        if (t->loader_time > 0)
                size = strpcpyf(&ptr, size, "%s (loader) + ", FORMAT_TIMESPAN(t->loader_time, USEC_PER_MSEC));
        if (t->kernel_done_time > 0)
                size = strpcpyf(&ptr, size, "%s (kernel) + ", FORMAT_TIMESPAN(t->kernel_done_time, USEC_PER_MSEC));
        if (t->initrd_time > 0)
                size = strpcpyf(&ptr, size, "%s (initrd) + ", FORMAT_TIMESPAN(t->userspace_time - t->initrd_time, USEC_PER_MSEC));

        size = strpcpyf(&ptr, size, "%s (userspace) ", FORMAT_TIMESPAN(t->finish_time - t->userspace_time, USEC_PER_MSEC));
        if (t->kernel_done_time > 0)
                strpcpyf(&ptr, size, "= %s ", FORMAT_TIMESPAN(t->firmware_time + t->finish_time, USEC_PER_MSEC));

        if (unit_id && timestamp_is_set(activated_time)) {
                usec_t base = t->userspace_time > 0 ? t->userspace_time : t->reverse_offset;

                size = strpcpyf(&ptr, size, "\n%s reached after %s in userspace", unit_id,
                                FORMAT_TIMESPAN(activated_time - base, USEC_PER_MSEC));
        } else if (unit_id && activated_time == 0)
                size = strpcpyf(&ptr, size, "\n%s was never reached", unit_id);
        else if (unit_id && activated_time == USEC_INFINITY)
                size = strpcpyf(&ptr, size, "\nCould not get time to reach %s.", unit_id);
        else if (!unit_id)
                size = strpcpyf(&ptr, size, "\ncould not find default.target");

        ptr = strdup(buf);
        if (!ptr)
                return log_oom();

        *_buf = ptr;
        return 0;
}

static void svg_graph_box(double height, double begin, double end) {
        /* outside box, fill */
        svg("<rect class=\"box\" x=\"0\" y=\"0\" width=\"%.03f\" height=\"%.03f\" />\n",
            SCALE_X * (end - begin),
            SCALE_Y * height);

        for (long long i = ((long long) (begin / 100000)) * 100000; i <= end; i += 100000) {
                /* lines for each second */
                if (i % 5000000 == 0)
                        svg("  <line class=\"sec5\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            SCALE_X * i,
                            SCALE_X * i,
                            SCALE_Y * height,
                            SCALE_X * i,
                            -5.0,
                            0.000001 * i);
                else if (i % 1000000 == 0)
                        svg("  <line class=\"sec1\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            SCALE_X * i,
                            SCALE_X * i,
                            SCALE_Y * height,
                            SCALE_X * i,
                            -5.0,
                            0.000001 * i);
                else
                        svg("  <line class=\"sec01\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n",
                            SCALE_X * i,
                            SCALE_X * i,
                            SCALE_Y * height);
        }
}

static int plot_unit_times(UnitTimes *u, double width, int y) {
        bool b;

        if (!u->name)
                return 0;

        svg_bar("activating",   u->activating, u->activated, y);
        svg_bar("active",       u->activated, u->deactivating, y);
        svg_bar("deactivating", u->deactivating, u->deactivated, y);

        /* place the text on the left if we have passed the half of the svg width */
        b = u->activating * SCALE_X < width / 2;
        if (u->time)
                svg_text(b, u->activating, y, "%s (%s)",
                         u->name, FORMAT_TIMESPAN(u->time, USEC_PER_MSEC));
        else
                svg_text(b, u->activating, y, "%s", u->name);

        return 1;
}

static int analyze_plot(int argc, char *argv[], void *userdata) {
        _cleanup_(free_host_infop) HostInfo *host = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        _cleanup_free_ char *pretty_times = NULL;
        bool use_full_bus = arg_scope == UNIT_FILE_SYSTEM;
        BootTimes *boot;
        UnitTimes *u;
        int n, m = 1, y = 0, r;
        double width;

        r = acquire_bus(&bus, &use_full_bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        n = acquire_boot_times(bus, &boot);
        if (n < 0)
                return n;

        n = pretty_boot_time(bus, &pretty_times);
        if (n < 0)
                return n;

        if (use_full_bus || arg_scope != UNIT_FILE_SYSTEM) {
                n = acquire_host_info(bus, &host);
                if (n < 0)
                        return n;
        }

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        typesafe_qsort(times, n, compare_unit_start);

        width = SCALE_X * (boot->firmware_time + boot->finish_time);
        if (width < 800.0)
                width = 800.0;

        if (boot->firmware_time > boot->loader_time)
                m++;
        if (boot->loader_time > 0) {
                m++;
                if (width < 1000.0)
                        width = 1000.0;
        }
        if (boot->initrd_time > 0)
                m++;
        if (boot->kernel_done_time > 0)
                m++;

        for (u = times; u->has_data; u++) {
                double text_start, text_width;

                if (u->activating > boot->finish_time) {
                        u->name = mfree(u->name);
                        continue;
                }

                /* If the text cannot fit on the left side then
                 * increase the svg width so it fits on the right.
                 * TODO: calculate the text width more accurately */
                text_width = 8.0 * strlen(u->name);
                text_start = (boot->firmware_time + u->activating) * SCALE_X;
                if (text_width > text_start && text_width + text_start > width)
                        width = text_width + text_start;

                if (u->deactivated > u->activating &&
                    u->deactivated <= boot->finish_time &&
                    u->activated == 0 && u->deactivating == 0)
                        u->activated = u->deactivating = u->deactivated;
                if (u->activated < u->activating || u->activated > boot->finish_time)
                        u->activated = boot->finish_time;
                if (u->deactivating < u->activated || u->deactivating > boot->finish_time)
                        u->deactivating = boot->finish_time;
                if (u->deactivated < u->deactivating || u->deactivated > boot->finish_time)
                        u->deactivated = boot->finish_time;
                m++;
        }

        svg("<?xml version=\"1.0\" standalone=\"no\"?>\n"
            "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" "
            "\"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n");

        svg("<svg width=\"%.0fpx\" height=\"%.0fpx\" version=\"1.1\" "
            "xmlns=\"http://www.w3.org/2000/svg\">\n\n",
                        80.0 + width, 150.0 + (m * SCALE_Y) +
                        5 * SCALE_Y /* legend */);

        /* write some basic info as a comment, including some help */
        svg("<!-- This file is a systemd-analyze SVG file. It is best rendered in a   -->\n"
            "<!-- browser such as Chrome, Chromium or Firefox. Other applications     -->\n"
            "<!-- that render these files properly but much slower are ImageMagick,   -->\n"
            "<!-- gimp, inkscape, etc. To display the files on your system, just      -->\n"
            "<!-- point your browser to this file.                                    -->\n\n"
            "<!-- This plot was generated by systemd-analyze version %-16.16s -->\n\n", GIT_VERSION);

        /* style sheet */
        svg("<defs>\n  <style type=\"text/css\">\n    <![CDATA[\n"
            "      rect       { stroke-width: 1; stroke-opacity: 0; }\n"
            "      rect.background   { fill: rgb(255,255,255); }\n"
            "      rect.activating   { fill: rgb(255,0,0); fill-opacity: 0.7; }\n"
            "      rect.active       { fill: rgb(200,150,150); fill-opacity: 0.7; }\n"
            "      rect.deactivating { fill: rgb(150,100,100); fill-opacity: 0.7; }\n"
            "      rect.kernel       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.initrd       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.firmware     { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.loader       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.userspace    { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.security     { fill: rgb(144,238,144); fill-opacity: 0.7; }\n"
            "      rect.generators   { fill: rgb(102,204,255); fill-opacity: 0.7; }\n"
            "      rect.unitsload    { fill: rgb( 82,184,255); fill-opacity: 0.7; }\n"
            "      rect.box   { fill: rgb(240,240,240); stroke: rgb(192,192,192); }\n"
            "      line       { stroke: rgb(64,64,64); stroke-width: 1; }\n"
            "//    line.sec1  { }\n"
            "      line.sec5  { stroke-width: 2; }\n"
            "      line.sec01 { stroke: rgb(224,224,224); stroke-width: 1; }\n"
            "      text       { font-family: Verdana, Helvetica; font-size: 14px; }\n"
            "      text.left  { font-family: Verdana, Helvetica; font-size: 14px; text-anchor: start; }\n"
            "      text.right { font-family: Verdana, Helvetica; font-size: 14px; text-anchor: end; }\n"
            "      text.sec   { font-size: 10px; }\n"
            "    ]]>\n   </style>\n</defs>\n\n");

        svg("<rect class=\"background\" width=\"100%%\" height=\"100%%\" />\n");
        svg("<text x=\"20\" y=\"50\">%s</text>", pretty_times);
        if (host)
                svg("<text x=\"20\" y=\"30\">%s %s (%s %s %s) %s %s</text>",
                    isempty(host->os_pretty_name) ? "Linux" : host->os_pretty_name,
                    strempty(host->hostname),
                    strempty(host->kernel_name),
                    strempty(host->kernel_release),
                    strempty(host->kernel_version),
                    strempty(host->architecture),
                    strempty(host->virtualization));

        svg("<g transform=\"translate(%.3f,100)\">\n", 20.0 + (SCALE_X * boot->firmware_time));
        svg_graph_box(m, -(double) boot->firmware_time, boot->finish_time);

        if (boot->firmware_time > 0) {
                svg_bar("firmware", -(double) boot->firmware_time, -(double) boot->loader_time, y);
                svg_text(true, -(double) boot->firmware_time, y, "firmware");
                y++;
        }
        if (boot->loader_time > 0) {
                svg_bar("loader", -(double) boot->loader_time, 0, y);
                svg_text(true, -(double) boot->loader_time, y, "loader");
                y++;
        }
        if (boot->kernel_done_time > 0) {
                svg_bar("kernel", 0, boot->kernel_done_time, y);
                svg_text(true, 0, y, "kernel");
                y++;
        }
        if (boot->initrd_time > 0) {
                svg_bar("initrd", boot->initrd_time, boot->userspace_time, y);
                if (boot->initrd_security_start_time < boot->initrd_security_finish_time)
                        svg_bar("security", boot->initrd_security_start_time, boot->initrd_security_finish_time, y);
                if (boot->initrd_generators_start_time < boot->initrd_generators_finish_time)
                        svg_bar("generators", boot->initrd_generators_start_time, boot->initrd_generators_finish_time, y);
                if (boot->initrd_unitsload_start_time < boot->initrd_unitsload_finish_time)
                        svg_bar("unitsload", boot->initrd_unitsload_start_time, boot->initrd_unitsload_finish_time, y);
                svg_text(true, boot->initrd_time, y, "initrd");
                y++;
        }

        for (u = times; u->has_data; u++) {
                if (u->activating >= boot->userspace_time)
                        break;

                y += plot_unit_times(u, width, y);
        }

        svg_bar("active", boot->userspace_time, boot->finish_time, y);
        if (boot->security_start_time > 0)
                svg_bar("security", boot->security_start_time, boot->security_finish_time, y);
        svg_bar("generators", boot->generators_start_time, boot->generators_finish_time, y);
        svg_bar("unitsload", boot->unitsload_start_time, boot->unitsload_finish_time, y);
        svg_text(true, boot->userspace_time, y, "systemd");
        y++;

        for (; u->has_data; u++)
                y += plot_unit_times(u, width, y);

        svg("</g>\n");

        /* Legend */
        svg("<g transform=\"translate(20,100)\">\n");
        y++;
        svg_bar("activating", 0, 300000, y);
        svg_text(true, 400000, y, "Activating");
        y++;
        svg_bar("active", 0, 300000, y);
        svg_text(true, 400000, y, "Active");
        y++;
        svg_bar("deactivating", 0, 300000, y);
        svg_text(true, 400000, y, "Deactivating");
        y++;
        if (boot->security_start_time > 0) {
                svg_bar("security", 0, 300000, y);
                svg_text(true, 400000, y, "Setting up security module");
                y++;
        }
        svg_bar("generators", 0, 300000, y);
        svg_text(true, 400000, y, "Generators");
        y++;
        svg_bar("unitsload", 0, 300000, y);
        svg_text(true, 400000, y, "Loading unit files");
        y++;

        svg("</g>\n\n");

        svg("</svg>\n");

        return 0;
}

static int list_dependencies_print(
                const char *name,
                unsigned level,
                unsigned branches,
                bool last,
                UnitTimes *times,
                BootTimes *boot) {

        for (unsigned i = level; i != 0; i--)
                printf("%s", special_glyph(branches & (1 << (i-1)) ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));

        printf("%s", special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH));

        if (times) {
                if (times->time > 0)
                        printf("%s%s @%s +%s%s", ansi_highlight_red(), name,
                               FORMAT_TIMESPAN(times->activating - boot->userspace_time, USEC_PER_MSEC),
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s", name, FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s", name);
        } else
                printf("%s", name);
        printf("\n");

        return 0;
}

static int list_dependencies_get_dependencies(sd_bus *bus, const char *name, char ***deps) {
        _cleanup_free_ char *path = NULL;

        assert(bus);
        assert(name);
        assert(deps);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        return bus_get_unit_property_strv(bus, path, "After", deps);
}

static Hashmap *unit_times_hashmap;

static int list_dependencies_compare(char *const *a, char *const *b) {
        usec_t usa = 0, usb = 0;
        UnitTimes *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->activated;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->activated;

        return CMP(usb, usa);
}

static bool times_in_range(const UnitTimes *times, const BootTimes *boot) {
        return times && times->activated > 0 && times->activated <= boot->finish_time;
}

static int list_dependencies_one(sd_bus *bus, const char *name, unsigned level, char ***units, unsigned branches) {
        _cleanup_strv_free_ char **deps = NULL;
        char **c;
        int r;
        usec_t service_longest = 0;
        int to_print = 0;
        UnitTimes *times;
        BootTimes *boot;

        if (strv_extend(units, name))
                return log_oom();

        r = list_dependencies_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        typesafe_qsort(deps, strv_length(deps), list_dependencies_compare);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (times_in_range(times, boot) && times->activated >= service_longest)
                        service_longest = times->activated;
        }

        if (service_longest == 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (times_in_range(times, boot) && service_longest - times->activated <= arg_fuzz)
                        to_print++;
        }

        if (!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (!times_in_range(times, boot) || service_longest - times->activated > arg_fuzz)
                        continue;

                to_print--;

                r = list_dependencies_print(*c, level, branches, to_print == 0, times, boot);
                if (r < 0)
                        return r;

                if (strv_contains(*units, *c)) {
                        r = list_dependencies_print("...", level + 1, (branches << 1) | (to_print ? 1 : 0),
                                                    true, NULL, boot);
                        if (r < 0)
                                return r;
                        continue;
                }

                r = list_dependencies_one(bus, *c, level + 1, units, (branches << 1) | (to_print ? 1 : 0));
                if (r < 0)
                        return r;

                if (to_print == 0)
                        break;
        }
        return 0;
}

static int list_dependencies(sd_bus *bus, const char *name) {
        _cleanup_strv_free_ char **units = NULL;
        UnitTimes *times;
        int r;
        const char *id;
        _cleanup_free_ char *path = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        BootTimes *boot;

        assert(bus);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Id",
                        &error,
                        &reply,
                        "s");
        if (r < 0)
                return log_error_errno(r, "Failed to get ID: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &id);
        if (r < 0)
                return bus_log_parse_error(r);

        times = hashmap_get(unit_times_hashmap, id);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        if (times) {
                if (times->time)
                        printf("%s%s +%s%s\n", ansi_highlight_red(), id,
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s\n", id,
                               FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

static int analyze_critical_chain(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        Hashmap *h;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return log_oom();

        for (UnitTimes *u = times; u->has_data; u++) {
                r = hashmap_put(h, u->name, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to add entry to hashmap: %m");
        }
        unit_times_hashmap = h;

        pager_open(arg_pager_flags);

        puts("The time when unit became active or started is printed after the \"@\" character.\n"
             "The time the unit took to start is printed after the \"+\" character.\n");

        if (argc > 1) {
                char **name;
                STRV_FOREACH(name, strv_skip(argv, 1))
                        list_dependencies(bus, *name);
        } else
                list_dependencies(bus, SPECIAL_DEFAULT_TARGET);

        h = hashmap_free(h);
        return 0;
}

static int analyze_blame(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        table = table_new("time", "unit");
        if (!table)
                return log_oom();

        table_set_header(table, false);

        assert_se(cell = table_get_cell(table, 0, 0));
        r = table_set_ellipsize_percent(table, cell, 100);
        if (r < 0)
                return r;

        r = table_set_align_percent(table, cell, 100);
        if (r < 0)
                return r;

        assert_se(cell = table_get_cell(table, 0, 1));
        r = table_set_ellipsize_percent(table, cell, 100);
        if (r < 0)
                return r;

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return r;

        r = table_set_reverse(table, 0, true);
        if (r < 0)
                return r;

        for (UnitTimes *u = times; u->has_data; u++) {
                if (u->time <= 0)
                        continue;

                r = table_add_many(table,
                                   TABLE_TIMESPAN_MSEC, u->time,
                                   TABLE_STRING, u->name);
                if (r < 0)
                        return table_log_add_error(r);
        }

        pager_open(arg_pager_flags);

        return table_print(table, NULL);
}

static int analyze_time(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return 0;
}

static int cat_config(int argc, char *argv[], void *userdata) {
        char **arg, **list;
        int r;

        pager_open(arg_pager_flags);

        list = strv_skip(argv, 1);
        STRV_FOREACH(arg, list) {
                const char *t = NULL;

                if (arg != list)
                        print_separator();

                if (path_is_absolute(*arg)) {
                        const char *dir;

                        NULSTR_FOREACH(dir, CONF_PATHS_NULSTR("")) {
                                t = path_startswith(*arg, dir);
                                if (t)
                                        break;
                        }

                        if (!t)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Path %s does not start with any known prefix.", *arg);
                } else
                        t = *arg;

                r = conf_files_cat(arg_root, t);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_log_control(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(IN_SET(argc, 1, 2));

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        return verb_log_control_common(bus, "org.freedesktop.systemd1", argv[0], argc == 2 ? argv[1] : NULL);
}

static bool strv_fnmatch_strv_or_empty(char* const* patterns, char **strv, int flags) {
        char **s;
        STRV_FOREACH(s, strv)
                if (strv_fnmatch_or_empty(patterns, *s, flags))
                        return true;

        return false;
}

static int do_unit_files(int argc, char *argv[], void *userdata) {
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_hashmap_free_ Hashmap *unit_ids = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_names = NULL;
        char **patterns = strv_skip(argv, 1);
        const char *k, *dst;
        char **v;
        int r;

        r = lookup_paths_init(&lp, arg_scope, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "lookup_paths_init() failed: %m");

        r = unit_file_build_name_map(&lp, NULL, &unit_ids, &unit_names, NULL);
        if (r < 0)
                return log_error_errno(r, "unit_file_build_name_map() failed: %m");

        HASHMAP_FOREACH_KEY(dst, k, unit_ids) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_or_empty(patterns, dst, FNM_NOESCAPE))
                        continue;

                printf("ids: %s → %s\n", k, dst);
        }

        HASHMAP_FOREACH_KEY(v, k, unit_names) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_strv_or_empty(patterns, v, FNM_NOESCAPE))
                        continue;

                _cleanup_free_ char *j = strv_join(v, ", ");
                printf("aliases: %s ← %s\n", k, j);
        }

        return 0;
}

static int dump_unit_paths(int argc, char *argv[], void *userdata) {
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        int r;
        char **p;

        r = lookup_paths_init(&paths, arg_scope, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "lookup_paths_init() failed: %m");

        STRV_FOREACH(p, paths.search_path)
                puts(*p);

        return 0;
}

static int dump_exit_status(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        table = table_new("name", "status", "class");
        if (!table)
                return log_oom();

        r = table_set_align_percent(table, table_get_cell(table, 0, 1), 100);
        if (r < 0)
                return log_error_errno(r, "Failed to right-align status: %m");

        if (strv_isempty(strv_skip(argv, 1)))
                for (size_t i = 0; i < ELEMENTSOF(exit_status_mappings); i++) {
                        if (!exit_status_mappings[i].name)
                                continue;

                        r = table_add_many(table,
                                           TABLE_STRING, exit_status_mappings[i].name,
                                           TABLE_INT, (int) i,
                                           TABLE_STRING, exit_status_class(i));
                        if (r < 0)
                                return table_log_add_error(r);
                }
        else
                for (int i = 1; i < argc; i++) {
                        int status;

                        status = exit_status_from_string(argv[i]);
                        if (status < 0)
                                return log_error_errno(status, "Invalid exit status \"%s\".", argv[i]);

                        assert(status >= 0 && (size_t) status < ELEMENTSOF(exit_status_mappings));
                        r = table_add_many(table,
                                           TABLE_STRING, exit_status_mappings[status].name ?: "-",
                                           TABLE_INT, status,
                                           TABLE_STRING, exit_status_class(status) ?: "-");
                        if (r < 0)
                                return table_log_add_error(r);
                }

        pager_open(arg_pager_flags);

        return table_print(table, NULL);
}

static int dump_capabilities(int argc, char *argv[], void *userdata) {
        _cleanup_(table_unrefp) Table *table = NULL;
        unsigned last_cap;
        int r;

        table = table_new("name", "number");
        if (!table)
                return log_oom();

        (void) table_set_align_percent(table, table_get_cell(table, 0, 1), 100);

        /* Determine the maximum of the last cap known by the kernel and by us */
        last_cap = MAX((unsigned) CAP_LAST_CAP, cap_last_cap());

        if (strv_isempty(strv_skip(argv, 1)))
                for (unsigned c = 0; c <= last_cap; c++) {
                        r = table_add_many(table,
                                           TABLE_STRING, capability_to_name(c) ?: "cap_???",
                                           TABLE_UINT, c);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        else {
                for (int i = 1; i < argc; i++) {
                        int c;

                        c = capability_from_name(argv[i]);
                        if (c < 0 || (unsigned) c > last_cap)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Capability \"%s\" not known.", argv[i]);

                        r = table_add_many(table,
                                           TABLE_STRING, capability_to_name(c) ?: "cap_???",
                                           TABLE_UINT, (unsigned) c);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                (void) table_set_sort(table, (size_t) 1);
        }

        pager_open(arg_pager_flags);

        return table_print(table, NULL);
}

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan) {
        if (calendar && calendar_spec_from_string(p, NULL) >= 0)
                log_notice("Hint: this expression is a valid calendar specification. "
                           "Use 'systemd-analyze calendar \"%s\"' instead?", p);
        if (timestamp && parse_timestamp(p, NULL) >= 0)
                log_notice("Hint: this expression is a valid timestamp. "
                           "Use 'systemd-analyze timestamp \"%s\"' instead?", p);
        if (timespan && parse_time(p, NULL, USEC_PER_SEC) >= 0)
                log_notice("Hint: this expression is a valid timespan. "
                           "Use 'systemd-analyze timespan \"%s\"' instead?", p);
}

static int do_condition(int argc, char *argv[], void *userdata) {
        return verify_conditions(strv_skip(argv, 1), arg_scope, arg_unit, arg_root);
}

static int do_verify(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **filenames = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;
        int r;

        r = mkdtemp_malloc("/tmp/systemd-analyze-XXXXXX", &tempdir);
        if (r < 0)
                return log_error_errno(r, "Failed to setup working directory: %m");

        r = process_aliases(argv, tempdir, &filenames);
        if (r < 0)
                return log_error_errno(r, "Couldn't process aliases: %m");

        return verify_units(filenames, arg_scope, arg_man, arg_generators, arg_recursive_errors, arg_root);
}

static int do_security(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *policy = NULL;
        int r;
        unsigned line, column;

        if (!arg_offline) {
                r = acquire_bus(&bus, NULL);
                if (r < 0)
                        return bus_log_connect_error(r, arg_transport);
        }

        pager_open(arg_pager_flags);

        if (arg_security_policy) {
                r = json_parse_file(/*f=*/ NULL, arg_security_policy, /*flags=*/ 0, &policy, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse '%s' at %u:%u: %m", arg_security_policy, line, column);
        } else {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *pp = NULL;

                r = search_and_fopen_nulstr("systemd-analyze-security.policy", "re", /*root=*/ NULL, CONF_PATHS_NULSTR("systemd"), &f, &pp);
                if (r < 0 && r != -ENOENT)
                        return r;

                if (f) {
                        r = json_parse_file(f, pp, /*flags=*/ 0, &policy, &line, &column);
                        if (r < 0)
                                return log_error_errno(r, "[%s:%u:%u] Failed to parse JSON policy: %m", pp, line, column);
                }
        }

        return analyze_security(bus,
                                strv_skip(argv, 1),
                                policy,
                                arg_scope,
                                arg_man,
                                arg_generators,
                                arg_offline,
                                arg_threshold,
                                arg_root,
                                arg_profile,
                                arg_json_format_flags,
                                arg_pager_flags,
                                /*flags=*/ 0);
}

static int do_elf_inspection(int argc, char *argv[], void *userdata) {
        pager_open(arg_pager_flags);

        return analyze_elf(strv_skip(argv, 1), arg_json_format_flags);
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL, *dot_link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-analyze", "1", &link);
        if (r < 0)
                return log_oom();

        /* Not using terminal_urlify_man() for this, since we don't want the "man page" text suffix in this case. */
        r = terminal_urlify("man:dot(1)", "dot(1)", &dot_link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sProfile systemd, show unit dependencies, check unit files.%s\n"
               "\nCommands:\n"
               "  [time]                     Print time required to boot the machine\n"
               "  blame                      Print list of running units ordered by\n"
               "                             time to init\n"
               "  critical-chain [UNIT...]   Print a tree of the time critical chain\n"
               "                             of units\n"
               "  plot                       Output SVG graphic showing service\n"
               "                             initialization\n"
               "  dot [UNIT...]              Output dependency graph in %s format\n"
               "  dump                       Output state serialization of service\n"
               "                             manager\n"
               "  cat-config                 Show configuration file and drop-ins\n"
               "  unit-files                 List files and symlinks for units\n"
               "  unit-paths                 List load directories for units\n"
               "  exit-status [STATUS...]    List exit status definitions\n"
               "  capability [CAP...]        List capability definitions\n"
               "  syscall-filter [NAME...]   List syscalls in seccomp filters\n"
               "  filesystems [NAME...]      List known filesystems\n"
               "  condition CONDITION...     Evaluate conditions and asserts\n"
               "  verify FILE...             Check unit files for correctness\n"
               "  calendar SPEC...           Validate repetitive calendar time\n"
               "                             events\n"
               "  timestamp TIMESTAMP...     Validate a timestamp\n"
               "  timespan SPAN...           Validate a time span\n"
               "  security [UNIT...]         Analyze security of unit\n"
               "  inspect-elf FILE...        Parse and print ELF package metadata\n"
               "\nOptions:\n"
               "     --recursive-errors=MODE Control which units are verified\n"
               "     --offline=BOOL          Perform a security review on unit file(s)\n"
               "     --threshold=N           Exit with a non-zero status when overall\n"
               "                             exposure level is over threshold value\n"
               "     --security-policy=PATH  Use custom JSON security policy instead\n"
               "                             of built-in one\n"
               "     --json=pretty|short|off Generate JSON output of the security\n"
               "                             analysis table\n"
               "     --no-pager              Do not pipe output into a pager\n"
               "     --system                Operate on system systemd instance\n"
               "     --user                  Operate on user systemd instance\n"
               "     --global                Operate on global user configuration\n"
               "  -H --host=[USER@]HOST      Operate on remote host\n"
               "  -M --machine=CONTAINER     Operate on local container\n"
               "     --order                 Show only order in the graph\n"
               "     --require               Show only requirement in the graph\n"
               "     --from-pattern=GLOB     Show only origins in the graph\n"
               "     --to-pattern=GLOB       Show only destinations in the graph\n"
               "     --fuzz=SECONDS          Also print services which finished SECONDS\n"
               "                             earlier than the latest in the branch\n"
               "     --man[=BOOL]            Do [not] check for existence of man pages\n"
               "     --generators[=BOOL]     Do [not] run unit generators\n"
               "                             (requires privileges)\n"
               "     --iterations=N          Show the specified number of iterations\n"
               "     --base-time=TIMESTAMP   Calculate calendar times relative to\n"
               "                             specified time\n"
               "     --profile=name|PATH     Include the specified profile in the\n"
               "                             security review of the unit(s)\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "  -q --quiet                 Do not emit hints\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               dot_link,
               link);

        /* When updating this list, including descriptions, apply changes to
         * shell-completion/bash/systemd-analyze and shell-completion/zsh/_systemd-analyze too. */

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_SYSTEM,
                ARG_USER,
                ARG_GLOBAL,
                ARG_DOT_FROM_PATTERN,
                ARG_DOT_TO_PATTERN,
                ARG_FUZZ,
                ARG_NO_PAGER,
                ARG_MAN,
                ARG_GENERATORS,
                ARG_ITERATIONS,
                ARG_BASE_TIME,
                ARG_RECURSIVE_ERRORS,
                ARG_OFFLINE,
                ARG_THRESHOLD,
                ARG_SECURITY_POLICY,
                ARG_JSON,
                ARG_PROFILE,
        };

        static const struct option options[] = {
                { "help",             no_argument,       NULL, 'h'                  },
                { "version",          no_argument,       NULL, ARG_VERSION          },
                { "quiet",            no_argument,       NULL, 'q'                  },
                { "order",            no_argument,       NULL, ARG_ORDER            },
                { "require",          no_argument,       NULL, ARG_REQUIRE          },
                { "root",             required_argument, NULL, ARG_ROOT             },
                { "image",            required_argument, NULL, ARG_IMAGE            },
                { "recursive-errors", required_argument, NULL, ARG_RECURSIVE_ERRORS },
                { "offline",          required_argument, NULL, ARG_OFFLINE          },
                { "threshold",        required_argument, NULL, ARG_THRESHOLD        },
                { "security-policy",  required_argument, NULL, ARG_SECURITY_POLICY  },
                { "system",           no_argument,       NULL, ARG_SYSTEM           },
                { "user",             no_argument,       NULL, ARG_USER             },
                { "global",           no_argument,       NULL, ARG_GLOBAL           },
                { "from-pattern",     required_argument, NULL, ARG_DOT_FROM_PATTERN },
                { "to-pattern",       required_argument, NULL, ARG_DOT_TO_PATTERN   },
                { "fuzz",             required_argument, NULL, ARG_FUZZ             },
                { "no-pager",         no_argument,       NULL, ARG_NO_PAGER         },
                { "man",              optional_argument, NULL, ARG_MAN              },
                { "generators",       optional_argument, NULL, ARG_GENERATORS       },
                { "host",             required_argument, NULL, 'H'                  },
                { "machine",          required_argument, NULL, 'M'                  },
                { "iterations",       required_argument, NULL, ARG_ITERATIONS       },
                { "base-time",        required_argument, NULL, ARG_BASE_TIME        },
                { "unit",             required_argument, NULL, 'U'                  },
                { "json",             required_argument, NULL, ARG_JSON             },
                { "profile",          required_argument, NULL, ARG_PROFILE          },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:U:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_RECURSIVE_ERRORS:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(recursive_errors, RecursiveErrors, _RECURSIVE_ERRORS_MAX);
                                return 0;
                        }
                        r = recursive_errors_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unknown mode passed to --recursive-errors='%s'.", optarg);

                        arg_recursive_errors = r;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SYSTEM:
                        arg_scope = UNIT_FILE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_scope = UNIT_FILE_USER;
                        break;

                case ARG_GLOBAL:
                        arg_scope = UNIT_FILE_GLOBAL;
                        break;

                case ARG_ORDER:
                        arg_dot = DEP_ORDER;
                        break;

                case ARG_REQUIRE:
                        arg_dot = DEP_REQUIRE;
                        break;

                case ARG_DOT_FROM_PATTERN:
                        if (strv_extend(&arg_dot_from_patterns, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_DOT_TO_PATTERN:
                        if (strv_extend(&arg_dot_to_patterns, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_FUZZ:
                        r = parse_sec(optarg, &arg_fuzz);
                        if (r < 0)
                                return r;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_MAN:
                        r = parse_boolean_argument("--man", optarg, &arg_man);
                        if (r < 0)
                                return r;
                        break;

                case ARG_GENERATORS:
                        r = parse_boolean_argument("--generators", optarg, &arg_generators);
                        if (r < 0)
                                return r;
                        break;

                case ARG_OFFLINE:
                        r = parse_boolean_argument("--offline", optarg, &arg_offline);
                        if (r < 0)
                                return r;
                        break;

                case ARG_THRESHOLD:
                        r = safe_atou(optarg, &arg_threshold);
                        if (r < 0 || arg_threshold > 100)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse threshold: %s", optarg);

                        break;

                case ARG_SECURITY_POLICY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_security_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_ITERATIONS:
                        r = safe_atou(optarg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations: %s", optarg);

                        break;

                case ARG_BASE_TIME:
                        r = parse_timestamp(optarg, &arg_base_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --base-time= parameter: %s", optarg);

                        break;

                case ARG_PROFILE:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Profile file name is empty");

                        if (is_path(optarg)) {
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_profile);
                                if (r < 0)
                                        return r;
                                if (!endswith(arg_profile, ".conf"))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Profile file name must end with .conf: %s", arg_profile);
                        } else {
                                r = free_and_strdup(&arg_profile, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        break;

                case 'U': {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle(optarg, UNIT_NAME_MANGLE_WARN, &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name %s: %m", optarg);

                        free_and_replace(arg_unit, mangled);
                        break;
                }
                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_offline && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= is only supported for security right now.");

        if (arg_json_format_flags != JSON_FORMAT_OFF && !STRPTR_IN_SET(argv[optind], "security", "inspect-elf"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --json= is only supported for security and inspect-elf right now.");

        if (arg_threshold != 100 && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --threshold= is only supported for security right now.");

        if (arg_scope == UNIT_FILE_GLOBAL &&
            !STR_IN_SET(argv[optind] ?: "time", "dot", "unit-paths", "verify"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verbs dot, unit-paths, verify.");

        if (streq_ptr(argv[optind], "cat-config") && arg_scope == UNIT_FILE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --user is not supported for cat-config right now.");

        if (arg_security_policy && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --security-policy= is only supported for security.");

        if ((arg_root || arg_image) && (!STRPTR_IN_SET(argv[optind], "cat-config", "verify", "condition")) &&
           (!(streq_ptr(argv[optind], "security") && arg_offline)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are only supported for cat-config, verify, condition and security when used with --offline= right now.");

        /* Having both an image and a root is not supported by the code */
        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_unit && !streq_ptr(argv[optind], "condition"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --unit= is only supported for condition");

        if (streq_ptr(argv[optind], "condition") && !arg_unit && optind >= argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments for condition");

        if (streq_ptr(argv[optind], "condition") && arg_unit && optind < argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No conditions can be passed if --unit= is used.");

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *unlink_dir = NULL;

        static const Verb verbs[] = {
                { "help",              VERB_ANY, VERB_ANY, 0,            help                   },
                { "time",              VERB_ANY, 1,        VERB_DEFAULT, analyze_time           },
                { "blame",             VERB_ANY, 1,        0,            analyze_blame          },
                { "critical-chain",    VERB_ANY, VERB_ANY, 0,            analyze_critical_chain },
                { "plot",              VERB_ANY, 1,        0,            analyze_plot           },
                { "dot",               VERB_ANY, VERB_ANY, 0,            dot                    },
                /* ↓ The following seven verbs are deprecated, from here … ↓ */
                { "log-level",         VERB_ANY, 2,        0,            verb_log_control       },
                { "log-target",        VERB_ANY, 2,        0,            verb_log_control       },
                { "set-log-level",     2,        2,        0,            verb_log_control       },
                { "get-log-level",     VERB_ANY, 1,        0,            verb_log_control       },
                { "set-log-target",    2,        2,        0,            verb_log_control       },
                { "get-log-target",    VERB_ANY, 1,        0,            verb_log_control       },
                { "service-watchdogs", VERB_ANY, 2,        0,            service_watchdogs      },
                /* ↑ … until here ↑ */
                { "dump",              VERB_ANY, 1,        0,            dump                   },
                { "cat-config",        2,        VERB_ANY, 0,            cat_config             },
                { "unit-files",        VERB_ANY, VERB_ANY, 0,            do_unit_files          },
                { "unit-paths",        1,        1,        0,            dump_unit_paths        },
                { "exit-status",       VERB_ANY, VERB_ANY, 0,            dump_exit_status       },
                { "syscall-filter",    VERB_ANY, VERB_ANY, 0,            dump_syscall_filters   },
                { "capability",        VERB_ANY, VERB_ANY, 0,            dump_capabilities      },
                { "filesystems",       VERB_ANY, VERB_ANY, 0,            dump_filesystems       },
                { "condition",         VERB_ANY, VERB_ANY, 0,            do_condition           },
                { "verify",            2,        VERB_ANY, 0,            do_verify              },
                { "calendar",          2,        VERB_ANY, 0,            test_calendar          },
                { "timestamp",         2,        VERB_ANY, 0,            test_timestamp         },
                { "timespan",          2,        VERB_ANY, 0,            dump_timespan          },
                { "security",          VERB_ANY, VERB_ANY, 0,            do_security            },
                { "inspect-elf",       2,        VERB_ANY, 0,            do_elf_inspection      },
                {}
        };

        int r;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Open up and mount the image */
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_READ_ONLY,
                                &unlink_dir,
                                &loop_device,
                                &decrypted_image);
                if (r < 0)
                        return r;

                arg_root = strdup(unlink_dir);
                if (!arg_root)
                        return log_oom();
        }

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
