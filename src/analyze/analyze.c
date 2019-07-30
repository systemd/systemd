/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2013 Simon Peeters
***/

#include <getopt.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze-condition.h"
#include "analyze-security.h"
#include "analyze-verify.h"
#include "build.h"
#include "bus-error.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "calendarspec.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "glob-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "log.h"
#include "main-func.h"
#include "nulstr-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#if HAVE_SECCOMP
#  include "seccomp-util.h"
#endif
#include "sort-util.h"
#include "special.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "time-util.h"
#include "unit-name.h"
#include "util.h"
#include "verbs.h"

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

static enum dot {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE
} arg_dot = DEP_ALL;
static char **arg_dot_from_patterns = NULL;
static char **arg_dot_to_patterns = NULL;
static usec_t arg_fuzz = 0;
static PagerFlags arg_pager_flags = 0;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static bool arg_man = true;
static bool arg_generators = false;
static const char *arg_root = NULL;
static unsigned arg_iterations = 1;

STATIC_DESTRUCTOR_REGISTER(arg_dot_from_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_dot_to_patterns, strv_freep);

struct boot_times {
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
};

struct unit_times {
        bool has_data;
        char *name;
        usec_t activating;
        usec_t activated;
        usec_t deactivated;
        usec_t deactivating;
        usec_t time;
};

struct host_info {
        char *hostname;
        char *kernel_name;
        char *kernel_release;
        char *kernel_version;
        char *os_pretty_name;
        char *virtualization;
        char *architecture;
};

static int acquire_bus(sd_bus **bus, bool *use_full_bus) {
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

static int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv) {
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

static int compare_unit_start(const struct unit_times *a, const struct unit_times *b) {
        return CMP(a->activating, b->activating);
}

static void unit_times_free(struct unit_times *t) {
        struct unit_times *p;

        for (p = t; p->has_data; p++)
                free(p->name);
        free(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct unit_times *, unit_times_free);

static void subtract_timestamp(usec_t *a, usec_t b) {
        assert(a);

        if (*a > 0) {
                assert(*a >= b);
                *a -= b;
        }
}

static int acquire_boot_times(sd_bus *bus, struct boot_times **bt) {
        static const struct bus_properties_map property_map[] = {
                { "FirmwareTimestampMonotonic",               "t", NULL, offsetof(struct boot_times, firmware_time)                 },
                { "LoaderTimestampMonotonic",                 "t", NULL, offsetof(struct boot_times, loader_time)                   },
                { "KernelTimestamp",                          "t", NULL, offsetof(struct boot_times, kernel_time)                   },
                { "InitRDTimestampMonotonic",                 "t", NULL, offsetof(struct boot_times, initrd_time)                   },
                { "UserspaceTimestampMonotonic",              "t", NULL, offsetof(struct boot_times, userspace_time)                },
                { "FinishTimestampMonotonic",                 "t", NULL, offsetof(struct boot_times, finish_time)                   },
                { "SecurityStartTimestampMonotonic",          "t", NULL, offsetof(struct boot_times, security_start_time)           },
                { "SecurityFinishTimestampMonotonic",         "t", NULL, offsetof(struct boot_times, security_finish_time)          },
                { "GeneratorsStartTimestampMonotonic",        "t", NULL, offsetof(struct boot_times, generators_start_time)         },
                { "GeneratorsFinishTimestampMonotonic",       "t", NULL, offsetof(struct boot_times, generators_finish_time)        },
                { "UnitsLoadStartTimestampMonotonic",         "t", NULL, offsetof(struct boot_times, unitsload_start_time)          },
                { "UnitsLoadFinishTimestampMonotonic",        "t", NULL, offsetof(struct boot_times, unitsload_finish_time)         },
                { "InitRDSecurityStartTimestampMonotonic",    "t", NULL, offsetof(struct boot_times, initrd_security_start_time)    },
                { "InitRDSecurityFinishTimestampMonotonic",   "t", NULL, offsetof(struct boot_times, initrd_security_finish_time)   },
                { "InitRDGeneratorsStartTimestampMonotonic",  "t", NULL, offsetof(struct boot_times, initrd_generators_start_time)  },
                { "InitRDGeneratorsFinishTimestampMonotonic", "t", NULL, offsetof(struct boot_times, initrd_generators_finish_time) },
                { "InitRDUnitsLoadStartTimestampMonotonic",   "t", NULL, offsetof(struct boot_times, initrd_unitsload_start_time)   },
                { "InitRDUnitsLoadFinishTimestampMonotonic",  "t", NULL, offsetof(struct boot_times, initrd_unitsload_finish_time)  },
                {},
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        static struct boot_times times;
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
                 * (see comment to reverse_offset in struct boot_times).
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

static void free_host_info(struct host_info *hi) {
        if (!hi)
                return;

        free(hi->hostname);
        free(hi->kernel_name);
        free(hi->kernel_release);
        free(hi->kernel_version);
        free(hi->os_pretty_name);
        free(hi->virtualization);
        free(hi->architecture);
        free(hi);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct host_info *, free_host_info);

static int acquire_time_data(sd_bus *bus, struct unit_times **out) {
        static const struct bus_properties_map property_map[] = {
                { "InactiveExitTimestampMonotonic",  "t", NULL, offsetof(struct unit_times, activating)   },
                { "ActiveEnterTimestampMonotonic",   "t", NULL, offsetof(struct unit_times, activated)    },
                { "ActiveExitTimestampMonotonic",    "t", NULL, offsetof(struct unit_times, deactivating) },
                { "InactiveEnterTimestampMonotonic", "t", NULL, offsetof(struct unit_times, deactivated)  },
                {},
        };
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_times_freep) struct unit_times *unit_times = NULL;
        struct boot_times *boot_times = NULL;
        size_t allocated = 0, c = 0;
        UnitInfo u;
        int r;

        r = acquire_boot_times(bus, &boot_times);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnits",
                        &error, &reply,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {
                struct unit_times *t;

                if (!GREEDY_REALLOC(unit_times, allocated, c + 2))
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

static int acquire_host_info(sd_bus *bus, struct host_info **hi) {
        static const struct bus_properties_map hostname_map[] = {
                { "Hostname",                  "s", NULL, offsetof(struct host_info, hostname)       },
                { "KernelName",                "s", NULL, offsetof(struct host_info, kernel_name)    },
                { "KernelRelease",             "s", NULL, offsetof(struct host_info, kernel_release) },
                { "KernelVersion",             "s", NULL, offsetof(struct host_info, kernel_version) },
                { "OperatingSystemPrettyName", "s", NULL, offsetof(struct host_info, os_pretty_name) },
                {}
        };

        static const struct bus_properties_map manager_map[] = {
                { "Virtualization", "s", NULL, offsetof(struct host_info, virtualization) },
                { "Architecture",   "s", NULL, offsetof(struct host_info, architecture)   },
                {}
        };

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        _cleanup_(free_host_infop) struct host_info *host;
        int r;

        host = new0(struct host_info, 1);
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
        char ts[FORMAT_TIMESPAN_MAX];
        struct boot_times *t;
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
                size = strpcpyf(&ptr, size, "%s (firmware) + ", format_timespan(ts, sizeof(ts), t->firmware_time - t->loader_time, USEC_PER_MSEC));
        if (t->loader_time > 0)
                size = strpcpyf(&ptr, size, "%s (loader) + ", format_timespan(ts, sizeof(ts), t->loader_time, USEC_PER_MSEC));
        if (t->kernel_done_time > 0)
                size = strpcpyf(&ptr, size, "%s (kernel) + ", format_timespan(ts, sizeof(ts), t->kernel_done_time, USEC_PER_MSEC));
        if (t->initrd_time > 0)
                size = strpcpyf(&ptr, size, "%s (initrd) + ", format_timespan(ts, sizeof(ts), t->userspace_time - t->initrd_time, USEC_PER_MSEC));

        size = strpcpyf(&ptr, size, "%s (userspace) ", format_timespan(ts, sizeof(ts), t->finish_time - t->userspace_time, USEC_PER_MSEC));
        if (t->kernel_done_time > 0)
                strpcpyf(&ptr, size, "= %s ", format_timespan(ts, sizeof(ts), t->firmware_time + t->finish_time, USEC_PER_MSEC));

        if (unit_id && timestamp_is_set(activated_time)) {
                usec_t base = t->userspace_time > 0 ? t->userspace_time : t->reverse_offset;

                size = strpcpyf(&ptr, size, "\n%s reached after %s in userspace", unit_id,
                                format_timespan(ts, sizeof(ts), activated_time - base, USEC_PER_MSEC));
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
        long long i;

        /* outside box, fill */
        svg("<rect class=\"box\" x=\"0\" y=\"0\" width=\"%.03f\" height=\"%.03f\" />\n",
            SCALE_X * (end - begin),
            SCALE_Y * height);

        for (i = ((long long) (begin / 100000)) * 100000; i <= end; i += 100000) {
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

static int plot_unit_times(struct unit_times *u, double width, int y) {
        char ts[FORMAT_TIMESPAN_MAX];
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
                         u->name, format_timespan(ts, sizeof(ts), u->time, USEC_PER_MSEC));
        else
                svg_text(b, u->activating, y, "%s", u->name);

        return 1;
}

static int analyze_plot(int argc, char *argv[], void *userdata) {
        _cleanup_(free_host_infop) struct host_info *host = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_freep) struct unit_times *times = NULL;
        _cleanup_free_ char *pretty_times = NULL;
        bool use_full_bus = arg_scope == UNIT_FILE_SYSTEM;
        struct boot_times *boot;
        struct unit_times *u;
        int n, m = 1, y = 0, r;
        double width;

        r = acquire_bus(&bus, &use_full_bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

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
                struct unit_times *times,
                struct boot_times *boot) {

        unsigned i;
        char ts[FORMAT_TIMESPAN_MAX], ts2[FORMAT_TIMESPAN_MAX];

        for (i = level; i != 0; i--)
                printf("%s", special_glyph(branches & (1 << (i-1)) ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));

        printf("%s", special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH));

        if (times) {
                if (times->time > 0)
                        printf("%s%s @%s +%s%s", ansi_highlight_red(), name,
                               format_timespan(ts, sizeof(ts), times->activating - boot->userspace_time, USEC_PER_MSEC),
                               format_timespan(ts2, sizeof(ts2), times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s", name, format_timespan(ts, sizeof(ts), times->activated - boot->userspace_time, USEC_PER_MSEC));
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
        struct unit_times *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->activated;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->activated;

        return CMP(usb, usa);
}

static bool times_in_range(const struct unit_times *times, const struct boot_times *boot) {
        return times && times->activated > 0 && times->activated <= boot->finish_time;
}

static int list_dependencies_one(sd_bus *bus, const char *name, unsigned level, char ***units, unsigned branches) {
        _cleanup_strv_free_ char **deps = NULL;
        char **c;
        int r = 0;
        usec_t service_longest = 0;
        int to_print = 0;
        struct unit_times *times;
        struct boot_times *boot;

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
                times = hashmap_get(unit_times_hashmap, *c);
                if (times_in_range(times, boot) && times->activated >= service_longest)
                        service_longest = times->activated;
        }

        if (service_longest == 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times_in_range(times, boot) && service_longest - times->activated <= arg_fuzz)
                        to_print++;
        }

        if (!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
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
        char ts[FORMAT_TIMESPAN_MAX];
        struct unit_times *times;
        int r;
        const char *id;
        _cleanup_free_ char *path = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        struct boot_times *boot;

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
                               format_timespan(ts, sizeof(ts), times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s\n", id, format_timespan(ts, sizeof(ts), times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

static int analyze_critical_chain(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_freep) struct unit_times *times = NULL;
        struct unit_times *u;
        Hashmap *h;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return log_oom();

        for (u = times; u->has_data; u++) {
                r = hashmap_put(h, u->name, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to add entry to hashmap: %m");
        }
        unit_times_hashmap = h;

        (void) pager_open(arg_pager_flags);

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
        _cleanup_(unit_times_freep) struct unit_times *times = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        struct unit_times *u;
        TableCell *cell;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

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

        r = table_set_sort(table, 0, SIZE_MAX);
        if (r < 0)
                return r;

        r = table_set_reverse(table, 0, true);
        if (r < 0)
                return r;

        for (u = times; u->has_data; u++) {
                if (u->time <= 0)
                        continue;

                r = table_add_cell(table, NULL, TABLE_TIMESPAN_MSEC, &u->time);
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_STRING, u->name);
                if (r < 0)
                        return r;
        }

        (void) pager_open(arg_pager_flags);

        return table_print(table, NULL);
}

static int analyze_time(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return 0;
}

static int graph_one_property(
                sd_bus *bus,
                const UnitInfo *u,
                const char *prop,
                const char *color,
                char *patterns[],
                char *from_patterns[],
                char *to_patterns[]) {

        _cleanup_strv_free_ char **units = NULL;
        char **unit;
        int r;
        bool match_patterns;

        assert(u);
        assert(prop);
        assert(color);

        match_patterns = strv_fnmatch(patterns, u->id, 0);

        if (!strv_isempty(from_patterns) && !match_patterns && !strv_fnmatch(from_patterns, u->id, 0))
                return 0;

        r = bus_get_unit_property_strv(bus, u->unit_path, prop, &units);
        if (r < 0)
                return r;

        STRV_FOREACH(unit, units) {
                bool match_patterns2;

                match_patterns2 = strv_fnmatch(patterns, *unit, 0);

                if (!strv_isempty(to_patterns) && !match_patterns2 && !strv_fnmatch(to_patterns, *unit, 0))
                        continue;

                if (!strv_isempty(patterns) && !match_patterns && !match_patterns2)
                        continue;

                printf("\t\"%s\"->\"%s\" [color=\"%s\"];\n", u->id, *unit, color);
        }

        return 0;
}

static int graph_one(sd_bus *bus, const UnitInfo *u, char *patterns[], char *from_patterns[], char *to_patterns[]) {
        int r;

        assert(bus);
        assert(u);

        if (IN_SET(arg_dot, DEP_ORDER, DEP_ALL)) {
                r = graph_one_property(bus, u, "After", "green", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
        }

        if (IN_SET(arg_dot, DEP_REQUIRE, DEP_ALL)) {
                r = graph_one_property(bus, u, "Requires", "black", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "Requisite", "darkblue", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "Wants", "grey66", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "Conflicts", "red", patterns, from_patterns, to_patterns);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int expand_patterns(sd_bus *bus, char **patterns, char ***ret) {
        _cleanup_strv_free_ char **expanded_patterns = NULL;
        char **pattern;
        int r;

        STRV_FOREACH(pattern, patterns) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_free_ char *unit = NULL, *unit_id = NULL;

                if (strv_extend(&expanded_patterns, *pattern) < 0)
                        return log_oom();

                if (string_is_glob(*pattern))
                        continue;

                unit = unit_dbus_path_from_name(*pattern);
                if (!unit)
                        return log_oom();

                r = sd_bus_get_property_string(
                                bus,
                                "org.freedesktop.systemd1",
                                unit,
                                "org.freedesktop.systemd1.Unit",
                                "Id",
                                &error,
                                &unit_id);
                if (r < 0)
                        return log_error_errno(r, "Failed to get ID: %s", bus_error_message(&error, r));

                if (!streq(*pattern, unit_id)) {
                        if (strv_extend(&expanded_patterns, unit_id) < 0)
                                return log_oom();
                }
        }

        *ret = expanded_patterns;
        expanded_patterns = NULL; /* do not free */

        return 0;
}

static int dot(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **expanded_patterns = NULL;
        _cleanup_strv_free_ char **expanded_from_patterns = NULL;
        _cleanup_strv_free_ char **expanded_to_patterns = NULL;
        int r;
        UnitInfo u;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = expand_patterns(bus, strv_skip(argv, 1), &expanded_patterns);
        if (r < 0)
                return r;

        r = expand_patterns(bus, arg_dot_from_patterns, &expanded_from_patterns);
        if (r < 0)
                return r;

        r = expand_patterns(bus, arg_dot_to_patterns, &expanded_to_patterns);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                       "org.freedesktop.systemd1",
                       "/org/freedesktop/systemd1",
                       "org.freedesktop.systemd1.Manager",
                       "ListUnits",
                       &error,
                       &reply,
                       "");
        if (r < 0)
                log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        printf("digraph systemd {\n");

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {

                r = graph_one(bus, &u, expanded_patterns, expanded_from_patterns, expanded_to_patterns);
                if (r < 0)
                        return r;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        printf("}\n");

        log_info("   Color legend: black     = Requires\n"
                 "                 dark blue = Requisite\n"
                 "                 dark grey = Wants\n"
                 "                 red       = Conflicts\n"
                 "                 green     = After\n");

        if (on_tty())
                log_notice("-- You probably want to process this output with graphviz' dot tool.\n"
                           "-- Try a shell pipeline like 'systemd-analyze dot | dot -Tsvg > systemd.svg'!\n");

        return 0;
}

static int dump_fallback(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *text = NULL;
        int r;

        assert(bus);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Dump",
                        &error,
                        &reply,
                        NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call Dump: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(text, stdout);
        return 0;
}

static int dump(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int fd = -1;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        (void) pager_open(arg_pager_flags);

        if (!sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD))
                return dump_fallback(bus);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "DumpByFileDescriptor",
                        &error,
                        &reply,
                        NULL);
        if (r < 0) {
                /* fall back to Dump if DumpByFileDescriptor is not supported */
                if (!IN_SET(r, -EACCES, -EBADR))
                        return log_error_errno(r, "Failed to issue method call DumpByFileDescriptor: %s",
                                               bus_error_message(&error, r));

                return dump_fallback(bus);
        }

        r = sd_bus_message_read(reply, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        fflush(stdout);
        return copy_bytes(fd, STDOUT_FILENO, (uint64_t) -1, 0);
}

static int cat_config(int argc, char *argv[], void *userdata) {
        char **arg, **list;
        int r;

        (void) pager_open(arg_pager_flags);

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

static int set_log_level(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(argc == 2);
        assert(argv);

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_set_property(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "LogLevel",
                        &error,
                        "s",
                        argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

        return 0;
}

static int get_log_level(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *level = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "LogLevel",
                        &error,
                        &level);
        if (r < 0)
                return log_error_errno(r, "Failed to get log level: %s", bus_error_message(&error, r));

        puts(level);
        return 0;
}

static int get_or_set_log_level(int argc, char *argv[], void *userdata) {
        return (argc == 1) ? get_log_level(argc, argv, userdata) : set_log_level(argc, argv, userdata);
}

static int set_log_target(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(argc == 2);
        assert(argv);

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_set_property(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "LogTarget",
                        &error,
                        "s",
                        argv[1]);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

        return 0;
}

static int get_log_target(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *target = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "LogTarget",
                        &error,
                        &target);
        if (r < 0)
                return log_error_errno(r, "Failed to get log target: %s", bus_error_message(&error, r));

        puts(target);
        return 0;
}

static int get_or_set_log_target(int argc, char *argv[], void *userdata) {
        return (argc == 1) ? get_log_target(argc, argv, userdata) : set_log_target(argc, argv, userdata);
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
        Iterator i;
        const char *k, *dst;
        char **v;
        int r;

        r = lookup_paths_init(&lp, arg_scope, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "lookup_paths_init() failed: %m");

        r = unit_file_build_name_map(&lp, NULL, &unit_ids, &unit_names, NULL);
        if (r < 0)
                return log_error_errno(r, "unit_file_build_name_map() failed: %m");

        HASHMAP_FOREACH_KEY(dst, k, unit_ids, i) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_or_empty(patterns, dst, FNM_NOESCAPE))
                        continue;

                printf("ids: %s → %s\n", k, dst);
        }

        HASHMAP_FOREACH_KEY(v, k, unit_names, i) {
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
                                return r;
                }
        else
                for (int i = 1; i < argc; i++) {
                        int status;

                        status = exit_status_from_string(argv[i]);
                        if (status < 0)
                                return log_error_errno(r, "Invalid exit status \"%s\": %m", argv[i]);

                        assert(status >= 0 && (size_t) status < ELEMENTSOF(exit_status_mappings));
                        r = table_add_many(table,
                                           TABLE_STRING, exit_status_mappings[status].name ?: "-",
                                           TABLE_INT, status,
                                           TABLE_STRING, exit_status_class(status) ?: "-");
                        if (r < 0)
                                return r;
                }

        (void) pager_open(arg_pager_flags);

        return table_print(table, NULL);
}

#if HAVE_SECCOMP

static int load_kernel_syscalls(Set **ret) {
        _cleanup_(set_free_freep) Set *syscalls = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Let's read the available system calls from the list of available tracing events. Slightly dirty,
         * but good enough for analysis purposes. */

        f = fopen("/sys/kernel/tracing/available_events", "re");
        if (!f) {
                /* We tried the non-debugfs mount point and that didn't work. If it wasn't mounted, maybe the
                 * old debugfs mount point works? */
                f = fopen("/sys/kernel/debug/tracing/available_events", "re");
                if (!f)
                        return log_full_errno(IN_SET(errno, EPERM, EACCES, ENOENT) ? LOG_DEBUG : LOG_WARNING, errno,
                                              "Can't read open tracefs' available_events file: %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *e;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read system call list: %m");
                if (r == 0)
                        break;

                e = startswith(line, "syscalls:sys_enter_");
                if (!e)
                        continue;

                /* These are named differently inside the kernel than their external name for historical
                 * reasons. Let's hide them here. */
                if (STR_IN_SET(e, "newuname", "newfstat", "newstat", "newlstat", "sysctl"))
                        continue;

                r = set_ensure_allocated(&syscalls, &string_hash_ops);
                if (r < 0)
                        return log_oom();

                r = set_put_strdup(syscalls, e);
                if (r < 0)
                        return log_error_errno(r, "Failed to add system call to list: %m");
        }

        *ret = TAKE_PTR(syscalls);
        return 0;
}

static void kernel_syscalls_remove(Set *s, const SyscallFilterSet *set) {
        const char *syscall;

        NULSTR_FOREACH(syscall, set->value) {
                if (syscall[0] == '@')
                        continue;

                (void) set_remove(s, syscall);
        }
}

static void dump_syscall_filter(const SyscallFilterSet *set) {
        const char *syscall;

        printf("%s%s%s\n"
               "    # %s\n",
               ansi_highlight(),
               set->name,
               ansi_normal(),
               set->help);

        NULSTR_FOREACH(syscall, set->value)
                printf("    %s%s%s\n", syscall[0] == '@' ? ansi_underline() : "", syscall, ansi_normal());
}

static int dump_syscall_filters(int argc, char *argv[], void *userdata) {
        bool first = true;

        (void) pager_open(arg_pager_flags);

        if (strv_isempty(strv_skip(argv, 1))) {
                _cleanup_(set_free_freep) Set *kernel = NULL;
                int i, k;

                k = load_kernel_syscalls(&kernel);

                for (i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                        const SyscallFilterSet *set = syscall_filter_sets + i;
                        if (!first)
                                puts("");

                        dump_syscall_filter(set);
                        kernel_syscalls_remove(kernel, set);
                        first = false;
                }

                if (k < 0) {
                        fputc('\n', stdout);
                        fflush(stdout);
                        log_notice_errno(k, "# Not showing unlisted system calls, couldn't retrieve kernel system call list: %m");
                } else if (!set_isempty(kernel)) {
                        const char *syscall;
                        Iterator j;

                        printf("\n"
                               "# %sUnlisted System Calls%s (supported by the local kernel, but not included in any of the groups listed above):\n",
                               ansi_highlight(), ansi_normal());

                        SET_FOREACH(syscall, kernel, j)
                                printf("#   %s\n", syscall);
                }
        } else {
                char **name;

                STRV_FOREACH(name, strv_skip(argv, 1)) {
                        const SyscallFilterSet *set;

                        if (!first)
                                puts("");

                        set = syscall_filter_set_find(*name);
                        if (!set) {
                                /* make sure the error appears below normal output */
                                fflush(stdout);

                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                                       "Filter set \"%s\" not found.", *name);
                        }

                        dump_syscall_filter(set);
                        first = false;
                }
        }

        return 0;
}

#else
static int dump_syscall_filters(int argc, char *argv[], void *userdata) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not compiled with syscall filters, sorry.");
}
#endif

static void parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan) {
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

static int dump_timespan(int argc, char *argv[], void *userdata) {
        char **input_timespan;

        STRV_FOREACH(input_timespan, strv_skip(argv, 1)) {
                _cleanup_(table_unrefp) Table *table = NULL;
                usec_t output_usecs;
                TableCell *cell;
                int r;

                r = parse_time(*input_timespan, &output_usecs, USEC_PER_SEC);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse time span '%s': %m", *input_timespan);
                        parsing_hint(*input_timespan, true, true, false);
                        return r;
                }

                table = table_new("name", "value");
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

                r = table_add_cell(table, NULL, TABLE_STRING, "Original:");
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_STRING, *input_timespan);
                if (r < 0)
                        return r;

                r = table_add_cell_stringf(table, NULL, "%ss:", special_glyph(SPECIAL_GLYPH_MU));
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_UINT64, &output_usecs);
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_STRING, "Human:");
                if (r < 0)
                        return r;

                r = table_add_cell(table, &cell, TABLE_TIMESPAN, &output_usecs);
                if (r < 0)
                        return r;

                r = table_set_color(table, cell, ansi_highlight());
                if (r < 0)
                        return r;

                r = table_print(table, NULL);
                if (r < 0)
                        return r;

                if (input_timespan[1])
                        putchar('\n');
        }

        return EXIT_SUCCESS;
}

static int test_timestamp_one(const char *p) {
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        usec_t usec;
        int r;

        r = parse_timestamp(p, &usec);
        if (r < 0) {
                log_error_errno(r, "Failed to parse \"%s\": %m", p);
                parsing_hint(p, true, false, true);
                return r;
        }

        table = table_new("name", "value");
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

        r = table_add_cell(table, NULL, TABLE_STRING, "Original form:");
        if (r < 0)
                return r;

        r = table_add_cell(table, NULL, TABLE_STRING, p);
        if (r < 0)
                return r;

        r = table_add_cell(table, NULL, TABLE_STRING, "Normalized form:");
        if (r < 0)
                return r;

        r = table_add_cell(table, &cell, TABLE_TIMESTAMP, &usec);
        if (r < 0)
                return r;

        r = table_set_color(table, cell, ansi_highlight_blue());
        if (r < 0)
                return r;

        if (!in_utc_timezone()) {
                r = table_add_cell(table, NULL, TABLE_STRING, "(in UTC):");
                if (r < 0)
                        return r;

                r = table_add_cell(table, &cell, TABLE_TIMESTAMP_UTC, &usec);
                if (r < 0)
                        return r;
        }

        r = table_add_cell(table, NULL, TABLE_STRING, "UNIX seconds:");
        if (r < 0)
                return r;

        if (usec % USEC_PER_SEC == 0)
                r = table_add_cell_stringf(table, &cell, "@%"PRI_USEC,
                                           usec / USEC_PER_SEC);
        else
                r = table_add_cell_stringf(table, &cell, "@%"PRI_USEC".%06"PRI_USEC"",
                                           usec / USEC_PER_SEC,
                                           usec % USEC_PER_SEC);
        if (r < 0)
                return r;

        r = table_add_cell(table, NULL, TABLE_STRING, "From now:");
        if (r < 0)
                return r;

        r = table_add_cell(table, &cell, TABLE_TIMESTAMP_RELATIVE, &usec);
        if (r < 0)
                return r;

        return table_print(table, NULL);
}

static int test_timestamp(int argc, char *argv[], void *userdata) {
        int ret = 0, r;
        char **p;

        STRV_FOREACH(p, strv_skip(argv, 1)) {
                r = test_timestamp_one(*p);
                if (ret == 0 && r < 0)
                        ret = r;

                if (*(p + 1))
                        putchar('\n');
        }

        return ret;
}

static int test_calendar_one(usec_t n, const char *p) {
        _cleanup_(calendar_spec_freep) CalendarSpec *spec = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *t = NULL;
        TableCell *cell;
        int r;

        r = calendar_spec_from_string(p, &spec);
        if (r < 0) {
                log_error_errno(r, "Failed to parse calendar specification '%s': %m", p);
                parsing_hint(p, false, true, true);
                return r;
        }

        r = calendar_spec_to_string(spec, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to format calendar specification '%s': %m", p);

        table = table_new("name", "value");
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

        if (!streq(t, p)) {
                r = table_add_cell(table, NULL, TABLE_STRING, "Original form:");
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_STRING, p);
                if (r < 0)
                        return r;
        }

        r = table_add_cell(table, NULL, TABLE_STRING, "Normalized form:");
        if (r < 0)
                return r;

        r = table_add_cell(table, NULL, TABLE_STRING, t);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < arg_iterations; i++) {
                usec_t next;

                r = calendar_spec_next_usec(spec, n, &next);
                if (r == -ENOENT) {
                        if (i == 0) {
                                r = table_add_cell(table, NULL, TABLE_STRING, "Next elapse:");
                                if (r < 0)
                                        return r;

                                r = table_add_cell(table, &cell, TABLE_STRING, "never");
                                if (r < 0)
                                        return r;

                                r = table_set_color(table, cell, ansi_highlight_yellow());
                                if (r < 0)
                                        return r;
                        }
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to determine next elapse for '%s': %m", p);

                if (i == 0) {
                        r = table_add_cell(table, NULL, TABLE_STRING, "Next elapse:");
                        if (r < 0)
                                return r;

                        r = table_add_cell(table, &cell, TABLE_TIMESTAMP, &next);
                        if (r < 0)
                                return r;

                        r = table_set_color(table, cell, ansi_highlight_blue());
                        if (r < 0)
                                return r;
                } else {
                        int k = DECIMAL_STR_WIDTH(i + 1);

                        if (k < 8)
                                k = 8 - k;
                        else
                                k = 0;

                        r = table_add_cell_stringf(table, NULL, "Iter. #%u:", i+1);
                        if (r < 0)
                                return r;

                        r = table_add_cell(table, &cell, TABLE_TIMESTAMP, &next);
                        if (r < 0)
                                return r;

                        r = table_set_color(table, cell, ansi_highlight_blue());
                        if (r < 0)
                                return r;
                }

                if (!in_utc_timezone()) {
                        r = table_add_cell(table, NULL, TABLE_STRING, "(in UTC):");
                        if (r < 0)
                                return r;

                        r = table_add_cell(table, NULL, TABLE_TIMESTAMP_UTC, &next);
                        if (r < 0)
                                return r;
                }

                r = table_add_cell(table, NULL, TABLE_STRING, "From now:");
                if (r < 0)
                        return r;

                r = table_add_cell(table, NULL, TABLE_TIMESTAMP_RELATIVE, &next);
                if (r < 0)
                        return r;

                n = next;
        }

        return table_print(table, NULL);
}

static int test_calendar(int argc, char *argv[], void *userdata) {
        int ret = 0, r;
        char **p;
        usec_t n;

        n = now(CLOCK_REALTIME); /* We want to use the same "base" for all expressions */

        STRV_FOREACH(p, strv_skip(argv, 1)) {
                r = test_calendar_one(n, *p);
                if (ret == 0 && r < 0)
                        ret = r;

                if (*(p + 1))
                        putchar('\n');
        }

        return ret;
}

static int service_watchdogs(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int b, r;

        assert(IN_SET(argc, 1, 2));
        assert(argv);

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        /* get ServiceWatchdogs */
        if (argc == 1) {
                r = sd_bus_get_property_trivial(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "ServiceWatchdogs",
                                &error,
                                'b',
                                &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to get service-watchdog state: %s", bus_error_message(&error, r));

                printf("%s\n", yes_no(!!b));

                return 0;
        }

        /* set ServiceWatchdogs */
        b = parse_boolean(argv[1]);
        if (b < 0) {
                log_error("Failed to parse service-watchdogs argument.");
                return -EINVAL;
        }

        r = sd_bus_set_property(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ServiceWatchdogs",
                        &error,
                        "b",
                        b);
        if (r < 0)
                return log_error_errno(r, "Failed to set service-watchdog state: %s", bus_error_message(&error, r));

        return 0;
}

static int do_condition(int argc, char *argv[], void *userdata) {
        return verify_conditions(strv_skip(argv, 1), arg_scope);
}

static int do_verify(int argc, char *argv[], void *userdata) {
        return verify_units(strv_skip(argv, 1), arg_scope, arg_man, arg_generators);
}

static int do_security(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        (void) pager_open(arg_pager_flags);

        return analyze_security(bus, strv_skip(argv, 1), 0);
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL, *dot_link = NULL;
        int r;

        (void) pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-analyze", "1", &link);
        if (r < 0)
                return log_oom();

        /* Not using terminal_urlify_man() for this, since we don't want the "man page" text suffix in this case. */
        r = terminal_urlify("man:dot(1)", "dot(1)", &dot_link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Profile systemd, show unit dependencies, check unit files.\n\n"
               "  -h --help                Show this help\n"
               "     --version             Show package version\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --system              Operate on system systemd instance\n"
               "     --user                Operate on user systemd instance\n"
               "     --global              Operate on global user configuration\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --order               Show only order in the graph\n"
               "     --require             Show only requirement in the graph\n"
               "     --from-pattern=GLOB   Show only origins in the graph\n"
               "     --to-pattern=GLOB     Show only destinations in the graph\n"
               "     --fuzz=SECONDS        Also print services which finished SECONDS earlier\n"
               "                           than the latest in the branch\n"
               "     --man[=BOOL]          Do [not] check for existence of man pages\n"
               "     --generators[=BOOL]   Do [not] run unit generators (requires privileges)\n"
               "     --iterations=N        Show the specified number of iterations\n"
               "\nCommands:\n"
               "  time                     Print time spent in the kernel\n"
               "  blame                    Print list of running units ordered by time to init\n"
               "  critical-chain [UNIT...] Print a tree of the time critical chain of units\n"
               "  plot                     Output SVG graphic showing service initialization\n"
               "  dot [UNIT...]            Output dependency graph in %s format\n"
               "  log-level [LEVEL]        Get/set logging threshold for manager\n"
               "  log-target [TARGET]      Get/set logging target for manager\n"
               "  dump                     Output state serialization of service manager\n"
               "  cat-config               Show configuration file and drop-ins\n"
               "  unit-files               List files and symlinks for units\n"
               "  unit-paths               List load directories for units\n"
               "  exit-status [STATUS...]  List exit status definitions\n"
               "  syscall-filter [NAME...] Print list of syscalls in seccomp filter\n"
               "  condition CONDITION...   Evaluate conditions and asserts\n"
               "  verify FILE...           Check unit files for correctness\n"
               "  service-watchdogs [BOOL] Get/set service watchdog state\n"
               "  calendar SPEC...         Validate repetitive calendar time events\n"
               "  timestamp TIMESTAMP...   Validate a timestamp\n"
               "  timespan SPAN...         Validate a time span\n"
               "  security [UNIT...]       Analyze security of unit\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , dot_link
               , link
        );

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
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'                  },
                { "version",      no_argument,       NULL, ARG_VERSION          },
                { "order",        no_argument,       NULL, ARG_ORDER            },
                { "require",      no_argument,       NULL, ARG_REQUIRE          },
                { "root",         required_argument, NULL, ARG_ROOT             },
                { "system",       no_argument,       NULL, ARG_SYSTEM           },
                { "user",         no_argument,       NULL, ARG_USER             },
                { "global",       no_argument,       NULL, ARG_GLOBAL           },
                { "from-pattern", required_argument, NULL, ARG_DOT_FROM_PATTERN },
                { "to-pattern",   required_argument, NULL, ARG_DOT_TO_PATTERN   },
                { "fuzz",         required_argument, NULL, ARG_FUZZ             },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER         },
                { "man",          optional_argument, NULL, ARG_MAN              },
                { "generators",   optional_argument, NULL, ARG_GENERATORS       },
                { "host",         required_argument, NULL, 'H'                  },
                { "machine",      required_argument, NULL, 'M'                  },
                { "iterations",   required_argument, NULL, ARG_ITERATIONS       },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        arg_root = optarg;
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
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --man= argument.");

                                arg_man = r;
                        } else
                                arg_man = true;

                        break;

                case ARG_GENERATORS:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --generators= argument.");

                                arg_generators = r;
                        } else
                                arg_generators = true;

                        break;

                case ARG_ITERATIONS:
                        r = safe_atou(optarg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations: %s", optarg);

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (arg_scope == UNIT_FILE_GLOBAL &&
            !STR_IN_SET(argv[optind] ?: "time", "dot", "unit-paths", "verify"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verbs dot, unit-paths, verify.");

        if (streq_ptr(argv[optind], "cat-config") && arg_scope == UNIT_FILE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --user is not supported for cat-config right now.");

        if (arg_root && !streq_ptr(argv[optind], "cat-config"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --root is only supported for cat-config right now.");

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help",              VERB_ANY, VERB_ANY, 0,            help                   },
                { "time",              VERB_ANY, 1,        VERB_DEFAULT, analyze_time           },
                { "blame",             VERB_ANY, 1,        0,            analyze_blame          },
                { "critical-chain",    VERB_ANY, VERB_ANY, 0,            analyze_critical_chain },
                { "plot",              VERB_ANY, 1,        0,            analyze_plot           },
                { "dot",               VERB_ANY, VERB_ANY, 0,            dot                    },
                { "log-level",         VERB_ANY, 2,        0,            get_or_set_log_level   },
                { "log-target",        VERB_ANY, 2,        0,            get_or_set_log_target  },
                /* The following four verbs are deprecated aliases */
                { "set-log-level",     2,        2,        0,            set_log_level          },
                { "get-log-level",     VERB_ANY, 1,        0,            get_log_level          },
                { "set-log-target",    2,        2,        0,            set_log_target         },
                { "get-log-target",    VERB_ANY, 1,        0,            get_log_target         },

                { "dump",              VERB_ANY, 1,        0,            dump                   },
                { "cat-config",        2,        VERB_ANY, 0,            cat_config             },
                { "unit-files",        VERB_ANY, VERB_ANY, 0,            do_unit_files          },
                { "unit-paths",        1,        1,        0,            dump_unit_paths        },
                { "exit-status",       VERB_ANY, VERB_ANY, 0,            dump_exit_status       },
                { "syscall-filter",    VERB_ANY, VERB_ANY, 0,            dump_syscall_filters   },
                { "condition",         2,        VERB_ANY, 0,            do_condition           },
                { "verify",            2,        VERB_ANY, 0,            do_verify              },
                { "calendar",          2,        VERB_ANY, 0,            test_calendar          },
                { "timestamp",         2,        VERB_ANY, 0,            test_timestamp         },
                { "timespan",          2,        VERB_ANY, 0,            dump_timespan          },
                { "service-watchdogs", VERB_ANY, 2,        0,            service_watchdogs      },
                { "security",          VERB_ANY, VERB_ANY, 0,            do_security            },
                {}
        };

        int r;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
