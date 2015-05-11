/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2013 Lennart Poettering
  Copyright 2013 Simon Peeters

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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>

#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "log.h"
#include "build.h"
#include "util.h"
#include "strxcpyx.h"
#include "strv.h"
#include "unit-name.h"
#include "special.h"
#include "hashmap.h"
#include "pager.h"
#include "analyze-verify.h"
#include "terminal-util.h"

#define SCALE_X (0.1 / 1000.0)   /* pixels per us */
#define SCALE_Y (20.0)

#define compare(a, b) (((a) > (b))? 1 : (((b) > (a))? -1 : 0))

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
        } while(false)

static enum dot {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE
} arg_dot = DEP_ALL;
static char** arg_dot_from_patterns = NULL;
static char** arg_dot_to_patterns = NULL;
static usec_t arg_fuzz = 0;
static bool arg_no_pager = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_user = false;
static bool arg_man = true;

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
};

struct unit_times {
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

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static int bus_get_uint64_property(sd_bus *bus, const char *path, const char *interface, const char *property, uint64_t *val) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
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

        if (r < 0) {
                log_error("Failed to parse reply: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
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
        if (r < 0) {
                log_error("Failed to get unit property %s: %s", property, bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int compare_unit_time(const void *a, const void *b) {
        return compare(((struct unit_times *)b)->time,
                       ((struct unit_times *)a)->time);
}

static int compare_unit_start(const void *a, const void *b) {
        return compare(((struct unit_times *)a)->activating,
                       ((struct unit_times *)b)->activating);
}

static void free_unit_times(struct unit_times *t, unsigned n) {
        struct unit_times *p;

        for (p = t; p < t + n; p++)
                free(p->name);

        free(t);
}

static int acquire_time_data(sd_bus *bus, struct unit_times **out) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, c = 0;
        struct unit_times *unit_times = NULL;
        size_t size = 0;
        UnitInfo u;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnits",
                        &error, &reply,
                        NULL);
        if (r < 0) {
                log_error("Failed to list units: %s", bus_error_message(&error, -r));
                goto fail;
        }

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0) {
                bus_log_parse_error(r);
                goto fail;
        }

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {
                struct unit_times *t;

                if (!GREEDY_REALLOC(unit_times, size, c+1)) {
                        r = log_oom();
                        goto fail;
                }

                t = unit_times+c;
                t->name = NULL;

                assert_cc(sizeof(usec_t) == sizeof(uint64_t));

                if (bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "InactiveExitTimestampMonotonic",
                                            &t->activating) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "ActiveEnterTimestampMonotonic",
                                            &t->activated) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "ActiveExitTimestampMonotonic",
                                            &t->deactivating) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "InactiveEnterTimestampMonotonic",
                                            &t->deactivated) < 0) {
                        r = -EIO;
                        goto fail;
                }

                if (t->activated >= t->activating)
                        t->time = t->activated - t->activating;
                else if (t->deactivated >= t->activating)
                        t->time = t->deactivated - t->activating;
                else
                        t->time = 0;

                if (t->activating == 0)
                        continue;

                t->name = strdup(u.id);
                if (t->name == NULL) {
                        r = log_oom();
                        goto fail;
                }
                c++;
        }
        if (r < 0) {
                bus_log_parse_error(r);
                goto fail;
        }

        *out = unit_times;
        return c;

fail:
        if (unit_times)
                free_unit_times(unit_times, (unsigned) c);
        return r;
}

static int acquire_boot_times(sd_bus *bus, struct boot_times **bt) {
        static struct boot_times times;
        static bool cached = false;

        if (cached)
                goto finish;

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        if (bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "FirmwareTimestampMonotonic",
                                    &times.firmware_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "LoaderTimestampMonotonic",
                                    &times.loader_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "KernelTimestamp",
                                    &times.kernel_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "InitRDTimestampMonotonic",
                                    &times.initrd_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "UserspaceTimestampMonotonic",
                                    &times.userspace_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "FinishTimestampMonotonic",
                                    &times.finish_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "SecurityStartTimestampMonotonic",
                                    &times.security_start_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "SecurityFinishTimestampMonotonic",
                                    &times.security_finish_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "GeneratorsStartTimestampMonotonic",
                                    &times.generators_start_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "GeneratorsFinishTimestampMonotonic",
                                    &times.generators_finish_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "UnitsLoadStartTimestampMonotonic",
                                    &times.unitsload_start_time) < 0 ||
            bus_get_uint64_property(bus,
                                    "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager",
                                    "UnitsLoadFinishTimestampMonotonic",
                                    &times.unitsload_finish_time) < 0)
                return -EIO;

        if (times.finish_time <= 0) {
                log_error("Bootup is not yet finished. Please try again later.");
                return -EINPROGRESS;
        }

        if (times.initrd_time)
                times.kernel_done_time = times.initrd_time;
        else
                times.kernel_done_time = times.userspace_time;

        cached = true;

finish:
        *bt = &times;
        return 0;
}

static void free_host_info(struct host_info *hi) {
        free(hi->hostname);
        free(hi->kernel_name);
        free(hi->kernel_release);
        free(hi->kernel_version);
        free(hi->os_pretty_name);
        free(hi->virtualization);
        free(hi->architecture);
        free(hi);
}

static int acquire_host_info(sd_bus *bus, struct host_info **hi) {
        int r;
        struct host_info *host;

        static const struct bus_properties_map hostname_map[] = {
                { "Hostname", "s", NULL, offsetof(struct host_info, hostname) },
                { "KernelName", "s", NULL, offsetof(struct host_info, kernel_name) },
                { "KernelRelease", "s", NULL, offsetof(struct host_info, kernel_release) },
                { "KernelVersion", "s", NULL, offsetof(struct host_info, kernel_version) },
                { "OperatingSystemPrettyName", "s", NULL, offsetof(struct host_info, os_pretty_name) },
                {}
        };

        static const struct bus_properties_map manager_map[] = {
                { "Virtualization", "s", NULL, offsetof(struct host_info, virtualization) },
                { "Architecture",   "s", NULL, offsetof(struct host_info, architecture) },
                {}
        };

        host = new0(struct host_info, 1);
        if (!host)
                return log_oom();

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.hostname1",
                                   "/org/freedesktop/hostname1",
                                   hostname_map,
                                   host);
        if (r < 0)
                goto fail;

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.systemd1",
                                   "/org/freedesktop/systemd1",
                                   manager_map,
                                   host);
        if (r < 0)
                goto fail;

        *hi = host;
        return 0;
fail:
        free_host_info(host);
        return r;
}

static int pretty_boot_time(sd_bus *bus, char **_buf) {
        char ts[FORMAT_TIMESPAN_MAX];
        struct boot_times *t;
        static char buf[4096];
        size_t size;
        char *ptr;
        int r;

        r = acquire_boot_times(bus, &t);
        if (r < 0)
                return r;

        ptr = buf;
        size = sizeof(buf);

        size = strpcpyf(&ptr, size, "Startup finished in ");
        if (t->firmware_time)
                size = strpcpyf(&ptr, size, "%s (firmware) + ", format_timespan(ts, sizeof(ts), t->firmware_time - t->loader_time, USEC_PER_MSEC));
        if (t->loader_time)
                size = strpcpyf(&ptr, size, "%s (loader) + ", format_timespan(ts, sizeof(ts), t->loader_time, USEC_PER_MSEC));
        if (t->kernel_time)
                size = strpcpyf(&ptr, size, "%s (kernel) + ", format_timespan(ts, sizeof(ts), t->kernel_done_time, USEC_PER_MSEC));
        if (t->initrd_time > 0)
                size = strpcpyf(&ptr, size, "%s (initrd) + ", format_timespan(ts, sizeof(ts), t->userspace_time - t->initrd_time, USEC_PER_MSEC));

        size = strpcpyf(&ptr, size, "%s (userspace) ", format_timespan(ts, sizeof(ts), t->finish_time - t->userspace_time, USEC_PER_MSEC));
        if (t->kernel_time > 0)
                strpcpyf(&ptr, size, "= %s", format_timespan(ts, sizeof(ts), t->firmware_time + t->finish_time, USEC_PER_MSEC));
        else
                strpcpyf(&ptr, size, "= %s", format_timespan(ts, sizeof(ts), t->finish_time - t->userspace_time, USEC_PER_MSEC));

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
            SCALE_X * (end - begin), SCALE_Y * height);

        for (i = ((long long) (begin / 100000)) * 100000; i <= end; i+=100000) {
                /* lines for each second */
                if (i % 5000000 == 0)
                        svg("  <line class=\"sec5\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            SCALE_X * i, SCALE_X * i, SCALE_Y * height, SCALE_X * i, -5.0, 0.000001 * i);
                else if (i % 1000000 == 0)
                        svg("  <line class=\"sec1\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            SCALE_X * i, SCALE_X * i, SCALE_Y * height, SCALE_X * i, -5.0, 0.000001 * i);
                else
                        svg("  <line class=\"sec01\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n",
                            SCALE_X * i, SCALE_X * i, SCALE_Y * height);
        }
}

static int analyze_plot(sd_bus *bus) {
        struct unit_times *times;
        struct boot_times *boot;
        struct host_info *host = NULL;
        int n, m = 1, y=0;
        double width;
        _cleanup_free_ char *pretty_times = NULL;
        struct unit_times *u;

        n = acquire_boot_times(bus, &boot);
        if (n < 0)
                return n;

        n = pretty_boot_time(bus, &pretty_times);
        if (n < 0)
                return n;

        n = acquire_host_info(bus, &host);
        if (n < 0)
                return n;

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                goto out;

        qsort(times, n, sizeof(struct unit_times), compare_unit_start);

        width = SCALE_X * (boot->firmware_time + boot->finish_time);
        if (width < 800.0)
                width = 800.0;

        if (boot->firmware_time > boot->loader_time)
                m++;
        if (boot->loader_time) {
                m++;
                if (width < 1000.0)
                        width = 1000.0;
        }
        if (boot->initrd_time)
                m++;
        if (boot->kernel_time)
                m++;

        for (u = times; u < times + n; u++) {
                double text_start, text_width;

                if (u->activating < boot->userspace_time ||
                    u->activating > boot->finish_time) {
                        free(u->name);
                        u->name = NULL;
                        continue;
                }

                /* If the text cannot fit on the left side then
                 * increase the svg width so it fits on the right.
                 * TODO: calculate the text width more accurately */
                text_width = 8.0 * strlen(u->name);
                text_start = (boot->firmware_time + u->activating) * SCALE_X;
                if (text_width > text_start && text_width + text_start > width)
                        width = text_width + text_start;

                if (u->deactivated > u->activating && u->deactivated <= boot->finish_time
                                && u->activated == 0 && u->deactivating == 0)
                        u->activated = u->deactivating = u->deactivated;
                if (u->activated < u->activating || u->activated > boot->finish_time)
                        u->activated = boot->finish_time;
                if (u->deactivating < u->activated || u->activated > boot->finish_time)
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
            "<!-- This plot was generated by systemd-analyze version %-16.16s -->\n\n", VERSION);

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
        svg("<text x=\"20\" y=\"30\">%s %s (%s %s %s) %s %s</text>",
            isempty(host->os_pretty_name) ? "Linux" : host->os_pretty_name,
            isempty(host->hostname) ? "" : host->hostname,
            isempty(host->kernel_name) ? "" : host->kernel_name,
            isempty(host->kernel_release) ? "" : host->kernel_release,
            isempty(host->kernel_version) ? "" : host->kernel_version,
            isempty(host->architecture) ? "" : host->architecture,
            isempty(host->virtualization) ? "" : host->virtualization);

        svg("<g transform=\"translate(%.3f,100)\">\n", 20.0 + (SCALE_X * boot->firmware_time));
        svg_graph_box(m, -(double) boot->firmware_time, boot->finish_time);

        if (boot->firmware_time) {
                svg_bar("firmware", -(double) boot->firmware_time, -(double) boot->loader_time, y);
                svg_text(true, -(double) boot->firmware_time, y, "firmware");
                y++;
        }
        if (boot->loader_time) {
                svg_bar("loader", -(double) boot->loader_time, 0, y);
                svg_text(true, -(double) boot->loader_time, y, "loader");
                y++;
        }
        if (boot->kernel_time) {
                svg_bar("kernel", 0, boot->kernel_done_time, y);
                svg_text(true, 0, y, "kernel");
                y++;
        }
        if (boot->initrd_time) {
                svg_bar("initrd", boot->initrd_time, boot->userspace_time, y);
                svg_text(true, boot->initrd_time, y, "initrd");
                y++;
        }
        svg_bar("active", boot->userspace_time, boot->finish_time, y);
        svg_bar("security", boot->security_start_time, boot->security_finish_time, y);
        svg_bar("generators", boot->generators_start_time, boot->generators_finish_time, y);
        svg_bar("unitsload", boot->unitsload_start_time, boot->unitsload_finish_time, y);
        svg_text(true, boot->userspace_time, y, "systemd");
        y++;

        for (u = times; u < times + n; u++) {
                char ts[FORMAT_TIMESPAN_MAX];
                bool b;

                if (!u->name)
                        continue;

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
                y++;
        }

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
        svg_bar("security", 0, 300000, y);
        svg_text(true, 400000, y, "Setting up security module");
        y++;
        svg_bar("generators", 0, 300000, y);
        svg_text(true, 400000, y, "Generators");
        y++;
        svg_bar("unitsload", 0, 300000, y);
        svg_text(true, 400000, y, "Loading unit files");
        y++;

        svg("</g>\n\n");

        svg("</svg>\n");

        free_unit_times(times, (unsigned) n);

        n = 0;
out:
        free_host_info(host);
        return n;
}

static int list_dependencies_print(const char *name, unsigned int level, unsigned int branches,
                                   bool last, struct unit_times *times, struct boot_times *boot) {
        unsigned int i;
        char ts[FORMAT_TIMESPAN_MAX], ts2[FORMAT_TIMESPAN_MAX];

        for (i = level; i != 0; i--)
                printf("%s", draw_special_char(branches & (1 << (i-1)) ? DRAW_TREE_VERTICAL : DRAW_TREE_SPACE));

        printf("%s", draw_special_char(last ? DRAW_TREE_RIGHT : DRAW_TREE_BRANCH));

        if (times) {
                if (times->time)
                        printf("%s%s @%s +%s%s", ANSI_HIGHLIGHT_RED_ON, name,
                               format_timespan(ts, sizeof(ts), times->activating - boot->userspace_time, USEC_PER_MSEC),
                               format_timespan(ts2, sizeof(ts2), times->time, USEC_PER_MSEC), ANSI_HIGHLIGHT_OFF);
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
        if (path == NULL)
                return -ENOMEM;

        return bus_get_unit_property_strv(bus, path, "After", deps);
}

static Hashmap *unit_times_hashmap;

static int list_dependencies_compare(const void *_a, const void *_b) {
        const char **a = (const char**) _a, **b = (const char**) _b;
        usec_t usa = 0, usb = 0;
        struct unit_times *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->activated;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->activated;

        return usb - usa;
}

static int list_dependencies_one(sd_bus *bus, const char *name, unsigned int level, char ***units,
                                 unsigned int branches) {
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

        qsort_safe(deps, strv_length(deps), sizeof (char*), list_dependencies_compare);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times
                    && times->activated
                    && times->activated <= boot->finish_time
                    && (times->activated >= service_longest
                        || service_longest == 0)) {
                        service_longest = times->activated;
                        break;
                }
        }

        if (service_longest == 0 )
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times && times->activated
                    && times->activated <= boot->finish_time
                    && (service_longest - times->activated) <= arg_fuzz) {
                        to_print++;
                }
        }

        if (!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (!times
                    || !times->activated
                    || times->activated > boot->finish_time
                    || service_longest - times->activated > arg_fuzz)
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

                r = list_dependencies_one(bus, *c, level + 1, units,
                                          (branches << 1) | (to_print ? 1 : 0));
                if (r < 0)
                        return r;

                if (!to_print)
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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        struct boot_times *boot;

        assert(bus);

        path = unit_dbus_path_from_name(name);
        if (path == NULL)
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
        if (r < 0) {
                log_error("Failed to get ID: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &id);
        if (r < 0)
                return bus_log_parse_error(r);

        times = hashmap_get(unit_times_hashmap, id);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        if (times) {
                if (times->time)
                        printf("%s%s +%s%s\n", ANSI_HIGHLIGHT_RED_ON, id,
                               format_timespan(ts, sizeof(ts), times->time, USEC_PER_MSEC), ANSI_HIGHLIGHT_OFF);
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s\n", id, format_timespan(ts, sizeof(ts), times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

static int analyze_critical_chain(sd_bus *bus, char *names[]) {
        struct unit_times *times;
        unsigned int i;
        Hashmap *h;
        int n, r;

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return -ENOMEM;

        for (i = 0; i < (unsigned)n; i++) {
                r = hashmap_put(h, times[i].name, &times[i]);
                if (r < 0)
                        return r;
        }
        unit_times_hashmap = h;

        pager_open_if_enabled();

        puts("The time after the unit is active or started is printed after the \"@\" character.\n"
             "The time the unit takes to start is printed after the \"+\" character.\n");

        if (!strv_isempty(names)) {
                char **name;
                STRV_FOREACH(name, names)
                        list_dependencies(bus, *name);
        } else
                list_dependencies(bus, SPECIAL_DEFAULT_TARGET);

        hashmap_free(h);
        free_unit_times(times, (unsigned) n);
        return 0;
}

static int analyze_blame(sd_bus *bus) {
        struct unit_times *times;
        unsigned i;
        int n;

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        qsort(times, n, sizeof(struct unit_times), compare_unit_time);

        pager_open_if_enabled();

        for (i = 0; i < (unsigned) n; i++) {
                char ts[FORMAT_TIMESPAN_MAX];

                if (times[i].time > 0)
                        printf("%16s %s\n", format_timespan(ts, sizeof(ts), times[i].time, USEC_PER_MSEC), times[i].name);
        }

        free_unit_times(times, (unsigned) n);
        return 0;
}

static int analyze_time(sd_bus *bus) {
        _cleanup_free_ char *buf = NULL;
        int r;

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return 0;
}

static int graph_one_property(sd_bus *bus, const UnitInfo *u, const char* prop, const char *color, char* patterns[]) {
        _cleanup_strv_free_ char **units = NULL;
        char **unit;
        int r;
        bool match_patterns;

        assert(u);
        assert(prop);
        assert(color);

        match_patterns = strv_fnmatch(patterns, u->id, 0);

        if (!strv_isempty(arg_dot_from_patterns) &&
            !match_patterns &&
            !strv_fnmatch(arg_dot_from_patterns, u->id, 0))
                        return 0;

        r = bus_get_unit_property_strv(bus, u->unit_path, prop, &units);
        if (r < 0)
                return r;

        STRV_FOREACH(unit, units) {
                bool match_patterns2;

                match_patterns2 = strv_fnmatch(patterns, *unit, 0);

                if (!strv_isempty(arg_dot_to_patterns) &&
                    !match_patterns2 &&
                    !strv_fnmatch(arg_dot_to_patterns, *unit, 0))
                        continue;

                if (!strv_isempty(patterns) && !match_patterns && !match_patterns2)
                        continue;

                printf("\t\"%s\"->\"%s\" [color=\"%s\"];\n", u->id, *unit, color);
        }

        return 0;
}

static int graph_one(sd_bus *bus, const UnitInfo *u, char *patterns[]) {
        int r;

        assert(bus);
        assert(u);

        if (arg_dot == DEP_ORDER ||arg_dot == DEP_ALL) {
                r = graph_one_property(bus, u, "After", "green", patterns);
                if (r < 0)
                        return r;
        }

        if (arg_dot == DEP_REQUIRE ||arg_dot == DEP_ALL) {
                r = graph_one_property(bus, u, "Requires", "black", patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "RequiresOverridable", "black", patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "RequisiteOverridable", "darkblue", patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "Wants", "grey66", patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "Conflicts", "red", patterns);
                if (r < 0)
                        return r;
                r = graph_one_property(bus, u, "ConflictedBy", "red", patterns);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dot(sd_bus *bus, char* patterns[]) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;
        UnitInfo u;

        r = sd_bus_call_method(
                        bus,
                       "org.freedesktop.systemd1",
                       "/org/freedesktop/systemd1",
                       "org.freedesktop.systemd1.Manager",
                       "ListUnits",
                       &error,
                       &reply,
                       "");
        if (r < 0) {
                log_error("Failed to list units: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        printf("digraph systemd {\n");

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {

                r = graph_one(bus, &u, patterns);
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

static int dump(sd_bus *bus, char **args) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *text = NULL;
        int r;

        if (!strv_isempty(args)) {
                log_error("Too many arguments.");
                return -E2BIG;
        }

        pager_open_if_enabled();

        r = sd_bus_call_method(
                        bus,
                       "org.freedesktop.systemd1",
                       "/org/freedesktop/systemd1",
                       "org.freedesktop.systemd1.Manager",
                       "Dump",
                       &error,
                       &reply,
                       "");
        if (r < 0) {
                log_error("Failed issue method call: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(text, stdout);
        return 0;
}

static int set_log_level(sd_bus *bus, char **args) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(args);

        if (strv_length(args) != 1) {
                log_error("This command expects one argument only.");
                return -E2BIG;
        }

        r = sd_bus_set_property(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "LogLevel",
                        &error,
                        "s",
                        args[0]);
        if (r < 0) {
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
                return -EIO;
        }

        return 0;
}

static void help(void) {

        pager_open_if_enabled();

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Profile systemd, show unit dependencies, check unit files.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --system             Operate on system systemd instance\n"
               "     --user               Operate on user systemd instance\n"
               "  -H --host=[USER@]HOST   Operate on remote host\n"
               "  -M --machine=CONTAINER  Operate on local container\n"
               "     --order              Show only order in the graph\n"
               "     --require            Show only requirement in the graph\n"
               "     --from-pattern=GLOB  Show only origins in the graph\n"
               "     --to-pattern=GLOB    Show only destinations in the graph\n"
               "     --fuzz=SECONDS       Also print also services which finished SECONDS\n"
               "                          earlier than the latest in the branch\n"
               "     --man[=BOOL]         Do [not] check for existence of man pages\n\n"
               "Commands:\n"
               "  time                    Print time spent in the kernel\n"
               "  blame                   Print list of running units ordered by time to init\n"
               "  critical-chain          Print a tree of the time critical chain of units\n"
               "  plot                    Output SVG graphic showing service initialization\n"
               "  dot                     Output dependency graph in dot(1) format\n"
               "  set-log-level LEVEL     Set logging threshold for systemd\n"
               "  dump                    Output state serialization of service manager\n"
               "  verify FILE...          Check unit files for correctness\n"
               , program_invocation_short_name);

        /* When updating this list, including descriptions, apply
         * changes to shell-completion/bash/systemd-analyze and
         * shell-completion/zsh/_systemd-analyze too. */
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_USER,
                ARG_SYSTEM,
                ARG_DOT_FROM_PATTERN,
                ARG_DOT_TO_PATTERN,
                ARG_FUZZ,
                ARG_NO_PAGER,
                ARG_MAN,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'                  },
                { "version",      no_argument,       NULL, ARG_VERSION          },
                { "order",        no_argument,       NULL, ARG_ORDER            },
                { "require",      no_argument,       NULL, ARG_REQUIRE          },
                { "user",         no_argument,       NULL, ARG_USER             },
                { "system",       no_argument,       NULL, ARG_SYSTEM           },
                { "from-pattern", required_argument, NULL, ARG_DOT_FROM_PATTERN },
                { "to-pattern",   required_argument, NULL, ARG_DOT_TO_PATTERN   },
                { "fuzz",         required_argument, NULL, ARG_FUZZ             },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER         },
                { "man",          optional_argument, NULL, ARG_MAN              },
                { "host",         required_argument, NULL, 'H'                  },
                { "machine",      required_argument, NULL, 'M'                  },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
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
                        arg_no_pager = true;
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
                                if (r < 0) {
                                        log_error("Failed to parse --man= argument.");
                                        return -EINVAL;
                                }

                                arg_man = !!r;
                        } else
                                arg_man = true;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        return 1; /* work to do */
}

int main(int argc, char *argv[]) {
        int r;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (streq_ptr(argv[optind], "verify"))
                r = verify_units(argv+optind+1,
                                 arg_user ? MANAGER_USER : MANAGER_SYSTEM,
                                 arg_man);
        else {
                _cleanup_bus_close_unref_ sd_bus *bus = NULL;

                r = bus_open_transport_systemd(arg_transport, arg_host, arg_user, &bus);
                if (r < 0) {
                        log_error_errno(r, "Failed to create bus connection: %m");
                        goto finish;
                }

                if (!argv[optind] || streq(argv[optind], "time"))
                        r = analyze_time(bus);
                else if (streq(argv[optind], "blame"))
                        r = analyze_blame(bus);
                else if (streq(argv[optind], "critical-chain"))
                        r = analyze_critical_chain(bus, argv+optind+1);
                else if (streq(argv[optind], "plot"))
                        r = analyze_plot(bus);
                else if (streq(argv[optind], "dot"))
                        r = dot(bus, argv+optind+1);
                else if (streq(argv[optind], "dump"))
                        r = dump(bus, argv+optind+1);
                else if (streq(argv[optind], "set-log-level"))
                        r = set_log_level(bus, argv+optind+1);
                else
                        log_error("Unknown operation '%s'.", argv[optind]);
        }

finish:
        pager_close();

        strv_free(arg_dot_from_patterns);
        strv_free(arg_dot_to_patterns);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
