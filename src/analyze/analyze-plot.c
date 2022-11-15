/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-plot.h"
#include "analyze-time-data.h"
#include "bus-error.h"
#include "bus-map-properties.h"
#include "sort-util.h"
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


typedef struct HostInfo {
        char *hostname;
        char *kernel_name;
        char *kernel_release;
        char *kernel_version;
        char *os_pretty_name;
        char *virtualization;
        char *architecture;
} HostInfo;

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

        if (arg_scope != LOOKUP_SCOPE_SYSTEM) {
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

static int compare_unit_start(const UnitTimes *a, const UnitTimes *b) {
        return CMP(a->activating, b->activating);
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

int verb_plot(int argc, char *argv[], void *userdata) {
        _cleanup_(free_host_infop) HostInfo *host = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        _cleanup_free_ char *pretty_times = NULL;
        bool use_full_bus = arg_scope == LOOKUP_SCOPE_SYSTEM;
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

        if (use_full_bus || arg_scope != LOOKUP_SCOPE_SYSTEM) {
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

        return EXIT_SUCCESS;
}
