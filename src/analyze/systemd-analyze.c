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
#include <sys/utsname.h>
#include <fnmatch.h>

#include "install.h"
#include "log.h"
#include "dbus-common.h"
#include "build.h"
#include "util.h"
#include "strxcpyx.h"
#include "fileio.h"
#include "strv.h"
#include "unit-name.h"
#include "special.h"
#include "hashmap.h"
#include "pager.h"

#define SCALE_X (0.1 / 1000.0)   /* pixels per us */
#define SCALE_Y 20.0

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

static UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static enum dot {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE
} arg_dot = DEP_ALL;
static char** arg_dot_from_patterns = NULL;
static char** arg_dot_to_patterns = NULL;
static usec_t arg_fuzz = 0;
static bool arg_no_pager = false;

struct boot_times {
        usec_t firmware_time;
        usec_t loader_time;
        usec_t kernel_time;
        usec_t kernel_done_time;
        usec_t initrd_time;
        usec_t userspace_time;
        usec_t finish_time;
        usec_t generators_start_time;
        usec_t generators_finish_time;
        usec_t unitsload_start_time;
        usec_t unitsload_finish_time;
};

struct unit_times {
        char *name;
        usec_t ixt;
        usec_t iet;
        usec_t axt;
        usec_t aet;
        usec_t time;
};

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static int bus_get_uint64_property(DBusConnection *bus, const char *path, const char *interface, const char *property, uint64_t *val) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r;

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &property,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT64)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_get_basic(&sub, val);

        return 0;
}

static int compare_unit_time(const void *a, const void *b) {
        return compare(((struct unit_times *)b)->time,
                       ((struct unit_times *)a)->time);
}

static int compare_unit_start(const void *a, const void *b) {
        return compare(((struct unit_times *)a)->ixt,
                       ((struct unit_times *)b)->ixt);
}

static int get_os_name(char **_n) {
        char *n = NULL;
        int r;

        r = parse_env_file("/etc/os-release", NEWLINE, "PRETTY_NAME", &n, NULL);
        if (r < 0)
                return r;

        if (!n)
                return -ENOENT;

        *_n = n;
        return 0;
}

static void free_unit_times(struct unit_times *t, unsigned n) {
        struct unit_times *p;

        for (p = t; p < t + n; p++)
                free(p->name);

        free(t);
}

static int acquire_time_data(DBusConnection *bus, struct unit_times **out) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r, c = 0, n_units = 0;
        struct unit_times *unit_times = NULL;

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnits",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                goto fail;

        if (!dbus_message_iter_init(reply, &iter) ||
                        dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                        dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto fail;
        }

        for (dbus_message_iter_recurse(&iter, &sub);
             dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID;
             dbus_message_iter_next(&sub)) {
                struct unit_info u;
                struct unit_times *t;

                if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRUCT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto fail;
                }

                if (c >= n_units) {
                        struct unit_times *w;

                        n_units = MAX(2*c, 16);
                        w = realloc(unit_times, sizeof(struct unit_times) * n_units);

                        if (!w) {
                                r = log_oom();
                                goto fail;
                        }

                        unit_times = w;
                }
                t = unit_times+c;
                t->name = NULL;

                r = bus_parse_unit_info(&sub, &u);
                if (r < 0)
                        goto fail;

                assert_cc(sizeof(usec_t) == sizeof(uint64_t));

                if (bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "InactiveExitTimestampMonotonic",
                                            &t->ixt) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "ActiveEnterTimestampMonotonic",
                                            &t->aet) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "ActiveExitTimestampMonotonic",
                                            &t->axt) < 0 ||
                    bus_get_uint64_property(bus, u.unit_path,
                                            "org.freedesktop.systemd1.Unit",
                                            "InactiveEnterTimestampMonotonic",
                                            &t->iet) < 0) {
                        r = -EIO;
                        goto fail;
                }

                if (t->aet >= t->ixt)
                        t->time = t->aet - t->ixt;
                else if (t->iet >= t->ixt)
                        t->time = t->iet - t->ixt;
                else
                        t->time = 0;

                if (t->ixt == 0)
                        continue;

                t->name = strdup(u.id);
                if (t->name == NULL) {
                        r = log_oom();
                        goto fail;
                }
                c++;
        }

        *out = unit_times;
        return c;

fail:
        free_unit_times(unit_times, (unsigned) c);
        return r;
}

static int acquire_boot_times(DBusConnection *bus, struct boot_times **bt) {
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
                return -EAGAIN;
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

static int pretty_boot_time(DBusConnection *bus, char **_buf) {
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
                size = strpcpyf(&ptr, size, "= %s", format_timespan(ts, sizeof(ts), t->firmware_time + t->finish_time, USEC_PER_MSEC));
        else
                size = strpcpyf(&ptr, size, "= %s", format_timespan(ts, sizeof(ts), t->finish_time - t->userspace_time, USEC_PER_MSEC));

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

static int analyze_plot(DBusConnection *bus) {
        struct unit_times *times;
        struct boot_times *boot;
        struct utsname name;
        int n, m = 1, y=0;
        double width;
        _cleanup_free_ char *pretty_times = NULL, *osname = NULL;
        struct unit_times *u;

        n = acquire_boot_times(bus, &boot);
        if (n < 0)
                return n;

        n = pretty_boot_time(bus, &pretty_times);
        if (n < 0)
                return n;

        get_os_name(&osname);
        assert_se(uname(&name) >= 0);

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

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
                double len;

                if (u->ixt < boot->userspace_time ||
                    u->ixt > boot->finish_time) {
                        free(u->name);
                        u->name = NULL;
                        continue;
                }
                len = ((boot->firmware_time + u->ixt) * SCALE_X)
                        + (10.0 * strlen(u->name));
                if (len > width)
                        width = len;

                if (u->iet > u->ixt && u->iet <= boot->finish_time
                                && u->aet == 0 && u->axt == 0)
                        u->aet = u->axt = u->iet;
                if (u->aet < u->ixt || u->aet > boot->finish_time)
                        u->aet = boot->finish_time;
                if (u->axt < u->aet || u->aet > boot->finish_time)
                        u->axt = boot->finish_time;
                if (u->iet < u->axt || u->iet > boot->finish_time)
                        u->iet = boot->finish_time;
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
            "      rect.activating   { fill: rgb(255,0,0); fill-opacity: 0.7; }\n"
            "      rect.active       { fill: rgb(200,150,150); fill-opacity: 0.7; }\n"
            "      rect.deactivating { fill: rgb(150,100,100); fill-opacity: 0.7; }\n"
            "      rect.kernel       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.initrd       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.firmware     { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.loader       { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
            "      rect.userspace    { fill: rgb(150,150,150); fill-opacity: 0.7; }\n"
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

        svg("<text x=\"20\" y=\"50\">%s</text>", pretty_times);
        svg("<text x=\"20\" y=\"30\">%s %s (%s %s) %s</text>",
            isempty(osname) ? "Linux" : osname,
            name.nodename, name.release, name.version, name.machine);

        svg("<g transform=\"translate(%.3f,100)\">\n", 20.0 + (SCALE_X * boot->firmware_time));
        svg_graph_box(m, -boot->firmware_time, boot->finish_time);

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
        svg_bar("generators", boot->generators_start_time, boot->generators_finish_time, y);
        svg_bar("unitsload", boot->unitsload_start_time, boot->unitsload_finish_time, y);
        svg_text("left", boot->userspace_time, y, "systemd");
        y++;

        for (u = times; u < times + n; u++) {
                char ts[FORMAT_TIMESPAN_MAX];
                bool b;

                if (!u->name)
                        continue;

                svg_bar("activating",   u->ixt, u->aet, y);
                svg_bar("active",       u->aet, u->axt, y);
                svg_bar("deactivating", u->axt, u->iet, y);

                b = u->ixt * SCALE_X > width * 2 / 3;
                if (u->time)
                        svg_text(b, u->ixt, y, "%s (%s)",
                                 u->name, format_timespan(ts, sizeof(ts), u->time, USEC_PER_MSEC));
                else
                        svg_text(b, u->ixt, y, "%s", u->name);
                y++;
        }

        /* Legend */
        y++;
        svg_bar("activating", 0, 300000, y);
        svg_text("right", 400000, y, "Activating");
        y++;
        svg_bar("active", 0, 300000, y);
        svg_text("right", 400000, y, "Active");
        y++;
        svg_bar("deactivating", 0, 300000, y);
        svg_text("right", 400000, y, "Deactivating");
        y++;
        svg_bar("generators", 0, 300000, y);
        svg_text("right", 400000, y, "Generators");
        y++;
        svg_bar("unitsload", 0, 300000, y);
        svg_text("right", 400000, y, "Loading unit files");
        y++;

        svg("</g>\n\n");

        svg("</svg>");

        free_unit_times(times, (unsigned) n);

        return 0;
}

static int list_dependencies_print(const char *name, unsigned int level, unsigned int branches,
                                   bool last, struct unit_times *times, struct boot_times *boot) {
        unsigned int i;
        char ts[FORMAT_TIMESPAN_MAX], ts2[FORMAT_TIMESPAN_MAX];

        for (i = level; i != 0; i--)
                printf("%s", draw_special_char(branches & (1 << (i-1)) ? DRAW_TREE_VERT : DRAW_TREE_SPACE));

        printf("%s", draw_special_char(last ? DRAW_TREE_RIGHT : DRAW_TREE_BRANCH));

        if (times) {
                if (times->time)
                        printf("%s%s @%s +%s%s", ANSI_HIGHLIGHT_RED_ON, name,
                               format_timespan(ts, sizeof(ts), times->ixt - boot->userspace_time, USEC_PER_MSEC),
                               format_timespan(ts2, sizeof(ts2), times->time, USEC_PER_MSEC), ANSI_HIGHLIGHT_OFF);
                else if (times->aet > boot->userspace_time)
                        printf("%s @%s", name, format_timespan(ts, sizeof(ts), times->aet - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s", name);
        } else printf("%s", name);
        printf("\n");

        return 0;
}

static int list_dependencies_get_dependencies(DBusConnection *bus, const char *name, char ***deps) {
        static const char dependencies[] =
                "After\0";

        _cleanup_free_ char *path;
        const char *interface = "org.freedesktop.systemd1.Unit";

        _cleanup_dbus_message_unref_  DBusMessage *reply = NULL;
        DBusMessageIter iter, sub, sub2, sub3;

        int r = 0;
        char **ret = NULL;

        assert(bus);
        assert(name);
        assert(deps);

        path = unit_dbus_path_from_name(name);
        if (path == NULL) {
                r = -EINVAL;
                goto finish;
        }

        r = bus_method_call_with_reply(
                bus,
                "org.freedesktop.systemd1",
                path,
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &reply,
                NULL,
                DBUS_TYPE_STRING, &interface,
                DBUS_TYPE_INVALID);
        if (r < 0)
                goto finish;

        if (!dbus_message_iter_init(reply, &iter) ||
                dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
                dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY) {
                log_error("Failed to parse reply.");
                r = -EIO;
                goto finish;
        }

        dbus_message_iter_recurse(&iter, &sub);

        while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
                const char *prop;

                assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_DICT_ENTRY);
                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &prop, true) < 0) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                if (dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT) {
                        log_error("Failed to parse reply.");
                        r = -EIO;
                        goto finish;
                }

                dbus_message_iter_recurse(&sub2, &sub3);
                dbus_message_iter_next(&sub);

                if (!nulstr_contains(dependencies, prop))
                        continue;

                if (dbus_message_iter_get_arg_type(&sub3) == DBUS_TYPE_ARRAY) {
                        if (dbus_message_iter_get_element_type(&sub3) == DBUS_TYPE_STRING) {
                                DBusMessageIter sub4;
                                dbus_message_iter_recurse(&sub3, &sub4);

                                while (dbus_message_iter_get_arg_type(&sub4) != DBUS_TYPE_INVALID) {
                                        const char *s;

                                        assert(dbus_message_iter_get_arg_type(&sub4) == DBUS_TYPE_STRING);
                                        dbus_message_iter_get_basic(&sub4, &s);

                                        r = strv_extend(&ret, s);
                                        if (r < 0) {
                                                log_oom();
                                                goto finish;
                                        }

                                        dbus_message_iter_next(&sub4);
                                }
                        }
                }
        }
finish:
        if (r < 0)
                strv_free(ret);
        else
                *deps = ret;
        return r;
}

static Hashmap *unit_times_hashmap;

static int list_dependencies_compare(const void *_a, const void *_b) {
        const char **a = (const char**) _a, **b = (const char**) _b;
        usec_t usa = 0, usb = 0;
        struct unit_times *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->aet;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->aet;

        return usb - usa;
}

static int list_dependencies_one(DBusConnection *bus, const char *name, unsigned int level, char ***units,
                                 unsigned int branches) {
        _cleanup_strv_free_ char **deps = NULL;
        char **c;
        int r = 0;
        usec_t service_longest = 0;
        int to_print = 0;
        struct unit_times *times;
        struct boot_times *boot;

        if(strv_extend(units, name))
                return log_oom();

        r = list_dependencies_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        qsort(deps, strv_length(deps), sizeof (char*), list_dependencies_compare);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times
                    && times->aet
                    && times->aet <= boot->finish_time
                    && (times->aet >= service_longest
                        || service_longest == 0)) {
                        service_longest = times->aet;
                        break;
                }
        }

        if (service_longest == 0 )
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (times && times->aet
                    && times->aet <= boot->finish_time
                    && (service_longest - times->aet) <= arg_fuzz) {
                        to_print++;
                }
        }

        if(!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c);
                if (!times
                    || !times->aet
                    || times->aet > boot->finish_time
                    || service_longest - times->aet > arg_fuzz)
                        continue;

                to_print--;

                r = list_dependencies_print(*c, level, branches, to_print == 0, times, boot);
                if (r < 0)
                        return r;

                if (strv_contains(*units, *c)) {
                        r = list_dependencies_print("...", level + 1, (branches << 1) | (to_print ? 1 : 0),
                                                    true, NULL, boot);
                        continue;
                }

                r = list_dependencies_one(bus, *c, level + 1, units,
                                          (branches << 1) | (to_print ? 1 : 0));
                if(r < 0)
                        return r;


                if(!to_print)
                        break;

        }
        return 0;
}

static int list_dependencies(DBusConnection *bus, const char *name) {
        _cleanup_strv_free_ char **units = NULL;
        char ts[FORMAT_TIMESPAN_MAX];
        struct unit_times *times;
        int r;
        const char
                *path, *id,
                *interface = "org.freedesktop.systemd1.Unit",
                *property = "Id";
        DBusMessageIter iter, sub;
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        struct boot_times *boot;

        assert(bus);

        path = unit_dbus_path_from_name(name);
        if (path == NULL)
                return -EINVAL;

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_STRING, &property,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_recurse(&iter, &sub);

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_get_basic(&sub, &id);

        times = hashmap_get(unit_times_hashmap, id);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        if (times) {
                if (times->time)
                        printf("%s%s +%s%s\n", ANSI_HIGHLIGHT_RED_ON, id,
                               format_timespan(ts, sizeof(ts), times->time, USEC_PER_MSEC), ANSI_HIGHLIGHT_OFF);
                else if (times->aet > boot->userspace_time)
                        printf("%s @%s\n", id, format_timespan(ts, sizeof(ts), times->aet - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

static int analyze_critical_chain(DBusConnection *bus, char *names[]) {
        struct unit_times *times;
        int n, r;
        unsigned int i;
        Hashmap *h;

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        h = hashmap_new(string_hash_func, string_compare_func);
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

static int analyze_blame(DBusConnection *bus) {
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

static int analyze_time(DBusConnection *bus) {
        _cleanup_free_ char *buf = NULL;
        int r;

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return 0;
}

static int graph_one_property(const char *name, const char *prop, DBusMessageIter *iter, char* patterns[]) {

        static const char * const colors[] = {
                "Requires",              "[color=\"black\"]",
                "RequiresOverridable",   "[color=\"black\"]",
                "Requisite",             "[color=\"darkblue\"]",
                "RequisiteOverridable",  "[color=\"darkblue\"]",
                "Wants",                 "[color=\"grey66\"]",
                "Conflicts",             "[color=\"red\"]",
                "ConflictedBy",          "[color=\"red\"]",
                "After",                 "[color=\"green\"]"
        };

        const char *c = NULL;
        unsigned i;

        assert(name);
        assert(prop);
        assert(iter);

        for (i = 0; i < ELEMENTSOF(colors); i += 2)
                if (streq(colors[i], prop)) {
                        c = colors[i+1];
                        break;
                }

        if (!c)
                return 0;

        if (arg_dot != DEP_ALL)
                if ((arg_dot == DEP_ORDER) != streq(prop, "After"))
                        return 0;

        if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_ARRAY &&
            dbus_message_iter_get_element_type(iter) == DBUS_TYPE_STRING) {
                DBusMessageIter sub;

                dbus_message_iter_recurse(iter, &sub);

                for (dbus_message_iter_recurse(iter, &sub);
                     dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID;
                     dbus_message_iter_next(&sub)) {
                        const char *s;
                        char **p;
                        bool match_found;

                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                        dbus_message_iter_get_basic(&sub, &s);

                        if (!strv_isempty(arg_dot_from_patterns)) {
                                match_found = false;

                                STRV_FOREACH(p, arg_dot_from_patterns)
                                        if (fnmatch(*p, name, 0) == 0) {
                                                match_found = true;
                                                break;
                                        }

                                if (!match_found)
                                        continue;
                        }

                        if (!strv_isempty(arg_dot_to_patterns)) {
                                match_found = false;

                                STRV_FOREACH(p, arg_dot_to_patterns)
                                        if (fnmatch(*p, s, 0) == 0) {
                                                match_found = true;
                                                break;
                                        }

                                if (!match_found)
                                        continue;
                        }

                        if (!strv_isempty(patterns)) {
                                match_found = false;

                                STRV_FOREACH(p, patterns)
                                        if (fnmatch(*p, name, 0) == 0 || fnmatch(*p, s, 0) == 0) {
                                                match_found = true;
                                                break;
                                        }
                                if (!match_found)
                                        continue;
                        }

                        printf("\t\"%s\"->\"%s\" %s;\n", name, s, c);
                }
        }

        return 0;
}

static int graph_one(DBusConnection *bus, const struct unit_info *u, char *patterns[]) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        const char *interface = "org.freedesktop.systemd1.Unit";
        int r;
        DBusMessageIter iter, sub, sub2, sub3;

        assert(bus);
        assert(u);

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        u->unit_path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        &reply,
                        NULL,
                        DBUS_TYPE_STRING, &interface,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        for (dbus_message_iter_recurse(&iter, &sub);
             dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID;
             dbus_message_iter_next(&sub)) {
                const char *prop;

                assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_DICT_ENTRY);
                dbus_message_iter_recurse(&sub, &sub2);

                if (bus_iter_get_basic_and_next(&sub2, DBUS_TYPE_STRING, &prop, true) < 0 ||
                    dbus_message_iter_get_arg_type(&sub2) != DBUS_TYPE_VARIANT) {
                        log_error("Failed to parse reply.");
                        return -EIO;
                }

                dbus_message_iter_recurse(&sub2, &sub3);
                r = graph_one_property(u->id, prop, &sub3, patterns);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dot(DBusConnection *bus, char* patterns[]) {
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r;

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnits",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_iter_init(reply, &iter) ||
            dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRUCT)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        printf("digraph systemd {\n");

        for (dbus_message_iter_recurse(&iter, &sub);
             dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID;
             dbus_message_iter_next(&sub)) {
                struct unit_info u;

                r = bus_parse_unit_info(&sub, &u);
                if (r < 0)
                        return -EIO;

                r = graph_one(bus, &u, patterns);
                if (r < 0)
                        return r;
        }

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

static int dump(DBusConnection *bus, char **args) {
        _cleanup_free_ DBusMessage *reply = NULL;
        DBusError error;
        int r;
        const char *text;

        dbus_error_init(&error);

        if (!strv_isempty(args)) {
                log_error("Too many arguments.");
                return -E2BIG;
        }

        pager_open_if_enabled();

        r = bus_method_call_with_reply(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Dump",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r < 0)
                return r;

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_STRING, &text,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse reply: %s", bus_error_message(&error));
                dbus_error_free(&error);
                return  -EIO;
        }

        fputs(text, stdout);
        return 0;
}

static int set_log_level(DBusConnection *bus, char **args) {
        _cleanup_dbus_error_free_ DBusError error;
        _cleanup_dbus_message_unref_ DBusMessage *m = NULL, *reply = NULL;
        DBusMessageIter iter, sub;
        const char* property = "LogLevel";
        const char* interface = "org.freedesktop.systemd1.Manager";
        const char* value;

        assert(bus);
        assert(args);

        if (strv_length(args) != 1) {
                log_error("This command expects one argument only.");
                return -E2BIG;
        }

        value = args[0];
        dbus_error_init(&error);

        m = dbus_message_new_method_call("org.freedesktop.systemd1",
                                         "/org/freedesktop/systemd1",
                                         "org.freedesktop.DBus.Properties",
                                         "Set");
        if (!m)
                return log_oom();

        dbus_message_iter_init_append(m, &iter);

        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface) ||
            !dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property) ||
            !dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &sub))
                return log_oom();

        if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &value))
                return log_oom();

        if (!dbus_message_iter_close_container(&iter, &sub))
                return log_oom();

        reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error);
        if (!reply) {
                log_error("Failed to issue method call: %s", bus_error_message(&error));
                return -EIO;
        }

        return 0;
}

static void analyze_help(void) {

        pager_open_if_enabled();

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Process systemd profiling information\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --system         Connect to system manager\n"
               "     --user           Connect to user service manager\n"
               "     --order          When generating a dependency graph, show only order\n"
               "     --require        When generating a dependency graph, show only requirement\n"
               "     --from-pattern=GLOB, --to-pattern=GLOB\n"
               "                      When generating a dependency graph, filter only origins\n"
               "                      or destinations, respectively\n"
               "     --fuzz=TIMESPAN  When printing the tree of the critical chain, print also\n"
               "                      services, which finished TIMESPAN earlier, than the\n"
               "                      latest in the branch. The unit of TIMESPAN is seconds\n"
               "                      unless specified with a different unit, i.e. 50ms\n"
               "     --no-pager       Do not pipe output into a pager\n\n"
               "Commands:\n"
               "  time                Print time spent in the kernel before reaching userspace\n"
               "  blame               Print list of running units ordered by time to init\n"
               "  critical-chain      Print a tree of the time critical chain of units\n"
               "  plot                Output SVG graphic showing service initialization\n"
               "  dot                 Output dependency graph in dot(1) format\n"
               "  set-log-level LEVEL Set logging threshold for systemd\n"
               "  dump                Output state serialization of service manager\n",
               program_invocation_short_name);

        /* When updating this list, including descriptions, apply
         * changes to shell-completion/bash/systemd and
         * shell-completion/systemd-zsh-completion.zsh too. */
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        enum {
                ARG_VERSION = 0x100,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_USER,
                ARG_SYSTEM,
                ARG_DOT_FROM_PATTERN,
                ARG_DOT_TO_PATTERN,
                ARG_FUZZ,
                ARG_NO_PAGER
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
                { NULL,           0,                 NULL, 0                    }
        };

        assert(argc >= 0);
        assert(argv);

        for (;;) {
                switch (getopt_long(argc, argv, "h", options, NULL)) {

                case 'h':
                        analyze_help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING "\n" SYSTEMD_FEATURES);
                        return 0;

                case ARG_USER:
                        arg_scope = UNIT_FILE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_scope = UNIT_FILE_SYSTEM;
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

                case -1:
                        return 1;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }
}

int main(int argc, char *argv[]) {
        int r;
        DBusConnection *bus = NULL;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        bus = dbus_bus_get(arg_scope == UNIT_FILE_SYSTEM ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION, NULL);
        if (!bus) {
                r = -EIO;
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

        dbus_connection_unref(bus);

finish:
        pager_close();

        strv_free(arg_dot_from_patterns);
        strv_free(arg_dot_to_patterns);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
