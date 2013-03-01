/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include "install.h"
#include "log.h"
#include "dbus-common.h"
#include "build.h"
#include "util.h"
#include "strxcpyx.h"
#include "fileio.h"

#define compare(a, b) (((a) > (b))? 1 : (((b) > (a))? -1 : 0))
#define svg(...) printf(__VA_ARGS__)
#define svg_bar(class, x1, x2, y) \
        svg("  <rect class=\"%s\" x=\"%.03f\" y=\"%.03f\" width=\"%.03f\" height=\"%.03f\" />\n", \
                        (class), \
                        scale_x * (x1), scale_y * (y), \
                        scale_x * ((x2) - (x1)), scale_y - 1.0)
#define svg_text(x, y, format, ...) do {\
        svg("  <text x=\"%.03f\" y=\"%.03f\">", scale_x * (x) + 5.0, scale_y * (y) + 14.0); \
        svg(format, ## __VA_ARGS__); \
        svg("</text>\n"); \
        } while(false)

static UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static enum dot {
        DEP_ALL,
        DEP_ORDER,
        DEP_REQUIRE
} arg_dot = DEP_ALL;

double scale_x = 0.1;   // pixels per ms
double scale_y = 20.0;

struct boot_times {
        uint64_t firmware_time;
        uint64_t loader_time;
        uint64_t kernel_time;
        uint64_t kernel_done_time;
        uint64_t initrd_time;
        uint64_t userspace_time;
        uint64_t finish_time;
};
struct unit_times {
        char *name;
        uint64_t ixt;
        uint64_t iet;
        uint64_t axt;
        uint64_t aet;
        uint64_t time;
};

static int bus_get_uint64_property (DBusConnection *bus, const char *path, const char *interface, const char *property, uint64_t *val)
{
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        int r;
        DBusMessageIter iter, sub;

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

        if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT64)  {
                log_error("Failed to parse reply.");
                return -EIO;
        }

        dbus_message_iter_get_basic(&sub, val);

        return 0;
}

static int compare_unit_time(const void *a, const void *b)
{
        return compare(((struct unit_times *)b)->time,
                       ((struct unit_times *)a)->time);
}

static int compare_unit_start(const void *a, const void *b)
{
        return compare(((struct unit_times *)a)->ixt,
                       ((struct unit_times *)b)->ixt);
}

static char *get_os_name(void)
{
        char *n = NULL;

        parse_env_file("/etc/os-release", NEWLINE, "PRETTY_NAME", &n, NULL);
        return n;
}

static int acquire_time_data(DBusConnection *bus, struct unit_times **out)
{
        _cleanup_dbus_message_unref_ DBusMessage *reply = NULL;
        DBusMessageIter iter, sub;
        int r, c = 0, n_units = 0;
        struct unit_times *unit_times = NULL;

        r = bus_method_call_with_reply (
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnits",
                        &reply,
                        NULL,
                        DBUS_TYPE_INVALID);
        if (r)
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

                t->iet /= 1000;
                t->ixt /= 1000;
                t->aet /= 1000;
                t->axt /= 1000;

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
        if (unit_times) {
                for (; c >= 0; c--)
                        free(unit_times[c].name);
                free(unit_times);
        }
        return r;
}

static struct boot_times *acquire_boot_times(DBusConnection *bus)
{
        static struct boot_times times;
        static bool cached = false;
        if (cached)
                return &times;

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
                                    &times.finish_time) < 0)
                return NULL;

        if (!times.finish_time) {
                log_error("Bootup is not yet finished. Please try again later.");
                return NULL;
        }

        times.firmware_time /= 1000;
        times.loader_time /= 1000;
        times.initrd_time /= 1000;
        times.userspace_time /= 1000;
        times.finish_time /= 1000;

        if (times.initrd_time)
                times.kernel_done_time = times.initrd_time;
        else
                times.kernel_done_time = times.userspace_time;

        cached = true;
        return &times;
}

static char *pretty_boot_time(DBusConnection *bus)
{
        struct boot_times *t;
        size_t size = 4096;
        static char buf[4096];
        char *ptr = buf;

        t = acquire_boot_times(bus);
        if (!t)
                return NULL;

        size = strpcpyf(&ptr, size, "Startup finished in ");
        if (t->firmware_time)
                size = strpcpyf(&ptr, size, "%llums (firmware) + ", (unsigned long long)(t->firmware_time - t->loader_time));
        if (t->loader_time)
                size = strpcpyf(&ptr, size, "%llums (loader) + ", (unsigned long long)t->loader_time);
        if (t->kernel_time)
                size = strpcpyf(&ptr, size, "%llums (kernel) + ", (unsigned long long)t->kernel_done_time);
        if (t->initrd_time > 0)
                size = strpcpyf(&ptr, size, "%llums (initrd) + ", (unsigned long long)(t->userspace_time - t->initrd_time));

        size = strpcpyf(&ptr, size, "%llums (userspace) ", (unsigned long long)(t->finish_time - t->userspace_time));
        if (t->kernel_time > 0)
                size = strpcpyf(&ptr, size, "= %llums", (unsigned long long)(t->firmware_time + t->finish_time));
        else
                size = strpcpyf(&ptr, size, "= %llums", (unsigned long long)(t->finish_time - t->userspace_time));

        return buf;
}

static void svg_graph_box(int height, int64_t begin, int64_t end)
{
        /* outside box, fill */
        svg("<rect class=\"box\" x=\"0\" y=\"0\" width=\"%.03f\" height=\"%.03f\" />\n",
            scale_x * (end - begin), scale_y * height);

        for (int i = (begin / 100) * 100; i <= end; i+=100) {
                /* lines for each second */
                if (i % 5000 == 0)
                        svg("  <line class=\"sec5\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            scale_x * i, scale_x * i, scale_y * height, scale_x * i, -5.0, 0.001 * i);
                else if (i % 1000 == 0)
                        svg("  <line class=\"sec1\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n"
                            "  <text class=\"sec\" x=\"%.03f\" y=\"%.03f\" >%.01fs</text>\n",
                            scale_x * i, scale_x * i, scale_y * height, scale_x * i, -5.0, 0.001 * i);
                else
                        svg("  <line class=\"sec01\" x1=\"%.03f\" y1=\"0\" x2=\"%.03f\" y2=\"%.03f\" />\n",
                            scale_x * i, scale_x * i, scale_y * height);
        }
}

static int analyze_plot(DBusConnection *bus)
{
        struct unit_times *times;
        struct boot_times *boot;
        struct utsname name;
        int n, m = 1, y=0;
        double width;
        char *osname;
        char *pretty_times;

        boot = acquire_boot_times(bus);
        if (!boot)
                return -EIO;
        pretty_times = pretty_boot_time(bus);
        if (!pretty_times)
                return -EIO;

        osname = get_os_name();

        n = uname(&name);
        if (n < 0) {
                log_error("Cannot get system name: %m");
                return -errno;
        }

        n = acquire_time_data(bus, &times);
        if (n<=0)
                return n;

        qsort(times, n, sizeof(struct unit_times), compare_unit_start);

        width = scale_x * (boot->firmware_time + boot->finish_time);
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

        for (struct unit_times *u = times; u < times + n; u++) {
                double len;
                if (u->ixt < boot->userspace_time ||
                    u->ixt > boot->finish_time) {
                        free(u->name);
                        u->name = NULL;
                        continue;
                }
                len = ((boot->firmware_time + u->ixt) * scale_x)
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
                        80.0 + width, 150.0 + (m * scale_y));

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
            "      rect.box   { fill: rgb(240,240,240); stroke: rgb(192,192,192); }\n"
            "      line       { stroke: rgb(64,64,64); stroke-width: 1; }\n"
            "//    line.sec1  { }\n"
            "      line.sec5  { stroke-width: 2; }\n"
            "      line.sec01 { stroke: rgb(224,224,224); stroke-width: 1; }\n"
            "      text       { font-family: Verdana, Helvetica; font-size: 10; }\n"
            "      text.sec   { font-size: 8; }\n"
            "    ]]>\n   </style>\n</defs>\n\n");

        svg("<text x=\"20\" y=\"50\">%s</text>", pretty_times);
        svg("<text x=\"20\" y=\"30\">%s %s (%s %s) %s</text>",
            isempty(osname)? "Linux" : osname,
            name.nodename, name.release, name.version, name.machine);
        svg("<text x=\"20\" y=\"%.0f\">Legend: Red = Activating; Pink = Active; Dark Pink = Deactivating</text>",
                        120.0 + (m *scale_y));

        svg("<g transform=\"translate(%.3f,100)\">\n", 20.0 + (scale_x * boot->firmware_time));
        svg_graph_box(m, -boot->firmware_time, boot->finish_time);

        if (boot->firmware_time) {
                svg_bar("firmware", -(int64_t) boot->firmware_time, -(int64_t) boot->loader_time, y);
                svg_text(-(int64_t) boot->firmware_time, y, "firmware");
                y++;
        }
        if (boot->loader_time) {
                svg_bar("loader", -(int64_t) boot->loader_time, 0, y);
                svg_text(-(int64_t) boot->loader_time, y, "loader");
                y++;
        }
        if (boot->kernel_time) {
                svg_bar("kernel", 0, boot->kernel_done_time, y);
                svg_text(0, y, "kernel");
                y++;
        }
        if (boot->initrd_time) {
                svg_bar("initrd", boot->initrd_time, boot->userspace_time, y);
                svg_text(boot->initrd_time, y, "initrd");
                y++;
        }
        svg_bar("userspace", boot->userspace_time, boot->finish_time, y);
        svg_text(boot->userspace_time, y, "userspace");
        y++;

        for (struct unit_times *u = times; u < times + n; u++) {
                if (!u->name)
                        continue;
                svg_bar("activating",   u->ixt, u->aet, y);
                svg_bar("active",       u->aet, u->axt, y);
                svg_bar("deactivating", u->axt, u->iet, y);
                svg_text(u->ixt, y, u->time? "%s (%llums)" : "%s", u->name, (unsigned long long)u->time);
                y++;
        }
        svg("</g>\n\n");

        svg("</svg>");
        return 0;
}

static int analyze_blame(DBusConnection *bus)
{
        struct unit_times *times;
        int n = acquire_time_data(bus, &times);
        if (n<=0)
                return n;

        qsort(times, n, sizeof(struct unit_times), compare_unit_time);

        for (int i = 0; i < n; i++) {
                if (times[i].time)
                        printf("%6llums %s\n", (unsigned long long)times[i].time, times[i].name);
        }
        return 0;
}

static int analyze_time(DBusConnection *bus)
{
        char *buf;
        buf = pretty_boot_time(bus);
        if (!buf)
                return -EIO;
        if (puts(buf) == EOF)
                return -errno;
        return 0;
}

static int graph_one_property(const char *name, const char *prop, DBusMessageIter *iter) {

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

                        assert(dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_STRING);
                        dbus_message_iter_get_basic(&sub, &s);
                        printf("\t\"%s\"->\"%s\" %s;\n", name, s, c);
                }
        }

        return 0;
}

static int graph_one(DBusConnection *bus, const struct unit_info *u) {
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
                r = graph_one_property(u->id, prop, &sub3);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dot(DBusConnection *bus) {
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

                r = graph_one(bus, &u);
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

static void analyze_help(void)
{
        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Process systemd profiling information\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --system         Connect to system manager\n"
               "     --user           Connect to user service manager\n"
               "     --order          When generating a dependency graph, show only order\n"
               "     --require        When generating a dependency graph, show only requirement\n\n"
               "Commands:\n"
               "  time                Print time spent in the kernel before reaching userspace\n"
               "  blame               Print list of running units ordered by time to init\n"
               "  plot                Output SVG graphic showing service initialization\n"
               "  dot                 Dump dependency graph (in dot(1) format)\n\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[])
{
        enum {
                ARG_VERSION = 0x100,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_USER,
                ARG_SYSTEM
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "order",     no_argument,       NULL, ARG_ORDER     },
                { "require",   no_argument,       NULL, ARG_REQUIRE   },
                { "user",      no_argument,       NULL, ARG_USER      },
                { "system",    no_argument,       NULL, ARG_SYSTEM    },
                { NULL,        0,                 NULL, 0             }
        };

        assert(argc >= 0);
        assert(argv);

        while (true) {
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
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r == 0)
                return 0;
        if (r < 0)
                return 1;

        bus = dbus_bus_get(arg_scope == UNIT_FILE_SYSTEM ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION, NULL);
        if (!bus)
                return 1;

        if (!argv[optind] || streq(argv[optind], "time"))
                r = analyze_time(bus);
        else if (streq(argv[optind], "blame"))
                r = analyze_blame(bus);
        else if (streq(argv[optind], "plot"))
                r = analyze_plot(bus);
        else if (streq(argv[optind], "dot"))
                r = dot(bus);
        else
                log_error("Unknown operation '%s'.", argv[optind]);

        dbus_connection_unref(bus);
        if (r)
                return 1;
        return 0;
}
