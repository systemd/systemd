/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <locale.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/mount.h>

#include "sd-bus.h"
#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "spawn-polkit-agent.h"
#include "bus-util.h"
#include "bus-error.h"
#include "build.h"
#include "strv.h"
#include "unit-name.h"
#include "cgroup-show.h"
#include "logs-show.h"
#include "cgroup-util.h"
#include "ptyfwd.h"
#include "event-util.h"
#include "path-util.h"
#include "mkdir.h"
#include "copy.h"
#include "verbs.h"
#include "import-util.h"
#include "process-util.h"
#include "terminal-util.h"
#include "signal-util.h"

static char **arg_property = NULL;
static bool arg_all = false;
static bool arg_full = false;
static bool arg_no_pager = false;
static bool arg_legend = true;
static const char *arg_kill_who = NULL;
static int arg_signal = SIGTERM;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_read_only = false;
static bool arg_mkdir = false;
static bool arg_quiet = false;
static bool arg_ask_password = true;
static unsigned arg_lines = 10;
static OutputMode arg_output = OUTPUT_SHORT;
static bool arg_force = false;
static ImportVerify arg_verify = IMPORT_VERIFY_SIGNATURE;
static const char* arg_dkr_index_url = NULL;
static const char* arg_format = NULL;

static void pager_open_if_enabled(void) {

        if (arg_no_pager)
                return;

        pager_open(false);
}

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */

        if (!arg_ask_password)
                return;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return;

        polkit_agent_open();
}

static OutputFlags get_output_flags(void) {
        return
                arg_all * OUTPUT_SHOW_ALL |
                arg_full * OUTPUT_FULL_WIDTH |
                (!on_tty() || pager_have()) * OUTPUT_FULL_WIDTH |
                on_tty() * OUTPUT_COLOR |
                !arg_quiet * OUTPUT_WARN_CUTOFF;
}

typedef struct MachineInfo {
        const char *name;
        const char *class;
        const char *service;
} MachineInfo;

static int compare_machine_info(const void *a, const void *b) {
        const MachineInfo *x = a, *y = b;

        return strcmp(x->name, y->name);
}

static int list_machines(int argc, char *argv[], void *userdata) {

        size_t max_name = strlen("MACHINE"), max_class = strlen("CLASS"), max_service = strlen("SERVICE");
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ MachineInfo *machines = NULL;
        const char *name, *class, *service, *object;
        size_t n_machines = 0, n_allocated = 0, j;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        pager_open_if_enabled();

        r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "ListMachines",
                                &error,
                                &reply,
                                NULL);
        if (r < 0) {
                log_error("Could not get machines: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(ssso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ssso)", &name, &class, &service, &object)) > 0) {
                size_t l;

                if (!GREEDY_REALLOC(machines, n_allocated, n_machines + 1))
                        return log_oom();

                machines[n_machines].name = name;
                machines[n_machines].class = class;
                machines[n_machines].service = service;

                l = strlen(name);
                if (l > max_name)
                        max_name = l;

                l = strlen(class);
                if (l > max_class)
                        max_class = l;

                l = strlen(service);
                if (l > max_service)
                        max_service = l;

                n_machines ++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        qsort_safe(machines, n_machines, sizeof(MachineInfo), compare_machine_info);

        if (arg_legend)
                printf("%-*s %-*s %-*s\n",
                       (int) max_name, "MACHINE",
                       (int) max_class, "CLASS",
                       (int) max_service, "SERVICE");

        for (j = 0; j < n_machines; j++)
                printf("%-*s %-*s %-*s\n",
                       (int) max_name, machines[j].name,
                       (int) max_class, machines[j].class,
                       (int) max_service, machines[j].service);

        if (arg_legend)
                printf("\n%zu machines listed.\n", n_machines);

        return 0;
}

typedef struct ImageInfo {
        const char *name;
        const char *type;
        bool read_only;
        usec_t crtime;
        usec_t mtime;
        uint64_t size;
} ImageInfo;

static int compare_image_info(const void *a, const void *b) {
        const ImageInfo *x = a, *y = b;

        return strcmp(x->name, y->name);
}

static int list_images(int argc, char *argv[], void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        size_t max_name = strlen("NAME"), max_type = strlen("TYPE"), max_size = strlen("USAGE"), max_crtime = strlen("CREATED"), max_mtime = strlen("MODIFIED");
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ ImageInfo *images = NULL;
        size_t n_images = 0, n_allocated = 0, j;
        const char *name, *type, *object;
        sd_bus *bus = userdata;
        uint64_t crtime, mtime, size;
        int read_only, r;

        assert(bus);

        pager_open_if_enabled();

        r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "ListImages",
                                &error,
                                &reply,
                                "");
        if (r < 0) {
                log_error("Could not get images: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssbttto)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ssbttto)", &name, &type, &read_only, &crtime, &mtime, &size, &object)) > 0) {
                char buf[MAX(FORMAT_TIMESTAMP_MAX, FORMAT_BYTES_MAX)];
                size_t l;

                if (name[0] == '.' && !arg_all)
                        continue;

                if (!GREEDY_REALLOC(images, n_allocated, n_images + 1))
                        return log_oom();

                images[n_images].name = name;
                images[n_images].type = type;
                images[n_images].read_only = read_only;
                images[n_images].crtime = crtime;
                images[n_images].mtime = mtime;
                images[n_images].size = size;

                l = strlen(name);
                if (l > max_name)
                        max_name = l;

                l = strlen(type);
                if (l > max_type)
                        max_type = l;

                if (crtime != 0) {
                        l = strlen(strna(format_timestamp(buf, sizeof(buf), crtime)));
                        if (l > max_crtime)
                                max_crtime = l;
                }

                if (mtime != 0) {
                        l = strlen(strna(format_timestamp(buf, sizeof(buf), mtime)));
                        if (l > max_mtime)
                                max_mtime = l;
                }

                if (size != (uint64_t) -1) {
                        l = strlen(strna(format_bytes(buf, sizeof(buf), size)));
                        if (l > max_size)
                                max_size = l;
                }

                n_images++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        qsort_safe(images, n_images, sizeof(ImageInfo), compare_image_info);

        if (arg_legend)
                printf("%-*s %-*s %-3s %-*s %-*s %-*s\n",
                       (int) max_name, "NAME",
                       (int) max_type, "TYPE",
                       "RO",
                       (int) max_size, "USAGE",
                       (int) max_crtime, "CREATED",
                       (int) max_mtime, "MODIFIED");

        for (j = 0; j < n_images; j++) {
                char crtime_buf[FORMAT_TIMESTAMP_MAX], mtime_buf[FORMAT_TIMESTAMP_MAX], size_buf[FORMAT_BYTES_MAX];

                printf("%-*s %-*s %s%-3s%s %-*s %-*s %-*s\n",
                       (int) max_name, images[j].name,
                       (int) max_type, images[j].type,
                       images[j].read_only ? ansi_highlight_red() : "", yes_no(images[j].read_only), images[j].read_only ? ansi_highlight_off() : "",
                       (int) max_size, strna(format_bytes(size_buf, sizeof(size_buf), images[j].size)),
                       (int) max_crtime, strna(format_timestamp(crtime_buf, sizeof(crtime_buf), images[j].crtime)),
                       (int) max_mtime, strna(format_timestamp(mtime_buf, sizeof(mtime_buf), images[j].mtime)));
        }

        if (arg_legend)
                printf("\n%zu images listed.\n", n_images);

        return 0;
}

static int show_unit_cgroup(sd_bus *bus, const char *unit, pid_t leader) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        const char *cgroup;
        int r;
        unsigned c;

        assert(bus);
        assert(unit);

        if (arg_transport == BUS_TRANSPORT_REMOTE)
                return 0;

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        endswith(unit, ".scope") ? "org.freedesktop.systemd1.Scope" : "org.freedesktop.systemd1.Service",
                        "ControlGroup",
                        &error,
                        &reply,
                        "s");
        if (r < 0) {
                log_error("Failed to query ControlGroup: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &cgroup);
        if (r < 0)
                return bus_log_parse_error(r);

        if (isempty(cgroup))
                return 0;

        if (cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, cgroup, false) != 0 && leader <= 0)
                return 0;

        c = columns();
        if (c > 18)
                c -= 18;
        else
                c = 0;

        show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, cgroup, "\t\t  ", c, false, &leader, leader > 0, get_output_flags());
        return 0;
}

static int print_addresses(sd_bus *bus, const char *name, int ifi, const char *prefix, const char *prefix2) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(prefix);
        assert(prefix2);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.machine1",
                               "/org/freedesktop/machine1",
                               "org.freedesktop.machine1.Manager",
                               "GetMachineAddresses",
                               NULL,
                               &reply,
                               "s", name);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'a', "(iay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "iay")) > 0) {
                int family;
                const void *a;
                size_t sz;
                char buffer[MAX(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];

                r = sd_bus_message_read(reply, "i", &family);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                fputs(prefix, stdout);
                fputs(inet_ntop(family, a, buffer, sizeof(buffer)), stdout);
                if (family == AF_INET6 && ifi > 0)
                        printf("%%%i", ifi);
                fputc('\n', stdout);

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (prefix != prefix2)
                        prefix = prefix2;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return 0;
}

static int print_os_release(sd_bus *bus, const char *name, const char *prefix) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        const char *k, *v, *pretty = NULL;
        int r;

        assert(bus);
        assert(name);
        assert(prefix);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.machine1",
                               "/org/freedesktop/machine1",
                               "org.freedesktop.machine1.Manager",
                               "GetMachineOSRelease",
                               NULL,
                               &reply,
                               "s", name);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(reply, 'a', "{ss}");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "{ss}", &k, &v)) > 0) {
                if (streq(k, "PRETTY_NAME"))
                        pretty = v;

        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (pretty)
                printf("%s%s\n", prefix, pretty);

        return 0;
}

typedef struct MachineStatusInfo {
        char *name;
        sd_id128_t id;
        char *class;
        char *service;
        char *unit;
        char *root_directory;
        pid_t leader;
        struct dual_timestamp timestamp;
        int *netif;
        unsigned n_netif;
} MachineStatusInfo;

static void machine_status_info_clear(MachineStatusInfo *info) {
        if (info) {
                free(info->name);
                free(info->class);
                free(info->service);
                free(info->unit);
                free(info->root_directory);
                free(info->netif);
                zero(*info);
        }
}

static void print_machine_status_info(sd_bus *bus, MachineStatusInfo *i) {
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
        int ifi = -1;

        assert(bus);
        assert(i);

        fputs(strna(i->name), stdout);

        if (!sd_id128_equal(i->id, SD_ID128_NULL))
                printf("(" SD_ID128_FORMAT_STR ")\n", SD_ID128_FORMAT_VAL(i->id));
        else
                putchar('\n');

        s1 = format_timestamp_relative(since1, sizeof(since1), i->timestamp.realtime);
        s2 = format_timestamp(since2, sizeof(since2), i->timestamp.realtime);

        if (s1)
                printf("\t   Since: %s; %s\n", s2, s1);
        else if (s2)
                printf("\t   Since: %s\n", s2);

        if (i->leader > 0) {
                _cleanup_free_ char *t = NULL;

                printf("\t  Leader: %u", (unsigned) i->leader);

                get_process_comm(i->leader, &t);
                if (t)
                        printf(" (%s)", t);

                putchar('\n');
        }

        if (i->service) {
                printf("\t Service: %s", i->service);

                if (i->class)
                        printf("; class %s", i->class);

                putchar('\n');
        } else if (i->class)
                printf("\t   Class: %s\n", i->class);

        if (i->root_directory)
                printf("\t    Root: %s\n", i->root_directory);

        if (i->n_netif > 0) {
                unsigned c;

                fputs("\t   Iface:", stdout);

                for (c = 0; c < i->n_netif; c++) {
                        char name[IF_NAMESIZE+1] = "";

                        if (if_indextoname(i->netif[c], name)) {
                                fputc(' ', stdout);
                                fputs(name, stdout);

                                if (ifi < 0)
                                        ifi = i->netif[c];
                                else
                                        ifi = 0;
                        } else
                                printf(" %i", i->netif[c]);
                }

                fputc('\n', stdout);
        }

        print_addresses(bus, i->name, ifi,
                       "\t Address: ",
                       "\t          ");

        print_os_release(bus, i->name, "\t      OS: ");

        if (i->unit) {
                printf("\t    Unit: %s\n", i->unit);
                show_unit_cgroup(bus, i->unit, i->leader);

                if (arg_transport == BUS_TRANSPORT_LOCAL) {

                        show_journal_by_unit(
                                        stdout,
                                        i->unit,
                                        arg_output,
                                        0,
                                        i->timestamp.monotonic,
                                        arg_lines,
                                        0,
                                        get_output_flags() | OUTPUT_BEGIN_NEWLINE,
                                        SD_JOURNAL_LOCAL_ONLY,
                                        true,
                                        NULL);
                }
        }
}

static int map_netif(sd_bus *bus, const char *member, sd_bus_message *m, sd_bus_error *error, void *userdata) {
        MachineStatusInfo *i = userdata;
        size_t l;
        const void *v;
        int r;

        assert_cc(sizeof(int32_t) == sizeof(int));
        r = sd_bus_message_read_array(m, SD_BUS_TYPE_INT32, &v, &l);
        if (r < 0)
                return r;
        if (r == 0)
                return -EBADMSG;

        i->n_netif = l / sizeof(int32_t);
        i->netif = memdup(v, l);
        if (!i->netif)
                return -ENOMEM;

        return 0;
}

static int show_machine_info(const char *verb, sd_bus *bus, const char *path, bool *new_line) {

        static const struct bus_properties_map map[]  = {
                { "Name",               "s",  NULL,          offsetof(MachineStatusInfo, name)                },
                { "Class",              "s",  NULL,          offsetof(MachineStatusInfo, class)               },
                { "Service",            "s",  NULL,          offsetof(MachineStatusInfo, service)             },
                { "Unit",               "s",  NULL,          offsetof(MachineStatusInfo, unit)                },
                { "RootDirectory",      "s",  NULL,          offsetof(MachineStatusInfo, root_directory)      },
                { "Leader",             "u",  NULL,          offsetof(MachineStatusInfo, leader)              },
                { "Timestamp",          "t",  NULL,          offsetof(MachineStatusInfo, timestamp.realtime)  },
                { "TimestampMonotonic", "t",  NULL,          offsetof(MachineStatusInfo, timestamp.monotonic) },
                { "Id",                 "ay", bus_map_id128, offsetof(MachineStatusInfo, id)                  },
                { "NetworkInterfaces",  "ai", map_netif,     0                                                },
                {}
        };

        _cleanup_(machine_status_info_clear) MachineStatusInfo info = {};
        int r;

        assert(verb);
        assert(bus);
        assert(path);
        assert(new_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   path,
                                   map,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %m");

        if (*new_line)
                printf("\n");
        *new_line = true;

        print_machine_status_info(bus, &info);

        return r;
}

static int show_machine_properties(sd_bus *bus, const char *path, bool *new_line) {
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        if (*new_line)
                printf("\n");

        *new_line = true;

        r = bus_print_all_properties(bus, "org.freedesktop.machine1", path, arg_property, arg_all);
        if (r < 0)
                log_error_errno(r, "Could not get properties: %m");

        return r;
}

static int show_machine(int argc, char *argv[], void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        bool properties, new_line = false;
        sd_bus *bus = userdata;
        int r = 0, i;

        assert(bus);

        properties = !strstr(argv[0], "status");

        pager_open_if_enabled();

        if (properties && argc <= 1) {

                /* If no argument is specified, inspect the manager
                 * itself */
                r = show_machine_properties(bus, "/org/freedesktop/machine1", &new_line);
                if (r < 0)
                        return r;
        }

        for (i = 1; i < argc; i++) {
                const char *path = NULL;

                r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.machine1",
                                        "/org/freedesktop/machine1",
                                        "org.freedesktop.machine1.Manager",
                                        "GetMachine",
                                        &error,
                                        &reply,
                                        "s", argv[i]);
                if (r < 0) {
                        log_error("Could not get path to machine: %s", bus_error_message(&error, -r));
                        return r;
                }

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (properties)
                        r = show_machine_properties(bus, path, &new_line);
                else
                        r = show_machine_info(argv[0], bus, path, &new_line);
        }

        return r;
}

typedef struct ImageStatusInfo {
        char *name;
        char *path;
        char *type;
        int read_only;
        usec_t crtime;
        usec_t mtime;
        uint64_t usage;
        uint64_t limit;
        uint64_t usage_exclusive;
        uint64_t limit_exclusive;
} ImageStatusInfo;

static void image_status_info_clear(ImageStatusInfo *info) {
        if (info) {
                free(info->name);
                free(info->path);
                free(info->type);
                zero(*info);
        }
}

static void print_image_status_info(sd_bus *bus, ImageStatusInfo *i) {
        char ts_relative[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char ts_absolute[FORMAT_TIMESTAMP_MAX], *s2;
        char bs[FORMAT_BYTES_MAX], *s3;
        char bs_exclusive[FORMAT_BYTES_MAX], *s4;

        assert(bus);
        assert(i);

        if (i->name) {
                fputs(i->name, stdout);
                putchar('\n');
        }

        if (i->type)
                printf("\t    Type: %s\n", i->type);

        if (i->path)
                printf("\t    Path: %s\n", i->path);

        printf("\t      RO: %s%s%s\n",
               i->read_only ? ansi_highlight_red() : "",
               i->read_only ? "read-only" : "writable",
               i->read_only ? ansi_highlight_off() : "");

        s1 = format_timestamp_relative(ts_relative, sizeof(ts_relative), i->crtime);
        s2 = format_timestamp(ts_absolute, sizeof(ts_absolute), i->crtime);
        if (s1 && s2)
                printf("\t Created: %s; %s\n", s2, s1);
        else if (s2)
                printf("\t Created: %s\n", s2);

        s1 = format_timestamp_relative(ts_relative, sizeof(ts_relative), i->mtime);
        s2 = format_timestamp(ts_absolute, sizeof(ts_absolute), i->mtime);
        if (s1 && s2)
                printf("\tModified: %s; %s\n", s2, s1);
        else if (s2)
                printf("\tModified: %s\n", s2);

        s3 = format_bytes(bs, sizeof(bs), i->usage);
        s4 = i->usage_exclusive != i->usage ? format_bytes(bs_exclusive, sizeof(bs_exclusive), i->usage_exclusive) : NULL;
        if (s3 && s4)
                printf("\t   Usage: %s (exclusive: %s)\n", s3, s4);
        else if (s3)
                printf("\t   Usage: %s\n", s3);

        s3 = format_bytes(bs, sizeof(bs), i->limit);
        s4 = i->limit_exclusive != i->limit ? format_bytes(bs_exclusive, sizeof(bs_exclusive), i->limit_exclusive) : NULL;
        if (s3 && s4)
                printf("\t   Limit: %s (exclusive: %s)\n", s3, s4);
        else if (s3)
                printf("\t   Limit: %s\n", s3);
}

static int show_image_info(sd_bus *bus, const char *path, bool *new_line) {

        static const struct bus_properties_map map[]  = {
                { "Name",                  "s",  NULL, offsetof(ImageStatusInfo, name)            },
                { "Path",                  "s",  NULL, offsetof(ImageStatusInfo, path)            },
                { "Type",                  "s",  NULL, offsetof(ImageStatusInfo, type)            },
                { "ReadOnly",              "b",  NULL, offsetof(ImageStatusInfo, read_only)       },
                { "CreationTimestamp",     "t",  NULL, offsetof(ImageStatusInfo, crtime)          },
                { "ModificationTimestamp", "t",  NULL, offsetof(ImageStatusInfo, mtime)           },
                { "Usage",                 "t",  NULL, offsetof(ImageStatusInfo, usage)           },
                { "Limit",                 "t",  NULL, offsetof(ImageStatusInfo, limit)           },
                { "UsageExclusive",        "t",  NULL, offsetof(ImageStatusInfo, usage_exclusive) },
                { "LimitExclusive",        "t",  NULL, offsetof(ImageStatusInfo, limit_exclusive) },
                {}
        };

        _cleanup_(image_status_info_clear) ImageStatusInfo info = {};
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   path,
                                   map,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %m");

        if (*new_line)
                printf("\n");
        *new_line = true;

        print_image_status_info(bus, &info);

        return r;
}

typedef struct PoolStatusInfo {
        char *path;
        uint64_t usage;
        uint64_t limit;
} PoolStatusInfo;

static void pool_status_info_clear(PoolStatusInfo *info) {
        if (info) {
                free(info->path);
                zero(*info);
                info->usage = -1;
                info->limit = -1;
        }
}

static void print_pool_status_info(sd_bus *bus, PoolStatusInfo *i) {
        char bs[FORMAT_BYTES_MAX], *s;

        if (i->path)
                printf("\t    Path: %s\n", i->path);

        s = format_bytes(bs, sizeof(bs), i->usage);
        if (s)
                printf("\t   Usage: %s\n", s);

        s = format_bytes(bs, sizeof(bs), i->limit);
        if (s)
                printf("\t   Limit: %s\n", s);
}

static int show_pool_info(sd_bus *bus) {

        static const struct bus_properties_map map[]  = {
                { "PoolPath",  "s",  NULL, offsetof(PoolStatusInfo, path)  },
                { "PoolUsage", "t",  NULL, offsetof(PoolStatusInfo, usage) },
                { "PoolLimit", "t",  NULL, offsetof(PoolStatusInfo, limit) },
                {}
        };

        _cleanup_(pool_status_info_clear) PoolStatusInfo info = {
                .usage = (uint64_t) -1,
                .limit = (uint64_t) -1,
        };
        int r;

        assert(bus);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   "/org/freedesktop/machine1",
                                   map,
                                   &info);
        if (r < 0)
                return log_error_errno(r, "Could not get properties: %m");

        print_pool_status_info(bus, &info);

        return 0;
}


static int show_image_properties(sd_bus *bus, const char *path, bool *new_line) {
        int r;

        assert(bus);
        assert(path);
        assert(new_line);

        if (*new_line)
                printf("\n");

        *new_line = true;

        r = bus_print_all_properties(bus, "org.freedesktop.machine1", path, arg_property, arg_all);
        if (r < 0)
                log_error_errno(r, "Could not get properties: %m");

        return r;
}

static int show_image(int argc, char *argv[], void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        bool properties, new_line = false;
        sd_bus *bus = userdata;
        int r = 0, i;

        assert(bus);

        properties = !strstr(argv[0], "status");

        pager_open_if_enabled();

        if (argc <= 1) {

                /* If no argument is specified, inspect the manager
                 * itself */

                if (properties)
                        r = show_image_properties(bus, "/org/freedesktop/machine1", &new_line);
                else
                        r = show_pool_info(bus);
                if (r < 0)
                        return r;
        }

        for (i = 1; i < argc; i++) {
                const char *path = NULL;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "GetImage",
                                &error,
                                &reply,
                                "s", argv[i]);
                if (r < 0) {
                        log_error("Could not get path to image: %s", bus_error_message(&error, -r));
                        return r;
                }

                r = sd_bus_message_read(reply, "o", &path);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (properties)
                        r = show_image_properties(bus, path, &new_line);
                else
                        r = show_image_info(bus, path, &new_line);
        }

        return r;
}

static int kill_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < argc; i++) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "KillMachine",
                                &error,
                                NULL,
                                "ssi", argv[i], arg_kill_who, arg_signal);
                if (r < 0) {
                        log_error("Could not kill machine: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int reboot_machine(int argc, char *argv[], void *userdata) {
        arg_kill_who = "leader";
        arg_signal = SIGINT; /* sysvinit + systemd */

        return kill_machine(argc, argv, userdata);
}

static int poweroff_machine(int argc, char *argv[], void *userdata) {
        arg_kill_who = "leader";
        arg_signal = SIGRTMIN+4; /* only systemd */

        return kill_machine(argc, argv, userdata);
}

static int terminate_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        for (i = 1; i < argc; i++) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "TerminateMachine",
                                &error,
                                NULL,
                                "s", argv[i]);
                if (r < 0) {
                        log_error("Could not terminate machine: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int copy_files(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        bool copy_from;
        int r;

        assert(bus);

        polkit_agent_open_if_enabled();

        copy_from = streq(argv[0], "copy-from");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        copy_from ? "CopyFromMachine" : "CopyToMachine",
                        &error,
                        NULL,
                        "sss",
                        argv[1],
                        argv[2],
                        argv[3]);
        if (r < 0) {
                log_error("Failed to copy: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int bind_mount(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        polkit_agent_open_if_enabled();

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "BindMountMachine",
                        &error,
                        NULL,
                        "sssbb",
                        argv[1],
                        argv[2],
                        argv[3],
                        arg_read_only,
                        arg_mkdir);
        if (r < 0) {
                log_error("Failed to bind mount: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int on_machine_removed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        PTYForward ** forward = (PTYForward**) userdata;
        int r;

        assert(m);
        assert(forward);

        if (*forward) {
                /* If the forwarder is already initialized, tell it to
                 * exit on the next vhangup(), so that we still flush
                 * out what might be queued and exit then. */

                r = pty_forward_set_ignore_vhangup(*forward, false);
                if (r >= 0)
                        return 0;

                log_error_errno(r, "Failed to set ignore_vhangup flag: %m");
        }

        /* On error, or when the forwarder is not initialized yet, quit immediately */
        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), EXIT_FAILURE);
        return 0;
}

static int login_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_slot_unref_ sd_bus_slot *slot = NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        int master = -1, r, ret = 0;
        sd_bus *bus = userdata;
        const char *pty, *match;
        char last_char = 0;
        bool machine_died;

        assert(bus);

        if (arg_transport != BUS_TRANSPORT_LOCAL &&
            arg_transport != BUS_TRANSPORT_MACHINE) {
                log_error("Login only supported on local machines.");
                return -EOPNOTSUPP;
        }

        polkit_agent_open_if_enabled();

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        match = strjoina("type='signal',"
                           "sender='org.freedesktop.machine1',"
                           "path='/org/freedesktop/machine1',",
                           "interface='org.freedesktop.machine1.Manager',"
                           "member='MachineRemoved',"
                           "arg0='",
                           argv[1],
                           "'");

        r = sd_bus_add_match(bus, &slot, match, on_machine_removed, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to add machine removal match: %m");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "OpenMachineLogin",
                        &error,
                        &reply,
                        "s", argv[1]);
        if (r < 0) {
                log_error("Failed to get machine PTY: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "hs", &master, &pty);
        if (r < 0)
                return bus_log_parse_error(r);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGWINCH, SIGTERM, SIGINT, -1) >= 0);

        log_info("Connected to machine %s. Press ^] three times within 1s to exit session.", argv[1]);

        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);

        r = pty_forward_new(event, master, true, false, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        pty_forward_get_last_char(forward, &last_char);
        machine_died = pty_forward_get_ignore_vhangup(forward) == 0;

        forward = pty_forward_free(forward);

        if (last_char != '\n')
                fputc('\n', stdout);

        if (machine_died)
                log_info("Machine %s terminated.", argv[1]);
        else
                log_info("Connection to machine %s terminated.", argv[1]);

        sd_event_get_exit_code(event, &ret);
        return ret;
}

static int remove_image(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        for (i = 1; i < argc; i++) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "RemoveImage",
                                &error,
                                NULL,
                                "s", argv[i]);
                if (r < 0) {
                        log_error("Could not remove image: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int rename_image(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r;

        polkit_agent_open_if_enabled();

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "RenameImage",
                        &error,
                        NULL,
                        "ss", argv[1], argv[2]);
        if (r < 0) {
                log_error("Could not rename image: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int clone_image(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r;

        polkit_agent_open_if_enabled();

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "CloneImage",
                        &error,
                        NULL,
                        "ssb", argv[1], argv[2], arg_read_only);
        if (r < 0) {
                log_error("Could not clone image: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int read_only_image(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int b = true, r;

        if (argc > 2) {
                b = parse_boolean(argv[2]);
                if (b < 0) {
                        log_error("Failed to parse boolean argument: %s", argv[2]);
                        return -EINVAL;
                }
        }

        polkit_agent_open_if_enabled();

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "MarkImageReadOnly",
                        &error,
                        NULL,
                        "sb", argv[1], b);
        if (r < 0) {
                log_error("Could not mark image read-only: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int make_service_name(const char *name, char **ret) {
        _cleanup_free_ char *e = NULL;
        int r;

        assert(name);
        assert(ret);

        if (!machine_name_is_valid(name)) {
                log_error("Invalid machine name %s.", name);
                return -EINVAL;
        }

        e = unit_name_escape(name);
        if (!e)
                return log_oom();

        r = unit_name_build("systemd-nspawn", e, ".service", ret);
        if (r < 0)
                return log_error_errno(r, "Failed to build unit name: %m");

        return 0;
}

static int start_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_oom();

        for (i = 1; i < argc; i++) {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                _cleanup_free_ char *unit = NULL;
                const char *object;

                r = make_service_name(argv[i], &unit);
                if (r < 0)
                        return r;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "StartUnit",
                                &error,
                                &reply,
                                "ss", unit, "fail");
                if (r < 0) {
                        log_error("Failed to start unit: %s", bus_error_message(&error, -r));
                        return r;
                }

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_add(w, object);
                if (r < 0)
                        return log_oom();
        }

        r = bus_wait_for_jobs(w, arg_quiet);
        if (r < 0)
                return r;

        return 0;
}

static int enable_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int carries_install_info = 0;
        const char *method = NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        method = streq(argv[0], "enable") ? "EnableUnitFiles" : "DisableUnitFiles";

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        method);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return bus_log_create_error(r);

        for (i = 1; i < argc; i++) {
                _cleanup_free_ char *unit = NULL;

                r = make_service_name(argv[i], &unit);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "s", unit);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        if (streq(argv[0], "enable"))
                r = sd_bus_message_append(m, "bb", false, false);
        else
                r = sd_bus_message_append(m, "b", false);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to enable or disable unit: %s", bus_error_message(&error, -r));
                return r;
        }

        if (streq(argv[0], "enable")) {
                r = sd_bus_message_read(reply, "b", carries_install_info);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = bus_deserialize_and_dump_unit_file_changes(reply, arg_quiet, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Reload",
                        &error,
                        NULL,
                        NULL);
        if (r < 0) {
                log_error("Failed to reload daemon: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int match_log_message(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *line;
        unsigned priority;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "us", &priority, &line);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, sd_bus_message_get_path(m)))
                return 0;

        if (arg_quiet && LOG_PRI(priority) >= LOG_INFO)
                return 0;

        log_full(priority, "%s", line);
        return 0;
}

static int match_transfer_removed(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char **our_path = userdata, *path, *result;
        uint32_t id;
        int r;

        assert(m);
        assert(our_path);

        r = sd_bus_message_read(m, "uos", &id, &path, &result);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (!streq_ptr(*our_path, path))
                return 0;

        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), !streq_ptr(result, "done"));
        return 0;
}

static int transfer_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(s);
        assert(si);

        if (!arg_quiet)
                log_info("Continuing download in the background. Use \"machinectl cancel-transfer %" PRIu32 "\" to abort transfer.", PTR_TO_UINT32(userdata));

        sd_event_exit(sd_event_source_get_event(s), EINTR);
        return 0;
}

static int transfer_image_common(sd_bus *bus, sd_bus_message *m) {
        _cleanup_bus_slot_unref_ sd_bus_slot *slot_job_removed = NULL, *slot_log_message = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_event_unref_ sd_event* event = NULL;
        const char *path = NULL;
        uint32_t id;
        int r;

        assert(bus);
        assert(m);

        polkit_agent_open_if_enabled();

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_bus_add_match(
                        bus,
                        &slot_job_removed,
                        "type='signal',"
                        "sender='org.freedesktop.import1',"
                        "interface='org.freedesktop.import1.Manager',"
                        "member='TransferRemoved',"
                        "path='/org/freedesktop/import1'",
                        match_transfer_removed, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to install match: %m");

        r = sd_bus_add_match(
                        bus,
                        &slot_log_message,
                        "type='signal',"
                        "sender='org.freedesktop.import1',"
                        "interface='org.freedesktop.import1.Transfer',"
                        "member='LogMessage'",
                        match_log_message, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to install match: %m");

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed transfer image: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "uo", &id, &path);
        if (r < 0)
                return bus_log_parse_error(r);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, -1) >= 0);

        if (!arg_quiet)
                log_info("Enqueued transfer job %u. Press C-c to continue download in background.", id);

        sd_event_add_signal(event, NULL, SIGINT, transfer_signal_handler, UINT32_TO_PTR(id));
        sd_event_add_signal(event, NULL, SIGTERM, transfer_signal_handler, UINT32_TO_PTR(id));

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return -r;
}

static int import_tar(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL;
        _cleanup_close_ int fd = -1;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        if (argc >= 2)
                path = argv[1];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (argc >= 3)
                local = argv[2];
        else if (path)
                local = basename(path);
        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (!local) {
                log_error("Need either path or local name.");
                return -EINVAL;
        }

        r = tar_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!machine_name_is_valid(local)) {
                log_error("Local name %s is not a suitable machine name.", local);
                return -EINVAL;
        }

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "ImportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int import_raw(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *ll = NULL;
        _cleanup_close_ int fd = -1;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        if (argc >= 2)
                path = argv[1];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (argc >= 3)
                local = argv[2];
        else if (path)
                local = basename(path);
        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (!local) {
                log_error("Need either path or local name.");
                return -EINVAL;
        }

        r = raw_strip_suffixes(local, &ll);
        if (r < 0)
                return log_oom();

        local = ll;

        if (!machine_name_is_valid(local)) {
                log_error("Local name %s is not a suitable machine name.", local);
                return -EINVAL;
        }

        if (path) {
                fd = open(path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "ImportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "hsbb",
                        fd >= 0 ? fd : STDIN_FILENO,
                        local,
                        arg_force,
                        arg_read_only);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static void determine_compression_from_filename(const char *p) {
        if (arg_format)
                return;

        if (!p)
                return;

        if (endswith(p, ".xz"))
                arg_format = "xz";
        else if (endswith(p, ".gz"))
                arg_format = "gzip";
        else if (endswith(p, ".bz2"))
                arg_format = "bzip2";
}

static int export_tar(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -1;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        local = argv[1];
        if (!machine_name_is_valid(local)) {
                log_error("Machine name %s is not valid.", local);
                return -EINVAL;
        }

        if (argc >= 3)
                path = argv[2];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "ExportTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int export_raw(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_close_ int fd = -1;
        const char *local = NULL, *path = NULL;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        local = argv[1];
        if (!machine_name_is_valid(local)) {
                log_error("Machine name %s is not valid.", local);
                return -EINVAL;
        }

        if (argc >= 3)
                path = argv[2];
        if (isempty(path) || streq(path, "-"))
                path = NULL;

        if (path) {
                determine_compression_from_filename(path);

                fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOCTTY, 0666);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "ExportRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "shs",
                        local,
                        fd >= 0 ? fd : STDOUT_FILENO,
                        arg_format);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_tar(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        remote = argv[1];
        if (!http_url_is_valid(remote)) {
                log_error("URL '%s' is not valid.", remote);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                r = tar_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!machine_name_is_valid(local)) {
                        log_error("Local name %s is not a suitable machine name.", local);
                        return -EINVAL;
                }
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "PullTar");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_raw(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_free_ char *l = NULL, *ll = NULL;
        const char *local, *remote;
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        remote = argv[1];
        if (!http_url_is_valid(remote)) {
                log_error("URL '%s' is not valid.", remote);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                r = import_url_last_component(remote, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to get final component of URL: %m");

                local = l;
        }

        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                r = raw_strip_suffixes(local, &ll);
                if (r < 0)
                        return log_oom();

                local = ll;

                if (!machine_name_is_valid(local)) {
                        log_error("Local name %s is not a suitable machine name.", local);
                        return -EINVAL;
                }
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "PullRaw");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssb",
                        remote,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

static int pull_dkr(int argc, char *argv[], void *userdata) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        const char *local, *remote, *tag;
        sd_bus *bus = userdata;
        int r;

        if (arg_verify != IMPORT_VERIFY_NO) {
                log_error("Imports from DKR do not support image verification, please pass --verify=no.");
                return -EINVAL;
        }

        remote = argv[1];
        tag = strchr(remote, ':');
        if (tag) {
                remote = strndupa(remote, tag - remote);
                tag++;
        }

        if (!dkr_name_is_valid(remote)) {
                log_error("DKR name '%s' is invalid.", remote);
                return -EINVAL;
        }
        if (tag && !dkr_tag_is_valid(tag)) {
                log_error("DKR tag '%s' is invalid.", remote);
                return -EINVAL;
        }

        if (argc >= 3)
                local = argv[2];
        else {
                local = strchr(remote, '/');
                if (local)
                        local++;
                else
                        local = remote;
        }

        if (isempty(local) || streq(local, "-"))
                local = NULL;

        if (local) {
                if (!machine_name_is_valid(local)) {
                        log_error("Local name %s is not a suitable machine name.", local);
                        return -EINVAL;
                }
        }

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.import1",
                        "/org/freedesktop/import1",
                        "org.freedesktop.import1.Manager",
                        "PullDkr");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "sssssb",
                        arg_dkr_index_url,
                        remote,
                        tag,
                        local,
                        import_verify_to_string(arg_verify),
                        arg_force);
        if (r < 0)
                return bus_log_create_error(r);

        return transfer_image_common(bus, m);
}

typedef struct TransferInfo {
        uint32_t id;
        const char *type;
        const char *remote;
        const char *local;
        double progress;
} TransferInfo;

static int compare_transfer_info(const void *a, const void *b) {
        const TransferInfo *x = a, *y = b;

        return strcmp(x->local, y->local);
}

static int list_transfers(int argc, char *argv[], void *userdata) {
        size_t max_type = strlen("TYPE"), max_local = strlen("LOCAL"), max_remote = strlen("REMOTE");
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ TransferInfo *transfers = NULL;
        size_t n_transfers = 0, n_allocated = 0, j;
        const char *type, *remote, *local, *object;
        sd_bus *bus = userdata;
        uint32_t id, max_id = 0;
        double progress;
        int r;

        pager_open_if_enabled();

        r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.import1",
                                "/org/freedesktop/import1",
                                "org.freedesktop.import1.Manager",
                                "ListTransfers",
                                &error,
                                &reply,
                                NULL);
        if (r < 0) {
                log_error("Could not get transfers: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(usssdo)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(usssdo)", &id, &type, &remote, &local, &progress, &object)) > 0) {
                size_t l;

                if (!GREEDY_REALLOC(transfers, n_allocated, n_transfers + 1))
                        return log_oom();

                transfers[n_transfers].id = id;
                transfers[n_transfers].type = type;
                transfers[n_transfers].remote = remote;
                transfers[n_transfers].local = local;
                transfers[n_transfers].progress = progress;

                l = strlen(type);
                if (l > max_type)
                        max_type = l;

                l = strlen(remote);
                if (l > max_remote)
                        max_remote = l;

                l = strlen(local);
                if (l > max_local)
                        max_local = l;

                if (id > max_id)
                        max_id = id;

                n_transfers ++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        qsort_safe(transfers, n_transfers, sizeof(TransferInfo), compare_transfer_info);

        if (arg_legend)
                printf("%-*s %-*s %-*s %-*s %-*s\n",
                       (int) MAX(2U, DECIMAL_STR_WIDTH(max_id)), "ID",
                       (int) 7, "PERCENT",
                       (int) max_type, "TYPE",
                       (int) max_local, "LOCAL",
                       (int) max_remote, "REMOTE");

        for (j = 0; j < n_transfers; j++)
                printf("%*" PRIu32 " %*u%% %-*s %-*s %-*s\n",
                       (int) MAX(2U, DECIMAL_STR_WIDTH(max_id)), transfers[j].id,
                       (int) 6, (unsigned) (transfers[j].progress * 100),
                       (int) max_type, transfers[j].type,
                       (int) max_local, transfers[j].local,
                       (int) max_remote, transfers[j].remote);

        if (arg_legend)
                printf("\n%zu transfers listed.\n", n_transfers);

        return 0;
}

static int cancel_transfer(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int r, i;

        assert(bus);

        polkit_agent_open_if_enabled();

        for (i = 1; i < argc; i++) {
                uint32_t id;

                r = safe_atou32(argv[i], &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse transfer id: %s", argv[i]);

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.import1",
                                "/org/freedesktop/import1",
                                "org.freedesktop.import1.Manager",
                                "CancelTransfer",
                                &error,
                                NULL,
                                "u", id);
                if (r < 0) {
                        log_error("Could not cancel transfer: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int set_limit(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        uint64_t limit;
        int r;

        if (streq(argv[argc-1], "-"))
                limit = (uint64_t) -1;
        else {
                off_t off;

                r = parse_size(argv[argc-1], 1024, &off);
                if (r < 0)
                        return log_error("Failed to parse size: %s", argv[argc-1]);

                limit = (uint64_t) off;
        }

        if (argc > 2)
                /* With two arguments changes the quota limit of the
                 * specified image */
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "SetImageLimit",
                                &error,
                                NULL,
                                "st", argv[1], limit);
        else
                /* With one argument changes the pool quota limit */
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "SetPoolLimit",
                                &error,
                                NULL,
                                "t", limit);

        if (r < 0) {
                log_error("Could not set limit: %s", bus_error_message(&error, -r));
                return r;
        }

        return 0;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the virtual machine and container\n"
               "registration manager.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "     --no-ask-password        Do not ask for system passwords\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "  -p --property=NAME          Show only properties by this name\n"
               "  -q --quiet                  Suppress output\n"
               "  -a --all                    Show all properties, including empty ones\n"
               "  -l --full                   Do not ellipsize output\n"
               "     --kill-who=WHO           Who to send signal to\n"
               "  -s --signal=SIGNAL          Which signal to send\n"
               "     --read-only              Create read-only bind mount\n"
               "     --mkdir                  Create directory before bind mounting, if missing\n"
               "  -n --lines=INTEGER          Number of journal entries to show\n"
               "  -o --output=STRING          Change journal output mode (short,\n"
               "                              short-monotonic, verbose, export, json,\n"
               "                              json-pretty, json-sse, cat)\n"
               "      --verify=MODE           Verification mode for downloaded images (no,\n"
               "                              checksum, signature)\n"
               "      --force                 Download image even if already exists\n"
               "      --dkr-index-url=URL     Specify the index URL to use for DKR image\n"
               "                              downloads\n\n"
               "Machine Commands:\n"
               "  list                        List running VMs and containers\n"
               "  status NAME...              Show VM/container details\n"
               "  show NAME...                Show properties of one or more VMs/containers\n"
               "  start NAME...               Start container as a service\n"
               "  login NAME                  Get a login prompt on a container\n"
               "  enable NAME...              Enable automatic container start at boot\n"
               "  disable NAME...             Disable automatic container start at boot\n"
               "  poweroff NAME...            Power off one or more containers\n"
               "  reboot NAME...              Reboot one or more containers\n"
               "  terminate NAME...           Terminate one or more VMs/containers\n"
               "  kill NAME...                Send signal to processes of a VM/container\n"
               "  copy-to NAME PATH [PATH]    Copy files from the host to a container\n"
               "  copy-from NAME PATH [PATH]  Copy files from a container to the host\n"
               "  bind NAME PATH [PATH]       Bind mount a path from the host into a container\n\n"
               "Image Commands:\n"
               "  list-images                 Show available container and VM images\n"
               "  image-status NAME...        Show image details\n"
               "  show-image NAME...          Show properties of image\n"
               "  clone NAME NAME             Clone an image\n"
               "  rename NAME NAME            Rename an image\n"
               "  read-only NAME [BOOL]       Mark or unmark image read-only\n"
               "  remove NAME...              Remove an image\n"
               "  set-limit [NAME] BYTES      Set image or pool size limit (disk quota)\n\n"
               "Image Transfer Commands:\n"
               "  pull-tar URL [NAME]         Download a TAR container image\n"
               "  pull-raw URL [NAME]         Download a RAW container or VM image\n"
               "  pull-dkr REMOTE [NAME]      Download a DKR container image\n"
               "  import-tar FILE [NAME]      Import a local TAR container image\n"
               "  import-raw FILE [NAME]      Import a local RAW container or VM image\n"
               "  export-tar NAME [FILE]      Export a TAR container image locally\n"
               "  export-raw NAME [FILE]      Export a RAW container or VM image locally\n"
               "  list-transfers              Show list of downloads in progress\n"
               "  cancel-transfer             Cancel a download\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_KILL_WHO,
                ARG_READ_ONLY,
                ARG_MKDIR,
                ARG_NO_ASK_PASSWORD,
                ARG_VERIFY,
                ARG_FORCE,
                ARG_DKR_INDEX_URL,
                ARG_FORMAT,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "property",        required_argument, NULL, 'p'                 },
                { "all",             no_argument,       NULL, 'a'                 },
                { "full",            no_argument,       NULL, 'l'                 },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "no-legend",       no_argument,       NULL, ARG_NO_LEGEND       },
                { "kill-who",        required_argument, NULL, ARG_KILL_WHO        },
                { "signal",          required_argument, NULL, 's'                 },
                { "host",            required_argument, NULL, 'H'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "read-only",       no_argument,       NULL, ARG_READ_ONLY       },
                { "mkdir",           no_argument,       NULL, ARG_MKDIR           },
                { "quiet",           no_argument,       NULL, 'q'                 },
                { "lines",           required_argument, NULL, 'n'                 },
                { "output",          required_argument, NULL, 'o'                 },
                { "no-ask-password", no_argument,       NULL, ARG_NO_ASK_PASSWORD },
                { "verify",          required_argument, NULL, ARG_VERIFY          },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                { "dkr-index-url",   required_argument, NULL, ARG_DKR_INDEX_URL   },
                { "format",          required_argument, NULL, ARG_FORMAT          },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:als:H:M:qn:o:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'p':
                        r = strv_extend(&arg_property, optarg);
                        if (r < 0)
                                return log_oom();

                        /* If the user asked for a particular
                         * property, show it to him, even if it is
                         * empty. */
                        arg_all = true;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0) {
                                log_error("Failed to parse lines '%s'", optarg);
                                return -EINVAL;
                        }
                        break;

                case 'o':
                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0) {
                                log_error("Unknown output '%s'.", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case 's':
                        arg_signal = signal_from_string_try_harder(optarg);
                        if (arg_signal < 0) {
                                log_error("Failed to parse signal string %s.", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_MKDIR:
                        arg_mkdir = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERIFY:
                        arg_verify = import_verify_from_string(optarg);
                        if (arg_verify < 0) {
                                log_error("Failed to parse --verify= setting: %s", optarg);
                                return -EINVAL;
                        }
                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case ARG_DKR_INDEX_URL:
                        if (!http_url_is_valid(optarg)) {
                                log_error("Index URL is invalid: %s", optarg);
                                return -EINVAL;
                        }

                        arg_dkr_index_url = optarg;
                        break;

                case ARG_FORMAT:
                        if (!STR_IN_SET(optarg, "uncompressed", "xz", "gzip", "bzip2")) {
                                log_error("Unknown format: %s", optarg);
                                return -EINVAL;
                        }

                        arg_format = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int machinectl_main(int argc, char *argv[], sd_bus *bus) {

        static const Verb verbs[] = {
                { "help",            VERB_ANY, VERB_ANY, 0,            help              },
                { "list",            VERB_ANY, 1,        VERB_DEFAULT, list_machines     },
                { "list-images",     VERB_ANY, 1,        0,            list_images       },
                { "status",          2,        VERB_ANY, 0,            show_machine      },
                { "image-status",    VERB_ANY, VERB_ANY, 0,            show_image        },
                { "show",            VERB_ANY, VERB_ANY, 0,            show_machine      },
                { "show-image",      VERB_ANY, VERB_ANY, 0,            show_image        },
                { "terminate",       2,        VERB_ANY, 0,            terminate_machine },
                { "reboot",          2,        VERB_ANY, 0,            reboot_machine    },
                { "poweroff",        2,        VERB_ANY, 0,            poweroff_machine  },
                { "kill",            2,        VERB_ANY, 0,            kill_machine      },
                { "login",           2,        2,        0,            login_machine     },
                { "bind",            3,        4,        0,            bind_mount        },
                { "copy-to",         3,        4,        0,            copy_files        },
                { "copy-from",       3,        4,        0,            copy_files        },
                { "remove",          2,        VERB_ANY, 0,            remove_image      },
                { "rename",          3,        3,        0,            rename_image      },
                { "clone",           3,        3,        0,            clone_image       },
                { "read-only",       2,        3,        0,            read_only_image   },
                { "start",           2,        VERB_ANY, 0,            start_machine     },
                { "enable",          2,        VERB_ANY, 0,            enable_machine    },
                { "disable",         2,        VERB_ANY, 0,            enable_machine    },
                { "import-tar",      2,        3,        0,            import_tar        },
                { "import-raw",      2,        3,        0,            import_raw        },
                { "export-tar",      2,        3,        0,            export_tar        },
                { "export-raw",      2,        3,        0,            export_raw        },
                { "pull-tar",        2,        3,        0,            pull_tar          },
                { "pull-raw",        2,        3,        0,            pull_raw          },
                { "pull-dkr",        2,        3,        0,            pull_dkr          },
                { "list-transfers",  VERB_ANY, 1,        0,            list_transfers    },
                { "cancel-transfer", 2,        VERB_ANY, 0,            cancel_transfer   },
                { "set-limit",       2,        3,        0,            set_limit         },
                {}
        };

        return dispatch_verb(argc, argv, verbs, bus);
}

int main(int argc, char*argv[]) {
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bus_open_transport(arg_transport, arg_host, false, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

        sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

        r = machinectl_main(argc, argv, bus);

finish:
        pager_close();
        polkit_agent_close();

        strv_free(arg_property);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
