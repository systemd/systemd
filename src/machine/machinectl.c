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
#include <pwd.h>
#include <locale.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/mount.h>
#include <libgen.h>

#include "sd-bus.h"
#include "log.h"
#include "util.h"
#include "macro.h"
#include "pager.h"
#include "bus-util.h"
#include "bus-error.h"
#include "build.h"
#include "strv.h"
#include "unit-name.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "ptyfwd.h"
#include "event-util.h"
#include "path-util.h"
#include "mkdir.h"
#include "copy.h"
#include "verbs.h"

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

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

static int list_machines(int argc, char *argv[], void *userdata) {

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *name, *class, *service, *object;
        sd_bus *bus = userdata;
        unsigned k = 0;
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
                                "");
        if (r < 0) {
                log_error("Could not get machines: %s", bus_error_message(&error, -r));
                return r;
        }

        if (arg_legend)
                printf("%-32s %-9s %-16s\n", "MACHINE", "CONTAINER", "SERVICE");

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ssso)", &name, &class, &service, &object)) > 0) {
                printf("%-32s %-9s %-16s\n", name, class, service);

                k++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (arg_legend)
                printf("\n%u machines listed.\n", k);

        return 0;
}

typedef struct ImageInfo {
        const char *name;
        const char *type;
        bool read_only;
        usec_t crtime;
        usec_t mtime;
} ImageInfo;

static int compare_image_info(const void *a, const void *b) {
        const ImageInfo *x = a, *y = b;

        return strcmp(x->name, y->name);
}

static int list_images(int argc, char *argv[], void *userdata) {

        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        size_t max_name = strlen("NAME"), max_type = strlen("TYPE"), max_crtime = strlen("CREATED"), max_mtime = strlen("MODIFIED");
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ ImageInfo *images = NULL;
        size_t n_images = 0, n_allocated = 0, j;
        const char *name, *type, *object;
        sd_bus *bus = userdata;
        uint64_t crtime, mtime;
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

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssbtto)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(reply, "(ssbtto)", &name, &type, &read_only, &crtime, &mtime, &object)) > 0) {
                char buf[FORMAT_TIMESTAMP_MAX];
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

                l = strlen(name);
                if (l > max_name)
                        max_name = l;

                l = strlen(type);
                if (l > max_type)
                        max_type = l;

                if (crtime != 0) {
                        l = strlen(format_timestamp(buf, sizeof(buf), crtime));
                        if (l > max_crtime)
                                max_crtime = l;
                }

                if (mtime != 0) {
                        l = strlen(format_timestamp(buf, sizeof(buf), mtime));
                        if (l > max_mtime)
                                max_mtime = l;
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
                printf("%-*s %-*s %-3s %-*s %-*s\n",
                       (int) max_name, "NAME",
                       (int) max_type, "TYPE",
                       "RO",
                       (int) max_crtime, "CREATED",
                       (int) max_mtime, "MODIFIED");

        for (j = 0; j < n_images; j++) {
                char crtime_buf[FORMAT_TIMESTAMP_MAX], mtime_buf[FORMAT_TIMESTAMP_MAX];

                printf("%-*s %-*s %s%-3s%s %-*s %-*s\n",
                       (int) max_name, images[j].name,
                       (int) max_type, images[j].type,
                       images[j].read_only ? ansi_highlight_red() : "", yes_no(images[j].read_only), images[j].read_only ? ansi_highlight_off() : "",
                       (int) max_crtime, images[j].crtime != 0 ? format_timestamp(crtime_buf, sizeof(crtime_buf), images[j].crtime) : "-",
                       (int) max_mtime, images[j].mtime != 0 ? format_timestamp(mtime_buf, sizeof(mtime_buf), images[j].mtime) : "-");
        }

        if (r < 0)
                return bus_log_parse_error(r);


        if (arg_legend)
                printf("\n%zu images listed.\n", n_images);

        return 0;
}

static int show_unit_cgroup(sd_bus *bus, const char *unit, pid_t leader) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL;
        const char *cgroup;
        int r, output_flags;
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

        output_flags =
                arg_all * OUTPUT_SHOW_ALL |
                arg_full * OUTPUT_FULL_WIDTH;

        c = columns();
        if (c > 18)
                c -= 18;
        else
                c = 0;

        show_cgroup_and_extra(SYSTEMD_CGROUP_CONTROLLER, cgroup, "\t\t  ", c, false, &leader, leader > 0, output_flags);
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
        usec_t timestamp;
        int *netif;
        unsigned n_netif;
} MachineStatusInfo;

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

        s1 = format_timestamp_relative(since1, sizeof(since1), i->timestamp);
        s2 = format_timestamp(since2, sizeof(since2), i->timestamp);

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

static int show_info(const char *verb, sd_bus *bus, const char *path, bool *new_line) {

        static const struct bus_properties_map map[]  = {
                { "Name",              "s",  NULL,          offsetof(MachineStatusInfo, name) },
                { "Class",             "s",  NULL,          offsetof(MachineStatusInfo, class) },
                { "Service",           "s",  NULL,          offsetof(MachineStatusInfo, service) },
                { "Unit",              "s",  NULL,          offsetof(MachineStatusInfo, unit) },
                { "RootDirectory",     "s",  NULL,          offsetof(MachineStatusInfo, root_directory) },
                { "Leader",            "u",  NULL,          offsetof(MachineStatusInfo, leader) },
                { "Timestamp",         "t",  NULL,          offsetof(MachineStatusInfo, timestamp) },
                { "Id",                "ay", bus_map_id128, offsetof(MachineStatusInfo, id) },
                { "NetworkInterfaces", "ai", map_netif,     0 },
                {}
        };

        MachineStatusInfo info = {};
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

        free(info.name);
        free(info.class);
        free(info.service);
        free(info.unit);
        free(info.root_directory);
        free(info.netif);

        return r;
}

static int show_properties(sd_bus *bus, const char *path, bool *new_line) {
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

static int show(int argc, char *argv[], void *userdata) {

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
                r = show_properties(bus, "/org/freedesktop/machine1", &new_line);
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
                        r = show_properties(bus, path, &new_line);
                else
                        r = show_info(argv[0], bus, path, &new_line);
        }

        return r;
}

static int kill_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus = userdata;
        int i;

        assert(bus);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < argc; i++) {
                int r;

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
        int i;

        assert(bus);

        for (i = 1; i < argc; i++) {
                int r;

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

static int machine_get_leader(sd_bus *bus, const char *name, pid_t *ret) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *reply2 = NULL;
        const char *object;
        uint32_t leader;
        int r;

        assert(bus);
        assert(name);
        assert(ret);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "GetMachine",
                        &error,
                        &reply,
                        "s", name);
        if (r < 0) {
                log_error("Could not get path to machine: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "o", &object);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.machine1",
                        object,
                        "org.freedesktop.machine1.Machine",
                        "Leader",
                        &error,
                        &reply2,
                        "u");
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve PID of leader: %m");

        r = sd_bus_message_read(reply2, "u", &leader);
        if (r < 0)
                return bus_log_parse_error(r);

        *ret = leader;
        return 0;
}

static int copy_files(int argc, char *argv[], void *userdata) {
        char *dest, *host_path, *container_path, *host_dirname, *host_basename, *container_dirname, *container_basename, *t;
        _cleanup_close_ int hostfd = -1;
        sd_bus *bus = userdata;
        pid_t child, leader;
        bool copy_from;
        siginfo_t si;
        int r;

        assert(bus);

        copy_from = streq(argv[0], "copy-from");
        dest = argv[3] ?: argv[2];
        host_path = strdupa(copy_from ? dest : argv[2]);
        container_path = strdupa(copy_from ? argv[2] : dest);

        if (!path_is_absolute(container_path)) {
                log_error("Container path not absolute.");
                return -EINVAL;
        }

        t = strdup(host_path);
        host_basename = basename(t);
        host_dirname = dirname(host_path);

        t = strdup(container_path);
        container_basename = basename(t);
        container_dirname = dirname(container_path);

        r = machine_get_leader(bus, argv[1], &leader);
        if (r < 0)
                return r;

        hostfd = open(host_dirname, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);
        if (r < 0)
                return log_error_errno(errno, "Failed to open source directory: %m");

        child = fork();
        if (child < 0)
                return log_error_errno(errno, "Failed to fork(): %m");

        if (child == 0) {
                int containerfd;
                const char *q;
                int mntfd;

                q = procfs_file_alloca(leader, "ns/mnt");
                mntfd = open(q, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntfd < 0) {
                        log_error_errno(errno, "Failed to open mount namespace of leader: %m");
                        _exit(EXIT_FAILURE);
                }

                if (setns(mntfd, CLONE_NEWNS) < 0) {
                        log_error_errno(errno, "Failed to join namespace of leader: %m");
                        _exit(EXIT_FAILURE);
                }

                containerfd = open(container_dirname, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_DIRECTORY);
                if (containerfd < 0) {
                        log_error_errno(errno, "Failed top open destination directory: %m");
                        _exit(EXIT_FAILURE);
                }

                if (copy_from)
                        r = copy_tree_at(containerfd, container_basename, hostfd, host_basename, true);
                else
                        r = copy_tree_at(hostfd, host_basename, containerfd, container_basename, true);
                if (r < 0) {
                        log_error_errno(errno, "Failed to copy tree: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for client: %m");
        if (si.si_code != CLD_EXITED) {
                log_error("Client died abnormally.");
                return -EIO;
        }
        if (si.si_status != EXIT_SUCCESS)
                return -EIO;

        return 0;
}

static int bind_mount(int argc, char *argv[], void *userdata) {
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        sd_bus *bus = userdata;
        pid_t child, leader;
        const char *dest;
        siginfo_t si;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        int r;

        assert(bus);

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        dest = argv[3] ?: argv[2];
        if (!path_is_absolute(dest)) {
                log_error("Destination path not absolute.");
                return -EINVAL;
        }

        p = strappenda("/run/systemd/nspawn/propagate/", argv[1], "/");
        if (access(p, F_OK) < 0) {
                log_error("Container does not allow propagation of mount points.");
                return -ENOTSUP;
        }

        r = machine_get_leader(bus, argv[1], &leader);
        if (r < 0)
                return r;

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOUNT cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave))
                return log_error_errno(errno, "Failed to create playground: %m");

        mount_slave_created = true;

        if (mount(mount_slave, mount_slave, NULL, MS_BIND, NULL) < 0) {
                r = log_error_errno(errno, "Failed to make bind mount: %m");
                goto finish;
        }

        mount_slave_mounted = true;

        if (mount(NULL, mount_slave, NULL, MS_SLAVE, NULL) < 0) {
                r = log_error_errno(errno, "Failed to remount slave: %m");
                goto finish;
        }

        /* Second, we mount the source directory to a directory inside
           of our MS_SLAVE playground. */
        mount_tmp = strappenda(mount_slave, "/mount");
        if (mkdir(mount_tmp, 0700) < 0) {
                r = log_error_errno(errno, "Failed to create temporary mount: %m");
                goto finish;
        }

        mount_tmp_created = true;

        if (mount(argv[2], mount_tmp, NULL, MS_BIND, NULL) < 0) {
                r = log_error_errno(errno, "Failed to overmount: %m");
                goto finish;
        }

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (arg_read_only)
                if (mount(NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
                        r = log_error_errno(errno, "Failed to mark read-only: %m");
                        goto finish;
                }

        /* Fourth, we move the new bind mount into the propagation
         * directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strappenda("/run/systemd/nspawn/propagate/", argv[1], "/XXXXXX");
        if (!mkdtemp(mount_outside)) {
                r = log_error_errno(errno, "Cannot create propagation directory: %m");
                goto finish;
        }

        mount_outside_created = true;

        if (mount(mount_tmp, mount_outside, NULL, MS_MOVE, NULL) < 0) {
                r = log_error_errno(errno, "Failed to move: %m");
                goto finish;
        }

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        (void) rmdir(mount_tmp);
        mount_tmp_created = false;

        (void) umount(mount_slave);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        child = fork();
        if (child < 0) {
                r = log_error_errno(errno, "Failed to fork(): %m");
                goto finish;
        }

        if (child == 0) {
                const char *mount_inside;
                int mntfd;
                const char *q;

                q = procfs_file_alloca(leader, "ns/mnt");
                mntfd = open(q, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntfd < 0) {
                        log_error_errno(errno, "Failed to open mount namespace of leader: %m");
                        _exit(EXIT_FAILURE);
                }

                if (setns(mntfd, CLONE_NEWNS) < 0) {
                        log_error_errno(errno, "Failed to join namespace of leader: %m");
                        _exit(EXIT_FAILURE);
                }

                if (arg_mkdir)
                        mkdir_p(dest, 0755);

                /* Fifth, move the mount to the right place inside */
                mount_inside = strappenda("/run/systemd/nspawn/incoming/", basename(mount_outside));
                if (mount(mount_inside, dest, NULL, MS_MOVE, NULL) < 0) {
                        log_error_errno(errno, "Failed to mount: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        r = wait_for_terminate(child, &si);
        if (r < 0) {
                log_error_errno(r, "Failed to wait for client: %m");
                goto finish;
        }
        if (si.si_code != CLD_EXITED) {
                log_error("Client died abnormally.");
                r = -EIO;
                goto finish;
        }
        if (si.si_status != EXIT_SUCCESS) {
                r = -EIO;
                goto finish;
        }

        r = 0;

finish:
        if (mount_outside_mounted)
                umount(mount_outside);
        if (mount_outside_created)
                rmdir(mount_outside);

        if (mount_tmp_mounted)
                umount(mount_tmp);
        if (mount_tmp_created)
                umount(mount_tmp);

        if (mount_slave_mounted)
                umount(mount_slave);
        if (mount_slave_created)
                umount(mount_slave);

        return r;
}

static int login_machine(int argc, char *argv[], void *userdata) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_event_unref_ sd_event *event = NULL;
        int master = -1, r, ret = 0;
        sd_bus *bus = userdata;
        const char *pty;
        sigset_t mask;
        char last_char = 0;

        assert(bus);

        if (arg_transport != BUS_TRANSPORT_LOCAL &&
            arg_transport != BUS_TRANSPORT_MACHINE) {
                log_error("Login only supported on local machines.");
                return -ENOTSUP;
        }

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get event loop: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = sd_bus_message_new_method_call(bus,
                                           &m,
                                           "org.freedesktop.machine1",
                                           "/org/freedesktop/machine1",
                                           "org.freedesktop.machine1.Manager",
                                           "OpenMachineLogin");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, true);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", argv[1]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("Failed to get machine PTY: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "hs", &master, &pty);
        if (r < 0)
                return bus_log_parse_error(r);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGWINCH, SIGTERM, SIGINT, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        log_info("Connected to container %s. Press ^] three times within 1s to exit session.", argv[1]);

        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
        sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);

        r = pty_forward_new(event, master, true, &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        pty_forward_last_char(forward, &last_char);

        forward = pty_forward_free(forward);

        if (last_char != '\n')
                fputc('\n', stdout);

        log_info("Connection to container %s terminated.", argv[1]);

        sd_event_get_exit_code(event, &ret);
        return ret;
}

static int help(int argc, char *argv[], void *userdata) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the virtual machine and container\n"
               "registration manager.\n\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not show the headers and footers\n"
               "  -H --host=[USER@]HOST       Operate on remote host\n"
               "  -M --machine=CONTAINER      Operate on local container\n"
               "  -p --property=NAME          Show only properties by this name\n"
               "  -a --all                    Show all properties, including empty ones\n"
               "  -l --full                   Do not ellipsize output\n"
               "     --kill-who=WHO           Who to send signal to\n"
               "  -s --signal=SIGNAL          Which signal to send\n"
               "     --read-only              Create read-only bind mount\n"
               "     --mkdir                  Create directory before bind mounting, if missing\n\n"
               "Machine Commands:\n"
               "  list                        List running VMs and containers\n"
               "  status NAME...              Show VM/container status\n"
               "  show NAME...                Show properties of one or more VMs/containers\n"
               "  login NAME                  Get a login prompt on a container\n"
               "  poweroff NAME...            Power off one or more containers\n"
               "  reboot NAME...              Reboot one or more containers\n"
               "  kill NAME...                Send signal to processes of a VM/container\n"
               "  terminate NAME...           Terminate one or more VMs/containers\n"
               "  bind NAME PATH [PATH]       Bind mount a path from the host into a container\n"
               "  copy-to NAME PATH [PATH]    Copy files from the host to a container\n"
               "  copy-from NAME PATH [PATH]  Copy files from a container to the host\n\n"
               "Image commands:\n"
               "  list-images                 Show available images\n",
               program_invocation_short_name);

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
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:als:H:M:", options, NULL)) >= 0)

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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int machinectl_main(int argc, char *argv[], sd_bus *bus) {

        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,            help              },
                { "list",        VERB_ANY, 1,        VERB_DEFAULT, list_machines     },
                { "list-images", VERB_ANY, 1,        0,            list_images       },
                { "status",      2,        VERB_ANY, 0,            show              },
                { "show",        VERB_ANY, VERB_ANY, 0,            show              },
                { "terminate",   2,        VERB_ANY, 0,            terminate_machine },
                { "reboot",      2,        VERB_ANY, 0,            reboot_machine    },
                { "poweroff",    2,        VERB_ANY, 0,            poweroff_machine  },
                { "kill",        2,        VERB_ANY, 0,            kill_machine      },
                { "login",       2,        2,        0,            login_machine     },
                { "bind",        3,        4,        0,            bind_mount        },
                { "copy-to",     3,        4,        0,            copy_files        },
                { "copy-from",   3,        4,        0,            copy_files        },
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

        r = machinectl_main(argc, argv, bus);

finish:
        pager_close();

        strv_free(arg_property);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
