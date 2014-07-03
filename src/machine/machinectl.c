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

static char **arg_property = NULL;
static bool arg_all = false;
static bool arg_full = false;
static bool arg_no_pager = false;
static bool arg_legend = true;
static const char *arg_kill_who = NULL;
static int arg_signal = SIGTERM;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

static int list_machines(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *name, *class, *service, *object;
        unsigned k = 0;
        int r;

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

static int print_addresses(sd_bus *bus, const char *name, const char *prefix, const char *prefix2) {
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

        r = sd_bus_message_enter_container(reply, 'a', "(yay)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_enter_container(reply, 'r', "yay")) > 0) {
                unsigned char family;
                const void *a;
                size_t sz;
                char buffer[MAX(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];

                r = sd_bus_message_read(reply, "y", &family);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_read_array(reply, 'y', &a, &sz);
                if (r < 0)
                        return bus_log_parse_error(r);

                printf("%s%s\n", prefix, inet_ntop(family, a, buffer, sizeof(buffer)));

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
} MachineStatusInfo;

static void print_machine_status_info(sd_bus *bus, MachineStatusInfo *i) {
        char since1[FORMAT_TIMESTAMP_RELATIVE_MAX], *s1;
        char since2[FORMAT_TIMESTAMP_MAX], *s2;
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

        print_addresses(bus, i->name,
                       "\t Address: ",
                       "\t          ");

        print_os_release(bus, i->name, "\t      OS: ");

        if (i->unit) {
                printf("\t    Unit: %s\n", i->unit);
                show_unit_cgroup(bus, i->unit, i->leader);
        }
}

static int show_info(const char *verb, sd_bus *bus, const char *path, bool *new_line) {

        static const struct bus_properties_map map[]  = {
                { "Name",          "s",  NULL,          offsetof(MachineStatusInfo, name) },
                { "Class",         "s",  NULL,          offsetof(MachineStatusInfo, class) },
                { "Service",       "s",  NULL,          offsetof(MachineStatusInfo, service) },
                { "Unit",          "s",  NULL,          offsetof(MachineStatusInfo, unit) },
                { "RootDirectory", "s",  NULL,          offsetof(MachineStatusInfo, root_directory) },
                { "Leader",        "u",  NULL,          offsetof(MachineStatusInfo, leader) },
                { "Timestamp",     "t",  NULL,          offsetof(MachineStatusInfo, timestamp) },
                { "Id",            "ay", bus_map_id128, offsetof(MachineStatusInfo, id) },
                {}
        };

        MachineStatusInfo info = {};
        int r;

        assert(path);
        assert(new_line);

        r = bus_map_all_properties(bus,
                                   "org.freedesktop.machine1",
                                   path,
                                   map,
                                   &info);
        if (r < 0) {
                log_error("Could not get properties: %s", strerror(-r));
                return r;
        }

        if (*new_line)
                printf("\n");
        *new_line = true;

        print_machine_status_info(bus, &info);

        free(info.name);
        free(info.class);
        free(info.service);
        free(info.unit);
        free(info.root_directory);

        return r;
}

static int show_properties(sd_bus *bus, const char *path, bool *new_line) {
        int r;

        if (*new_line)
                printf("\n");

        *new_line = true;

        r = bus_print_all_properties(bus, "org.freedesktop.machine1", path, arg_property, arg_all);
        if (r < 0)
                log_error("Could not get properties: %s", strerror(-r));

        return r;
}

static int show(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r = 0;
        unsigned i;
        bool properties, new_line = false;

        assert(bus);
        assert(args);

        properties = !strstr(args[0], "status");

        pager_open_if_enabled();

        if (properties && n <= 1) {

                /* If no argument is specified, inspect the manager
                 * itself */
                r = show_properties(bus, "/org/freedesktop/machine1", &new_line);
                if (r < 0)
                        return r;
        }

        for (i = 1; i < n; i++) {
                const char *path = NULL;

                r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.machine1",
                                        "/org/freedesktop/machine1",
                                        "org.freedesktop.machine1.Manager",
                                        "GetMachine",
                                        &error,
                                        &reply,
                                        "s", args[i]);
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
                        r = show_info(args[0], bus, path, &new_line);
        }

        return r;
}

static int kill_machine(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned i;

        assert(args);

        if (!arg_kill_who)
                arg_kill_who = "all";

        for (i = 1; i < n; i++) {
                int r;

                r = sd_bus_call_method(
                                        bus,
                                        "org.freedesktop.machine1",
                                        "/org/freedesktop/machine1",
                                        "org.freedesktop.machine1.Manager",
                                        "KillMachine",
                                        &error,
                                        NULL,
                                        "ssi", args[i], arg_kill_who, arg_signal);
                if (r < 0) {
                        log_error("Could not kill machine: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int reboot_machine(sd_bus *bus, char **args, unsigned n) {
        arg_kill_who = "leader";
        arg_signal = SIGINT; /* sysvinit + systemd */

        return kill_machine(bus, args, n);
}

static int poweroff_machine(sd_bus *bus, char **args, unsigned n) {
        arg_kill_who = "leader";
        arg_signal = SIGRTMIN+4; /* only systemd */

        return kill_machine(bus, args, n);
}

static int terminate_machine(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned i;

        assert(args);

        for (i = 1; i < n; i++) {
                int r;

                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "TerminateMachine",
                                &error,
                                NULL,
                                "s", args[i]);
                if (r < 0) {
                        log_error("Could not terminate machine: %s", bus_error_message(&error, -r));
                        return r;
                }
        }

        return 0;
}

static int openpt_in_namespace(pid_t pid, int flags) {
        _cleanup_close_pair_ int pair[2] = { -1, -1 };
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, rootfd = -1;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        int master = -1, r;
        pid_t child;
        siginfo_t si;

        r = namespace_open(pid, &pidnsfd, &mntnsfd, NULL, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
                return -errno;

        child = fork();
        if (child < 0)
                return -errno;

        if (child == 0) {
                pair[0] = safe_close(pair[0]);

                r = namespace_enter(pidnsfd, mntnsfd, -1, rootfd);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                master = posix_openpt(flags);
                if (master < 0)
                        _exit(EXIT_FAILURE);

                cmsg = CMSG_FIRSTHDR(&mh);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), &master, sizeof(int));

                mh.msg_controllen = cmsg->cmsg_len;

                if (sendmsg(pair[1], &mh, MSG_NOSIGNAL) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = wait_for_terminate(child, &si);
        if (r < 0)
                return r;
        if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS)
                return -EIO;

        if (recvmsg(pair[0], &mh, MSG_NOSIGNAL|MSG_CMSG_CLOEXEC) < 0)
                return -errno;

        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                        int *fds;
                        unsigned n_fds;

                        fds = (int*) CMSG_DATA(cmsg);
                        n_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                        if (n_fds != 1) {
                                close_many(fds, n_fds);
                                return -EIO;
                        }

                        master = fds[0];
                }

        if (master < 0)
                return -EIO;

        return master;
}

static int login_machine(sd_bus *bus, char **args, unsigned n) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL, *reply2 = NULL, *reply3 = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *container_bus = NULL;
        _cleanup_close_ int master = -1;
        _cleanup_free_ char *getty = NULL;
        const char *path, *pty, *p;
        uint32_t leader;
        sigset_t mask;
        int r;

        assert(bus);
        assert(args);

        if (arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Login only supported on local machines.");
                return -ENOTSUP;
        }

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "GetMachine",
                        &error,
                        &reply,
                        "s", args[1]);
        if (r < 0) {
                log_error("Could not get path to machine: %s", bus_error_message(&error, -r));
                return r;
        }

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.machine1",
                        path,
                        "org.freedesktop.machine1.Machine",
                        "Leader",
                        &error,
                        &reply2,
                        "u");
        if (r < 0) {
                log_error("Failed to retrieve PID of leader: %s", strerror(-r));
                return r;
        }

        r = sd_bus_message_read(reply2, "u", &leader);
        if (r < 0)
                return bus_log_parse_error(r);

        master = openpt_in_namespace(leader, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NDELAY);
        if (master < 0) {
                log_error("Failed to acquire pseudo tty: %s", strerror(-master));
                return master;
        }

        pty = ptsname(master);
        if (!pty) {
                log_error("Failed to get pty name: %m");
                return -errno;
        }

        p = startswith(pty, "/dev/pts/");
        if (!p) {
                log_error("Invalid pty name %s.", pty);
                return -EIO;
        }

        r = sd_bus_open_system_container(&container_bus, args[1]);
        if (r < 0) {
                log_error("Failed to get container bus: %s", strerror(-r));
                return r;
        }

        getty = strjoin("container-getty@", p, ".service", NULL);
        if (!getty)
                return log_oom();

        if (unlockpt(master) < 0) {
                log_error("Failed to unlock tty: %m");
                return -errno;
        }

        r = sd_bus_call_method(container_bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "StartUnit",
                               &error, &reply3,
                               "ss", getty, "replace");
        if (r < 0) {
                log_error("Failed to start getty service: %s", bus_error_message(&error, r));
                return r;
        }

        container_bus = sd_bus_unref(container_bus);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGWINCH, SIGTERM, SIGINT, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        log_info("Connected to container %s. Press ^] three times within 1s to exit session.", args[1]);

        r = process_pty(master, &mask, 0, 0);
        if (r < 0) {
                log_error("Failed to process pseudo tty: %s", strerror(-r));
                return r;
        }

        fputc('\n', stdout);

        log_info("Connection to container %s terminated.", args[1]);

        return 0;
}

static int help(void) {

        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Send control commands to or query the virtual machine and container registration manager.\n\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-legend         Do not show the headers and footers\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n"
               "  -M --machine=CONTAINER Operate on local container\n"
               "  -p --property=NAME     Show only properties by this name\n"
               "  -a --all               Show all properties, including empty ones\n"
               "  -l --full              Do not ellipsize output\n"
               "     --kill-who=WHO      Who to send signal to\n"
               "  -s --signal=SIGNAL     Which signal to send\n\n"
               "Commands:\n"
               "  list                   List running VMs and containers\n"
               "  status NAME...         Show VM/container status\n"
               "  show NAME...           Show properties of one or more VMs/containers\n"
               "  login NAME             Get a login prompt on a container\n"
               "  poweroff NAME...       Power off one or more containers\n"
               "  reboot NAME...         Reboot one or more containers\n"
               "  kill NAME...           Send signal to processes of a VM/container\n"
               "  terminate NAME...      Terminate one or more VMs/containers\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_KILL_WHO,
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
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp:als:H:M:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

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
                        arg_transport = BUS_TRANSPORT_CONTAINER;
                        arg_host = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        return 1;
}

static int machinectl_main(sd_bus *bus, int argc, char *argv[]) {

        static const struct {
                const char* verb;
                const enum {
                        MORE,
                        LESS,
                        EQUAL
                } argc_cmp;
                const int argc;
                int (* const dispatch)(sd_bus *bus, char **args, unsigned n);
        } verbs[] = {
                { "list",                  LESS,   1, list_machines     },
                { "status",                MORE,   2, show              },
                { "show",                  MORE,   1, show              },
                { "terminate",             MORE,   2, terminate_machine },
                { "reboot",                MORE,   2, reboot_machine    },
                { "poweroff",              MORE,   2, poweroff_machine  },
                { "kill",                  MORE,   2, kill_machine      },
                { "login",                 MORE,   2, login_machine     },
        };

        int left;
        unsigned i;

        assert(argc >= 0);
        assert(argv);

        left = argc - optind;

        if (left <= 0)
                /* Special rule: no arguments means "list" */
                i = 0;
        else {
                if (streq(argv[optind], "help")) {
                        help();
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(verbs); i++)
                        if (streq(argv[optind], verbs[i].verb))
                                break;

                if (i >= ELEMENTSOF(verbs)) {
                        log_error("Unknown operation %s", argv[optind]);
                        return -EINVAL;
                }
        }

        switch (verbs[i].argc_cmp) {

        case EQUAL:
                if (left != verbs[i].argc) {
                        log_error("Invalid number of arguments.");
                        return -EINVAL;
                }

                break;

        case MORE:
                if (left < verbs[i].argc) {
                        log_error("Too few arguments.");
                        return -EINVAL;
                }

                break;

        case LESS:
                if (left > verbs[i].argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                break;

        default:
                assert_not_reached("Unknown comparison operator.");
        }

        return verbs[i].dispatch(bus, argv + optind, left);
}

int main(int argc, char*argv[]) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = bus_open_transport(arg_transport, arg_host, false, &bus);
        if (r < 0) {
                log_error("Failed to create bus connection: %s", strerror(-r));
                goto finish;
        }

        r = machinectl_main(bus, argc, argv);

finish:
        pager_close();

        strv_free(arg_property);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
