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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cgroup-show.h"
#include "cgroup-util.h"
#include "fileio.h"
#include "log.h"
#include "output-mode.h"
#include "pager.h"
#include "path-util.h"
#include "unit-name.h"
#include "util.h"

static bool arg_no_pager = false;
static bool arg_kernel_threads = false;
static bool arg_all = false;
static int arg_full = -1;
static char* arg_machine = NULL;

static void help(void) {
        printf("%s [OPTIONS...] [CGROUP...]\n\n"
               "Recursively show control group contents.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "  -a --all            Show all groups, including empty\n"
               "  -l --full           Do not ellipsize output\n"
               "  -k                  Include kernel threads in output\n"
               "  -M --machine=       Show container\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_NO_PAGER = 0x100,
                ARG_VERSION,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'          },
                { "version",   no_argument,       NULL, ARG_VERSION  },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER },
                { "all",       no_argument,       NULL, 'a'          },
                { "full",      no_argument,       NULL, 'l'          },
                { "machine",   required_argument, NULL, 'M'          },
                {}
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hkalM:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case 'k':
                        arg_kernel_threads = true;
                        break;

                case 'M':
                        arg_machine = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int get_cgroup_root(char **ret) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        _cleanup_free_ char *unit = NULL, *path = NULL;
        const char *m;
        int r;

        if (!arg_machine) {
                r = cg_get_root_path(ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to get root control group path: %m");

                return 0;
        }

        m = strjoina("/run/systemd/machines/", arg_machine);
        r = parse_env_file(m, NEWLINE, "SCOPE", &unit, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to load machine data: %m");

        path = unit_dbus_path_from_name(unit);
        if (!path)
                return log_oom();

        r = bus_connect_transport_systemd(BUS_TRANSPORT_LOCAL, NULL, false, &bus);
        if (r < 0)
                return log_error_errno(r, "Failed to create bus connection: %m");

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        unit_dbus_interface_from_name(unit),
                        "ControlGroup",
                        &error,
                        ret);
        if (r < 0)
                return log_error_errno(r, "Failed to query unit control group path: %s", bus_error_message(&error, r));

        return 0;
}

static void show_cg_info(const char *controller, const char *path) {

        if (cg_unified() <= 0 && controller && !streq(controller, SYSTEMD_CGROUP_CONTROLLER))
                printf("Controller %s; ", controller);

        printf("Control group %s:\n", isempty(path) ? "/" : path);
        fflush(stdout);
}

int main(int argc, char *argv[]) {
        int r, output_flags;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (!arg_no_pager) {
                r = pager_open(false);
                if (r > 0 && arg_full < 0)
                        arg_full = true;
        }

        output_flags =
                arg_all * OUTPUT_SHOW_ALL |
                (arg_full > 0) * OUTPUT_FULL_WIDTH;

        if (optind < argc) {
                _cleanup_free_ char *root = NULL;
                int i;

                r = get_cgroup_root(&root);
                if (r < 0)
                        goto finish;

                for (i = optind; i < argc; i++) {
                        int q;

                        if (path_startswith(argv[i], "/sys/fs/cgroup")) {

                                printf("Directory %s:\n", argv[i]);
                                fflush(stdout);

                                q = show_cgroup_by_path(argv[i], NULL, 0, arg_kernel_threads, output_flags);
                        } else {
                                _cleanup_free_ char *c = NULL, *p = NULL, *j = NULL;
                                const char *controller, *path;

                                r = cg_split_spec(argv[i], &c, &p);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to split argument %s: %m", argv[i]);
                                        goto finish;
                                }

                                controller = c ?: SYSTEMD_CGROUP_CONTROLLER;
                                if (p) {
                                        j = strjoin(root, "/", p, NULL);
                                        if (!j) {
                                                r = log_oom();
                                                goto finish;
                                        }

                                        path_kill_slashes(j);
                                        path = j;
                                } else
                                        path = root;

                                show_cg_info(controller, path);

                                q = show_cgroup(controller, path, NULL, 0, arg_kernel_threads, output_flags);
                        }

                        if (q < 0)
                                r = q;
                }

        } else {
                bool done = false;

                if (!arg_machine)  {
                        _cleanup_free_ char *cwd = NULL;

                        cwd = get_current_dir_name();
                        if (!cwd) {
                                r = log_error_errno(errno, "Cannot determine current working directory: %m");
                                goto finish;
                        }

                        if (path_startswith(cwd, "/sys/fs/cgroup")) {
                                printf("Working directory %s:\n", cwd);
                                fflush(stdout);

                                r = show_cgroup_by_path(cwd, NULL, 0, arg_kernel_threads, output_flags);
                                done = true;
                        }
                }

                if (!done) {
                        _cleanup_free_ char *root = NULL;

                        r = get_cgroup_root(&root);
                        if (r < 0)
                                goto finish;

                        show_cg_info(SYSTEMD_CGROUP_CONTROLLER, root);

                        printf("-.slice\n");
                        r = show_cgroup(SYSTEMD_CGROUP_CONTROLLER, root, NULL, 0, arg_kernel_threads, output_flags);
                }
        }

        if (r < 0)
                log_error_errno(r, "Failed to list cgroup tree: %m");

finish:
        pager_close();

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
