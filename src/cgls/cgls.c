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
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>

#include "cgroup-show.h"
#include "cgroup-util.h"
#include "log.h"
#include "path-util.h"
#include "util.h"
#include "pager.h"
#include "build.h"
#include "output-mode.h"
#include "fileio.h"
#include "sd-bus.h"
#include "bus-util.h"
#include "bus-error.h"
#include "unit-name.h"

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
               "  -M --machine        Show container\n"
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
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

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

int main(int argc, char *argv[]) {
        int r = 0, retval = EXIT_FAILURE;
        int output_flags;
        _cleanup_free_ char *root = NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (!arg_no_pager) {
                r = pager_open(false);
                if (r > 0) {
                        if (arg_full == -1)
                                arg_full = true;
                }
        }

        output_flags =
                arg_all * OUTPUT_SHOW_ALL |
                (arg_full > 0) * OUTPUT_FULL_WIDTH;

        r = bus_open_transport(BUS_TRANSPORT_LOCAL, NULL, false, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

        if (optind < argc) {
                int i;

                for (i = optind; i < argc; i++) {
                        int q;

                        fprintf(stdout, "%s:\n", argv[i]);
                        fflush(stdout);

                        if (arg_machine)
                                root = strjoin("machine/", arg_machine, "/", argv[i], NULL);
                        else
                                root = strdup(argv[i]);
                        if (!root)
                                return log_oom();

                        q = show_cgroup_by_path(root, NULL, 0,
                                                arg_kernel_threads, output_flags);
                        if (q < 0)
                                r = q;
                }

        } else {
                _cleanup_free_ char *p;

                p = get_current_dir_name();
                if (!p) {
                        log_error_errno(errno, "Cannot determine current working directory: %m");
                        goto finish;
                }

                if (path_startswith(p, "/sys/fs/cgroup") && !arg_machine) {
                        printf("Working Directory %s:\n", p);
                        r = show_cgroup_by_path(p, NULL, 0,
                                                arg_kernel_threads, output_flags);
                } else {
                        if (arg_machine) {
                                char *m;
                                const char *cgroup;
                                _cleanup_free_ char *scope = NULL;
                                _cleanup_free_ char *path = NULL;
                                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;

                                m = strjoina("/run/systemd/machines/", arg_machine);
                                r = parse_env_file(m, NEWLINE, "SCOPE", &scope, NULL);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to get machine path: %m");
                                        goto finish;
                                }

                                path = unit_dbus_path_from_name(scope);
                                if (!path) {
                                        log_oom();
                                        goto finish;
                                }

                                r = sd_bus_get_property(
                                                bus,
                                                "org.freedesktop.systemd1",
                                                path,
                                                "org.freedesktop.systemd1.Scope",
                                                "ControlGroup",
                                                &error,
                                                &reply,
                                                "s");

                                if (r < 0) {
                                        log_error("Failed to query ControlGroup: %s", bus_error_message(&error, -r));
                                        goto finish;
                                }

                                r = sd_bus_message_read(reply, "s", &cgroup);
                                if (r < 0) {
                                        bus_log_parse_error(r);
                                        goto finish;
                                }

                                root = strdup(cgroup);
                                if (!root) {
                                        log_oom();
                                        goto finish;
                                }

                        } else
                                r = cg_get_root_path(&root);
                        if (r < 0) {
                                log_error_errno(r, "Failed to get %s path: %m",
                                                arg_machine ? "machine" : "root");
                                goto finish;
                        }

                        r = show_cgroup(SYSTEMD_CGROUP_CONTROLLER, root, NULL, 0,
                                        arg_kernel_threads, output_flags);
                }
        }

        if (r < 0) {
                log_error_errno(r, "Failed to list cgroup tree %s: %m", root);
                retval = EXIT_FAILURE;
        } else
                retval = EXIT_SUCCESS;

finish:
        pager_close();

        return retval;
}
