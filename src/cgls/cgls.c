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

#include <limits.h>
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

static bool arg_no_pager = false;
static bool arg_kernel_threads = false;
static bool arg_all = false;

static void help(void) {

        printf("%s [OPTIONS...] [CGROUP...]\n\n"
               "Recursively show control group contents.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --no-pager       Do not pipe output into a pager\n"
               "  -a --all            Show all groups, including empty\n"
               "  -k                  Include kernel threads in output\n",
               program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_NO_PAGER = 0x100,
                ARG_VERSION
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'          },
                { "version",   no_argument,       NULL, ARG_VERSION  },
                { "no-pager",  no_argument,       NULL, ARG_NO_PAGER },
                { "all",       no_argument,       NULL, 'a'          },
                { NULL,        0,                 NULL, 0            }
        };

        int c;

        assert(argc >= 1);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hka", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 'k':
                        arg_kernel_threads = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r = 0, retval = EXIT_FAILURE;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto finish;
        else if (r == 0) {
                retval = EXIT_SUCCESS;
                goto finish;
        }

        if (!arg_no_pager)
                pager_open();

        if (optind < argc) {
                unsigned i;

                for (i = (unsigned) optind; i < (unsigned) argc; i++) {
                        int q;
                        printf("%s:\n", argv[i]);

                        q = show_cgroup_by_path(argv[i], NULL, 0, arg_kernel_threads, arg_all);
                        if (q < 0)
                                r = q;
                }

        } else {
                char _cleanup_free_ *p;

                p = get_current_dir_name();
                if (!p) {
                        log_error("Cannot determine current working directory: %m");
                        goto finish;
                }

                if (path_startswith(p, "/sys/fs/cgroup")) {
                        printf("Working Directory %s:\n", p);
                        r = show_cgroup_by_path(p, NULL, 0, arg_kernel_threads, arg_all);
                } else {
                        char _cleanup_free_ *root = NULL;
                        const char *t = NULL;

                        r = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 1, &root);
                        if (r < 0)
                                t = "/";
                        else {
                                if (endswith(root, "/system"))
                                        root[strlen(root)-7] = 0;

                                t = root[0] ? root : "/";
                        }

                        r = show_cgroup(SYSTEMD_CGROUP_CONTROLLER, t, NULL, 0, arg_kernel_threads, arg_all);
                }
        }

        if (r < 0)
                log_error("Failed to list cgroup tree: %s", strerror(-r));

        retval = EXIT_SUCCESS;

finish:
        pager_close();

        return retval;
}
