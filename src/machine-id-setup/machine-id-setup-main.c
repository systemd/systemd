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
#include <stdlib.h>

#include "log.h"
#include "machine-id-setup.h"
#include "path-util.h"
#include "util.h"

static char *arg_root = NULL;
static bool arg_commit = false;

static void help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Initialize /etc/machine-id from a random source.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --root=ROOT        Filesystem root\n"
               "     --commit           Commit transient ID\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_COMMIT,
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "root",      required_argument, NULL, ARG_ROOT      },
                { "commit",    no_argument,       NULL, ARG_COMMIT    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqcv", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        r = parse_path_argument_and_warn(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_COMMIT:
                        arg_commit = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc) {
                log_error("Extraneous arguments");
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_commit)
                r = machine_id_commit(arg_root);
        else
                r = machine_id_setup(arg_root);

finish:
        free(arg_root);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
