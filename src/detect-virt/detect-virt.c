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

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>

#include "util.h"
#include "virt.h"
#include "build.h"

static bool arg_quiet = false;
static enum {
        ANY_VIRTUALIZATION,
        ONLY_VM,
        ONLY_CONTAINER
} arg_mode = ANY_VIRTUALIZATION;

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Detect execution in a virtualized environment.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "  -c --container        Only detect whether we are run in a container\n"
               "  -v --vm               Only detect whether we are run in a VM\n"
               "  -q --quiet            Don't output anything, just set return value\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100
        };

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "container", no_argument,       NULL, 'c'           },
                { "vm",        optional_argument, NULL, 'v'           },
                { "quiet",     no_argument,       NULL, 'q'           },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqcv", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'c':
                        arg_mode = ONLY_CONTAINER;
                        break;

                case 'v':
                        arg_mode = ONLY_VM;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
        }

        if (optind < argc) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        const char *id = NULL;
        int retval = EXIT_SUCCESS;
        int r;

        /* This is mostly intended to be used for scripts which want
         * to detect whether we are being run in a virtualized
         * environment or not */

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

        switch (arg_mode) {

        case ANY_VIRTUALIZATION: {
                int v;

                v = detect_virtualization(&id);
                if (v < 0) {
                        log_error("Failed to check for virtualization: %s", strerror(-v));
                        return EXIT_FAILURE;
                }

                retval = v != VIRTUALIZATION_NONE ? EXIT_SUCCESS : EXIT_FAILURE;
                break;
        }

        case ONLY_CONTAINER:
                r = detect_container(&id);
                if (r < 0) {
                        log_error("Failed to check for container: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                retval = r > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                break;

        case ONLY_VM:
                r = detect_vm(&id);
                if (r < 0) {
                        log_error("Failed to check for vm: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                retval = r > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
                break;
        }

        if (!arg_quiet)
                puts(id ? id : "none");

        return retval;
}
