/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "id128-util.h"
#include "log.h"
#include "machine-id-setup.h"
#include "main-func.h"
#include "path-util.h"
#include "pretty-print.h"
#include "util.h"

static char *arg_root = NULL;
static bool arg_commit = false;
static bool arg_print = false;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-machine-id-setup", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Initialize /etc/machine-id from a random source.\n\n"
               "  -h --help             Show this help\n"
               "     --version          Show package version\n"
               "     --root=ROOT        Filesystem root\n"
               "     --commit           Commit transient ID\n"
               "     --print            Print used machine ID\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum
        {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_COMMIT,
                ARG_PRINT,
        };

        static const struct option options[] = { { "help", no_argument, NULL, 'h' },
                                                 { "version", no_argument, NULL, ARG_VERSION },
                                                 { "root", required_argument, NULL, ARG_ROOT },
                                                 { "commit", no_argument, NULL, ARG_COMMIT },
                                                 { "print", no_argument, NULL, ARG_PRINT },
                                                 {} };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqcv", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

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

                case ARG_PRINT:
                        arg_print = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Extraneous arguments");

        return 1;
}

static int run(int argc, char *argv[]) {
        char buf[SD_ID128_STRING_MAX];
        sd_id128_t id;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_commit) {
                const char *etc_machine_id;

                r = machine_id_commit(arg_root);
                if (r < 0)
                        return r;

                etc_machine_id = prefix_roota(arg_root, "/etc/machine-id");
                r = id128_read(etc_machine_id, ID128_PLAIN, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to read machine ID back: %m");
        } else {
                r = machine_id_setup(arg_root, SD_ID128_NULL, &id);
                if (r < 0)
                        return r;
        }

        if (arg_print)
                puts(sd_id128_to_string(id, buf));

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
