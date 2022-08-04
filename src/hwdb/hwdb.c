/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "hwdb-util.h"
#include "main-func.h"
#include "pretty-print.h"
#include "selinux-util.h"
#include "terminal-util.h"
#include "util.h"
#include "verbs.h"

static const char *arg_hwdb_bin_dir = NULL;
static const char *arg_root = NULL;
static bool arg_strict = false;

static int verb_query(int argc, char *argv[], void *userdata) {
        return hwdb_query(argv[1], arg_root);
}

static int verb_update(int argc, char *argv[], void *userdata) {
        return hwdb_update(arg_root, arg_hwdb_bin_dir, arg_strict, false);
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-hwdb", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sUpdate or query the hardware database.%s\n"
               "\nCommands:\n"
               "  update          Update the hwdb database\n"
               "  query MODALIAS  Query database and print result\n"
               "\nOptions:\n"
               "  -h --help       Show this help\n"
               "     --version    Show package version\n"
               "  -s --strict     When updating, return non-zero exit value on any parsing error\n"
               "     --usr        Generate in " UDEVLIBEXECDIR " instead of /etc/udev\n"
               "  -r --root=PATH  Alternative root path in the filesystem\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_USR,
        };

        static const struct option options[] = {
                { "help",     no_argument,       NULL, 'h'         },
                { "version",  no_argument,       NULL, ARG_VERSION },
                { "usr",      no_argument,       NULL, ARG_USR     },
                { "strict",   no_argument,       NULL, 's'         },
                { "root",     required_argument, NULL, 'r'         },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "sr:h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_USR:
                        arg_hwdb_bin_dir = UDEVLIBEXECDIR;
                        break;

                case 's':
                        arg_strict = true;
                        break;

                case 'r':
                        arg_root = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int hwdb_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "update", 1, 1, 0, verb_update },
                { "query",  2, 2, 0, verb_query  },
                {},
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = mac_selinux_init();
        if (r < 0)
                return r;

        return hwdb_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
