/* SPDX-License-Identifier: LGPL-2.1+ */

#include <getopt.h>

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "hwdb-util.h"
#include "selinux-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"
#include "verbs.h"

static const char *arg_hwdb_bin_dir = NULL;
static const char *arg_root = NULL;
static bool arg_strict = false;

static int verb_query(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;
        const char *modalias;
        int r;

        assert(argc >= 2);
        assert(argv);

        modalias = argv[1];

        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return r;

        SD_HWDB_FOREACH_PROPERTY(hwdb, modalias, key, value)
                printf("%s=%s\n", key, value);

        return 0;
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

        printf("%s OPTIONS COMMAND\n\n"
               "Update or query the hardware database.\n\n"
               "  -h --help       Show this help\n"
               "     --version    Show package version\n"
               "  -s --strict     When updating, return non-zero exit value on any parsing error\n"
               "     --usr        Generate in " UDEVLIBEXECDIR " instead of /etc/udev\n"
               "  -r --root=PATH  Alternative root path in the filesystem\n\n"
               "Commands:\n"
               "  update          Update the hwdb database\n"
               "  query MODALIAS  Query database and print result\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

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

        while ((c = getopt_long(argc, argv, "ust:r:h", options, NULL)) >= 0)
                switch(c) {

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
                        assert_not_reached("Unknown option");
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

int main (int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        mac_selinux_init();

        r = hwdb_main(argc, argv);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
