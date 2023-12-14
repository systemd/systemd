/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "hwdb-util.h"
#include "udevadm.h"

static const char *arg_test = NULL;
static const char *arg_root = NULL;
static const char *arg_hwdb_bin_dir = NULL;
static bool arg_update = false;
static bool arg_strict = false;

static int help(void) {
        printf("%s hwdb [OPTIONS]\n\n"
               "  -h --help            Print this message\n"
               "  -V --version         Print version of the program\n"
               "  -u --update          Update the hardware database\n"
               "  -s --strict          When updating, return non-zero exit value on any parsing error\n"
               "     --usr             Generate in " UDEVLIBEXECDIR " instead of /etc/udev\n"
               "  -t --test=MODALIAS   Query database and print result\n"
               "  -r --root=PATH       Alternative root path in the filesystem\n\n"
               "NOTE:\n"
               "The sub-command 'hwdb' is deprecated, and is left for backwards compatibility.\n"
               "Please use systemd-hwdb instead.\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_USR = 0x100,
        };

        static const struct option options[] = {
                { "update",  no_argument,       NULL, 'u'     },
                { "usr",     no_argument,       NULL, ARG_USR },
                { "strict",  no_argument,       NULL, 's'     },
                { "test",    required_argument, NULL, 't'     },
                { "root",    required_argument, NULL, 'r'     },
                { "version", no_argument,       NULL, 'V'     },
                { "help",    no_argument,       NULL, 'h'     },
                {}
        };

        int c;

        while ((c = getopt_long(argc, argv, "ust:r:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'u':
                        arg_update = true;
                        break;
                case ARG_USR:
                        arg_hwdb_bin_dir = UDEVLIBEXECDIR;
                        break;
                case 's':
                        arg_strict = true;
                        break;
                case 't':
                        arg_test = optarg;
                        break;
                case 'r':
                        arg_root = optarg;
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        return 1;
}

int hwdb_main(int argc, char *argv[], void *userdata) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (!arg_update && !arg_test)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Either --update or --test must be used.");

        log_notice("udevadm hwdb is deprecated. Use systemd-hwdb instead.");

        if (arg_update && !hwdb_bypass()) {
                r = hwdb_update(arg_root, arg_hwdb_bin_dir, arg_strict, true);
                if (r < 0)
                        return r;
        }

        if (arg_test)
                return hwdb_query(arg_test, NULL);

        return 0;
}
