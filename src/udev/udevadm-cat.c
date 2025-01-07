/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>

#include "log.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "static-destruct.h"
#include "strv.h"
#include "udevadm.h"
#include "udevadm-util.h"

static char *arg_root = NULL;
static CatFlags arg_cat_flags = 0;
static bool arg_config = false;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("udevadm", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s cat [OPTIONS] [FILE...]\n"
               "\n%sShow udev rules files.%s\n\n"
               "  -h --help            Show this help\n"
               "  -V --version         Show package version\n"
               "     --root=PATH       Operate on an alternate filesystem root\n"
               "     --tldr            Skip comments and empty lines\n"
               "     --config          Show udev.conf rather than udev rules files\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_ROOT = 0x100,
                ARG_TLDR,
                ARG_CONFIG,
        };
        static const struct option options[] = {
                { "help",          no_argument,       NULL, 'h'             },
                { "version",       no_argument,       NULL, 'V'             },
                { "root",          required_argument, NULL, ARG_ROOT        },
                { "tldr",          no_argument,       NULL, ARG_TLDR        },
                { "config",        no_argument,       NULL, ARG_CONFIG      },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hVN:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();
                case 'V':
                        return print_version();
                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;
                case ARG_TLDR:
                        arg_cat_flags = CAT_TLDR;
                        break;
                case ARG_CONFIG:
                        arg_config = true;
                        break;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (arg_config && optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Combination of --config and FILEs is not supported.");

        return 1;
}

int cat_main(int argc, char *argv[], void *userdata) {
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_config)
                return conf_files_cat(arg_root, "udev/udev.conf", arg_cat_flags);

        _cleanup_strv_free_ char **files = NULL;
        r = search_rules_files(strv_skip(argv, optind), arg_root, &files);
        if (r < 0)
                return r;

        /* udev rules file does not support dropin configs. So, we can safely pass multiple files as dropins. */
        return cat_files(/* file = */ NULL, /* dropins = */ files, arg_cat_flags);
}
