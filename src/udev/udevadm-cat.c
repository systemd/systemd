/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>

#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "log.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "static-destruct.h"
#include "strv.h"
#include "udevadm.h"

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
        int r, ret = 0;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_config)
                return conf_files_cat(arg_root, "udev/udev.conf", arg_cat_flags);

        if (optind >= argc) {
                _cleanup_strv_free_ char **files = NULL;

                r = conf_files_list_strv(&files, ".rules", arg_root, 0, (const char* const*) CONF_PATHS_STRV("udev/rules.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files: %m");

                if (arg_root && strv_isempty(files))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No rules files found in %s.", arg_root);

                /* udev rules file does not support dropin configs. So, we can safely pass multiple files as dropins. */
                return cat_files(/* file = */ NULL, /* dropins = */ files, arg_cat_flags);
        }

        bool needs_newline = false;
        STRV_FOREACH(s, strv_skip(argv, optind)) {
                if (needs_newline)
                        puts("");

                needs_newline = true;

                if (path_is_absolute(*s)) {
                        _cleanup_free_ char *resolved = NULL;

                        r = chase(*s, arg_root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd = */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to chase \"%s\": %m", *s);

                        if (!endswith(resolved, ".rules"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "File name must end with '.rules': %s", resolved);

                        r = cat_files(resolved, /* dropins = */ NULL, arg_cat_flags);
                        if (r < 0)
                                return r;

                } else {
                        _cleanup_free_ char *filename = NULL;

                        if (!endswith(*s, ".rules"))
                                filename = strjoin(*s, ".rules");
                        else
                                filename = strdup(*s);
                        if (!s)
                                return log_oom();

                        if (!filename_is_valid(filename))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid udev rules file name: %s", *s);

                        bool found = false;
                        STRV_FOREACH(p, CONF_PATHS_STRV("udev/rules.d")) {
                                _cleanup_free_ char *path = NULL, *resolved = NULL;

                                path = path_join(*p, filename);
                                if (!path)
                                        return log_oom();

                                r = chase(path, arg_root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd = */ NULL);
                                if (r == -ENOENT)
                                        continue;
                                if (r < 0)
                                        return log_error_errno(r, "Failed to chase \"%s\": %m", path);

                                r = cat_files(resolved, /* dropins = */ NULL, arg_cat_flags);
                                if (r < 0)
                                        return r;
                                found = true;
                                break;
                        }
                        if (!found)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Cannout find udev rules file: %s", filename);
                }
        }

        return ret;
}
