/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "architecture.h"
#include "build.h"
#include "fs-util.h"
#include "main-func.h"
#include "path-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "vpick.h"

static char *arg_search_basename = NULL;
static char *arg_search_version = NULL;
static Architecture arg_search_architecture = _ARCHITECTURE_INVALID;
static char *arg_search_suffix = NULL;
static mode_t arg_search_mode = 0;
static enum {
        PRINT_PATH,
        PRINT_FILENAME,
        PRINT_VERSION,
        PRINT_ARCHITECTURE,
} arg_print = PRINT_PATH;

STATIC_DESTRUCTOR_REGISTER(arg_search_basename, freep);
STATIC_DESTRUCTOR_REGISTER(arg_search_version, freep);
STATIC_DESTRUCTOR_REGISTER(arg_search_suffix, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-vpick", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] PATH...\n"
               "\n%5$sPick entry from versioned directory.%6$s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "\n%3$sLookup Keys:%4$s\n"
               "  -B --basename=BASENAME\n"
               "                       Look for specified basename\n"
               "  -V VERSION           Look for specified version\n"
               "  -A ARCH              Look for specified architecture\n"
               "  -S --suffix=SUFFIX   Look for specified suffix\n"
               "  -t --type=TYPE       Look for specified inode type\n"
               "\n%3$sOutput:%4$s\n"
               "     --print=filename  Print selected filename rather than path\n"
               "     --print=basename  Print selected basename rather than path\n"
               "     --print=version   Print selected version rather than path\n"
               "     --print=arch      Print selected architecture rather than path\n"
               "     --print=suffix    Print selected suffix rather than path\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(), ansi_normal(),
               ansi_highlight(), ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_PRINT,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'          },
                { "version",      no_argument,       NULL, ARG_VERSION  },
                { "basename",     required_argument, NULL, 'B'          },
                { "suffix",       required_argument, NULL, 'S'          },
                { "print",        required_argument, NULL, ARG_PRINT    },
                { "type",         required_argument, NULL, 't'          },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hB:V:A:S:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'B':
                        if (!filename_part_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid basename string: %s", optarg);

                        r = free_and_strdup_warn(&arg_search_basename, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 'V':
                        if (!version_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid version string: %s", optarg);

                        r = free_and_strdup_warn(&arg_search_version, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 'A':
                        if (streq(optarg, "native"))
                                arg_search_architecture = native_architecture();
                        else if (streq(optarg, "secondary")) {
#ifdef ARCHITECTURE_SECONDARY
                                arg_search_architecture = ARCHITECTURE_SECONDARY;
#else
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Local architecture has no secondary architecture.");
#endif
                        } else if (streq(optarg, "uname"))
                                arg_search_architecture = uname_architecture();
                        else if (streq(optarg, "auto"))
                                arg_search_architecture = _ARCHITECTURE_INVALID;
                        else {
                                arg_search_architecture = architecture_from_string(optarg);
                                if (arg_search_architecture < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown architecture: %s", optarg);
                        }
                        break;

                case 'S':
                        if (!filename_part_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid suffix string: %s", optarg);

                        r = free_and_strdup_warn(&arg_search_suffix, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 't':
                        if (isempty(optarg))
                                arg_search_mode = 0;
                        else {
                                mode_t m;

                                m = inode_type_from_string(optarg);
                                if (m == MODE_INVALID)
                                        return log_error_errno(m, "Unknown inode type: %s", optarg);

                                arg_search_mode = m;
                        }

                        break;

                case ARG_PRINT:
                        if (streq(optarg, "path"))
                                arg_print = PRINT_PATH;
                        else if (streq(optarg, "filename"))
                                arg_print = PRINT_FILENAME;
                        else if (streq(optarg, "version"))
                                arg_print = PRINT_VERSION;
                        else if (STR_IN_SET(optarg, "arch", "architecture"))
                                arg_print = PRINT_ARCHITECTURE;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown --print= argument: %s", optarg);

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path to resolve must be specified.");

        for (int i = optind; i < argc; i++) {
                _cleanup_free_ char *p = NULL, *v = NULL, *found = NULL;
                Architecture a;
                mode_t m;

                r = path_make_absolute_cwd(argv[i], &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path '%s' absolute: %m", argv[i]);

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              p,
                              MODE_INVALID,
                              arg_search_basename,
                              arg_search_version,
                              arg_search_architecture,
                              arg_search_suffix,
                              &found,
                              /* inode_fd= */ NULL,
                              &m,
                              &v,
                              &a);
                if (r < 0)
                        return log_error_errno(r, "Failed to pick version for '%s': %m", p);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No version for '%s' found.", p);

                switch (arg_print) {

                case PRINT_PATH:
                        fputs(found, stdout);
                        if (S_ISDIR(m))
                                fputc('/', stdout);
                        fputc('\n', stdout);
                        break;

                case PRINT_FILENAME: {
                        _cleanup_free_ char *fname = NULL;

                        r = path_extract_filename(found, &fname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from path '%s': %m", found);

                        puts(fname);
                        break;
                }

                case PRINT_VERSION:
                        if (!v)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No version information discovered.");

                        puts(v);
                        break;

                case PRINT_ARCHITECTURE:
                        if (a < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No architecture information discovered.");

                        puts(architecture_to_string(a));
                        break;
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
