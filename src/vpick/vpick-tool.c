/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <getopt.h>

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "vpick.h"

typedef enum {
        PRINT_PATH,
        PRINT_FILENAME,
        PRINT_VERSION,
        PRINT_TYPE,
        PRINT_ARCHITECTURE,
        PRINT_TRIES,
        PRINT_ALL,
        _PRINT_MAX,
        _PRINT_INVALID = -EINVAL,
} Print;

static char *arg_filter_basename = NULL;
static char *arg_filter_version = NULL;
static Architecture arg_filter_architecture = _ARCHITECTURE_INVALID;
static char *arg_filter_suffix = NULL;
static uint32_t arg_filter_type_mask = 0;
static Print arg_print = _PRINT_INVALID;
static PickFlags arg_flags = PICK_ARCHITECTURE|PICK_TRIES;

STATIC_DESTRUCTOR_REGISTER(arg_filter_basename, freep);
STATIC_DESTRUCTOR_REGISTER(arg_filter_version, freep);
STATIC_DESTRUCTOR_REGISTER(arg_filter_suffix, freep);

static const char *print_table[_PRINT_MAX] = {
        [PRINT_PATH]         = "path",
        [PRINT_FILENAME]     = "filename",
        [PRINT_VERSION]      = "version",
        [PRINT_TYPE]         = "type",
        [PRINT_ARCHITECTURE] = "architecture",
        [PRINT_TRIES]        = "tries",
        [PRINT_ALL]          = "all",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(print, Print);

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
               "  -p --print=filename  Print selected filename rather than path\n"
               "  -p --print=version   Print selected version rather than path\n"
               "  -p --print=type      Print selected inode type rather than path\n"
               "  -p --print=arch      Print selected architecture rather than path\n"
               "  -p --print=tries     Print selected tries left/tries done rather than path\n"
               "  -p --print=all       Print all of the above\n"
               "     --resolve=yes     Canonicalize the result path\n"
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
                ARG_RESOLVE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'          },
                { "version",      no_argument,       NULL, ARG_VERSION  },
                { "basename",     required_argument, NULL, 'B'          },
                { "suffix",       required_argument, NULL, 'S'          },
                { "type",         required_argument, NULL, 't'          },
                { "print",        required_argument, NULL, 'p'          },
                { "resolve",      required_argument, NULL, ARG_RESOLVE  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hB:V:A:S:t:p:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'B':
                        if (!filename_part_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid basename string: %s", optarg);

                        r = free_and_strdup_warn(&arg_filter_basename, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 'V':
                        if (!version_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid version string: %s", optarg);

                        r = free_and_strdup_warn(&arg_filter_version, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 'A':
                        if (streq(optarg, "native"))
                                arg_filter_architecture = native_architecture();
                        else if (streq(optarg, "secondary")) {
#ifdef ARCHITECTURE_SECONDARY
                                arg_filter_architecture = ARCHITECTURE_SECONDARY;
#else
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Local architecture has no secondary architecture.");
#endif
                        } else if (streq(optarg, "uname"))
                                arg_filter_architecture = uname_architecture();
                        else if (streq(optarg, "auto"))
                                arg_filter_architecture = _ARCHITECTURE_INVALID;
                        else {
                                arg_filter_architecture = architecture_from_string(optarg);
                                if (arg_filter_architecture < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown architecture: %s", optarg);
                        }
                        break;

                case 'S':
                        if (!filename_part_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid suffix string: %s", optarg);

                        r = free_and_strdup_warn(&arg_filter_suffix, optarg);
                        if (r < 0)
                                return r;

                        break;

                case 't':
                        if (isempty(optarg))
                                arg_filter_type_mask = 0;
                        else {
                                mode_t m;

                                m = inode_type_from_string(optarg);
                                if (m == MODE_INVALID)
                                        return log_error_errno(m, "Unknown inode type: %s", optarg);

                                arg_filter_type_mask |= UINT32_C(1) << IFTODT(m);
                        }

                        break;

                case 'p':
                        if (streq(optarg, "arch")) /* accept abbreviation too */
                                arg_print = PRINT_ARCHITECTURE;
                        else
                                arg_print = print_from_string(optarg);
                        if (arg_print < 0)
                                        return log_error_errno(arg_print, "Unknown --print= argument: %s", optarg);

                        break;

                case ARG_RESOLVE:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --resolve= value: %m");

                        SET_FLAG(arg_flags, PICK_RESOLVE, r);
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (arg_print < 0)
                arg_print = PRINT_PATH;

        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path to resolve must be specified.");

        for (int i = optind; i < argc; i++) {
                _cleanup_free_ char *p = NULL;
                r = path_make_absolute_cwd(argv[i], &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path '%s' absolute: %m", argv[i]);

                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              p,
                              &(PickFilter) {
                                      .basename = arg_filter_basename,
                                      .version = arg_filter_version,
                                      .architecture = arg_filter_architecture,
                                      .suffix = arg_filter_suffix,
                                      .type_mask = arg_filter_type_mask,
                              },
                              /* n_filters= */ 1,
                              arg_flags,
                              &result);
                if (r < 0)
                        return log_error_errno(r, "Failed to pick version for '%s': %m", p);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No matching version for '%s' found.", p);

                switch (arg_print) {

                case PRINT_PATH:
                        fputs(result.path, stdout);
                        if (result.st.st_mode != MODE_INVALID && S_ISDIR(result.st.st_mode) && !endswith(result.path, "/"))
                                fputc('/', stdout);
                        fputc('\n', stdout);
                        break;

                case PRINT_FILENAME: {
                        _cleanup_free_ char *fname = NULL;

                        r = path_extract_filename(result.path, &fname);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from path '%s': %m", result.path);

                        puts(fname);
                        break;
                }

                case PRINT_VERSION:
                        if (!result.version)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No version information discovered.");

                        puts(result.version);
                        break;

                case PRINT_TYPE:
                        if (result.st.st_mode == MODE_INVALID)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No inode type information discovered.");

                        puts(inode_type_to_string(result.st.st_mode));
                        break;

                case PRINT_ARCHITECTURE:
                        if (result.architecture < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No architecture information discovered.");

                        puts(architecture_to_string(result.architecture));
                        break;

                case PRINT_TRIES:
                        if (result.tries_left == UINT_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No tries left/tries done information discovered.");

                        printf("+%u-%u", result.tries_left, result.tries_done);
                        break;

                case PRINT_ALL: {
                        _cleanup_(table_unrefp) Table *t = NULL;

                        t = table_new_vertical();
                        if (!t)
                                return log_oom();

                        table_set_ersatz_string(t, TABLE_ERSATZ_NA);

                        r = table_add_many(
                                        t,
                                        TABLE_FIELD, "Path",
                                        TABLE_PATH, result.path,
                                        TABLE_FIELD, "Version",
                                        TABLE_STRING, result.version,
                                        TABLE_FIELD, "Type",
                                        TABLE_STRING, result.st.st_mode == MODE_INVALID ? NULL : inode_type_to_string(result.st.st_mode),
                                        TABLE_FIELD, "Architecture",
                                        TABLE_STRING, result.architecture < 0 ? NULL : architecture_to_string(result.architecture));
                        if (r < 0)
                                return table_log_add_error(r);

                        if (result.tries_left != UINT_MAX) {
                                r = table_add_many(
                                                t,
                                                TABLE_FIELD, "Tries left",
                                                TABLE_UINT, result.tries_left,
                                                TABLE_FIELD, "Tries done",
                                                TABLE_UINT, result.tries_done);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }

                        r = table_print(t, stdout);
                        if (r < 0)
                                return table_log_print_error(r);

                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
