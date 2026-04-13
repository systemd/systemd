/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "format-table.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
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
        _cleanup_(table_unrefp) Table *lookup_keys = NULL, *output = NULL;
        int r;

        r = terminal_urlify_man("systemd-vpick", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&lookup_keys);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("Output", &output);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, lookup_keys, output);

        printf("%s [OPTIONS...] PATH...\n"
               "\n%sPick entry from versioned directory.%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        printf("\n%sLookup Keys:%s\n", ansi_underline(), ansi_normal());
        r = table_print_or_warn(lookup_keys);
        if (r < 0)
                return r;

        printf("\n%sOutput:%s\n", ansi_underline(), ansi_normal());
        r = table_print_or_warn(output);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION('B', "basename", "BASENAME", "Look for specified basename"):
                        if (!filename_part_is_valid(arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid basename string: %s", arg);

                        r = free_and_strdup_warn(&arg_filter_basename, arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_SHORT('V', "VERSION", "Look for specified version"):
                        if (!version_is_valid(arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid version string: %s", arg);

                        r = free_and_strdup_warn(&arg_filter_version, arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_SHORT('A', "ARCH", "Look for specified architecture"):
                        if (streq(arg, "native"))
                                arg_filter_architecture = native_architecture();
                        else if (streq(arg, "secondary")) {
#ifdef ARCHITECTURE_SECONDARY
                                arg_filter_architecture = ARCHITECTURE_SECONDARY;
#else
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Local architecture has no secondary architecture.");
#endif
                        } else if (streq(arg, "uname"))
                                arg_filter_architecture = uname_architecture();
                        else if (streq(arg, "auto"))
                                arg_filter_architecture = _ARCHITECTURE_INVALID;
                        else {
                                arg_filter_architecture = architecture_from_string(arg);
                                if (arg_filter_architecture < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown architecture: %s", arg);
                        }
                        break;

                OPTION('S', "suffix", "SUFFIX", "Look for specified suffix"):
                        if (!filename_part_is_valid(arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid suffix string: %s", arg);

                        r = free_and_strdup_warn(&arg_filter_suffix, arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION('t', "type", "TYPE", "Look for specified inode type"):
                        if (isempty(arg))
                                arg_filter_type_mask = 0;
                        else {
                                mode_t m;

                                m = inode_type_from_string(arg);
                                if (m == MODE_INVALID)
                                        return log_error_errno(m, "Unknown inode type: %s", arg);

                                arg_filter_type_mask |= UINT32_C(1) << IFTODT(m);
                        }

                        break;

                OPTION_GROUP("Output"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('p', "print", "WHAT",
                       "Print selected WHAT rather than path"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "filename",
                                  "... print selected filename"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "version",
                                  "... print selected version"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "type",
                                  "... print selected inode type"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "arch",
                                  "... print selected architecture"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "tries",
                                  "... print selected tries left/tries done"): {}
                OPTION_LONG_FLAGS(OPTION_HELP_ENTRY, "print", "all",
                                  "... print all of the above"):

                        if (streq(arg, "arch")) /* accept abbreviation too */
                                arg_print = PRINT_ARCHITECTURE;
                        else
                                arg_print = print_from_string(arg);
                        if (arg_print < 0)
                                return log_error_errno(arg_print, "Unknown --print= argument: %s", arg);

                        break;

                OPTION_LONG("resolve", "BOOL", "Canonicalize the result path"):
                        r = parse_boolean(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --resolve= value: %m");

                        SET_FLAG(arg_flags, PICK_RESOLVE, r);
                        break;
                }

        if (arg_print < 0)
                arg_print = PRINT_PATH;

        *ret_args = option_parser_get_args(&state);
        return 1;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (strv_isempty(args))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path to resolve must be specified.");

        STRV_FOREACH(i, args) {
                _cleanup_free_ char *p = NULL;
                r = path_make_absolute_cwd(*i, &p);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path '%s' absolute: %m", *i);

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

                        r = table_print_or_warn(t);
                        if (r < 0)
                                return r;

                        break;
                }

                default:
                        assert_not_reached();
                }
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
