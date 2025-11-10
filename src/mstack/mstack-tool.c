/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include "argv-util.h"
#include "build.h"
#include "chase.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-table.h"
#include "image-policy.h"
#include "main-func.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "string-util.h"

static enum {
        ACTION_INSPECT,
        ACTION_MOUNT,
        ACTION_UMOUNT,
} arg_action = ACTION_INSPECT;
static char *arg_what = NULL;
static char *arg_where = NULL;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static int arg_legend = true;
static MStackFlags arg_mstack_flags = 0;
static bool arg_rmdir = false;
static ImagePolicy *arg_image_policy = NULL;
static ImageFilter *arg_image_filter = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_where, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_filter, image_filter_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-mstack", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] WHAT\n"
               "%1$s [OPTIONS...] --mount WHAT WHERE\n"
               "%1$s [OPTIONS...] --umount WHERE\n"
               "\n%5$sInspect or apply mount stack.%6$s\n\n"
               "%3$sOptions:%4$s\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --no-legend              Do not print the column headers\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               "  -r --read-only              Mount read-only\n"
               "     --mkdir                  Make mount directory before mounting, if missing\n"
               "     --rmdir                  Remove mount directory after unmounting\n"
               "     --image-policy=POLICY\n"
               "                              Specify image dissection policy\n"
               "     --image-filter=FILTER\n"
               "                              Specify image dissection filter\n"
               "\n%3$sCommands:%4$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Show package version\n"
               "  -m --mount                  Mount the mstack to the specified directory\n"
               "  -M                          Shortcut for --mount --mkdir\n"
               "  -u --umount                 Unmount the image from the specified directory\n"
               "  -U                          Shortcut for --umount --rmdir\n"
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
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_JSON,
                ARG_MKDIR,
                ARG_RMDIR,
                ARG_IMAGE_POLICY,
                ARG_IMAGE_FILTER,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND    },
                { "mount",        no_argument,       NULL, 'm'              },
                { "umount",       no_argument,       NULL, 'u'              },
                { "json",         required_argument, NULL, ARG_JSON         },
                { "read-only",    no_argument,       NULL, 'r'              },
                { "rmdir",        no_argument,       NULL, ARG_RMDIR        },
                { "image-policy", required_argument, NULL, ARG_IMAGE_POLICY },
                { "image-filter", required_argument, NULL, ARG_IMAGE_FILTER },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hmMuUr", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case 'r':
                        arg_mstack_flags |= MSTACK_RDONLY;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_FILTER: {
                        _cleanup_(image_filter_freep) ImageFilter *f = NULL;
                        r = image_filter_parse(optarg, &f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse image filter expression: %s", optarg);

                        image_filter_free(arg_image_filter);
                        arg_image_filter = TAKE_PTR(f);
                        break;
                }

                case ARG_MKDIR:
                        arg_mstack_flags |= MSTACK_MKDIR;
                        break;

                case ARG_RMDIR:
                        arg_rmdir = true;
                        break;

                case 'm':
                        arg_action = ACTION_MOUNT;
                        break;

                case 'M':
                        /* Shortcut combination of --mkdir + --mount */
                        arg_action = ACTION_MOUNT;
                        arg_mstack_flags |= MSTACK_MKDIR;
                        break;

                case 'u':
                        arg_action = ACTION_UMOUNT;
                        break;

                case 'U':
                        /* Shortcut combination of --rmdir + --umount */
                        arg_action = ACTION_UMOUNT;
                        arg_rmdir = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        switch (arg_action) {

        case ACTION_INSPECT:
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected one argument.");

                r = parse_path_argument(argv[optind], /* suppress_root= */ false, &arg_what);
                if (r < 0)
                        return r;

                break;

        case ACTION_MOUNT:
                if (optind + 2 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments.");

                r = parse_path_argument(argv[optind], /* suppress_root= */ false, &arg_what);
                if (r < 0)
                        return r;

                r = parse_path_argument(argv[optind+1], /* suppress_root= */ false, &arg_where);
                if (r < 0)
                        return r;

                break;

        case ACTION_UMOUNT:
                if (optind + 1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected one argument.");

                r = parse_path_argument(argv[optind], /* suppress_root= */ false, &arg_where);
                if (r < 0)
                        return r;

                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int parse_argv_as_mount_helper(int argc, char *argv[]) {
        const char *options = NULL;
        bool fake = false;
        int c, r;

        /* Implements util-linux "external helper" command line interface, as per mount(8) man page. */

        while ((c = getopt(argc, argv, "sfnvN:o:t:")) >= 0) {
                switch (c) {

                case 'f':
                        fake = true;
                        break;

                case 'o':
                        options = optarg;
                        break;

                case 't':
                        if (!streq(optarg, "mstack"))
                                log_debug("Unexpected file system type '%s', ignoring.", optarg);
                        break;

                case 's': /* sloppy mount options */
                case 'n': /* aka --no-mtab */
                case 'v': /* aka --verbose */
                        log_debug("Ignoring option -%c, not implemented.", c);
                        break;

                case 'N': /* aka --namespace= */
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Option -%c is not implemented, refusing.", c);

                case '?':
                        return -EINVAL;
                }
        }

        if (optind + 2 != argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected an image file path and target directory as only argument.");

        for (const char *p = options;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", EXTRACT_KEEP_QUOTE);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract mount option: %m");
                if (r == 0)
                        break;

                if (streq(word, "ro"))
                        SET_FLAG(arg_mstack_flags, MSTACK_RDONLY, true);
                else if (streq(word, "rw"))
                        SET_FLAG(arg_mstack_flags, MSTACK_RDONLY, false);
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unknown mount option '%s'.", word);
        }

        if (fake)
                return 0;

        r = parse_path_argument(argv[optind], /* suppress_root= */ false, &arg_what);
        if (r < 0)
                return r;

        r = parse_path_argument(argv[optind+1], /* suppress_root= */ false, &arg_where);
        if (r < 0)
                return r;

        arg_action = ACTION_MOUNT;
        return 1;
}

static int inspect_mstack(void) {
        _cleanup_(mstack_freep) MStack *mstack = NULL;
        int r;

        assert(arg_what);

        r = mstack_load(arg_what, /* dir_fd= */ -EBADF, &mstack);
        if (r < 0)
                return log_debug_errno(r, "Failed to load .mstack/ directory '%s': %m", arg_what);

        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("type", "name", "image", "what", "where", "sort");
        if (!t)
                return log_oom();

        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        FOREACH_ARRAY(m, mstack->mounts, mstack->n_mounts) {
                _cleanup_free_ char *w = NULL;
                r = fd_get_path(m->what_fd, &w);
                if (r < 0)
                        return log_error_errno(r, "Failed to get path of what file descriptor: %m");

                r = table_add_many(
                                t,
                                TABLE_STRING, mstack_mount_type_to_string(m->mount_type),
                                TABLE_STRING, m->what,
                                TABLE_STRING, image_type_to_string(m->image_type),
                                TABLE_PATH, w,
                                TABLE_PATH, m->where ?: ((mstack->root_mount && mstack->root_mount != m) ? "/usr" : "/"),
                                TABLE_STRING, m->sort_key);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int mount_mstack(void) {
        int r;

        assert(arg_what);
        assert(arg_where);

        r = mstack_apply(
                        arg_what,
                        /* dir_fd= */ -EBADF,
                        arg_where,
                        /* temp_mount_dir= */ NULL,  /* auto-create temporary directory */
                        /* userns_fd= */ -EBADF,
                        arg_image_policy,
                        arg_image_filter,
                        arg_mstack_flags,
                        /* ret_root_fd= */ NULL);
         if (r < 0)
                 return log_error_errno(r, "Failed to apply .mstack/ directory '%s': %m", arg_what);

         return 0;
}

static int umount_mstack(void) {
        int r;

        assert(arg_where);

        _cleanup_free_ char *canonical = NULL;
        _cleanup_close_ int fd = chase_and_open(arg_where, /* root= */ NULL, /* chase_flags= */ 0, O_DIRECTORY, &canonical);
        if (fd == -ENOTDIR)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "'%s' is not a directory", arg_where);
        if (fd < 0)
                return log_error_errno(fd, "Failed to resolve path '%s': %m", arg_where);

        r = is_mount_point_at(fd, /* path= */ NULL, /* flags= */ 0);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "'%s' is not a mount point", canonical);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", canonical);

        fd = safe_close(fd);

        r = umount_recursive(canonical, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unmount '%s': %m", canonical);

        if (arg_rmdir) {
                r = RET_NERRNO(rmdir(canonical));
                if (r < 0)
                        return log_error_errno(r, "Failed to remove mount directory '%s': %m", canonical);
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (invoked_as(argv, "mount.mstack"))
                r = parse_argv_as_mount_helper(argc, argv);
        else
                r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        switch (arg_action) {

        case ACTION_INSPECT:
                return inspect_mstack();

        case ACTION_MOUNT:
                return mount_mstack();

        case ACTION_UMOUNT:
                return umount_mstack();

        default:
                assert_not_reached();
        }
}

DEFINE_MAIN_FUNCTION(run);
