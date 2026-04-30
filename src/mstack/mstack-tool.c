/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "argv-util.h"
#include "build.h"
#include "chase.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-table.h"
#include "help-util.h"
#include "image-policy.h"
#include "main-func.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "options.h"
#include "parse-argument.h"
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
        _cleanup_(table_unrefp) Table *options = NULL, *commands = NULL;
        int r;

        r = option_parser_get_help_table_ns("systemd-mstack", &options);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_full("systemd-mstack", "Commands", &commands);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, options, commands);

        help_cmdline("[OPTIONS...] WHAT");
        help_cmdline("[OPTIONS...] --mount WHAT WHERE");
        help_cmdline("[OPTIONS...] --umount WHERE");
        help_abstract("Inspect or apply mount stack.");

        help_section("Commands:");
        r = table_print_or_warn(commands);
        if (r < 0)
                return r;

        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-mstack", "1");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "systemd-mstack" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_NAMESPACE("systemd-mstack"): {}

                OPTION('r', "read-only", NULL, "Mount read-only"):
                        arg_mstack_flags |= MSTACK_RDONLY;
                        break;

                OPTION_LONG("mkdir", NULL, "Make mount directory before mounting, if missing"):
                        arg_mstack_flags |= MSTACK_MKDIR;
                        break;

                OPTION_LONG("rmdir", NULL, "Remove mount directory after unmounting"):
                        arg_rmdir = true;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-filter", "FILTER", "Specify image dissection filter"): {
                        _cleanup_(image_filter_freep) ImageFilter *f = NULL;
                        r = image_filter_parse(opts.arg, &f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse image filter expression: %s", opts.arg);

                        image_filter_free(arg_image_filter);
                        arg_image_filter = TAKE_PTR(f);
                        break;
                }

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_GROUP("Commands"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('m', "mount", NULL, "Mount the mstack to the specified directory"):
                        arg_action = ACTION_MOUNT;
                        break;

                OPTION_SHORT('M', NULL, "Shortcut for --mount --mkdir"):
                        arg_action = ACTION_MOUNT;
                        arg_mstack_flags |= MSTACK_MKDIR;
                        break;

                OPTION('u', "umount", NULL, "Unmount the image from the specified directory"):
                        arg_action = ACTION_UMOUNT;
                        break;

                OPTION_SHORT('U', NULL, "Shortcut for --umount --rmdir"):
                        arg_action = ACTION_UMOUNT;
                        arg_rmdir = true;
                        break;
                }

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        switch (arg_action) {

        case ACTION_INSPECT:
                if (n_args != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected one argument.");

                r = parse_path_argument(args[0], /* suppress_root= */ false, &arg_what);
                if (r < 0)
                        return r;

                break;

        case ACTION_MOUNT:
                if (n_args != 2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments.");

                r = parse_path_argument(args[0], /* suppress_root= */ false, &arg_what);
                if (r < 0)
                        return r;

                r = parse_path_argument(args[1], /* suppress_root= */ false, &arg_where);
                if (r < 0)
                        return r;

                break;

        case ACTION_UMOUNT:
                if (n_args != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected one argument.");

                r = parse_path_argument(args[0], /* suppress_root= */ false, &arg_where);
                if (r < 0)
                        return r;

                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int parse_argv_as_mount_helper(int argc, char *argv[]) {
        const char *mount_options = NULL;
        bool fake = false;
        int r;

        /* Implements util-linux "external helper" command line interface, as per mount(8) man page. */

        OptionParser opts = { argc, argv, .namespace = "mount.mstack" };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_NAMESPACE("mount.mstack"): {}

                OPTION_SHORT('f', NULL, NULL):
                        fake = true;
                        break;

                OPTION_SHORT('o', "OPTIONS", NULL):
                        mount_options = opts.arg;
                        break;

                OPTION_SHORT('t', "TYPE", NULL):
                        if (!streq(opts.arg, "mstack"))
                                log_debug("Unexpected file system type '%s', ignoring.", opts.arg);
                        break;

                OPTION_SHORT('s', NULL, NULL): {} /* sloppy mount options, fall-through */
                OPTION_SHORT('n', NULL, NULL): {} /* aka --no-mtab, fall-through */
                OPTION_SHORT('v', NULL, NULL):    /* aka --verbose */
                        log_debug("Ignoring option -%c, not implemented.", opts.opt->short_code);
                        break;

                OPTION_SHORT('N', "NAMESPACE", NULL): /* aka --namespace= */
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Option -%c is not implemented, refusing.", opts.opt->short_code);
                }

        char **args = option_parser_get_args(&opts);
        if (option_parser_get_n_args(&opts) != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected an image file path and target directory as arguments.");

        for (const char *p = mount_options;;) {
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

        r = parse_path_argument(args[0], /* suppress_root= */ false, &arg_what);
        if (r < 0)
                return r;

        r = parse_path_argument(args[1], /* suppress_root= */ false, &arg_where);
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
                        /* mountfsd_link= */ NULL,
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
