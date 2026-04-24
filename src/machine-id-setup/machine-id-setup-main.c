/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "dissect-image.h"
#include "format-table.h"
#include "id128-util.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "machine-id-setup.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "parse-argument.h"
#include "pretty-print.h"

static char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_commit = false;
static bool arg_print = false;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *commands = NULL, *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-machine-id-setup", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&commands);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("Options", &options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, commands, options);

        printf("%s [OPTIONS...]\n\n"
               "%sInitialize /etc/machine-id from a random source.%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(commands);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("commit", NULL, "Commit transient ID"):
                        arg_commit = true;
                        break;

                OPTION_GROUP("Options"): {}

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(arg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("print", NULL, "Print used machine ID"):
                        arg_print = true;
                        break;
                }

        if (option_parser_get_n_args(&state) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_FSCK |
                                DISSECT_IMAGE_GROWFS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        if (arg_commit) {
                sd_id128_t id;

                r = machine_id_commit(arg_root);
                if (r < 0)
                        return r;

                r = id128_get_machine(arg_root, &id);
                if (r < 0)
                        return log_error_errno(r, "Failed to read machine ID back: %m");

                if (arg_print)
                        puts(SD_ID128_TO_STRING(id));

        } else if (id128_get_machine(arg_root, NULL) == -ENOPKG) {
                if (arg_print)
                        puts("uninitialized");
        } else {
                sd_id128_t id;

                r = machine_id_setup(arg_root, SD_ID128_NULL, /* flags= */ 0, &id);
                if (r < 0)
                        return r;

                if (arg_print)
                        puts(SD_ID128_TO_STRING(id));
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
