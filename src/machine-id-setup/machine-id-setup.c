/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdio.h>

#include "alloc-util.h"
#include "build.h"
#include "dissect-image.h"
#include "id128-util.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "machine-id-util.h"
#include "main-func.h"
#include "mount-util.h"
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

#include "machine-id-setup.args.inc"

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-machine-id-setup", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%2$sInitialize /etc/machine-id from a random source.%4$s\n"
               "\n%3$sCommands:%4$s\n"
               OPTION_HELP_GENERATED_COMMANDS
               "\n%3$sOptions:%4$s\n"
               OPTION_HELP_GENERATED
               "\nSee the %5$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        log_setup();

        r = parse_argv_generated(argc, argv);
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
