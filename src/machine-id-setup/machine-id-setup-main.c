/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "build.h"
#include "dissect-image.h"
#include "id128-util.h"
#include "log.h"
#include "machine-id-setup.h"
#include "main-func.h"
#include "mount-util.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "terminal-util.h"

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
        int r;

        r = terminal_urlify_man("systemd-machine-id-setup", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n"
               "\n%2$sInitialize /etc/machine-id from a random source.%4$s\n"
               "\n%3$sCommands:%4$s\n"
               "     --commit               Commit transient ID\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               "     --image=PATH           Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY  Specify disk image dissection policy\n"
               "     --print                Print used machine ID\n"
               "\nSee the %5$s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_underline(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_COMMIT,
                ARG_PRINT,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "root",         required_argument, NULL, ARG_ROOT         },
                { "image",        required_argument, NULL, ARG_IMAGE        },
                { "image-policy", required_argument, NULL, ARG_IMAGE_POLICY },
                { "commit",       no_argument,       NULL, ARG_COMMIT       },
                { "print",        no_argument,       NULL, ARG_PRINT        },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_ROOT:
                        r = parse_path_argument(optarg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_COMMIT:
                        arg_commit = true;
                        break;

                case ARG_PRINT:
                        arg_print = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (optind < argc)
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

                r = machine_id_setup(arg_root, SD_ID128_NULL, /* flags = */ 0, &id);
                if (r < 0)
                        return r;

                if (arg_print)
                        puts(SD_ID128_TO_STRING(id));
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
