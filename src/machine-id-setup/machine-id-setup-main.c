/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "dissect-image.h"
#include "dlopen-note.h"
#include "escape.h"
#include "id128-util.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "machine-id-setup.h"
#include "main-func.h"
#include "mount-util.h"
#include "parse-argument.h"
#include "string-util.h"
#include "verbs.h"

static char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_commit = false;
static bool arg_print = false;
static bool arg_force = false;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

COMMAND(
        "systemd-machine-id-setup\0",
        "Initialize /etc/machine-id from a random source.",
        .man_pages = "systemd-machine-id-setup(1)\0",
);

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_GROUP("Commands"): {}

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("commit", NULL, "Commit transient ID"):
                        arg_commit = true;
                        break;

                OPTION_GROUP("Options"): {}

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("print", NULL, "Print used machine ID"):
                        arg_print = true;
                        break;

                OPTION_LONG("force", NULL, "Generate a new ID, even if one is already set"):
                        arg_force = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Extraneous arguments");

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_commit && arg_force)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify either --commit or --force, "
                                       "the combination of both is not supported.");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        LIBBLKID_NOTE(recommended);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(suggested);
        LIBMOUNT_NOTE(recommended);
        TPM2_NOTE(suggested);

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_free_ char *user_root_option = NULL;

        /* Remember what the caller actually passed, for the --force hint further down: arg_root is
         * overwritten with the private mount below when --image= is used, and that path is gone once we
         * exit, so it must not end up in hints. The hint is offered for copy-paste into a root shell, so
         * quote the path rather than splicing an arbitrary byte string into a command line. */
        if (arg_force && (arg_image || arg_root)) {
                _cleanup_free_ char *quoted = NULL;

                quoted = shell_maybe_quote(arg_image ?: arg_root, SHELL_ESCAPE_POSIX);
                if (!quoted)
                        return log_oom();

                user_root_option = strjoin(arg_image ? " --image=" : " --root=", quoted);
                if (!user_root_option)
                        return log_oom();
        }

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
                /* The ID is explicitly marked as "uninitialized", which carries no identity that could have
                 * been duplicated by cloning, and doubles as the first boot marker. Leave it alone, even
                 * with --force: overriding it here would silently cancel first boot initialization. Say so,
                 * so that --force is not silently a no-op. */
                /* Repeat whatever --root=/--image= the caller gave us, so that the hint cannot be
                 * copy-pasted into reprovisioning the host by accident. */
                if (arg_force)
                        log_notice("Machine ID is marked 'uninitialized', which doubles as the first "
                                   "boot marker, leaving it as it is. "
                                   "To assign one anyway use "
                                   "'systemd-firstboot%s --force --setup-machine-id', "
                                   "but note it writes the file directly: none of the checks --force makes "
                                   "apply, and stale copies in /run/machine-id and /var/lib/dbus/machine-id "
                                   "are left as they are.",
                                   strempty(user_root_option));

                if (arg_print)
                        puts("uninitialized");
        } else {
                sd_id128_t id;

                r = machine_id_setup(arg_root, SD_ID128_NULL,
                                     arg_force ? MACHINE_ID_SETUP_FORCE_NEW : 0,
                                     &id);
                if (r < 0)
                        return r;

                if (arg_print)
                        puts(SD_ID128_TO_STRING(id));
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
