/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>

#include "dissect-image.h"
#include "glyph-util.h"
#include "log.h"
#include "logs-show.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "stat-util.h"
#include "strv.h"
#include "systemctl-compat-halt.h"
#include "systemctl-logind.h"
#include "systemctl-util.h"
#include "systemctl.h"
#include "virt.h"

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        char **args = STRV_EMPTY;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = systemctl_dispatch_parse_argv(argc, argv, /* log_level_shift= */ 0, &args);
        if (r <= 0)
                goto finish;

        journal_browse_prepare();

        if (proc_mounted() == 0)
                log_full(arg_no_warn ? LOG_DEBUG : LOG_WARNING,
                         "%s%s/proc/ is not mounted. This is not a supported mode of operation. Please fix\n"
                         "your invocation environment to mount /proc/ and /sys/ properly. Proceeding anyway.\n"
                         "Your mileage may vary.",
                         optional_glyph(GLYPH_WARNING_SIGN),
                         optional_glyph(GLYPH_SPACE));

        if (arg_action != ACTION_SYSTEMCTL && running_in_chroot() > 0) {
                if (!arg_quiet)
                        log_info("Running in chroot, ignoring request.");
                r = 0;
                goto finish;
        }

        /* systemctl_main() will print an error message for the bus connection, but only if it needs to */

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_VALIDATE_OS |
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

        switch (arg_action) {

        case ACTION_SYSTEMCTL:
                r = systemctl_main(args);
                break;

        /* Legacy command aliases set arg_action. They provide some fallbacks, e.g. to tell sysvinit to
         * reboot after you have installed systemd binaries. */

        case ACTION_HALT:
        case ACTION_POWEROFF:
        case ACTION_REBOOT:
        case ACTION_KEXEC:
                r = halt_main();
                break;

        case ACTION_CANCEL_SHUTDOWN:
                r = logind_cancel_shutdown();
                break;

        case ACTION_SHOW_SHUTDOWN:
        case ACTION_SYSTEMCTL_SHOW_SHUTDOWN:
                r = logind_show_shutdown();
                break;

        case ACTION_RESCUE:
        case ACTION_RELOAD:
        case ACTION_REEXEC:
        case ACTION_EXIT:
        case ACTION_SLEEP:
        case ACTION_SUSPEND:
        case ACTION_HIBERNATE:
        case ACTION_HYBRID_SLEEP:
        case ACTION_SUSPEND_THEN_HIBERNATE:
        case ACTION_EMERGENCY:
        case ACTION_DEFAULT:
                /* systemctl verbs with no equivalent in the legacy commands. These cannot appear in
                 * arg_action. Fall through. */

        case _ACTION_INVALID:
        default:
                assert_not_reached();
        }

finish:
        release_busses();

        /* Note that we return r here, not 0, so that we can implement the LSB-like return codes */
        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
