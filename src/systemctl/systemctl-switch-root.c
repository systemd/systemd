/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "chase.h"
#include "fd-util.h"
#include "initrd-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "systemctl.h"
#include "systemctl-switch-root.h"
#include "systemctl-util.h"

static int same_file_in_root(
                const char *root,
                const char *a,
                const char *b) {

        struct stat sta, stb;
        int r;

        r = chase_and_stat(a, root, CHASE_PREFIX_ROOT, NULL, &sta);
        if (r < 0)
                return r;

        r = chase_and_stat(b, root, CHASE_PREFIX_ROOT, NULL, &stb);
        if (r < 0)
                return r;

        return stat_inode_same(&sta, &stb);
}

int verb_switch_root(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *cmdline_init = NULL;
        const char *root, *init;
        sd_bus *bus;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot switch root remotely.");

        if (argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

        if (argc >= 2) {
                root = argv[1];

                if (!path_is_valid(root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid root path: %s", root);

                if (!path_is_absolute(root))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Root path is not absolute: %s", root);

                r = path_is_root(root);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if switch-root directory '%s' is current root: %m", root);
                if (r > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot switch to current root directory: %s", root);
        } else
                root = "/sysroot";

        if (!in_initrd())
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not in initrd, refusing switch-root operation.");

        if (argc >= 3)
                init = argv[2];
        else {
                r = proc_cmdline_get_key("init", 0, &cmdline_init);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse /proc/cmdline: %m");

                init = cmdline_init;
        }

        init = empty_to_null(init);
        if (init) {
                if (!path_is_valid(init))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path to init binary: %s", init);
                if (!path_is_absolute(init))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path to init binary is not absolute: %s", init);

                /* If the passed init is actually the same as the systemd binary, then let's suppress it. */
                if (same_file_in_root(root, SYSTEMD_BINARY_PATH, init) > 0)
                        init = NULL;
        }

        /* Instruct PID1 to exclude us from its killing spree applied during the transition. Otherwise we
         * would exit with a failure status even though the switch to the new root has succeed. */
        assert(saved_argv);
        assert(saved_argv[0]);
        saved_argv[0][0] = '@';

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        /* If we are slow to exit after the root switch, the new systemd instance will send us a signal to
         * terminate. Just ignore it and exit normally.  This way the unit does not end up as failed. */
        r = ignore_signals(SIGTERM);
        if (r < 0)
                log_warning_errno(r, "Failed to change disposition of SIGTERM to ignore: %m");

        log_debug("Switching root - root: %s; init: %s", root, strna(init));

        r = bus_call_method(bus, bus_systemd_mgr, "SwitchRoot", &error, NULL, "ss", root, init);
        if (r < 0) {
                (void) default_signals(SIGTERM);

                return log_error_errno(r, "Failed to switch root: %s", bus_error_message(&error, r));
        }

        return 0;
}
