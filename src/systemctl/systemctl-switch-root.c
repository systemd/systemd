/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "signal-util.h"
#include "stat-util.h"
#include "systemctl-switch-root.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_switch_root(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *cmdline_init = NULL;
        const char *root, *init;
        sd_bus *bus;
        int r;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot switch root remotely.");

        if (argc < 2 || argc > 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Wrong number of arguments.");

        root = argv[1];

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
                const char *root_systemd_path = NULL, *root_init_path = NULL;

                root_systemd_path = prefix_roota(root, "/" SYSTEMD_BINARY_PATH);
                root_init_path = prefix_roota(root, init);

                /* If the passed init is actually the same as the systemd binary, then let's suppress it. */
                if (files_same(root_init_path, root_systemd_path, 0) > 0)
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
