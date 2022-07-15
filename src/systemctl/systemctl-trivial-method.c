/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl.h"

/* A generic implementation for cases we just need to invoke a simple method call on the Manager object. */

int verb_trivial_method(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *method;
        sd_bus *bus;
        int r;

        if (arg_dry_run)
                return 0;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        method =
                streq(argv[0], "clear-jobs")    ||
                streq(argv[0], "cancel")        ? "ClearJobs" :
                streq(argv[0], "reset-failed")  ? "ResetFailed" :
                streq(argv[0], "halt")          ? "Halt" :
                streq(argv[0], "reboot")        ? "Reboot" :
                streq(argv[0], "kexec")         ? "KExec" :
                streq(argv[0], "exit")          ? "Exit" :
                             /* poweroff */       "PowerOff";

        r = bus_call_method(bus, bus_systemd_mgr, method, &error, NULL, NULL);
        if (r < 0 && arg_action == ACTION_SYSTEMCTL)
                return log_error_errno(r, "Failed to execute operation: %s", bus_error_message(&error, r));

        /* Note that for the legacy commands (i.e. those with action != ACTION_SYSTEMCTL) we support
         * fallbacks to the old ways of doing things, hence don't log any error in that case here. */

        return r < 0 ? r : 0;
}
