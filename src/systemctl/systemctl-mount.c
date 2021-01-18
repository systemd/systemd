/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-mount.h"
#include "systemctl-util.h"
#include "systemctl.h"

int mount_bind(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *n = NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = unit_name_mangle(argv[1], arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "BindMountUnit",
                        &error,
                        NULL,
                        "sssbb",
                        n,
                        argv[2],
                        argv[3],
                        arg_read_only,
                        arg_mkdir);
        if (r < 0)
                return log_error_errno(r, "Failed to bind mount: %s", bus_error_message(&error, r));

        return 0;
}
