/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-id128.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "macro.h"
#include "process-util.h"
#include "string-util.h"
#include "vmspawn-register.h"

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *directory,
                const char *address,
                const char *key_path) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(machine_name);
        assert(service);

        r = bus_call_method(
                        bus,
                        bus_machine_mgr,
                        "RegisterMachineWithSSH",
                        &error,
                        NULL,
                        "sayssusss",
                        machine_name,
                        SD_BUS_MESSAGE_APPEND_ID128(uuid),
                        service,
                        "vm",
                        (uint32_t) getpid_cached(),
                        strempty(directory),
                        strempty(address),
                        strempty(key_path));
        if (r < 0)
                return log_error_errno(r, "Failed to register machine: %s", bus_error_message(&error, r));

        return 0;
}

int unregister_machine(sd_bus *bus, const char *machine_name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_machine_mgr, "UnregisterMachine", &error, NULL, "s", machine_name);
        if (r < 0)
                log_debug("Failed to unregister machine: %s", bus_error_message(&error, r));

        return 0;
}
