/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-id128.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "json.h"
#include "macro.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "varlink.h"
#include "vmspawn-register.h"

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *directory,
                unsigned cid,
                const char *address,
                const char *key_path) {

        _cleanup_(varlink_unrefp) Varlink *vl = NULL;
        int r;

        assert(machine_name);
        assert(service);

        /* First try to use varlink, as it provides more features (such as SSH support). */
        r = varlink_connect_address(&vl, "/run/systemd/machine/io.systemd.Machine");
        if (r == -ENOENT || ERRNO_IS_DISCONNECT(r)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                assert(bus);

                /* In case we are running with an older machined, fallback to the existing D-Bus method. */
                r = bus_call_method(
                                bus,
                                bus_machine_mgr,
                                "RegisterMachine",
                                &error,
                                NULL,
                                "sayssus",
                                machine_name,
                                SD_BUS_MESSAGE_APPEND_ID128(uuid),
                                service,
                                "vm",
                                (uint32_t) getpid_cached(),
                                strempty(directory));
                if (r < 0)
                       return log_error_errno(r, "Failed to register machine: %s", bus_error_message(&error, r));

                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to connect to machined on /run/systemd/machine/io.systemd.Machine: %m");

        return varlink_callb_and_log(vl,
                        "io.systemd.Machine.Register",
                        NULL,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("name", machine_name),
                                        JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(uuid), "id", JSON_BUILD_ID128(uuid)),
                                        JSON_BUILD_PAIR_STRING("service", service),
                                        JSON_BUILD_PAIR_STRING("class", "vm"),
                                        JSON_BUILD_PAIR_CONDITION(VSOCK_CID_IS_REGULAR(cid), "vSockCid", JSON_BUILD_UNSIGNED(cid)),
                                        JSON_BUILD_PAIR_CONDITION(directory, "rootDirectory", JSON_BUILD_STRING(directory)),
                                        JSON_BUILD_PAIR_CONDITION(address, "sshAddress", JSON_BUILD_STRING(address)),
                                        JSON_BUILD_PAIR_CONDITION(key_path, "sshPrivateKeyPath", JSON_BUILD_STRING(key_path))));
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
