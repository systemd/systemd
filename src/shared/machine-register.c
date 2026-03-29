/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "errno-util.h"
#include "json-util.h"
#include "log.h"
#include "machine-register.h"
#include "path-lookup.h"
#include "pidref.h"
#include "socket-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "varlink-util.h"

static int register_machine_dbus_ex(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *class,
                const PidRef *pidref,
                const char *directory,
                int local_ifindex,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(machine_name);
        assert(service);
        assert(class);

        r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "RegisterMachineEx");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", machine_name);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "(sv)(sv)(sv)",
                        "Id", "ay", SD_BUS_MESSAGE_APPEND_ID128(uuid),
                        "Service", "s", service,
                        "Class", "s", class);
        if (r < 0)
                return bus_log_create_error(r);

        if (pidref_is_set(pidref)) {
                if (pidref->fd >= 0) {
                        r = sd_bus_message_append(m, "(sv)", "LeaderPIDFD", "h", pidref->fd);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                if (pidref->fd_id > 0) {
                        r = sd_bus_message_append(m, "(sv)", "LeaderPIDFDID", "t", pidref->fd_id);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "(sv)", "LeaderPID", "u", pidref->pid);
                        if (r < 0)
                                return bus_log_create_error(r);
                }
        }

        if (!isempty(directory)) {
                r = sd_bus_message_append(m, "(sv)", "RootDirectory", "s", directory);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (local_ifindex > 0) {
                r = sd_bus_message_append(m, "(sv)", "NetworkInterfaces", "ai", 1, local_ifindex);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        return sd_bus_call(bus, m, 0, error, NULL);
}

static int register_machine_dbus(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *class,
                const PidRef *pidref,
                const char *directory,
                int local_ifindex) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(machine_name);
        assert(service);
        assert(class);

        /* First try RegisterMachineEx which supports PIDFD-based leader tracking. */
        r = register_machine_dbus_ex(bus, machine_name, uuid, service, class, pidref, directory, local_ifindex, &error);
        if (r >= 0)
                return 0;
        if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                return log_debug_errno(r, "Failed to register machine via D-Bus: %s", bus_error_message(&error, r));

        sd_bus_error_free(&error);

        r = bus_call_method(
                        bus,
                        bus_machine_mgr,
                        "RegisterMachineWithNetwork",
                        &error,
                        NULL,
                        "sayssusai",
                        machine_name,
                        SD_BUS_MESSAGE_APPEND_ID128(uuid),
                        service,
                        class,
                        pidref_is_set(pidref) ? (uint32_t) pidref->pid : 0,
                        strempty(directory),
                        local_ifindex > 0 ? 1 : 0, local_ifindex);
        if (r < 0)
                return log_debug_errno(r, "Failed to register machine via D-Bus: %s", bus_error_message(&error, r));

        return 0;
}

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *class,
                const PidRef *pidref,
                const char *directory,
                unsigned cid,
                int local_ifindex,
                const char *address,
                const char *key_path,
                bool allocate_unit,
                RuntimeScope scope) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(machine_name);
        assert(service);
        assert(class);

        /* First try to use varlink, as it provides more features (such as SSH support). */
        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd/machine/io.systemd.Machine", &p);
        if (r >= 0)
                r = sd_varlink_connect_address(&vl, p);
        if (r == -ENOENT || ERRNO_IS_DISCONNECT(r)) {
                log_debug_errno(r, "Failed to connect to machined via varlink%s%s, falling back to D-Bus: %m",
                                p ? " on " : "", strempty(p));

                /* In case we are running with an older machined, fall back to D-Bus. */
                if (!bus)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Varlink connection to machined not available and no bus provided.");

                return register_machine_dbus(bus, machine_name, uuid, service, class, pidref, directory, local_ifindex);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to machined on %s: %m", strna(p));

        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Machine.Register",
                        /* ret_reply= */ NULL,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", machine_name),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(uuid), "id", SD_JSON_BUILD_ID128(uuid)),
                        SD_JSON_BUILD_PAIR_STRING("service", service),
                        SD_JSON_BUILD_PAIR_STRING("class", class),
                        SD_JSON_BUILD_PAIR_CONDITION(VSOCK_CID_IS_REGULAR(cid), "vSockCid", SD_JSON_BUILD_UNSIGNED(cid)),
                        SD_JSON_BUILD_PAIR_CONDITION(local_ifindex > 0, "networkInterfaces", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_INTEGER(local_ifindex))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!directory, "rootDirectory", SD_JSON_BUILD_STRING(directory)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!address, "sshAddress", SD_JSON_BUILD_STRING(address)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!key_path, "sshPrivateKeyPath", SD_JSON_BUILD_STRING(key_path)),
                        SD_JSON_BUILD_PAIR_CONDITION(isatty_safe(STDIN_FILENO), "allowInteractiveAuthentication", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(allocate_unit, "allocateUnit", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(pidref), "leaderProcessId", JSON_BUILD_PIDREF(pidref)));
        if (r < 0)
                return log_debug_errno(r, "Failed to register machine via varlink: %m");
        if (error_id)
                return log_debug_errno(sd_varlink_error_to_errno(error_id, NULL),
                                       "Failed to register machine via varlink: %s", error_id);

        return 0;
}

int register_machine_with_fallback(
                RuntimeScope scope,
                sd_bus *system_bus,
                sd_bus *user_bus,
                const char *machine_name,
                sd_id128_t uuid,
                const char *service,
                const char *class,
                const PidRef *pidref,
                const char *directory,
                unsigned cid,
                int local_ifindex,
                const char *address,
                const char *key_path,
                bool allocate_unit,
                bool *reterr_registered_system,
                bool *reterr_registered_user) {

        bool registered_system = false, registered_user = false;
        int r = 0;

        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID));
        assert(system_bus || !IN_SET(scope, RUNTIME_SCOPE_SYSTEM, _RUNTIME_SCOPE_INVALID));
        assert(user_bus || !IN_SET(scope, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID));
        assert(machine_name);
        assert(service);
        assert(class);

        if (IN_SET(scope, RUNTIME_SCOPE_SYSTEM, _RUNTIME_SCOPE_INVALID)) {
                int q = register_machine(
                                system_bus,
                                machine_name,
                                uuid,
                                service,
                                class,
                                pidref,
                                directory,
                                cid,
                                local_ifindex,
                                address,
                                key_path,
                                scope == RUNTIME_SCOPE_SYSTEM ? allocate_unit : false,
                                RUNTIME_SCOPE_SYSTEM);
                if (q < 0)
                        RET_GATHER(r, q);
                else
                        registered_system = true;
        }

        if (IN_SET(scope, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID)) {
                int q = register_machine(
                                user_bus,
                                machine_name,
                                uuid,
                                service,
                                class,
                                pidref,
                                directory,
                                cid,
                                local_ifindex,
                                address,
                                key_path,
                                allocate_unit,
                                RUNTIME_SCOPE_USER);
                if (q < 0)
                        RET_GATHER(r, q);
                else
                        registered_user = true;
        }

        if (reterr_registered_system)
                *reterr_registered_system = registered_system;
        if (reterr_registered_user)
                *reterr_registered_user = registered_user;

        return r;
}

int unregister_machine_with_fallback(
                sd_bus *system_bus,
                sd_bus *user_bus,
                const char *machine_name,
                bool registered_system,
                bool registered_user) {

        int r = 0;

        if (registered_system)
                RET_GATHER(r, unregister_machine(system_bus, machine_name, RUNTIME_SCOPE_SYSTEM));
        if (registered_user)
                RET_GATHER(r, unregister_machine(user_bus, machine_name, RUNTIME_SCOPE_USER));

        return r;
}

int unregister_machine(sd_bus *bus, const char *machine_name, RuntimeScope scope) {
        int r;

        assert(machine_name);

        /* First try varlink */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd/machine/io.systemd.Machine", &p);
        if (r < 0)
                log_debug_errno(r, "Failed to determine runtime directory for varlink, falling back to D-Bus: %m");
        else {
                r = sd_varlink_connect_address(&vl, p);
                if (r < 0)
                        log_debug_errno(r, "Failed to connect to machined via varlink on %s, falling back to D-Bus: %m", p);
                else {
                        const char *error_id = NULL;
                        r = sd_varlink_callbo(
                                        vl,
                                        "io.systemd.Machine.Unregister",
                                        /* ret_reply= */ NULL,
                                        &error_id,
                                        SD_JSON_BUILD_PAIR_STRING("name", machine_name));
                        if (r >= 0 && !error_id)
                                return 0;
                        if (r >= 0)
                                r = sd_varlink_error_to_errno(error_id, NULL);

                        log_debug_errno(r, "Failed to unregister machine via varlink, falling back to D-Bus: %m");
                }
        }

        /* Fall back to D-Bus */
        if (bus) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                r = bus_call_method(bus, bus_machine_mgr, "UnregisterMachine", &error, NULL, "s", machine_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to unregister machine via D-Bus: %s", bus_error_message(&error, r));

                return 0;
        }

        return r;
}
