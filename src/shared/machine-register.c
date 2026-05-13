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
#include "runtime-scope.h"
#include "socket-util.h"
#include "string-util.h"
#include "terminal-util.h"

static int register_machine_dbus_ex(
                sd_bus *bus,
                const MachineRegistration *reg,
                sd_bus_error *error) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(reg);
        assert(reg->name);
        assert(reg->service);
        assert(reg->class);
        assert(error);

        r = bus_message_new_method_call(bus, &m, bus_machine_mgr, "RegisterMachineEx");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", reg->name);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(
                        m,
                        "(sv)(sv)(sv)",
                        "Id", "ay", SD_BUS_MESSAGE_APPEND_ID128(reg->id),
                        "Service", "s", reg->service,
                        "Class", "s", reg->class);
        if (r < 0)
                return bus_log_create_error(r);

        if (pidref_is_set(reg->pidref)) {
                if (reg->pidref->fd >= 0) {
                        r = sd_bus_message_append(m, "(sv)", "LeaderPIDFD", "h", reg->pidref->fd);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                if (reg->pidref->fd_id > 0) {
                        r = sd_bus_message_append(m, "(sv)", "LeaderPIDFDID", "t", reg->pidref->fd_id);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = sd_bus_message_append(m, "(sv)", "LeaderPID", "u", reg->pidref->pid);
                        if (r < 0)
                                return bus_log_create_error(r);
                }
        }

        if (!isempty(reg->root_directory)) {
                r = sd_bus_message_append(m, "(sv)", "RootDirectory", "s", reg->root_directory);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        if (reg->local_ifindex > 0) {
                r = sd_bus_message_append(m, "(sv)", "NetworkInterfaces", "ai", 1, reg->local_ifindex);
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
                const MachineRegistration *reg) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(reg);
        assert(reg->name);
        assert(reg->service);
        assert(reg->class);

        /* First try RegisterMachineEx which supports PIDFD-based leader tracking. */
        r = register_machine_dbus_ex(bus, reg, &error);
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
                        reg->name,
                        SD_BUS_MESSAGE_APPEND_ID128(reg->id),
                        reg->service,
                        reg->class,
                        pidref_is_set(reg->pidref) ? (uint32_t) reg->pidref->pid : 0,
                        strempty(reg->root_directory),
                        reg->local_ifindex > 0 ? 1 : 0, reg->local_ifindex);
        if (r < 0)
                return log_debug_errno(r, "Failed to register machine via D-Bus: %s", bus_error_message(&error, r));

        return 0;
}

int register_machine(
                sd_bus *bus,
                const MachineRegistration *reg,
                RuntimeScope scope) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        int r;

        assert(reg);
        assert(reg->name);
        assert(reg->service);
        assert(reg->class);

        /* First try to use varlink, as it provides more features (such as SSH support). */
        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd/machine/io.systemd.Machine", &p);
        if (r >= 0)
                r = sd_varlink_connect_address(&vl, p);
        if (r == -ENOENT || ERRNO_IS_DISCONNECT(r)) {
                log_debug_errno(r, "Failed to connect to machined via varlink%s%s, falling back to D-Bus: %m",
                                p ? " on " : "", strempty(p));

                /* In case we are running with an older machined, fall back to D-Bus. Note that the D-Bus
                 * methods do not support the allocateUnit feature — machined will look up the caller's
                 * existing cgroup unit instead of creating a dedicated scope. Callers that skip client-side
                 * scope allocation when allocate_unit is set should be aware that on the D-Bus path no scope
                 * will be created at all. */
                if (!bus)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Varlink connection to machined not available and no bus provided.");

                return register_machine_dbus(bus, reg);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to machined on %s: %m", strna(p));
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Machine.Register",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("name", reg->name),
                        SD_JSON_BUILD_PAIR_CONDITION(!sd_id128_is_null(reg->id), "id", SD_JSON_BUILD_ID128(reg->id)),
                        SD_JSON_BUILD_PAIR_STRING("service", reg->service),
                        SD_JSON_BUILD_PAIR_STRING("class", reg->class),
                        SD_JSON_BUILD_PAIR_CONDITION(VSOCK_CID_IS_REGULAR(reg->vsock_cid), "vSockCid", SD_JSON_BUILD_UNSIGNED(reg->vsock_cid)),
                        SD_JSON_BUILD_PAIR_CONDITION(reg->local_ifindex > 0, "ifIndices", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_INTEGER(reg->local_ifindex))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!reg->root_directory, "rootDirectory", SD_JSON_BUILD_STRING(reg->root_directory)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!reg->ssh_address, "sshAddress", SD_JSON_BUILD_STRING(reg->ssh_address)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!reg->ssh_private_key_path, "sshPrivateKeyPath", SD_JSON_BUILD_STRING(reg->ssh_private_key_path)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!reg->control_address, "controlAddress", SD_JSON_BUILD_STRING(reg->control_address)),
                        SD_JSON_BUILD_PAIR_CONDITION(isatty_safe(STDIN_FILENO), "allowInteractiveAuthentication", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(reg->allocate_unit, "allocateUnit", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(pidref_is_set(reg->pidref), "leaderProcessId", JSON_BUILD_PIDREF(reg->pidref)));
        if (r < 0)
                return log_debug_errno(r, "Failed to register machine via varlink: %m");
        if (error_id)
                return log_debug_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to register machine via varlink: %s", error_id);

        return 0;
}

static const char* machine_registration_scope_string(RuntimeScope scope, bool registered_system, bool registered_user) {
        if (scope == _RUNTIME_SCOPE_INVALID) {
                if (!registered_system && !registered_user)
                        return "system and user";
                if (!registered_system)
                        return "system";
                return "user";
        }

        return runtime_scope_to_string(scope);
}

int register_machine_with_fallback_and_log(
                MachineRegistrationContext *ctx,
                const MachineRegistration *reg,
                bool graceful) {

        int r = 0;

        assert(ctx);
        assert(IN_SET(ctx->scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID));
        assert(ctx->system_bus || !IN_SET(ctx->scope, RUNTIME_SCOPE_SYSTEM, _RUNTIME_SCOPE_INVALID));
        assert(ctx->user_bus || !IN_SET(ctx->scope, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID));
        assert(reg);
        assert(reg->name);
        assert(reg->service);
        assert(reg->class);

        if (IN_SET(ctx->scope, RUNTIME_SCOPE_SYSTEM, _RUNTIME_SCOPE_INVALID)) {
                MachineRegistration system_reg = *reg;
                if (ctx->scope != RUNTIME_SCOPE_SYSTEM)
                        system_reg.allocate_unit = false;

                int q = register_machine(ctx->system_bus, &system_reg, RUNTIME_SCOPE_SYSTEM);
                if (q < 0)
                        RET_GATHER(r, q);
                else
                        ctx->registered_system = true;
        }

        if (IN_SET(ctx->scope, RUNTIME_SCOPE_USER, _RUNTIME_SCOPE_INVALID)) {
                int q = register_machine(ctx->user_bus, reg, RUNTIME_SCOPE_USER);
                if (q < 0)
                        RET_GATHER(r, q);
                else
                        ctx->registered_user = true;
        }

        if (r < 0) {
                if (graceful) {
                        log_notice_errno(r, "Failed to register machine in %s context, ignoring: %m",
                                         machine_registration_scope_string(ctx->scope, ctx->registered_system, ctx->registered_user));
                        r = 0;
                } else
                        r = log_error_errno(r, "Failed to register machine in %s context: %m",
                                            machine_registration_scope_string(ctx->scope, ctx->registered_system, ctx->registered_user));
        }

        return r;
}

void unregister_machine_with_fallback_and_log(
                const MachineRegistrationContext *ctx,
                const char *machine_name) {

        int r = 0;
        bool failed_system = false, failed_user = false;

        assert(ctx);

        if (ctx->registered_system) {
                int q = unregister_machine(ctx->system_bus, machine_name, RUNTIME_SCOPE_SYSTEM);
                if (q < 0) {
                        RET_GATHER(r, q);
                        failed_system = true;
                }
        }

        if (ctx->registered_user) {
                int q = unregister_machine(ctx->user_bus, machine_name, RUNTIME_SCOPE_USER);
                if (q < 0) {
                        RET_GATHER(r, q);
                        failed_user = true;
                }
        }

        if (r < 0)
                log_notice_errno(r, "Failed to unregister machine in %s context, ignoring: %m",
                                 machine_registration_scope_string(
                                                 ctx->registered_system && ctx->registered_user ? _RUNTIME_SCOPE_INVALID :
                                                 ctx->registered_system ? RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER,
                                                 !failed_system, !failed_user));
}

int unregister_machine(sd_bus *bus, const char *machine_name, RuntimeScope scope) {
        int r;

        assert(machine_name);

        /* First try varlink */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        _cleanup_free_ char *p = NULL;
        r = runtime_directory_generic(scope, "systemd/machine/io.systemd.Machine", &p);
        if (r >= 0)
                r = sd_varlink_connect_address(&vl, p);
        if (r >= 0) {
                sd_json_variant *reply = NULL;
                const char *error_id = NULL;
                r = sd_varlink_callbo(
                                vl,
                                "io.systemd.Machine.Unregister",
                                &reply,
                                &error_id,
                                SD_JSON_BUILD_PAIR_STRING("name", machine_name));
                if (r >= 0 && !error_id)
                        return 0;
                if (r >= 0)
                        r = sd_varlink_error_to_errno(error_id, reply);
        }

        log_debug_errno(r, "Failed to unregister machine via varlink, falling back to D-Bus: %m");

        /* Fall back to D-Bus */
        if (!bus)
                return log_debug_errno(SYNTHETIC_ERRNO(ESRCH), "Varlink connection to machined not available and no bus provided.");

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_call_method(bus, bus_machine_mgr, "UnregisterMachine", &error, NULL, "s", machine_name);
        if (r < 0)
                return log_debug_errno(r, "Failed to unregister machine via D-Bus: %s", bus_error_message(&error, r));

        return 0;
}
