/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "runtime-scope.h"
#include "shared-forward.h"

typedef struct MachineRegistration {
        const char *name;
        sd_id128_t id;
        const char *service;
        const char *class;
        const PidRef *pidref;
        const char *root_directory;
        unsigned vsock_cid;
        int local_ifindex;
        const char *ssh_address;
        const char *ssh_private_key_path;
        const char *control_address;
        bool allocate_unit;
} MachineRegistration;

typedef struct MachineRegistrationContext {
        RuntimeScope scope;
        sd_bus *system_bus;
        sd_bus *user_bus;
        bool registered_system;
        bool registered_user;
} MachineRegistrationContext;

int register_machine(
                sd_bus *bus,
                const MachineRegistration *reg,
                RuntimeScope scope);
int register_machine_with_fallback_and_log(
                MachineRegistrationContext *ctx,
                const MachineRegistration *reg,
                bool graceful);

int unregister_machine(sd_bus *bus, const char *machine_name, RuntimeScope scope);
void unregister_machine_with_fallback_and_log(
                const MachineRegistrationContext *ctx,
                const char *machine_name);
