/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "sd-id128.h"

#include "nspawn-mount.h"
#include "nspawn-settings.h"

typedef enum RegisterMachineFlags {
        REGISTER_MACHINE_KEEP_UNIT   = 1 << 0,
        REGISTER_MACHINE_ENABLE_FUSE = 1 << 1,
} RegisterMachineFlags;

int register_machine(
                sd_bus *bus,
                const char *machine_name,
                pid_t pid,
                const char *directory,
                sd_id128_t uuid,
                int local_ifindex,
                const char *slice,
                CustomMount *mounts, unsigned n_mounts,
                int kill_signal,
                char **properties,
                sd_bus_message *properties_message,
                const char *service,
                StartMode start_mode,
                RegisterMachineFlags flags);
int unregister_machine(sd_bus *bus, const char *machine_name);

typedef enum AllocateScopeFlags {
        ALLOCATE_SCOPE_ALLOW_PIDFD = 1 << 0,
        ALLOCATE_SCOPE_ENABLE_FUSE = 1 << 1,
} AllocateScopeFlags;

int allocate_scope(
                sd_bus *bus,
                const char *machine_name,
                pid_t pid,
                const char *slice,
                CustomMount *mounts, unsigned n_mounts,
                int kill_signal,
                char **properties,
                sd_bus_message *properties_message,
                StartMode start_mode,
                AllocateScopeFlags flags);
int terminate_scope(sd_bus *bus, const char *machine_name);
