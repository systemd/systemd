/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

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
                RuntimeScope scope);
int register_machine_with_fallback_and_log(
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
                bool graceful,
                bool *reterr_registered_system,
                bool *reterr_registered_user);

int unregister_machine(sd_bus *bus, const char *machine_name, RuntimeScope scope);
int unregister_machine_with_fallback_and_log(
                sd_bus *system_bus,
                sd_bus *user_bus,
                const char *machine_name,
                bool registered_system,
                bool registered_user);
