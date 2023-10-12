/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

#include "sd-id128.h"

#include "nspawn-mount.h"
#include "nspawn-settings.h"

int register_machine(sd_bus *bus, const char *machine_name, pid_t pid, const char *directory, sd_id128_t uuid, int local_ifindex, const char *slice, CustomMount *mounts, unsigned n_mounts, int kill_signal, char **properties, sd_bus_message *properties_message, bool keep_unit, const char *service, StartMode start_mode);
int unregister_machine(sd_bus *bus, const char *machine_name);

int allocate_scope(sd_bus *bus, const char *machine_name, pid_t pid, const char *slice, CustomMount *mounts, unsigned n_mounts, int kill_signal, char **properties, sd_bus_message *properties_message, bool allow_pidfds, StartMode start_mode);
int terminate_scope(sd_bus *bus, const char *machine_name);
