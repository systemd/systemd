/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus-vtable.h"

#include "manager.h"

extern const sd_bus_vtable bus_manager_vtable[];

void bus_manager_send_finished(Manager *m, usec_t firmware_usec, usec_t loader_usec, usec_t kernel_usec, usec_t initrd_usec, usec_t userspace_usec, usec_t total_usec);
void bus_manager_send_reloading(Manager *m, bool active);
void bus_manager_send_change_signal(Manager *m);

int verify_run_space_and_log(const char *message);

int bus_property_get_oom_policy(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);
