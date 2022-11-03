/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-util.h"
#include "machine.h"

typedef enum {
        MACHINE_COPY_REPLACE = 1 << 0, /* Public API via DBUS, do not change */
        _MACHINE_COPY_FLAGS_MASK_PUBLIC = MACHINE_COPY_REPLACE,
} MachineCopyFlags;

extern const BusObjectImplementation machine_object;

char *machine_bus_path(Machine *s);

int bus_machine_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_get_addresses(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_open_pty(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_open_login(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_open_shell(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_bind_mount(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_copy(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_open_root_directory(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_machine_method_get_uid_shift(sd_bus_message *message, void *userdata, sd_bus_error *error);

int machine_send_signal(Machine *m, bool new_machine);
int machine_send_create_reply(Machine *m, sd_bus_error *error);
