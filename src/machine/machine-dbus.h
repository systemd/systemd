/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "machine.h"

extern const sd_bus_vtable machine_vtable[];

char *machine_bus_path(Machine *s);
int machine_object_find(sd_bus *bus,
                        const char *path,
                        const char *interface,
                        void *userdata,
                        void **found,
                        sd_bus_error *error);
int machine_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

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
