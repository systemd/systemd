/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

extern const sd_bus_vtable machine_vtable[];

char *machine_bus_path(Machine *s);
int machine_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
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

int machine_send_signal(Machine *m, bool new_machine);
int machine_send_create_reply(Machine *m, sd_bus_error *error);
