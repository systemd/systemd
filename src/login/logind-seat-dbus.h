/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "logind-seat.h"

extern const sd_bus_vtable seat_vtable[];

int seat_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int seat_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *seat_bus_path(Seat *s);

int seat_send_signal(Seat *s, bool new_seat);
int seat_send_changed(Seat *s, const char *properties, ...) _sentinel_;

int bus_seat_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
