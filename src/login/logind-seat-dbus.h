/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

extern const BusObjectImplementation seat_object;

char* seat_bus_path(Seat *s);

int seat_send_signal(Seat *s, bool new_seat);
int seat_send_changed_strv(Seat *s, char **properties);
#define seat_send_changed(s, ...) seat_send_changed_strv(s, STRV_MAKE(__VA_ARGS__))

int bus_seat_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
