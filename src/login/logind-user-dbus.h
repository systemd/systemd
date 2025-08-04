/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"

extern const BusObjectImplementation user_object;

char* user_bus_path(User *s);

int user_send_signal(User *u, bool new_user);
int user_send_changed_strv(User *u, char **properties);
#define user_send_changed(u, ...) user_send_changed_strv(u, STRV_MAKE(__VA_ARGS__))

int bus_user_method_terminate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_user_method_kill(sd_bus_message *message, void *userdata, sd_bus_error *error);
