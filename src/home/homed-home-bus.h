/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-object.h"
#include "homed-home.h"

int bus_home_client_is_trusted(Home *h, sd_bus_message *message);
int bus_home_get_record_json(Home *h, sd_bus_message *message, char **ret, bool *ret_incomplete);

int bus_home_method_activate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_deactivate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_realize(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_remove(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_fixate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_authenticate(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_update(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_update_record(Home *home, sd_bus_message *message, UserRecord *hr, sd_bus_error *error);
int bus_home_method_resize(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_change_password(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_lock(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_unlock(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_acquire(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_ref(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_home_method_release(sd_bus_message *message, void *userdata, sd_bus_error *error);

extern const BusObjectImplementation home_object;

int bus_home_path(Home *h, char **ret);

int bus_home_emit_change(Home *h);
int bus_home_emit_remove(Home *h);
