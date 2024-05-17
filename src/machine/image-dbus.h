/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-object.h"
#include "discover-image.h"
#include "machined.h"

extern const BusObjectImplementation image_object;

int manager_acquire_image(Manager *m, const char *name, Image **ret);
char *image_bus_path(const char *name);

int bus_image_method_remove(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_rename(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_clone(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_mark_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_set_limit(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_machine_id(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_machine_info(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error);
