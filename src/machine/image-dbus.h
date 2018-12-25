/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "machined.h"

extern const sd_bus_vtable image_vtable[];

char *image_bus_path(const char *name);

int image_object_find(sd_bus *bus,
                      const char *path,
                      const char *interface,
                      void *userdata,
                      void **found,
                      sd_bus_error *error);
int image_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

int bus_image_method_remove(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_rename(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_clone(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_mark_read_only(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_set_limit(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_hostname(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_machine_id(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_machine_info(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_image_method_get_os_release(sd_bus_message *message, void *userdata, sd_bus_error *error);
