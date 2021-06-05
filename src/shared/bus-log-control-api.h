/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-object.h"

extern const BusObjectImplementation log_control_object;
static inline int bus_log_control_api_register(sd_bus *bus) {
        return bus_add_implementation(bus, &log_control_object, NULL);
}

int bus_property_get_log_level(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int bus_property_set_log_level(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *error);

int bus_property_get_log_target(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int bus_property_set_log_target(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

int bus_property_get_syslog_identifier(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
