/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-object.h"

typedef struct Link Link;

extern const BusObjectImplementation network_object;

int network_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int network_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
