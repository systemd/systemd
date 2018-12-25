#pragma once

#include "sd-bus.h"

extern const sd_bus_vtable dnssd_vtable[];

int dnssd_object_find(sd_bus *bus,
                      const char *path,
                      const char *interface,
                      void *userdata,
                      void **found,
                      sd_bus_error *error);
int dnssd_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

int bus_dnssd_method_unregister(sd_bus_message *message, void *userdata, sd_bus_error *error);
