/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "resolved-manager.h"

int manager_connect_bus(Manager *m);
int bus_dns_server_append(sd_bus_message *reply, DnsServer *s, bool with_ifindex);
int bus_property_get_resolve_support(sd_bus *bus, const char *path, const char *interface,
                                     const char *property, sd_bus_message *reply,
                                     void *userdata, sd_bus_error *error);
