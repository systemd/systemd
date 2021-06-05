/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-object.h"
#include "resolved-manager.h"

extern const BusObjectImplementation manager_object;

int manager_connect_bus(Manager *m);
int _manager_send_changed(Manager *manager, const char *property, ...) _sentinel_;
#define manager_send_changed(manager, ...) _manager_send_changed(manager, __VA_ARGS__, NULL)
int bus_dns_server_append(sd_bus_message *reply, DnsServer *s, bool with_ifindex, bool extended);
int bus_property_get_resolve_support(sd_bus *bus, const char *path, const char *interface,
                                     const char *property, sd_bus_message *reply,
                                     void *userdata, sd_bus_error *error);

void bus_client_log(sd_bus_message *m, const char *what);
