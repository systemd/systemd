/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

extern const BusObjectImplementation manager_object;

int manager_connect_bus(Manager *m);
int manager_send_changed_strv(Manager *manager, char **properties);
#define manager_send_changed(manager, ...) manager_send_changed_strv(manager, STRV_MAKE(__VA_ARGS__));

typedef int (*DnsServerBusAppend)(sd_bus_message *reply, DnsServer *s, bool with_ifindex);
int bus_dns_server_append(sd_bus_message *reply, DnsServer *s, bool with_ifindex);
int bus_append_dns_servers(sd_bus_message *reply, DnsServer *first, bool with_ifindex, DnsServerBusAppend append);
int bus_dns_server_append_legacy(sd_bus_message *reply, DnsServer *s, bool with_ifindex, bool extended);
int bus_dns_server_append_legacy_plain(sd_bus_message *reply, DnsServer *s, bool with_ifindex);
int bus_dns_server_append_legacy_ex(sd_bus_message *reply, DnsServer *s, bool with_ifindex);

int bus_property_get_resolve_support(sd_bus *bus, const char *path, const char *interface,
                                     const char *property, sd_bus_message *reply,
                                     void *userdata, sd_bus_error *error);

void bus_client_log(sd_bus_message *m, const char *what);
