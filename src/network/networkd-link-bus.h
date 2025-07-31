/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

extern const BusObjectImplementation link_object;

char* link_bus_path(Link *link);
int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);
int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
int link_send_changed_strv(Link *link, char **properties);
#define link_send_changed(link, ...) link_send_changed_strv(link, STRV_MAKE(__VA_ARGS__));

int property_get_operational_state(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int property_get_carrier_state(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int property_get_address_state(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);
int property_get_online_state(sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *error);

int bus_link_method_set_ntp_servers(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dns_servers_ex(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_domains(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_default_route(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dns_over_tls(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_revert_ntp(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_revert_dns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_renew(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_force_renew(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_reconfigure(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_describe(sd_bus_message *message, void *userdata, sd_bus_error *error);
