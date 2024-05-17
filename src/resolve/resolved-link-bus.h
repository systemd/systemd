/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "bus-util.h"
#include "resolved-link.h"

extern const BusObjectImplementation link_object;

char* link_bus_path(const Link *link);

int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dns_servers_ex(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_domains(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_default_route(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dns_over_tls(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_revert(sd_bus_message *message, void *userdata, sd_bus_error *error);
