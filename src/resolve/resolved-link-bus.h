/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include "sd-bus.h"

#include "resolved-link.h"

extern const sd_bus_vtable link_vtable[];

int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *link_bus_path(Link *link);
int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_domains(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_private_dns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_revert(sd_bus_message *message, void *userdata, sd_bus_error *error);
