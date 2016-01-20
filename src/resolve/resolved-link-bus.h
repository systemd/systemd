/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"

#include "resolved-link.h"

extern const sd_bus_vtable link_vtable[];

int link_object_find(sd_bus *bus, const char *path, const char *interface, void *userdata, void **found, sd_bus_error *error);
char *link_bus_path(Link *link);
int link_node_enumerator(sd_bus *bus, const char *path, void *userdata, char ***nodes, sd_bus_error *error);

int bus_link_method_set_dns_servers(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_search_domains(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_llmnr(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_mdns(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_set_dnssec_negative_trust_anchors(sd_bus_message *message, void *userdata, sd_bus_error *error);
int bus_link_method_revert(sd_bus_message *message, void *userdata, sd_bus_error *error);
