/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include <stdbool.h>

#include "udev.h"
#include "condition.h"

bool net_match_config(const struct ether_addr *match_mac,
                      char * const *match_path,
                      char * const *match_driver,
                      char * const *match_type,
                      char * const *match_name,
                      Condition *match_host,
                      Condition *match_virt,
                      Condition *match_kernel,
                      Condition *match_arch,
                      const struct ether_addr *dev_mac,
                      const char *dev_path,
                      const char *dev_parent_driver,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name);

int config_parse_net_condition(const char *unit, const char *filename, unsigned line,
                               const char *section, unsigned section_line, const char *lvalue,
                               int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_hwaddr(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_ifname(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_ifnames(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_ifalias(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int net_get_unique_predictable_data(struct udev_device *device, uint8_t result[8]);
const char *net_get_name(struct udev_device *device);

void serialize_in_addrs(FILE *f, const struct in_addr *addresses, size_t size);
int deserialize_in_addrs(struct in_addr **addresses, const char *string);
void serialize_in6_addrs(FILE *f, const struct in6_addr *addresses,
                         size_t size);
int deserialize_in6_addrs(struct in6_addr **addresses, const char *string);

/* don't include "dhcp-lease-internal.h" as it causes conflicts between netinet/ip.h and linux/ip.h */
struct sd_dhcp_route;

void serialize_dhcp_routes(FILE *f, const char *key, struct sd_dhcp_route *routes, size_t size);
int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size, size_t *ret_allocated, const char *string);

int serialize_dhcp_option(FILE *f, const char *key, const void *data, size_t size);
int deserialize_dhcp_option(void **data, size_t *data_len, const char *string);
