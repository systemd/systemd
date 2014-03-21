/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#pragma once

#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "udev.h"
#include "condition-util.h"

bool net_match_config(const struct ether_addr *match_mac,
                      const char *match_path,
                      const char *match_driver,
                      const char *match_type,
                      const char *match_name,
                      Condition *match_host,
                      Condition *match_virt,
                      Condition *match_kernel,
                      Condition *match_arch,
                      const char *dev_mac,
                      const char *dev_path,
                      const char *dev_parent_driver,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name);

unsigned net_netmask_to_prefixlen(const struct in_addr *netmask);

int config_parse_net_condition(const char *unit, const char *filename, unsigned line,
                               const char *section, unsigned section_line, const char *lvalue,
                               int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_hwaddr(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_ifname(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line, const char *lvalue,
                        int ltype, const char *rvalue, void *data, void *userdata);

int config_parse_ifalias(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line, const char *lvalue,
                         int ltype, const char *rvalue, void *data, void *userdata);

int net_parse_inaddr(const char *address, unsigned char *family, void *dst);

int net_get_unique_predictable_data(struct udev_device *device, uint8_t result[8]);
