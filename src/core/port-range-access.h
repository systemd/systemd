/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack
  Copyright 2017 Intel Corporation.

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

#include "list.h"

typedef struct PortRangeAccessItem PortRangeAccessItem;

struct PortRangeAccessItem {
        unsigned char prefixlen;
        uint16_t port;
        uint16_t protocol;
        LIST_FIELDS(PortRangeAccessItem, items);
};

int config_parse_port_range_access(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

PortRangeAccessItem* port_range_access_free_all(PortRangeAccessItem *first);
