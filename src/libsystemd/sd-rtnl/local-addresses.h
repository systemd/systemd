/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2008-2011 Lennart Poettering

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


#include "sd-rtnl.h"
#include "in-addr-util.h"

struct local_address {
        int family, ifindex;
        unsigned char scope;
        uint32_t metric;
        union in_addr_union address;
};

int local_addresses(sd_rtnl *rtnl, int ifindex, int af, struct local_address **ret);

int local_gateways(sd_rtnl *rtnl, int ifindex, int af, struct local_address **ret);
