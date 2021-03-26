/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "in-addr-util.h"

struct local_address {
        int family, ifindex;
        unsigned char scope;
        uint32_t metric;
        union in_addr_union address;
};

int local_addresses(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);

int local_gateways(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);

int local_outbounds(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);
