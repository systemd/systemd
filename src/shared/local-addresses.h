/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "in-addr-util.h"

struct local_address {
        int ifindex;
        unsigned char scope;
        uint32_t priority;
        uint32_t weight;
        int family;
        union in_addr_union address;
        union in_addr_union prefsrc;
};

bool has_local_address(const struct local_address *addresses, size_t n_addresses, const struct local_address *needle);

int add_local_address(struct local_address **list, size_t *n_list, int ifindex, unsigned char scope, int family, const union in_addr_union *address);

int local_addresses(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);

int local_gateways(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);

int local_outbounds(sd_netlink *rtnl, int ifindex, int af, struct local_address **ret);
