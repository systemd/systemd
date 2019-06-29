/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-dhcp6-client.h"

#include "conf-parser.h"

typedef struct Link Link;
typedef struct Manager Manager;

int dhcp6_request_prefix_delegation(Link *link);
int dhcp6_configure(Link *link);
int dhcp6_request_address(Link *link, int ir);
int dhcp6_lease_pd_prefix_lost(sd_dhcp6_client *client, Link* link);
int dhcp6_prefix_remove(Manager *m, struct in6_addr *addr);
