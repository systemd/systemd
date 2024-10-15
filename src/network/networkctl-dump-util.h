/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dhcp-lease.h"
#include "sd-hwdb.h"
#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "format-table.h"

int dump_list(Table *table, const char *key, char * const *l);
int ieee_oui(sd_hwdb *hwdb, const struct ether_addr *mac, char **ret);
int dump_gateways(sd_netlink *rtnl, sd_hwdb *hwdb, Table *table, int ifindex);
int dump_addresses(sd_netlink *rtnl, sd_dhcp_lease *lease, Table *table, int ifindex);
