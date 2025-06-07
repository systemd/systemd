/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "network-util.h"

typedef struct DNSConfiguration DNSConfiguration;
typedef struct Manager Manager;

typedef struct Link {
        Manager *manager;

        int ifindex;
        char *ifname;
        char **altnames;
        unsigned flags;

        bool required_for_online;
        LinkOperationalStateRange required_operstate;
        LinkOperationalState operational_state;
        AddressFamily required_family;
        LinkAddressState ipv4_address_state;
        LinkAddressState ipv6_address_state;
        char *state;
        DNSConfiguration *dns_configuration;
} Link;

int rtnl_process_link(sd_netlink *rtnl, sd_netlink_message *mm, void *userdata);
int link_update_monitor(Link *l);
