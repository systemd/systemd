/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <net/ethernet.h>
#include <stdio.h>

#include "hashmap.h"
#include "in-addr-util.h"
#include "list.h"

typedef enum DHCPType {
        DHCP_TYPE_NONE,
        DHCP_TYPE_OFF,
        DHCP_TYPE_ON,
        DHCP_TYPE_ANY,
        DHCP_TYPE_DHCP,
        DHCP_TYPE_DHCP6,
        DHCP_TYPE_AUTO6,
        DHCP_TYPE_EITHER6,
        DHCP_TYPE_IBFT,
        _DHCP_TYPE_MAX,
        _DHCP_TYPE_INVALID = -1,
} DHCPType;

typedef struct Address Address;
typedef struct Link Link;
typedef struct NetDev NetDev;
typedef struct Network Network;
typedef struct Route Route;
typedef struct Context Context;

struct Address {
        Network *network;

        union in_addr_union address, peer;
        unsigned char prefixlen;
        int family;

        LIST_FIELDS(Address, addresses);
};

struct Route {
        Network *network;

        union in_addr_union dest, gateway;
        unsigned char prefixlen;
        int family;

        LIST_FIELDS(Route, routes);
};

struct Network {
        /* [Match] */
        char *ifname;

        /* [Link] */
        struct ether_addr mac;
        uint32_t mtu;

        /* [Network] */
        DHCPType dhcp_type;
        char **dns;
        char *vlan;
        char *bridge;
        char *bond;

        /* [DHCP] */
        char *hostname;
        int dhcp_use_dns;

        LIST_HEAD(Address, addresses);
        LIST_HEAD(Route, routes);
};

struct NetDev {
        /* [NetDev] */
        char *ifname;
        char *kind;
        uint32_t mtu;
};

struct Link {
        /* [Match] */
        char *ifname;
        struct ether_addr mac;
};

typedef struct Context {
        Hashmap *networks_by_name;
        Hashmap *netdevs_by_name;
        Hashmap *links_by_name;
} Context;

int parse_cmdline_item(const char *key, const char *value, void *data);
int context_merge_networks(Context *context);
void context_clear(Context *context);

Network *network_get(Context *context, const char *ifname);
void network_dump(Network *network, FILE *f);
int network_format(Network *network, char **ret);

NetDev *netdev_get(Context *context, const char *ifname);
void netdev_dump(NetDev *netdev, FILE *f);
int netdev_format(NetDev *netdev, char **ret);

Link *link_get(Context *context, const char *ifname);
void link_dump(Link *link, FILE *f);
int link_format(Link *link, char **ret);
