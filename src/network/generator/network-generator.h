/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "ether-addr-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "list.h"

typedef enum DHCPType {
        DHCP_TYPE_NONE,
        DHCP_TYPE_OFF,   /* Same as DHCP_TYPE_NONE */
        DHCP_TYPE_ON,
        DHCP_TYPE_ANY,   /* Same as DHCP_TYPE_ON */
        DHCP_TYPE_DHCP,  /* Actually means: DHCPv4 */
        DHCP_TYPE_DHCP6,
        DHCP_TYPE_AUTO6,
        DHCP_TYPE_EITHER6,
        DHCP_TYPE_IBFT,
        DHCP_TYPE_LINK6,
        DHCP_TYPE_LINK_LOCAL,
        _DHCP_TYPE_MAX,
        _DHCP_TYPE_INVALID = -EINVAL,
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
        char **vlan;
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

        /* [VLAN] */
        uint16_t vlan_id;
};

struct Link {
        char *filename;

        /* [Match] */
        struct hw_addr_data mac;

        /* [Link] */
        char *ifname;
        char **policies;
        char **alt_policies;
};

typedef struct Context {
        Hashmap *networks_by_name;
        Hashmap *netdevs_by_name;
        Hashmap *links_by_filename;
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

Link *link_get(Context *context, const char *filename);
void link_dump(Link *link, FILE *f);
int link_format(Link *link, char **ret);
