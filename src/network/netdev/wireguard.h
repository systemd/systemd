/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

typedef struct Wireguard Wireguard;

#include <netinet/in.h>
#include <linux/wireguard.h>

#include "sd-event.h"
#include "sd-resolve.h"

#include "in-addr-util.h"
#include "netdev.h"
#include "socket-util.h"

typedef struct WireguardIPmask {
        uint16_t family;
        union in_addr_union ip;
        uint8_t cidr;

        LIST_FIELDS(struct WireguardIPmask, ipmasks);
} WireguardIPmask;

typedef struct WireguardPeer {
        Wireguard *wireguard;
        ConfigSection *section;

        uint8_t public_key[WG_KEY_LEN];
        uint8_t preshared_key[WG_KEY_LEN];
        char *preshared_key_file;
        uint32_t flags;
        uint16_t persistent_keepalive_interval;

        union sockaddr_union endpoint;
        char *endpoint_host;
        char *endpoint_port;

        unsigned n_retries;
        sd_event_source *resolve_retry_event_source;
        sd_resolve_query *resolve_query;

        uint32_t route_table;
        uint32_t route_priority;
        bool route_table_set;
        bool route_priority_set;

        LIST_HEAD(WireguardIPmask, ipmasks);
        LIST_FIELDS(struct WireguardPeer, peers);
} WireguardPeer;

struct Wireguard {
        NetDev meta;
        unsigned last_peer_section;

        uint32_t flags;
        uint8_t private_key[WG_KEY_LEN];
        char *private_key_file;
        uint16_t port;
        uint32_t fwmark;

        Hashmap *peers_by_section;
        LIST_HEAD(WireguardPeer, peers);

        Set *routes;
        uint32_t route_table;
        uint32_t route_priority;
};

DEFINE_NETDEV_CAST(WIREGUARD, Wireguard);
extern const NetDevVTable wireguard_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_allowed_ips);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_endpoint);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_listen_port);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_key);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_private_key);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_private_key_file);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_preshared_key_file);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_keepalive);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_route_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_route_priority);
