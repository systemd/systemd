/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <linux/amneziawg.h>
#include <linux/wireguard.h>

#include "in-addr-util.h"
#include "list.h"
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
        char *public_key_file;
        char *preshared_key_file;
        uint32_t flags;
        uint16_t persistent_keepalive_interval;
        uint16_t persistent_keepalive_interval_max;

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

typedef struct Wireguard {
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

        /* Indexed by netlink attribute; ranges pack the upper bound above the lower bound. */
        uint64_t amnezia_parameters[AWGDEVICE_A_MAX + 1];
        char *amnezia_signatures[5];
        uint8_t header_protection_key[WG_KEY_LEN];
        char *header_protection_key_file;
        bool header_protection_key_set;
} Wireguard;

static inline Wireguard* WIREGUARD(NetDev *netdev) {
        assert(netdev);
        assert(IN_SET(netdev->kind, NETDEV_KIND_WIREGUARD, NETDEV_KIND_AMNEZIAWG));
        assert(netdev->state < _NETDEV_STATE_MAX);

        return (Wireguard*) netdev;
}

extern const NetDevVTable wireguard_vtable;
extern const NetDevVTable amneziawg_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_amneziawg_parameter);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_allowed_ips);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_endpoint);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_listen_port);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_key);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_key_file);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_private_key);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_private_key_file);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_keepalive);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_route_table);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_route_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_wireguard_peer_route_priority);
