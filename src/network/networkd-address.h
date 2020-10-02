/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "sd-ipv4acd.h"

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-link.h"
#include "networkd-util.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU

typedef struct Manager Manager;
typedef struct Network Network;
typedef int (*address_ready_callback_t)(Address *address);

typedef struct Address {
        Network *network;
        NetworkConfigSection *section;

        Link *link;

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        char *label;

        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool scope_set:1;
        bool ip_masquerade_done:1;
        bool manage_temporary_address:1;
        bool home_address:1;
        bool prefix_route:1;
        bool autojoin:1;
        AddressFamily duplicate_address_detection;

        /* Called when address become ready */
        address_ready_callback_t callback;

        sd_ipv4acd *acd;
} Address;

int address_new(Address **ret);
Address *address_free(Address *address);
int address_get(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
bool address_exists(Link *link, int family, const union in_addr_union *in_addr);
int address_configure(Address *address, Link *link, link_netlink_message_handler_t callback, bool update, Address **ret);
int address_remove(Address *address, Link *link, link_netlink_message_handler_t callback);
bool address_equal(Address *a1, Address *a2);
bool address_is_ready(const Address *a);

int generate_ipv6_eui_64_address(Link *link, struct in6_addr *ret);

DEFINE_NETWORK_SECTION_FUNCTIONS(Address, address_free);

int link_set_addresses(Link *link);
int link_drop_addresses(Link *link);
int link_drop_foreign_addresses(Link *link);
int link_serialize_addresses(Link *link, FILE *f);
int link_deserialize_addresses(Link *link, const char *addresses);
int link_configure_ipv4_dad(Link *link);
int link_stop_ipv4_dad(Link *link);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, Manager *m);

void network_verify_addresses(Network *network);

void address_hash_func(const Address *a, struct siphash *state);
int address_compare_func(const Address *a1, const Address *a2);
extern const struct hash_ops address_hash_ops;

CONFIG_PARSER_PROTOTYPE(config_parse_address);
CONFIG_PARSER_PROTOTYPE(config_parse_broadcast);
CONFIG_PARSER_PROTOTYPE(config_parse_label);
CONFIG_PARSER_PROTOTYPE(config_parse_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_address_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_address_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_duplicate_address_detection);
