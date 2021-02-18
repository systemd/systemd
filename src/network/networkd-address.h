/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

        int set_broadcast;
        struct in_addr broadcast;
        struct ifa_cacheinfo cinfo;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        bool scope_set:1;
        bool ip_masquerade_done:1;
        AddressFamily duplicate_address_detection;

        /* Called when address become ready */
        address_ready_callback_t callback;

        sd_ipv4acd *acd;
} Address;

int address_new(Address **ret);
Address *address_free(Address *address);
int address_get(Link *link, const Address *in, Address **ret);
int address_configure(const Address *address, Link *link, link_netlink_message_handler_t callback, Address **ret);
int address_remove(const Address *address, Link *link, link_netlink_message_handler_t callback);
bool address_equal(const Address *a1, const Address *a2);
bool address_is_ready(const Address *a);

int generate_ipv6_eui_64_address(const Link *link, struct in6_addr *ret);

DEFINE_NETWORK_SECTION_FUNCTIONS(Address, address_free);

int link_set_addresses(Link *link);
int link_drop_addresses(Link *link);
int link_drop_foreign_addresses(Link *link);
bool link_address_is_dynamic(const Link *link, const Address *address);
int link_has_ipv6_address(Link *link, const struct in6_addr *address);

void ipv4_dad_unref(Link *link);
int ipv4_dad_stop(Link *link);
int ipv4_dad_update_mac(Link *link);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, Manager *m);

void network_drop_invalid_addresses(Network *network);

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

#define IPV4_ADDRESS_FMT_STR     "%u.%u.%u.%u"
#define IPV4_ADDRESS_FMT_VAL(address)              \
        be32toh((address).s_addr) >> 24,           \
        (be32toh((address).s_addr) >> 16) & 0xFFu, \
        (be32toh((address).s_addr) >> 8) & 0xFFu,  \
        be32toh((address).s_addr) & 0xFFu
