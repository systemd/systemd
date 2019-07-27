/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct Address Address;

#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

#define CACHE_INFO_INFINITY_LIFE_TIME 0xFFFFFFFFU

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;

struct Address {
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

        bool ip_masquerade_done:1;
        bool duplicate_address_detection;
        bool manage_temporary_address;
        bool home_address;
        bool prefix_route;
        bool autojoin;

        LIST_FIELDS(Address, addresses);
};

int address_new(Address **ret);
void address_free(Address *address);
int address_add_foreign(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_add(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_get(Link *link, int family, const union in_addr_union *in_addr, unsigned char prefixlen, Address **ret);
int address_update(Address *address, unsigned char flags, unsigned char scope, const struct ifa_cacheinfo *cinfo);
int address_drop(Address *address);
int address_configure(Address *address, Link *link, link_netlink_message_handler_t callback, bool update);
int address_remove(Address *address, Link *link, link_netlink_message_handler_t callback);
bool address_equal(Address *a1, Address *a2);
bool address_is_ready(const Address *a);
int address_section_verify(Address *a);

DEFINE_NETWORK_SECTION_FUNCTIONS(Address, address_free);

CONFIG_PARSER_PROTOTYPE(config_parse_address);
CONFIG_PARSER_PROTOTYPE(config_parse_broadcast);
CONFIG_PARSER_PROTOTYPE(config_parse_label);
CONFIG_PARSER_PROTOTYPE(config_parse_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_address_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_address_scope);
