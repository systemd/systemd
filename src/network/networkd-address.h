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
#include "time-util.h"

typedef struct Address Address;
typedef struct Manager Manager;
typedef struct Network Network;
typedef struct Request Request;
typedef int (*address_ready_callback_t)(Address *address);

struct Address {
        Link *link;
        Network *network;
        NetworkConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;
        union in_addr_union provider; /* DHCP server or router address */

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        uint32_t route_metric; /* route metric for prefix route */
        char *label;

        int set_broadcast;
        struct in_addr broadcast;

        union in_addr_union in_addr;
        union in_addr_union in_addr_peer;

        /* These are absolute points in time, and NOT timespans/durations.
         * Must be specified with clock_boottime_or_monotonic(). */
        usec_t lifetime_valid_usec;
        usec_t lifetime_preferred_usec;

        bool scope_set:1;
        bool ip_masquerade_done:1;
        AddressFamily duplicate_address_detection;
        sd_ipv4acd *acd;

        /* Called when address become ready */
        address_ready_callback_t callback;
};

const char* format_lifetime(char *buf, size_t l, usec_t lifetime_usec) _warn_unused_result_;
/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_LIFETIME(lifetime) \
        format_lifetime((char[FORMAT_TIMESPAN_MAX+STRLEN("for ")]){}, FORMAT_TIMESPAN_MAX+STRLEN("for "), lifetime)

int address_new(Address **ret);
Address* address_free(Address *address);
int address_get(Link *link, const Address *in, Address **ret);
int address_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg);
int address_remove(Address *address);
int address_dup(const Address *src, Address **ret);
bool address_is_ready(const Address *a);
void address_set_broadcast(Address *a);

DEFINE_NETWORK_SECTION_FUNCTIONS(Address, address_free);

int link_drop_addresses(Link *link);
int link_drop_foreign_addresses(Link *link);
int link_drop_ipv6ll_addresses(Link *link);
bool link_address_is_dynamic(const Link *link, const Address *address);
int link_get_ipv6_address(Link *link, const struct in6_addr *address, Address **ret);
int link_get_ipv4_address(Link *link, const struct in_addr *address, unsigned char prefixlen, Address **ret);
int manager_has_address(Manager *manager, int family, const union in_addr_union *address, bool check_ready);

void address_cancel_request(Address *address);
int link_request_address(
                Link *link,
                Address *address,
                bool consume_object,
                unsigned *message_counter,
                link_netlink_message_handler_t netlink_handler,
                Request **ret);
int link_request_static_address(Link *link, Address *address, bool consume);
int link_request_static_addresses(Link *link);
int request_process_address(Request *req);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, Manager *m);

int network_drop_invalid_addresses(Network *network);

void address_hash_func(const Address *a, struct siphash *state);
int address_compare_func(const Address *a1, const Address *a2);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Address, address);
static inline void address_enter_probing(Address *address) {
        address_update_state(address, NETWORK_CONFIG_STATE_PROBING, NETWORK_CONFIG_STATE_PROBING);
}
static inline void address_cancel_probing(Address *address) {
        address_update_state(address, NETWORK_CONFIG_STATE_PROBING, 0);
}

void link_mark_addresses(Link *link, NetworkConfigSource source, const struct in6_addr *router);

CONFIG_PARSER_PROTOTYPE(config_parse_address);
CONFIG_PARSER_PROTOTYPE(config_parse_broadcast);
CONFIG_PARSER_PROTOTYPE(config_parse_label);
CONFIG_PARSER_PROTOTYPE(config_parse_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_address_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_address_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_address_route_metric);
CONFIG_PARSER_PROTOTYPE(config_parse_duplicate_address_detection);
