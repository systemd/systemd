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
typedef int (*address_netlink_handler_t)(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Address *address);

struct Address {
        Link *link;
        Network *network;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;
        union in_addr_union provider; /* DHCP server or router address */

        int family;
        unsigned char prefixlen;
        unsigned char scope;
        uint32_t flags;
        uint32_t route_metric; /* route metric for prefix route */
        char *label, *netlabel;

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

        /* duplicate_address_detection is only used by static or IPv4 dynamic addresses.
         * To control DAD for IPv6 dynamic addresses, set IFA_F_NODAD to flags. */
        AddressFamily duplicate_address_detection;
        sd_ipv4acd *acd;
        bool acd_bound;

        /* Called when address become ready */
        address_ready_callback_t callback;
};

const char* format_lifetime(char *buf, size_t l, usec_t lifetime_usec) _warn_unused_result_;
/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_LIFETIME(lifetime) \
        format_lifetime((char[FORMAT_TIMESPAN_MAX+STRLEN("for ")]){}, FORMAT_TIMESPAN_MAX+STRLEN("for "), lifetime)

int address_flags_to_string_alloc(uint32_t flags, int family, char **ret);

int address_new(Address **ret);
Address* address_free(Address *address);
int address_get(Link *link, const Address *in, Address **ret);
int address_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg);
int address_remove(Address *address);
int address_remove_and_drop(Address *address);
int address_dup(const Address *src, Address **ret);
bool address_is_ready(const Address *a);
void address_set_broadcast(Address *a, Link *link);

DEFINE_SECTION_CLEANUP_FUNCTIONS(Address, address_free);

int link_drop_managed_addresses(Link *link);
int link_drop_foreign_addresses(Link *link);
int link_drop_ipv6ll_addresses(Link *link);
void link_foreignize_addresses(Link *link);
bool link_address_is_dynamic(const Link *link, const Address *address);
int link_get_address(Link *link, int family, const union in_addr_union *address, unsigned char prefixlen, Address **ret);
static inline int link_get_ipv6_address(Link *link, const struct in6_addr *address, unsigned char prefixlen, Address **ret) {
        assert(address);
        return link_get_address(link, AF_INET6, &(union in_addr_union) { .in6 = *address }, prefixlen, ret);
}
static inline int link_get_ipv4_address(Link *link, const struct in_addr *address, unsigned char prefixlen, Address **ret) {
        assert(address);
        return link_get_address(link, AF_INET, &(union in_addr_union) { .in = *address }, prefixlen, ret);
}
int manager_get_address(Manager *manager, int family, const union in_addr_union *address, unsigned char prefixlen, Address **ret);
bool manager_has_address(Manager *manager, int family, const union in_addr_union *address, bool check_ready);

void address_cancel_request(Address *address);
int link_request_address(
                Link *link,
                Address *address,
                bool consume_object,
                unsigned *message_counter,
                address_netlink_handler_t netlink_handler,
                Request **ret);
int link_request_static_address(Link *link, Address *address, bool consume);
int link_request_static_addresses(Link *link);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, Manager *m);

int network_drop_invalid_addresses(Network *network);

int address_compare_func(const Address *a1, const Address *a2);
int address_equal(const Address *a1, const Address *a2);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(Address, address);

void link_mark_addresses(Link *link, NetworkConfigSource source);

CONFIG_PARSER_PROTOTYPE(config_parse_address);
CONFIG_PARSER_PROTOTYPE(config_parse_broadcast);
CONFIG_PARSER_PROTOTYPE(config_parse_label);
CONFIG_PARSER_PROTOTYPE(config_parse_lifetime);
CONFIG_PARSER_PROTOTYPE(config_parse_address_flags);
CONFIG_PARSER_PROTOTYPE(config_parse_address_scope);
CONFIG_PARSER_PROTOTYPE(config_parse_address_route_metric);
CONFIG_PARSER_PROTOTYPE(config_parse_duplicate_address_detection);
CONFIG_PARSER_PROTOTYPE(config_parse_address_netlabel);
