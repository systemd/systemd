/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "conf-parser.h"
#include "firewall-util.h"
#include "hash-funcs.h"
#include "in-addr-util.h"
#include "network-util.h"
#include "networkd-address-generation.h"
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

        unsigned n_ref;

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
        bool requested_as_null:1;
        bool used_by_dhcp_server:1;
        /* If this address is configured by non-DHCPv6 protocol (i.e. statically, NDISC, or any foreign
         * methods), and the DHCPv6 client requests the same address, set this flag.
         * See link_check_addresses_ready() and verify_dhcp6_address(). */
        bool also_requested_by_dhcp6:1;

        /* duplicate_address_detection is only used by static or IPv4 dynamic addresses.
         * To control DAD for IPv6 dynamic addresses, set IFA_F_NODAD to flags. */
        AddressFamily duplicate_address_detection;

        /* Used by address generator. */
        IPv6Token *token;

        /* Called when address become ready */
        address_ready_callback_t callback;

        NFTSetContext nft_set_context;
};

const char* format_lifetime(char *buf, size_t l, usec_t lifetime_usec) _warn_unused_result_;
/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_LIFETIME(lifetime) \
        format_lifetime((char[FORMAT_TIMESPAN_MAX+STRLEN("for ")]){}, FORMAT_TIMESPAN_MAX+STRLEN("for "), lifetime)

int address_flags_to_string_alloc(uint32_t flags, int family, char **ret);

void link_get_address_states(
                Link *link,
                LinkAddressState *ret_ipv4,
                LinkAddressState *ret_ipv6,
                LinkAddressState *ret_all);

extern const struct hash_ops address_hash_ops;

bool address_can_update(const Address *existing, const Address *requesting);

Address* address_ref(Address *address);
Address* address_unref(Address *address);

int address_new(Address **ret);
int address_new_static(Network *network, const char *filename, unsigned section_line, Address **ret);
int address_get(Link *link, const Address *in, Address **ret);
int address_get_harder(Link *link, const Address *in, Address **ret);
int address_configure_handler_internal(sd_netlink *rtnl, sd_netlink_message *m, Link *link, const char *error_msg);
int address_remove(Address *address, Link *link);
int address_remove_and_cancel(Address *address, Link *link);
int address_dup(const Address *src, Address **ret);
bool address_is_ready(const Address *a);
bool link_check_addresses_ready(Link *link, NetworkConfigSource source);

DEFINE_SECTION_CLEANUP_FUNCTIONS(Address, address_unref);

int link_drop_static_addresses(Link *link);
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
bool manager_has_address(Manager *manager, int family, const union in_addr_union *address);

int link_request_address(
                Link *link,
                const Address *address,
                unsigned *message_counter,
                address_netlink_handler_t netlink_handler,
                Request **ret);
int link_request_static_address(Link *link, const Address *address);
int link_request_static_addresses(Link *link);

int manager_rtnl_process_address(sd_netlink *nl, sd_netlink_message *message, Manager *m);

int address_section_verify(Address *address);
int network_drop_invalid_addresses(Network *network);

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
CONFIG_PARSER_PROTOTYPE(config_parse_address_ip_nft_set);
