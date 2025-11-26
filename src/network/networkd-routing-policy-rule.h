/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fib_rules.h>

#include "in-addr-prefix-util.h"
#include "networkd-forward.h"
#include "networkd-util.h"

typedef struct RoutingPolicyRule {
        /* Pointers and other 8-byte aligned types */
        Manager *manager;
        Network *network;
        ConfigSection *section;
        char *iif; /* FRA_IIFNAME */
        char *oif; /* FRA_OIFNAME */

        /* Large structs */
        struct in_addr_prefix to; /* FRA_DST */
        struct in_addr_prefix from; /* FRA_SRC */
        struct fib_rule_uid_range uid_range; /* FRA_UID_RANGE */
        struct fib_rule_port_range sport; /* FRA_SPORT_RANGE */
        struct fib_rule_port_range dport; /* FRA_DPORT_RANGE */

        /* 64-bit integers */
        uint64_t tunnel_id; /* FRA_TUN_ID */

        /* 32-bit integers and enums */
        NetworkConfigSource source;
        NetworkConfigState state;
        unsigned n_ref;
        AddressFamily address_family; /* Used when parsing Family= */
        int family; /* Automatically determined by From=, To=, and Family= */
        uint32_t flags;
        uint32_t priority_goto; /* FRA_GOTO */
        uint32_t priority; /* FRA_PRIORITY */
        uint32_t fwmark; /* FRA_FWMARK */
        uint32_t realms; /* FRA_FLOW (IPv4 only) */
        int32_t suppress_ifgroup; /* FRA_SUPPRESS_IFGROUP */
        int32_t suppress_prefixlen; /* FRA_SUPPRESS_PREFIXLEN */
        uint32_t table; /* FRA_TABLE, also used in struct fib_rule_hdr */
        uint32_t fwmask; /* FRA_FWMASK */

        /* 8-bit integers and booleans */
        uint8_t tos;
        uint8_t action;
        uint8_t protocol; /* FRA_PROTOCOL */
        uint8_t ipproto; /* FRA_IP_PROTO */
        bool l3mdev; /* FRA_L3MDEV */
        bool priority_set:1;
} RoutingPolicyRule;

int fr_act_type_from_string(const char *s) _pure_;
const char* fr_act_type_to_string(int t) _const_;

RoutingPolicyRule* routing_policy_rule_ref(RoutingPolicyRule *rule);
RoutingPolicyRule* routing_policy_rule_unref(RoutingPolicyRule *rule);

void network_drop_invalid_routing_policy_rules(Network *network);

int link_request_static_routing_policy_rules(Link *link);

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

int link_drop_routing_policy_rules(Link *link, bool only_static);
static inline int link_drop_unmanaged_routing_policy_rules(Link *link) {
        return link_drop_routing_policy_rules(link, false);
}
static inline int link_drop_static_routing_policy_rules(Link *link) {
        return link_drop_routing_policy_rules(link, true);
}

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(RoutingPolicyRule, routing_policy_rule);

typedef enum RoutingPolicyRuleConfParserType {
        ROUTING_POLICY_RULE_IIF,
        ROUTING_POLICY_RULE_OIF,
        ROUTING_POLICY_RULE_FAMILY,
        ROUTING_POLICY_RULE_FWMARK,
        ROUTING_POLICY_RULE_GOTO,
        ROUTING_POLICY_RULE_INVERT,
        ROUTING_POLICY_RULE_IP_PROTOCOL,
        ROUTING_POLICY_RULE_L3MDEV,
        ROUTING_POLICY_RULE_SPORT,
        ROUTING_POLICY_RULE_DPORT,
        ROUTING_POLICY_RULE_FROM,
        ROUTING_POLICY_RULE_TO,
        ROUTING_POLICY_RULE_PRIORITY,
        ROUTING_POLICY_RULE_SUPPRESS_IFGROUP,
        ROUTING_POLICY_RULE_SUPPRESS_PREFIXLEN,
        ROUTING_POLICY_RULE_TABLE,
        ROUTING_POLICY_RULE_TOS,
        ROUTING_POLICY_RULE_ACTION,
        ROUTING_POLICY_RULE_UID_RANGE,
        _ROUTING_POLICY_RULE_CONF_PARSER_MAX,
        _ROUTING_POLICY_RULE_CONF_PARSER_INVALID = -EINVAL,
} RoutingPolicyRuleConfParserType;

CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule);
