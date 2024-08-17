/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <linux/fib_rules.h>
#include <stdbool.h>

#include "conf-parser.h"
#include "in-addr-util.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef struct RoutingPolicyRule {
        Manager *manager;
        Network *network;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

        /* struct fib_rule_hdr */
        AddressFamily address_family; /* Specified by Family= */
        int family; /* Automatically determined by From= or To= */
        uint8_t to_prefixlen;
        uint8_t from_prefixlen;
        uint8_t tos;
        uint8_t type; /* a.k.a action */
        uint32_t flags;

        /* attributes */
        union in_addr_union to; /* FRA_DST */
        union in_addr_union from; /* FRA_SRC */
        char *iif; /* FRA_IIFNAME */
        /* FRA_GOTO */
        bool priority_set;
        uint32_t priority; /* FRA_PRIORITY */
        uint32_t fwmark; /* FRA_FWMARK */
        /* FRA_FLOW */
        /* FRA_TUN_ID */
        int32_t suppress_ifgroup; /* FRA_SUPPRESS_IFGROUP */
        int32_t suppress_prefixlen; /* FRA_SUPPRESS_PREFIXLEN */
        uint32_t table; /* FRA_TABLE, also used in struct fib_rule_hdr */
        uint32_t fwmask; /* FRA_FWMASK */
        char *oif; /* FRA_OIFNAME */
        bool l3mdev; /* FRA_L3MDEV */
        struct fib_rule_uid_range uid_range; /* FRA_UID_RANGE */
        uint8_t protocol; /* FRA_PROTOCOL */
        uint8_t ipproto; /* FRA_IP_PROTO */
        struct fib_rule_port_range sport; /* FRA_SPORT_RANGE */
        struct fib_rule_port_range dport; /* FRA_DPORT_RANGE */
} RoutingPolicyRule;

const char* fr_act_type_full_to_string(int t) _const_;

RoutingPolicyRule *routing_policy_rule_free(RoutingPolicyRule *rule);

void network_drop_invalid_routing_policy_rules(Network *network);

int link_request_static_routing_policy_rules(Link *link);

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);
int manager_drop_routing_policy_rules_internal(Manager *m, bool foreign, const Link *except);
static inline int manager_drop_foreign_routing_policy_rules(Manager *m) {
        return manager_drop_routing_policy_rules_internal(m, true, NULL);
}
static inline int link_drop_static_routing_policy_rules(Link *link) {
        assert(link);
        return manager_drop_routing_policy_rules_internal(link->manager, false, link);
}
void link_foreignize_routing_policy_rules(Link *link);

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(RoutingPolicyRule, routing_policy_rule);

CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_tos);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_table);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_fwmark_mask);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_prefix);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_device);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_l3mdev);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_port_range);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_ip_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_invert);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_family);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_uid_range);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_suppress_prefixlen);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_suppress_ifgroup);
CONFIG_PARSER_PROTOTYPE(config_parse_routing_policy_rule_type);
