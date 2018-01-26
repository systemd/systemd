/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Susant Sahani

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <stdbool.h>

#include "in-addr-util.h"

typedef struct RoutingPolicyRule RoutingPolicyRule;

#include "networkd-link.h"
#include "networkd-network.h"

typedef struct Network Network;
typedef struct Link Link;
typedef struct NetworkConfigSection NetworkConfigSection;
typedef struct Manager Manager;

struct RoutingPolicyRule {
        Manager *manager;
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        uint8_t tos;

        uint32_t table;
        uint32_t fwmark;
        uint32_t fwmask;
        uint32_t priority;

        int family;
        unsigned char to_prefixlen;
        unsigned char from_prefixlen;

        char *iif;
        char *oif;

        union in_addr_union to;
        union in_addr_union from;

        LIST_FIELDS(RoutingPolicyRule, rules);
};

int routing_policy_rule_new(RoutingPolicyRule **ret);
void routing_policy_rule_free(RoutingPolicyRule *rule);

DEFINE_TRIVIAL_CLEANUP_FUNC(RoutingPolicyRule*, routing_policy_rule_free);
#define _cleanup_routing_policy_rule_free_ _cleanup_(routing_policy_rule_freep)

int routing_policy_rule_configure(RoutingPolicyRule *address, Link *link, sd_netlink_message_handler_t callback, bool update);
int routing_policy_rule_remove(RoutingPolicyRule *routing_policy_rule, Link *link, sd_netlink_message_handler_t callback);
int link_routing_policy_rule_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata);
int link_routing_policy_rule_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata);

int routing_policy_rule_add(Manager *m, int family, const union in_addr_union *from, uint8_t from_prefixlen, const union in_addr_union *to, uint8_t to_prefixlen,
                            uint8_t tos, uint32_t fwmark, uint32_t table, char *iif, char *oif, RoutingPolicyRule **ret);
int routing_policy_rule_add_foreign(Manager *m, int family, const union in_addr_union *from, uint8_t from_prefixlen, const union in_addr_union *to, uint8_t to_prefixlen,
                                    uint8_t tos, uint32_t fwmark, uint32_t table, char *iif, char *oif, RoutingPolicyRule **ret);
int routing_policy_rule_get(Manager *m, int family, const union in_addr_union *from, uint8_t from_prefixlen, const union in_addr_union *to, uint8_t to_prefixlen, uint8_t tos,
                            uint32_t fwmark, uint32_t table, char *iif, char *oif, RoutingPolicyRule **ret);
int routing_policy_rule_make_local(Manager *m, RoutingPolicyRule *rule);
int routing_policy_serialize_rules(Set *rules, FILE *f);
int routing_policy_load_rules(const char *state_file, Set **rules);
void routing_policy_rule_purge(Manager *m, Link *link);

int config_parse_routing_policy_rule_tos(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data,void *userdata);
int config_parse_routing_policy_rule_table(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_routing_policy_rule_fwmark_mask(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_routing_policy_rule_prefix(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_routing_policy_rule_priority(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data,void *userdata);
int config_parse_routing_policy_rule_device(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data,void *userdata);
