/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/fib_rules.h>

#include "af-list.h"
#include "alloc-util.h"
#include "conf-parser.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "ip-protocol-list.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-queue.h"
#include "networkd-route-util.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static const char *const fr_act_type_table[__FR_ACT_MAX] = {
        [FR_ACT_BLACKHOLE]   = "blackhole",
        [FR_ACT_UNREACHABLE] = "unreachable",
        [FR_ACT_PROHIBIT]    = "prohibit",
};

static const char *const fr_act_type_full_table[__FR_ACT_MAX] = {
        [FR_ACT_TO_TBL]      = "table",
        [FR_ACT_GOTO]        = "goto",
        [FR_ACT_NOP]         = "nop",
        [FR_ACT_BLACKHOLE]   = "blackhole",
        [FR_ACT_UNREACHABLE] = "unreachable",
        [FR_ACT_PROHIBIT]    = "prohibit",
};

assert_cc(__FR_ACT_MAX <= UINT8_MAX);
DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(fr_act_type, int);
DEFINE_STRING_TABLE_LOOKUP_TO_STRING(fr_act_type_full, int);

RoutingPolicyRule *routing_policy_rule_free(RoutingPolicyRule *rule) {
        if (!rule)
                return NULL;

        if (rule->network) {
                assert(rule->section);
                hashmap_remove(rule->network->rules_by_section, rule->section);
        }

        if (rule->manager)
                set_remove(rule->manager->rules, rule);

        config_section_free(rule->section);
        free(rule->iif);
        free(rule->oif);

        return mfree(rule);
}

DEFINE_SECTION_CLEANUP_FUNCTIONS(RoutingPolicyRule, routing_policy_rule_free);

static int routing_policy_rule_new(RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        rule = new(RoutingPolicyRule, 1);
        if (!rule)
                return -ENOMEM;

        *rule = (RoutingPolicyRule) {
                .table = RT_TABLE_MAIN,
                .uid_range.start = UID_INVALID,
                .uid_range.end = UID_INVALID,
                .suppress_prefixlen = -1,
                .suppress_ifgroup = -1,
                .protocol = RTPROT_UNSPEC,
                .type = FR_ACT_TO_TBL,
        };

        *ret = rule;
        return 0;
}

static int routing_policy_rule_new_static(Network *network, const char *filename, unsigned section_line, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        rule = hashmap_get(network->rules_by_section, n);
        if (rule) {
                *ret = TAKE_PTR(rule);
                return 0;
        }

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        rule->network = network;
        rule->section = TAKE_PTR(n);
        rule->source = NETWORK_CONFIG_SOURCE_STATIC;
        rule->protocol = RTPROT_STATIC;

        r = hashmap_ensure_put(&network->rules_by_section, &config_section_hash_ops, rule->section, rule);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(rule);
        return 0;
}

static int routing_policy_rule_dup(const RoutingPolicyRule *src, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *dest = NULL;

        assert(src);
        assert(ret);

        dest = newdup(RoutingPolicyRule, src, 1);
        if (!dest)
                return -ENOMEM;

        /* Unset all pointers */
        dest->manager = NULL;
        dest->network = NULL;
        dest->section = NULL;
        dest->iif = dest->oif = NULL;

        if (src->iif) {
                dest->iif = strdup(src->iif);
                if (!dest->iif)
                        return -ENOMEM;
        }

        if (src->oif) {
                dest->oif = strdup(src->oif);
                if (!dest->oif)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(dest);
        return 0;
}

static void routing_policy_rule_hash_func(const RoutingPolicyRule *rule, struct siphash *state) {
        assert(rule);

        siphash24_compress_typesafe(rule->family, state);

        switch (rule->family) {
        case AF_INET:
        case AF_INET6:
                in_addr_hash_func(&rule->from, rule->family, state);
                siphash24_compress_typesafe(rule->from_prefixlen, state);

                in_addr_hash_func(&rule->to, rule->family, state);
                siphash24_compress_typesafe(rule->to_prefixlen, state);

                siphash24_compress_boolean(rule->invert_rule, state);

                siphash24_compress_typesafe(rule->tos, state);
                siphash24_compress_typesafe(rule->type, state);
                siphash24_compress_typesafe(rule->fwmark, state);
                siphash24_compress_typesafe(rule->fwmask, state);
                siphash24_compress_typesafe(rule->priority, state);
                siphash24_compress_typesafe(rule->table, state);
                siphash24_compress_typesafe(rule->suppress_prefixlen, state);
                siphash24_compress_typesafe(rule->suppress_ifgroup, state);

                siphash24_compress_typesafe(rule->ipproto, state);
                siphash24_compress_typesafe(rule->protocol, state);
                siphash24_compress_typesafe(rule->sport, state);
                siphash24_compress_typesafe(rule->dport, state);
                siphash24_compress_typesafe(rule->uid_range, state);

                siphash24_compress_string(rule->iif, state);
                siphash24_compress_string(rule->oif, state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int routing_policy_rule_compare_func(const RoutingPolicyRule *a, const RoutingPolicyRule *b) {
        int r;

        r = CMP(a->family, b->family);
        if (r != 0)
                return r;

        switch (a->family) {
        case AF_INET:
        case AF_INET6:
                r = CMP(a->from_prefixlen, b->from_prefixlen);
                if (r != 0)
                        return r;

                r = memcmp(&a->from, &b->from, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = CMP(a->to_prefixlen, b->to_prefixlen);
                if (r != 0)
                        return r;

                r = memcmp(&a->to, &b->to, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = CMP(a->invert_rule, b->invert_rule);
                if (r != 0)
                        return r;

                r = CMP(a->tos, b->tos);
                if (r != 0)
                        return r;

                r = CMP(a->type, b->type);
                if (r != 0)
                        return r;

                r = CMP(a->fwmark, b->fwmark);
                if (r != 0)
                        return r;

                r = CMP(a->fwmask, b->fwmask);
                if (r != 0)
                        return r;

                r = CMP(a->priority, b->priority);
                if (r != 0)
                        return r;

                r = CMP(a->table, b->table);
                if (r != 0)
                        return r;

                r = CMP(a->suppress_prefixlen, b->suppress_prefixlen);
                if (r != 0)
                        return r;

                r = CMP(a->suppress_ifgroup, b->suppress_ifgroup);
                if (r != 0)
                        return r;

                r = CMP(a->ipproto, b->ipproto);
                if (r != 0)
                        return r;

                r = CMP(a->protocol, b->protocol);
                if (r != 0)
                        return r;

                r = memcmp(&a->sport, &b->sport, sizeof(a->sport));
                if (r != 0)
                        return r;

                r = memcmp(&a->dport, &b->dport, sizeof(a->dport));
                if (r != 0)
                        return r;

                r = memcmp(&a->uid_range, &b->uid_range, sizeof(a->uid_range));
                if (r != 0)
                        return r;

                r = strcmp_ptr(a->iif, b->iif);
                if (r != 0)
                        return r;

                r = strcmp_ptr(a->oif, b->oif);
                if (r != 0)
                        return r;

                return 0;
        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

static bool routing_policy_rule_equal(const RoutingPolicyRule *rule1, const RoutingPolicyRule *rule2) {
        if (rule1 == rule2)
                return true;

        if (!rule1 || !rule2)
                return false;

        return routing_policy_rule_compare_func(rule1, rule2) == 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                routing_policy_rule_hash_ops,
                RoutingPolicyRule,
                routing_policy_rule_hash_func,
                routing_policy_rule_compare_func,
                routing_policy_rule_free);

static int routing_policy_rule_get(Manager *m, const RoutingPolicyRule *in, RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        assert(m);
        assert(in);

        rule = set_get(m->rules, in);
        if (rule) {
                if (ret)
                        *ret = rule;
                return 0;
        }

        if (in->priority_set)
                return -ENOENT;

        /* Also find rules configured without priority. */
        SET_FOREACH(rule, m->rules) {
                uint32_t priority;
                bool found;

                if (rule->priority_set)
                        /* The rule is configured with priority. */
                        continue;

                priority = rule->priority;
                rule->priority = 0;
                found = routing_policy_rule_equal(rule, in);
                rule->priority = priority;

                if (found) {
                        if (ret)
                                *ret = rule;
                        return 0;
                }
        }

        return -ENOENT;
}

static int routing_policy_rule_add(Manager *m, RoutingPolicyRule *rule) {
        int r;

        assert(m);
        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));

        r = set_ensure_put(&m->rules, &routing_policy_rule_hash_ops, rule);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        rule->manager = m;
        return 0;
}

static int routing_policy_rule_acquire_priority(Manager *manager, RoutingPolicyRule *rule) {
        _cleanup_set_free_ Set *priorities = NULL;
        RoutingPolicyRule *tmp;
        uint32_t priority;
        Network *network;
        int r;

        assert(manager);
        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));

        if (rule->priority_set)
                return 0;

        /* Find the highest unused priority. Note that 32766 is already used by kernel.
         * See kernel_rules[] below. */

        SET_FOREACH(tmp, manager->rules) {
                if (tmp->family != rule->family)
                        continue;
                if (tmp->priority == 0 || tmp->priority > 32765)
                        continue;
                r = set_ensure_put(&priorities, NULL, UINT32_TO_PTR(tmp->priority));
                if (r < 0)
                        return r;
        }

        ORDERED_HASHMAP_FOREACH(network, manager->networks)
                HASHMAP_FOREACH(tmp, network->rules_by_section) {
                        if (tmp->family != AF_UNSPEC && tmp->family != rule->family)
                                continue;
                        if (!tmp->priority_set)
                                continue;
                        if (tmp->priority == 0 || tmp->priority > 32765)
                                continue;
                        r = set_ensure_put(&priorities, NULL, UINT32_TO_PTR(tmp->priority));
                        if (r < 0)
                                return r;
                }

        for (priority = 32765; priority > 0; priority--)
                if (!set_contains(priorities, UINT32_TO_PTR(priority)))
                        break;

        rule->priority = priority;
        return 0;
}

static void log_routing_policy_rule_debug(const RoutingPolicyRule *rule, const char *str, const Link *link, const Manager *m) {
        _cleanup_free_ char *state = NULL, *table = NULL;

        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));
        assert(str);
        assert(m);

        /* link may be NULL. */

        if (!DEBUG_LOGGING)
                return;

        (void) network_config_state_to_string_alloc(rule->state, &state);
        (void) manager_get_route_table_to_string(m, rule->table, /* append_num = */ true, &table);

        log_link_debug(link,
                       "%s %s routing policy rule (%s): priority: %"PRIu32", %s -> %s, iif: %s, oif: %s, table: %s",
                       str, strna(network_config_source_to_string(rule->source)), strna(state),
                       rule->priority,
                       IN_ADDR_PREFIX_TO_STRING(rule->family, &rule->from, rule->from_prefixlen),
                       IN_ADDR_PREFIX_TO_STRING(rule->family, &rule->to, rule->to_prefixlen),
                       strna(rule->iif), strna(rule->oif), strna(table));
}

static int routing_policy_rule_set_netlink_message(const RoutingPolicyRule *rule, sd_netlink_message *m, Link *link) {
        int r;

        assert(rule);
        assert(m);

        /* link may be NULL. */

        if (rule->from_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, FRA_SRC, rule->family, &rule->from);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_routing_policy_rule_set_fib_src_prefixlen(m, rule->from_prefixlen);
                if (r < 0)
                        return r;
        }

        if (rule->to_prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, FRA_DST, rule->family, &rule->to);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_routing_policy_rule_set_fib_dst_prefixlen(m, rule->to_prefixlen);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u32(m, FRA_PRIORITY, rule->priority);
        if (r < 0)
                return r;

        if (rule->tos > 0) {
                r = sd_rtnl_message_routing_policy_rule_set_tos(m, rule->tos);
                if (r < 0)
                        return r;
        }

        if (rule->table < 256) {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, rule->table);
                if (r < 0)
                        return r;
        } else {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, RT_TABLE_UNSPEC);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u32(m, FRA_TABLE, rule->table);
                if (r < 0)
                        return r;
        }

        if (rule->fwmark > 0) {
                r = sd_netlink_message_append_u32(m, FRA_FWMARK, rule->fwmark);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u32(m, FRA_FWMASK, rule->fwmask);
                if (r < 0)
                        return r;
        }

        if (rule->iif) {
                r = sd_netlink_message_append_string(m, FRA_IIFNAME, rule->iif);
                if (r < 0)
                        return r;
        }

        if (rule->oif) {
                r = sd_netlink_message_append_string(m, FRA_OIFNAME, rule->oif);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, FRA_IP_PROTO, rule->ipproto);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, FRA_PROTOCOL, rule->protocol);
        if (r < 0)
                return r;

        if (rule->sport.start != 0 || rule->sport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_SPORT_RANGE, &rule->sport, sizeof(rule->sport));
                if (r < 0)
                        return r;
        }

        if (rule->dport.start != 0 || rule->dport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_DPORT_RANGE, &rule->dport, sizeof(rule->dport));
                if (r < 0)
                        return r;
        }

        if (rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID) {
                r = sd_netlink_message_append_data(m, FRA_UID_RANGE, &rule->uid_range, sizeof(rule->uid_range));
                if (r < 0)
                        return r;
        }

        if (rule->invert_rule) {
                r = sd_rtnl_message_routing_policy_rule_set_flags(m, FIB_RULE_INVERT);
                if (r < 0)
                        return r;
        }

        if (rule->suppress_prefixlen >= 0) {
                r = sd_netlink_message_append_u32(m, FRA_SUPPRESS_PREFIXLEN, (uint32_t) rule->suppress_prefixlen);
                if (r < 0)
                        return r;
        }

        if (rule->suppress_ifgroup >= 0) {
                r = sd_netlink_message_append_u32(m, FRA_SUPPRESS_IFGROUP, (uint32_t) rule->suppress_ifgroup);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_routing_policy_rule_set_fib_type(m, rule->type);
        if (r < 0)
                return r;

        return 0;
}

static int routing_policy_rule_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        int r;

        assert(m);

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_message_warning_errno(m, r, "Could not drop routing policy rule");

        return 1;
}

static int routing_policy_rule_remove(RoutingPolicyRule *rule) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(rule->manager);
        assert(rule->manager->rtnl);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));

        log_routing_policy_rule_debug(rule, "Removing", NULL, rule->manager);

        r = sd_rtnl_message_new_routing_policy_rule(rule->manager->rtnl, &m, RTM_DELRULE, rule->family);
        if (r < 0)
                return log_warning_errno(r, "Could not allocate netlink message: %m");

        r = routing_policy_rule_set_netlink_message(rule, m, NULL);
        if (r < 0)
                return log_warning_errno(r, "Could not create netlink message: %m");

        r = netlink_call_async(rule->manager->rtnl, NULL, m,
                               routing_policy_rule_remove_handler,
                               NULL, NULL);
        if (r < 0)
                return log_warning_errno(r, "Could not send netlink message: %m");

        routing_policy_rule_enter_removing(rule);
        return 0;
}

static int routing_policy_rule_configure(RoutingPolicyRule *rule, Link *link, Request *req) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(req);

        log_routing_policy_rule_debug(rule, "Configuring", link, link->manager);

        r = sd_rtnl_message_new_routing_policy_rule(link->manager->rtnl, &m, RTM_NEWRULE, rule->family);
        if (r < 0)
                return r;

        r = routing_policy_rule_set_netlink_message(rule, m, link);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static void manager_mark_routing_policy_rules(Manager *m, bool foreign, const Link *except) {
        RoutingPolicyRule *rule;
        Link *link;

        assert(m);

        /* First, mark all existing rules. */
        SET_FOREACH(rule, m->rules) {
                /* Do not touch rules managed by kernel. */
                if (rule->protocol == RTPROT_KERNEL)
                        continue;

                /* When 'foreign' is true, mark only foreign rules, and vice versa. */
                if (foreign != (rule->source == NETWORK_CONFIG_SOURCE_FOREIGN))
                        continue;

                /* Ignore rules not assigned yet or already removing. */
                if (!routing_policy_rule_exists(rule))
                        continue;

                routing_policy_rule_mark(rule);
        }

        /* Then, unmark all rules requested by active links. */
        HASHMAP_FOREACH(link, m->links_by_index) {
                if (link == except)
                        continue;

                if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                HASHMAP_FOREACH(rule, link->network->rules_by_section) {
                        RoutingPolicyRule *existing;

                        if (IN_SET(rule->family, AF_INET, AF_INET6)) {
                                if (routing_policy_rule_get(m, rule, &existing) >= 0)
                                        routing_policy_rule_unmark(existing);
                        } else {
                                /* The case Family=both. */
                                rule->family = AF_INET;
                                if (routing_policy_rule_get(m, rule, &existing) >= 0)
                                        routing_policy_rule_unmark(existing);

                                rule->family = AF_INET6;
                                if (routing_policy_rule_get(m, rule, &existing) >= 0)
                                        routing_policy_rule_unmark(existing);

                                rule->family = AF_UNSPEC;
                        }
                }
        }
}

int manager_drop_routing_policy_rules_internal(Manager *m, bool foreign, const Link *except) {
        RoutingPolicyRule *rule;
        int r = 0;

        assert(m);

        manager_mark_routing_policy_rules(m, foreign, except);

        SET_FOREACH(rule, m->rules) {
                if (!routing_policy_rule_is_marked(rule))
                        continue;

                RET_GATHER(r, routing_policy_rule_remove(rule));
        }

        return r;
}

void link_foreignize_routing_policy_rules(Link *link) {
        RoutingPolicyRule *rule;

        assert(link);
        assert(link->manager);

        manager_mark_routing_policy_rules(link->manager, /* foreign = */ false, link);

        SET_FOREACH(rule, link->manager->rules) {
                if (!routing_policy_rule_is_marked(rule))
                        continue;

                rule->source = NETWORK_CONFIG_SOURCE_FOREIGN;
        }
}

static int routing_policy_rule_process_request(Request *req, Link *link, RoutingPolicyRule *rule) {
        int r;

        assert(req);
        assert(link);
        assert(rule);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = routing_policy_rule_configure(rule, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure routing policy rule: %m");

        routing_policy_rule_enter_configuring(rule);
        return 1;
}

static int static_routing_policy_rule_configure_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                RoutingPolicyRule *rule) {

        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add routing policy rule");
                link_enter_failed(link);
                return 1;
        }

        if (link->static_routing_policy_rule_messages == 0) {
                log_link_debug(link, "Routing policy rule configured");
                link->static_routing_policy_rules_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_request_routing_policy_rule(Link *link, RoutingPolicyRule *rule) {
        RoutingPolicyRule *existing;
        int r;

        assert(link);
        assert(link->manager);
        assert(rule);
        assert(rule->source != NETWORK_CONFIG_SOURCE_FOREIGN);

        if (routing_policy_rule_get(link->manager, rule, &existing) < 0) {
                _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *tmp = NULL;

                r = routing_policy_rule_dup(rule, &tmp);
                if (r < 0)
                        return r;

                r = routing_policy_rule_acquire_priority(link->manager, tmp);
                if (r < 0)
                        return r;

                r = routing_policy_rule_add(link->manager, tmp);
                if (r < 0)
                        return r;

                existing = TAKE_PTR(tmp);
        } else
                existing->source = rule->source;

        log_routing_policy_rule_debug(existing, "Requesting", link, link->manager);
        r = link_queue_request_safe(link, REQUEST_TYPE_ROUTING_POLICY_RULE,
                                    existing, NULL,
                                    routing_policy_rule_hash_func,
                                    routing_policy_rule_compare_func,
                                    routing_policy_rule_process_request,
                                    &link->static_routing_policy_rule_messages,
                                    static_routing_policy_rule_configure_handler,
                                    NULL);
        if (r <= 0)
                return r;

        routing_policy_rule_enter_requesting(existing);
        return 1;
}

static int link_request_static_routing_policy_rule(Link *link, RoutingPolicyRule *rule) {
        int r;

        if (IN_SET(rule->family, AF_INET, AF_INET6))
                return link_request_routing_policy_rule(link, rule);

        rule->family = AF_INET;
        r = link_request_routing_policy_rule(link, rule);
        if (r < 0) {
                rule->family = AF_UNSPEC;
                return r;
        }

        rule->family = AF_INET6;
        r = link_request_routing_policy_rule(link, rule);
        rule->family = AF_UNSPEC;
        return r;
}

int link_request_static_routing_policy_rules(Link *link) {
        RoutingPolicyRule *rule;
        int r;

        assert(link);
        assert(link->network);

        link->static_routing_policy_rules_configured = false;

        HASHMAP_FOREACH(rule, link->network->rules_by_section) {
                r = link_request_static_routing_policy_rule(link, rule);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not request routing policy rule: %m");
        }

        if (link->static_routing_policy_rule_messages == 0) {
                link->static_routing_policy_rules_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Requesting routing policy rules");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static const RoutingPolicyRule kernel_rules[] = {
        { .family = AF_INET,  .priority_set = true, .priority = 0,     .table = RT_TABLE_LOCAL,   .type = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET,  .priority_set = true, .priority = 32766, .table = RT_TABLE_MAIN,    .type = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET,  .priority_set = true, .priority = 32767, .table = RT_TABLE_DEFAULT, .type = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET6, .priority_set = true, .priority = 0,     .table = RT_TABLE_LOCAL,   .type = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET6, .priority_set = true, .priority = 32766, .table = RT_TABLE_MAIN,    .type = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
};

static bool routing_policy_rule_is_created_by_kernel(const RoutingPolicyRule *rule) {
        assert(rule);

        if (rule->l3mdev > 0)
                /* Currently, [RoutingPolicyRule] does not explicitly set FRA_L3MDEV. So, if the flag
                 * is set, it is safe to treat the rule as created by kernel. */
                return true;

        for (size_t i = 0; i < ELEMENTSOF(kernel_rules); i++)
                if (routing_policy_rule_equal(rule, &kernel_rules[i]))
                        return true;

        return false;
}

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *tmp = NULL;
        RoutingPolicyRule *rule = NULL;
        bool adjust_protocol = false;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(message);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive rule message, ignoring");

                return 0;
        }

        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWRULE, RTM_DELRULE)) {
                log_warning("rtnl: received unexpected message type %u when processing rule, ignoring.", type);
                return 0;
        }

        r = routing_policy_rule_new(&tmp);
        if (r < 0) {
                log_oom();
                return 0;
        }

        r = sd_rtnl_message_get_family(message, &tmp->family);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get rule family, ignoring: %m");
                return 0;
        } else if (!IN_SET(tmp->family, AF_INET, AF_INET6)) {
                log_debug("rtnl: received rule message with invalid family %d, ignoring.", tmp->family);
                return 0;
        }

        r = netlink_message_read_in_addr_union(message, FRA_SRC, tmp->family, &tmp->from);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = sd_rtnl_message_routing_policy_rule_get_fib_src_prefixlen(message, &tmp->from_prefixlen);
                if (r < 0) {
                        log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                        return 0;
                }
        }

        r = netlink_message_read_in_addr_union(message, FRA_DST, tmp->family, &tmp->to);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = sd_rtnl_message_routing_policy_rule_get_fib_dst_prefixlen(message, &tmp->to_prefixlen);
                if (r < 0) {
                        log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                        return 0;
                }
        }

        unsigned flags;
        r = sd_rtnl_message_routing_policy_rule_get_flags(message, &flags);
        if (r < 0) {
                log_warning_errno(r, "rtnl: received rule message without valid flag, ignoring: %m");
                return 0;
        }
        tmp->invert_rule = flags & FIB_RULE_INVERT;

        r = sd_netlink_message_read_u32(message, FRA_FWMARK, &tmp->fwmark);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_FWMARK attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, FRA_FWMASK, &tmp->fwmask);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_FWMASK attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u32(message, FRA_PRIORITY, &tmp->priority);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_PRIORITY attribute, ignoring: %m");
                return 0;
        }
        /* The kernel does not send priority if priority is zero. So, the flag below must be always set
         * even if the message does not contain FRA_PRIORITY. */
        tmp->priority_set = true;

        r = sd_netlink_message_read_u32(message, FRA_TABLE, &tmp->table);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_TABLE attribute, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_routing_policy_rule_get_tos(message, &tmp->tos);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FIB rule TOS, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_routing_policy_rule_get_fib_type(message, &tmp->type);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FIB rule type, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, FRA_IIFNAME, &tmp->iif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IIFNAME attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string_strdup(message, FRA_OIFNAME, &tmp->oif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_OIFNAME attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u8(message, FRA_IP_PROTO, &tmp->ipproto);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IP_PROTO attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u8(message, FRA_PROTOCOL, &tmp->protocol);
        if (r == -ENODATA)
                /* If FRA_PROTOCOL is supported by kernel, then the attribute is always appended.
                 * When the received message does not have FRA_PROTOCOL, then we need to adjust the
                 * protocol of the rule later. */
                adjust_protocol = true;
        else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get FRA_PROTOCOL attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_u8(message, FRA_L3MDEV, &tmp->l3mdev);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_L3MDEV attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read(message, FRA_SPORT_RANGE, sizeof(tmp->sport), &tmp->sport);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SPORT_RANGE attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read(message, FRA_DPORT_RANGE, sizeof(tmp->dport), &tmp->dport);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_DPORT_RANGE attribute, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read(message, FRA_UID_RANGE, sizeof(tmp->uid_range), &tmp->uid_range);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_UID_RANGE attribute, ignoring: %m");
                return 0;
        }

        uint32_t suppress_prefixlen;
        r = sd_netlink_message_read_u32(message, FRA_SUPPRESS_PREFIXLEN, &suppress_prefixlen);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SUPPRESS_PREFIXLEN attribute, ignoring: %m");
                return 0;
        }
        if (r >= 0)
                tmp->suppress_prefixlen = (int32_t) suppress_prefixlen;

        uint32_t suppress_ifgroup;
        r = sd_netlink_message_read_u32(message, FRA_SUPPRESS_IFGROUP, &suppress_ifgroup);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SUPPRESS_IFGROUP attribute, ignoring: %m");
                return 0;
        }
        if (r >= 0)
                tmp->suppress_ifgroup = (int32_t) suppress_ifgroup;

        if (adjust_protocol)
                /* As .network files does not have setting to specify protocol, we can assume the
                 * protocol of the received rule is RTPROT_KERNEL or RTPROT_STATIC. */
                tmp->protocol = routing_policy_rule_is_created_by_kernel(tmp) ? RTPROT_KERNEL : RTPROT_STATIC;

        (void) routing_policy_rule_get(m, tmp, &rule);

        switch (type) {
        case RTM_NEWRULE:
                if (rule) {
                        routing_policy_rule_enter_configured(rule);
                        log_routing_policy_rule_debug(rule, "Received remembered", NULL, m);
                } else if (!m->manage_foreign_rules) {
                        routing_policy_rule_enter_configured(tmp);
                        log_routing_policy_rule_debug(tmp, "Ignoring received", NULL, m);
                } else {
                        routing_policy_rule_enter_configured(tmp);
                        log_routing_policy_rule_debug(tmp, "Remembering", NULL, m);
                        r = routing_policy_rule_add(m, tmp);
                        if (r < 0) {
                                log_warning_errno(r, "Could not remember foreign rule, ignoring: %m");
                                return 0;
                        }
                        TAKE_PTR(tmp);
                }
                break;
        case RTM_DELRULE:
                if (rule) {
                        routing_policy_rule_enter_removed(rule);
                        if (rule->state == 0) {
                                log_routing_policy_rule_debug(rule, "Forgetting", NULL, m);
                                routing_policy_rule_free(rule);
                        } else
                                log_routing_policy_rule_debug(rule, "Removed", NULL, m);
                } else
                        log_routing_policy_rule_debug(tmp, "Kernel removed unknown", NULL, m);
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

static int parse_fwmark_fwmask(const char *s, uint32_t *ret_fwmark, uint32_t *ret_fwmask) {
        _cleanup_free_ char *fwmark_str = NULL;
        uint32_t fwmark, fwmask = 0;
        const char *slash;
        int r;

        assert(s);
        assert(ret_fwmark);
        assert(ret_fwmask);

        slash = strchr(s, '/');
        if (slash) {
                fwmark_str = strndup(s, slash - s);
                if (!fwmark_str)
                        return -ENOMEM;
        }

        r = safe_atou32(fwmark_str ?: s, &fwmark);
        if (r < 0)
                return r;

        if (fwmark > 0) {
                if (slash) {
                        r = safe_atou32(slash + 1, &fwmask);
                        if (r < 0)
                                return r;
                } else
                        fwmask = UINT32_MAX;
        }

        *ret_fwmark = fwmark;
        *ret_fwmask = fwmask;

        return 0;
}

int config_parse_routing_policy_rule_tos(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = safe_atou8(rvalue, &n->tos);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule TOS, ignoring: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_priority(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                n->priority = 0;
                n->priority_set = false;
                TAKE_PTR(n);
                return 0;
        }

        r = safe_atou32(rvalue, &n->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule priority, ignoring: %s", rvalue);
                return 0;
        }
        n->priority_set = true;

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_table(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = manager_get_route_table_from_string(network->manager, rvalue, &n->table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse RPDB rule route table \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_fwmark_mask(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_fwmark_fwmask(rvalue, &n->fwmark, &n->fwmask);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule firewall mark or mask, ignoring: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_prefix(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        union in_addr_union *buffer;
        uint8_t *prefixlen;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (streq(lvalue, "To")) {
                buffer = &n->to;
                prefixlen = &n->to_prefixlen;
        } else {
                buffer = &n->from;
                prefixlen = &n->from_prefixlen;
        }

        if (n->family == AF_UNSPEC)
                r = in_addr_prefix_from_string_auto(rvalue, &n->family, buffer, prefixlen);
        else
                r = in_addr_prefix_from_string(rvalue, n->family, buffer, prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "RPDB rule prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_device(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid interface name '%s' in %s=, ignoring assignment.", rvalue, lvalue);
                return 0;
        }

        r = free_and_strdup(streq(lvalue, "IncomingInterface") ? &n->iif : &n->oif, rvalue);
        if (r < 0)
                return log_oom();

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_port_range(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        uint16_t low, high;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_ip_port_range(rvalue, &low, &high);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse routing policy rule port range '%s'", rvalue);
                return 0;
        }

        if (streq(lvalue, "SourcePort")) {
                n->sport.start = low;
                n->sport.end = high;
        } else {
                n->dport.start = low;
                n->dport.end = high;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_ip_protocol(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_ip_protocol(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse IP protocol '%s' for routing policy rule, ignoring: %m", rvalue);
                return 0;
        }

        n->ipproto = r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_invert(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule invert, ignoring: %s", rvalue);
                return 0;
        }

        n->invert_rule = r;

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_family(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        AddressFamily a;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        a = routing_policy_rule_address_family_from_string(rvalue);
        if (a < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, a,
                           "Invalid address family '%s', ignoring.", rvalue);
                return 0;
        }

        n->address_family = a;

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_uid_range(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        uid_t start, end;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = get_user_creds(&rvalue, &start, NULL, NULL, NULL, 0);
        if (r >= 0)
                end = start;
        else {
                r = parse_uid_range(rvalue, &start, &end);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Invalid uid or uid range '%s', ignoring: %m", rvalue);
                        return 0;
                }
        }

        n->uid_range.start = start;
        n->uid_range.end = end;

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_suppress_prefixlen(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        r = parse_ip_prefix_length(rvalue, &n->suppress_prefixlen);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Prefix length outside of valid range 0-128, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule suppress_prefixlen, ignoring: %s", rvalue);
                return 0;
        }

        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_suppress_ifgroup(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int32_t suppress_ifgroup;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                n->suppress_ifgroup = -1;
                return 0;
        }

        r = safe_atoi32(rvalue, &suppress_ifgroup);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SuppressInterfaceGroup=, ignoring assignment: %s", rvalue);
                return 0;
        }
        if (suppress_ifgroup < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Value of SuppressInterfaceGroup= must be in the range 0…2147483647, ignoring assignment: %s", rvalue);
                return 0;
        }
        n->suppress_ifgroup = suppress_ifgroup;
        TAKE_PTR(n);
        return 0;
}

int config_parse_routing_policy_rule_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_(routing_policy_rule_free_or_set_invalidp) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r, t;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return log_oom();

        t = fr_act_type_from_string(rvalue);
        if (t < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, t,
                           "Could not parse FIB rule type \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        n->type = (uint8_t) t;

        TAKE_PTR(n);
        return 0;
}

static int routing_policy_rule_section_verify(RoutingPolicyRule *rule) {
        if (section_is_invalid(rule->section))
                return -EINVAL;

        if ((rule->family == AF_INET && FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV6)) ||
            (rule->family == AF_INET6 && FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV4)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                "%s: address family specified by Family= conflicts with the address "
                                "specified by To= or From=. Ignoring [RoutingPolicyRule] section from line %u.",
                                rule->section->filename, rule->section->line);

        if (rule->family == AF_UNSPEC) {
                if (IN_SET(rule->address_family, ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_NO))
                        rule->family = AF_INET;
                else if (rule->address_family == ADDRESS_FAMILY_IPV6)
                        rule->family = AF_INET6;
                /* rule->family can be AF_UNSPEC only when Family=both. */
        }

        /* Currently, [RoutingPolicyRule] does not have a setting to set FRA_L3MDEV flag. Please also
         * update routing_policy_rule_is_created_by_kernel() when a new setting which sets the flag is
         * added in the future. */
        if (rule->l3mdev > 0)
                assert_not_reached();

        return 0;
}

void network_drop_invalid_routing_policy_rules(Network *network) {
        RoutingPolicyRule *rule;

        assert(network);

        HASHMAP_FOREACH(rule, network->rules_by_section)
                if (routing_policy_rule_section_verify(rule) < 0)
                        routing_policy_rule_free(rule);
}
