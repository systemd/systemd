/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/fib_rules.h>

#include "af-list.h"
#include "alloc-util.h"
#include "conf-parser.h"
#include "fileio.h"
#include "format-util.h"
#include "ip-protocol-list.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-util.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

RoutingPolicyRule *routing_policy_rule_free(RoutingPolicyRule *rule) {
        if (!rule)
                return NULL;

        if (rule->network) {
                assert(rule->section);
                hashmap_remove(rule->network->rules_by_section, rule->section);
        }

        if (rule->manager) {
                if (set_get(rule->manager->rules, rule) == rule)
                        set_remove(rule->manager->rules, rule);
                if (set_get(rule->manager->rules_foreign, rule) == rule)
                        set_remove(rule->manager->rules_foreign, rule);
        }

        network_config_section_free(rule->section);
        free(rule->iif);
        free(rule->oif);

        return mfree(rule);
}

DEFINE_NETWORK_SECTION_FUNCTIONS(RoutingPolicyRule, routing_policy_rule_free);

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
        };

        *ret = rule;
        return 0;
}

static int routing_policy_rule_new_static(Network *network, const char *filename, unsigned section_line, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
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

        r = hashmap_ensure_allocated(&network->rules_by_section, &network_config_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_put(network->rules_by_section, rule->section, rule);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(rule);
        return 0;
}

static int routing_policy_rule_copy(RoutingPolicyRule *dest, RoutingPolicyRule *src) {
        _cleanup_free_ char *iif = NULL, *oif = NULL;

        assert(dest);
        assert(src);

        if (src->iif) {
                iif = strdup(src->iif);
                if (!iif)
                        return -ENOMEM;
        }

        if (src->oif) {
                oif = strdup(src->oif);
                if (!oif)
                        return -ENOMEM;
        }

        dest->family = src->family;
        dest->from = src->from;
        dest->from_prefixlen = src->from_prefixlen;
        dest->to = src->to;
        dest->to_prefixlen = src->to_prefixlen;
        dest->invert_rule = src->invert_rule;
        dest->tos = src->tos;
        dest->fwmark = src->fwmark;
        dest->fwmask = src->fwmask;
        dest->priority = src->priority;
        dest->table = src->table;
        dest->iif = TAKE_PTR(iif);
        dest->oif = TAKE_PTR(oif);
        dest->protocol = src->protocol;
        dest->sport = src->sport;
        dest->dport = src->dport;
        dest->uid_range = src->uid_range;
        dest->suppress_prefixlen = src->suppress_prefixlen;

        return 0;
}

static void routing_policy_rule_hash_func(const RoutingPolicyRule *rule, struct siphash *state) {
        assert(rule);

        siphash24_compress(&rule->family, sizeof(rule->family), state);

        switch (rule->family) {
        case AF_INET:
        case AF_INET6:
                siphash24_compress(&rule->from, FAMILY_ADDRESS_SIZE(rule->family), state);
                siphash24_compress(&rule->from_prefixlen, sizeof(rule->from_prefixlen), state);

                siphash24_compress(&rule->to, FAMILY_ADDRESS_SIZE(rule->family), state);
                siphash24_compress(&rule->to_prefixlen, sizeof(rule->to_prefixlen), state);

                siphash24_compress_boolean(rule->invert_rule, state);

                siphash24_compress(&rule->tos, sizeof(rule->tos), state);
                siphash24_compress(&rule->fwmark, sizeof(rule->fwmark), state);
                siphash24_compress(&rule->fwmask, sizeof(rule->fwmask), state);
                siphash24_compress(&rule->priority, sizeof(rule->priority), state);
                siphash24_compress(&rule->table, sizeof(rule->table), state);
                siphash24_compress(&rule->suppress_prefixlen, sizeof(rule->suppress_prefixlen), state);

                siphash24_compress(&rule->protocol, sizeof(rule->protocol), state);
                siphash24_compress(&rule->sport, sizeof(rule->sport), state);
                siphash24_compress(&rule->dport, sizeof(rule->dport), state);
                siphash24_compress(&rule->uid_range, sizeof(rule->uid_range), state);

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

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                routing_policy_rule_hash_ops,
                RoutingPolicyRule,
                routing_policy_rule_hash_func,
                routing_policy_rule_compare_func,
                routing_policy_rule_free);

static int routing_policy_rule_get(Manager *m, RoutingPolicyRule *rule, RoutingPolicyRule **ret) {

        RoutingPolicyRule *existing;

        assert(m);

        existing = set_get(m->rules, rule);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(m->rules_foreign, rule);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

static int routing_policy_rule_add_internal(Manager *m, Set **rules, RoutingPolicyRule *in, int family, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        int r;

        assert(m);
        assert(rules);
        assert(in);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(in->family == AF_UNSPEC || in->family == family);

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        rule->manager = m;

        r = routing_policy_rule_copy(rule, in);
        if (r < 0)
                return r;

        rule->family = family;

        r = set_ensure_put(rules, &routing_policy_rule_hash_ops, rule);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        if (ret)
                *ret = rule;

        TAKE_PTR(rule);
        return 0;
}

static int routing_policy_rule_add(Manager *m, RoutingPolicyRule *rule, int family, RoutingPolicyRule **ret) {
        return routing_policy_rule_add_internal(m, &m->rules, rule, family, ret);
}

static int routing_policy_rule_add_foreign(Manager *m, RoutingPolicyRule *rule, RoutingPolicyRule **ret) {
        return routing_policy_rule_add_internal(m, &m->rules_foreign, rule, rule->family, ret);
}

static int routing_policy_rule_set_netlink_message(RoutingPolicyRule *rule, sd_netlink_message *m, Link *link) {
        int r;

        assert(rule);
        assert(m);
        assert(link);

        if (in_addr_is_null(rule->family, &rule->from) == 0) {
                r = netlink_message_append_in_addr_union(m, FRA_SRC, rule->family, &rule->from);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_SRC attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_src_prefixlen(m, rule->from_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set source prefix length: %m");
        }

        if (in_addr_is_null(rule->family, &rule->to) == 0) {
                r = netlink_message_append_in_addr_union(m, FRA_DST, rule->family, &rule->to);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_DST attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_dst_prefixlen(m, rule->to_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set destination prefix length: %m");
        }

        r = sd_netlink_message_append_u32(m, FRA_PRIORITY, rule->priority);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append FRA_PRIORITY attribute: %m");

        if (rule->tos > 0) {
                r = sd_rtnl_message_routing_policy_rule_set_tos(m, rule->tos);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set IP rule TOS: %m");
        }

        if (rule->table < 256) {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, rule->table);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set IP rule table: %m");
        } else {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, RT_TABLE_UNSPEC);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not set IP rule table: %m");

                r = sd_netlink_message_append_u32(m, FRA_TABLE, rule->table);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_TABLE attribute: %m");
        }

        if (rule->fwmark > 0) {
                r = sd_netlink_message_append_u32(m, FRA_FWMARK, rule->fwmark);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_FWMARK attribute: %m");

                r = sd_netlink_message_append_u32(m, FRA_FWMASK, rule->fwmask);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_FWMASK attribute: %m");
        }

        if (rule->iif) {
                r = sd_netlink_message_append_string(m, FRA_IIFNAME, rule->iif);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_IIFNAME attribute: %m");
        }

        if (rule->oif) {
                r = sd_netlink_message_append_string(m, FRA_OIFNAME, rule->oif);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_OIFNAME attribute: %m");
        }

        r = sd_netlink_message_append_u8(m, FRA_IP_PROTO, rule->protocol);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append FRA_IP_PROTO attribute: %m");

        if (rule->sport.start != 0 || rule->sport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_SPORT_RANGE, &rule->sport, sizeof(rule->sport));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_SPORT_RANGE attribute: %m");
        }

        if (rule->dport.start != 0 || rule->dport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_DPORT_RANGE, &rule->dport, sizeof(rule->dport));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_DPORT_RANGE attribute: %m");
        }

        if (rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID) {
                r = sd_netlink_message_append_data(m, FRA_UID_RANGE, &rule->uid_range, sizeof(rule->uid_range));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_UID_RANGE attribute: %m");
        }

        if (rule->invert_rule) {
                r = sd_rtnl_message_routing_policy_rule_set_flags(m, FIB_RULE_INVERT);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FIB_RULE_INVERT attribute: %m");
        }

        if (rule->suppress_prefixlen >= 0) {
                r = sd_netlink_message_append_u32(m, FRA_SUPPRESS_PREFIXLEN, (uint32_t) rule->suppress_prefixlen);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append FRA_SUPPRESS_PREFIXLEN attribute: %m");
        }

        return 0;
}

static int routing_policy_rule_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        link->routing_policy_rule_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_message_warning_errno(link, m, r, "Could not drop routing policy rule");

        return 1;
}

static int routing_policy_rule_remove(RoutingPolicyRule *rule, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *from = NULL, *to = NULL;

                (void) in_addr_to_string(rule->family, &rule->from, &from);
                (void) in_addr_to_string(rule->family, &rule->to, &to);

                log_link_debug(link,
                               "Removing routing policy rule: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32,
                               rule->priority, strna(from), rule->from_prefixlen, strna(to), rule->to_prefixlen, strna(rule->iif), strna(rule->oif), rule->table);
        }

        r = sd_rtnl_message_new_routing_policy_rule(link->manager->rtnl, &m, RTM_DELRULE, rule->family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_DELRULE message: %m");

        r = routing_policy_rule_set_netlink_message(rule, m, link);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, m,
                               routing_policy_rule_remove_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int routing_policy_rule_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(rtnl);
        assert(m);
        assert(link);
        assert(link->ifname);
        assert(link->routing_policy_rule_messages > 0);

        link->routing_policy_rule_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "Could not add routing policy rule");
                link_enter_failed(link);
                return 1;
        }

        if (link->routing_policy_rule_messages == 0) {
                log_link_debug(link, "Routing policy rule configured");
                link->routing_policy_rules_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int routing_policy_rule_configure_internal(RoutingPolicyRule *rule, int family, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *from = NULL, *to = NULL;

                (void) in_addr_to_string(family, &rule->from, &from);
                (void) in_addr_to_string(family, &rule->to, &to);

                log_link_debug(link,
                               "Configuring routing policy rule: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32,
                               rule->priority, strna(from), rule->from_prefixlen, strna(to), rule->to_prefixlen, strna(rule->iif), strna(rule->oif), rule->table);
        }

        r = sd_rtnl_message_new_routing_policy_rule(link->manager->rtnl, &m, RTM_NEWRULE, family);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_NEWRULE message: %m");

        r = routing_policy_rule_set_netlink_message(rule, m, link);
        if (r < 0)
                return r;

        r = netlink_call_async(link->manager->rtnl, NULL, m,
                               routing_policy_rule_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->routing_policy_rule_messages++;

        r = routing_policy_rule_add(link->manager, rule, family, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not add rule: %m");

        return 1;
}

static int routing_policy_rule_configure(RoutingPolicyRule *rule, Link *link) {
        int r;

        if (IN_SET(rule->family, AF_INET, AF_INET6))
                return routing_policy_rule_configure_internal(rule, rule->family, link);

        if (FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV4)) {
                r = routing_policy_rule_configure_internal(rule, AF_INET, link);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV6)) {
                r = routing_policy_rule_configure_internal(rule, AF_INET6, link);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool manager_links_have_routing_policy_rule(Manager *m, RoutingPolicyRule *rule) {
        Link *link;

        assert(m);
        assert(rule);

        HASHMAP_FOREACH(link, m->links) {
                RoutingPolicyRule *link_rule;

                if (!link->network)
                        continue;

                HASHMAP_FOREACH(link_rule, link->network->rules_by_section)
                        if (routing_policy_rule_compare_func(link_rule, rule) == 0)
                                return true;
        }

        return false;
}

static void routing_policy_rule_purge(Manager *m, Link *link) {
        RoutingPolicyRule *rule;
        int r;

        assert(m);
        assert(link);

        SET_FOREACH(rule, m->rules_saved) {
                RoutingPolicyRule *existing;

                existing = set_get(m->rules_foreign, rule);
                if (!existing)
                        continue; /* Saved rule does not exist anymore. */

                if (manager_links_have_routing_policy_rule(m, existing))
                        continue; /* Existing links have the saved rule. */

                /* Existing links do not have the saved rule. Let's drop the rule now, and re-configure it
                 * later when it is requested. */

                r = routing_policy_rule_remove(existing, link);
                if (r < 0) {
                        log_warning_errno(r, "Could not remove routing policy rules: %m");
                        continue;
                }

                link->routing_policy_rule_remove_messages++;

                assert_se(set_remove(m->rules_foreign, existing) == existing);
                routing_policy_rule_free(existing);
        }
}

int link_set_routing_policy_rules(Link *link) {
        RoutingPolicyRule *rule;
        int r;

        assert(link);
        assert(link->network);

        link->routing_policy_rules_configured = false;

        HASHMAP_FOREACH(rule, link->network->rules_by_section) {
                RoutingPolicyRule *existing;

                r = routing_policy_rule_get(link->manager, rule, &existing);
                if (r > 0)
                        continue;
                if (r == 0) {
                        r = set_ensure_put(&link->manager->rules, &routing_policy_rule_hash_ops, existing);
                        if (r < 0)
                                return log_link_warning_errno(link, r, "Could not store existing routing policy rule: %m");

                        set_remove(link->manager->rules_foreign, existing);
                        continue;
                }

                r = routing_policy_rule_configure(rule, link);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Could not set routing policy rule: %m");
        }

        routing_policy_rule_purge(link->manager, link);
        if (link->routing_policy_rule_messages == 0)
                link->routing_policy_rules_configured = true;
        else {
                log_link_debug(link, "Setting routing policy rules");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *tmp = NULL;
        _cleanup_free_ char *from = NULL, *to = NULL;
        RoutingPolicyRule *rule = NULL;
        const char *iif = NULL, *oif = NULL;
        uint32_t suppress_prefixlen;
        unsigned flags;
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

        switch (tmp->family) {
        case AF_INET:
                r = sd_netlink_message_read_in_addr(message, FRA_SRC, &tmp->from.in);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_src_prefixlen(message, &tmp->from_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                                return 0;
                        }
                }

                r = sd_netlink_message_read_in_addr(message, FRA_DST, &tmp->to.in);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_dst_prefixlen(message, &tmp->to_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                                return 0;
                        }
                }

                break;

        case AF_INET6:
                r = sd_netlink_message_read_in6_addr(message, FRA_SRC, &tmp->from.in6);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_src_prefixlen(message, &tmp->from_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                                return 0;
                        }
                }

                r = sd_netlink_message_read_in6_addr(message, FRA_DST, &tmp->to.in6);
                if (r < 0 && r != -ENODATA) {
                        log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                        return 0;
                } else if (r >= 0) {
                        r = sd_rtnl_message_routing_policy_rule_get_rtm_dst_prefixlen(message, &tmp->to_prefixlen);
                        if (r < 0) {
                                log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                                return 0;
                        }
                }

                break;

        default:
                assert_not_reached("Received rule message with unsupported address family");
        }

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

        r = sd_netlink_message_read_u32(message, FRA_TABLE, &tmp->table);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_TABLE attribute, ignoring: %m");
                return 0;
        }

        r = sd_rtnl_message_routing_policy_rule_get_tos(message, &tmp->tos);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get ip rule TOS, ignoring: %m");
                return 0;
        }

        r = sd_netlink_message_read_string(message, FRA_IIFNAME, &iif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IIFNAME attribute, ignoring: %m");
                return 0;
        }
        r = free_and_strdup(&tmp->iif, iif);
        if (r < 0)
                return log_oom();

        r = sd_netlink_message_read_string(message, FRA_OIFNAME, &oif);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_OIFNAME attribute, ignoring: %m");
                return 0;
        }
        r = free_and_strdup(&tmp->oif, oif);
        if (r < 0)
                return log_oom();

        r = sd_netlink_message_read_u8(message, FRA_IP_PROTO, &tmp->protocol);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_IP_PROTO attribute, ignoring: %m");
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

        r = sd_netlink_message_read_u32(message, FRA_SUPPRESS_PREFIXLEN, &suppress_prefixlen);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SUPPRESS_PREFIXLEN attribute, ignoring: %m");
                return 0;
        }
        if (r >= 0)
                tmp->suppress_prefixlen = (int) suppress_prefixlen;

        (void) routing_policy_rule_get(m, tmp, &rule);

        if (DEBUG_LOGGING) {
                (void) in_addr_to_string(tmp->family, &tmp->from, &from);
                (void) in_addr_to_string(tmp->family, &tmp->to, &to);
        }

        switch (type) {
        case RTM_NEWRULE:
                if (rule)
                        log_debug("Received remembered routing policy rule: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32,
                                  tmp->priority, strna(from), tmp->from_prefixlen, strna(to), tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                else {
                        log_debug("Remembering foreign routing policy rule: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32,
                                  tmp->priority, strna(from), tmp->from_prefixlen, strna(to), tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                        r = routing_policy_rule_add_foreign(m, tmp, &rule);
                        if (r < 0) {
                                log_warning_errno(r, "Could not remember foreign rule, ignoring: %m");
                                return 0;
                        }
                }
                break;
        case RTM_DELRULE:
                if (rule) {
                        log_debug("Forgetting routing policy rule: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32,
                                  tmp->priority, strna(from), tmp->from_prefixlen, strna(to), tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                        routing_policy_rule_free(rule);
                } else
                        log_debug("Kernel removed a routing policy rule we don't remember: priority: %"PRIu32", %s/%u -> %s/%u, iif: %s, oif: %s, table: %"PRIu32", ignoring.",
                                  tmp->priority, strna(from), tmp->from_prefixlen, strna(to), tmp->to_prefixlen, strna(tmp->iif), strna(tmp->oif), tmp->table);
                break;

        default:
                assert_not_reached("Received invalid RTNL message type");
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

        n = NULL;

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

        r = safe_atou32(rvalue, &n->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule priority, ignoring: %s", rvalue);
                return 0;
        }

        n = NULL;

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

        r = safe_atou32(rvalue, &n->table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule table, ignoring: %s", rvalue);
                return 0;
        }

        n = NULL;

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

        n = NULL;

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

        n = NULL;

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
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Failed to parse '%s' interface name, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "IncomingInterface")) {
                r = free_and_strdup(&n->iif, rvalue);
                if (r < 0)
                        return log_oom();
        } else {
                r = free_and_strdup(&n->oif, rvalue);
                if (r < 0)
                        return log_oom();
        }

        n = NULL;

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

        n = NULL;

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

        n->protocol = r;

        n = NULL;

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

        n = NULL;

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
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid address family '%s', ignoring.", rvalue);
                return 0;
        }

        n->address_family = a;
        n = NULL;

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
        n = NULL;

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

        n = NULL;

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

        if (rule->family == AF_UNSPEC && rule->address_family == ADDRESS_FAMILY_NO)
                rule->family = AF_INET;

        return 0;
}

void network_drop_invalid_routing_policy_rules(Network *network) {
        RoutingPolicyRule *rule;

        assert(network);

        HASHMAP_FOREACH(rule, network->rules_by_section)
                if (routing_policy_rule_section_verify(rule) < 0)
                        routing_policy_rule_free(rule);
}

int routing_policy_serialize_rules(Set *rules, FILE *f) {
        RoutingPolicyRule *rule;
        int r;

        assert(f);

        SET_FOREACH(rule, rules) {
                const char *family_str;
                bool space = false;

                fputs("RULE=", f);

                family_str = af_to_name(rule->family);
                if (family_str) {
                        fprintf(f, "family=%s",
                                family_str);
                        space = true;
                }

                if (!in_addr_is_null(rule->family, &rule->from)) {
                        _cleanup_free_ char *str = NULL;

                        r = in_addr_to_string(rule->family, &rule->from, &str);
                        if (r < 0)
                                return r;

                        fprintf(f, "%sfrom=%s/%hhu",
                                space ? " " : "",
                                str, rule->from_prefixlen);
                        space = true;
                }

                if (!in_addr_is_null(rule->family, &rule->to)) {
                        _cleanup_free_ char *str = NULL;

                        r = in_addr_to_string(rule->family, &rule->to, &str);
                        if (r < 0)
                                return r;

                        fprintf(f, "%sto=%s/%hhu",
                                space ? " " : "",
                                str, rule->to_prefixlen);
                        space = true;
                }

                if (rule->tos != 0) {
                        fprintf(f, "%stos=%hhu",
                                space ? " " : "",
                                rule->tos);
                        space = true;
                }

                if (rule->priority != 0) {
                        fprintf(f, "%spriority=%"PRIu32,
                                space ? " " : "",
                                rule->priority);
                        space = true;
                }

                if (rule->fwmark != 0) {
                        fprintf(f, "%sfwmark=%"PRIu32,
                                space ? " " : "",
                                rule->fwmark);
                        if (rule->fwmask != UINT32_MAX)
                                fprintf(f, "/%"PRIu32, rule->fwmask);
                        space = true;
                }

                if (rule->iif) {
                        fprintf(f, "%siif=%s",
                                space ? " " : "",
                                rule->iif);
                        space = true;
                }

                if (rule->oif) {
                        fprintf(f, "%soif=%s",
                                space ? " " : "",
                                rule->oif);
                        space = true;
                }

                if (rule->protocol != 0) {
                        fprintf(f, "%sprotocol=%hhu",
                                space ? " " : "",
                                rule->protocol);
                        space = true;
                }

                if (rule->sport.start != 0 || rule->sport.end != 0) {
                        fprintf(f, "%ssourcesport=%"PRIu16"-%"PRIu16,
                                space ? " " : "",
                                rule->sport.start, rule->sport.end);
                        space = true;
                }

                if (rule->dport.start != 0 || rule->dport.end != 0) {
                        fprintf(f, "%sdestinationport=%"PRIu16"-%"PRIu16,
                                space ? " " : "",
                                rule->dport.start, rule->dport.end);
                        space = true;
                }

                if (rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID) {
                        assert_cc(sizeof(uid_t) == sizeof(uint32_t));
                        fprintf(f, "%suidrange="UID_FMT"-"UID_FMT,
                                space ? " " : "",
                                rule->uid_range.start, rule->uid_range.end);
                        space = true;
                }

                if (rule->suppress_prefixlen >= 0) {
                        fprintf(f, "%ssuppress_prefixlen=%d",
                                space ? " " : "",
                                rule->suppress_prefixlen);
                        space = true;
                }

                fprintf(f, "%sinvert_rule=%s table=%"PRIu32"\n",
                        space ? " " : "",
                        yes_no(rule->invert_rule),
                        rule->table);
        }

        return 0;
}

static int routing_policy_rule_read_full_file(const char *state_file, char ***ret) {
        _cleanup_strv_free_ char **lines = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert(state_file);

        r = read_full_file(state_file, &s, NULL);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return r;

        lines = strv_split_newlines(s);
        if (!lines)
                return -ENOMEM;

        *ret = TAKE_PTR(lines);
        return 0;
}

int routing_policy_load_rules(const char *state_file, Set **rules) {
        _cleanup_strv_free_ char **data = NULL;
        char **i;
        int r;

        assert(state_file);
        assert(rules);

        r = routing_policy_rule_read_full_file(state_file, &data);
        if (r < 0)
                return log_warning_errno(r, "Failed to read %s, ignoring: %m", state_file);

        STRV_FOREACH(i, data) {
                _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
                const char *p;

                p = startswith(*i, "RULE=");
                if (!p)
                        continue;

                r = routing_policy_rule_new(&rule);
                if (r < 0)
                        return log_oom();

                for (;;) {
                        _cleanup_free_ char *a = NULL;
                        char *b;

                        r = extract_first_word(&p, &a, NULL, 0);
                        if (r < 0)
                                return log_oom();
                        if (r == 0)
                                break;

                        b = strchr(a, '=');
                        if (!b) {
                                log_warning_errno(r, "Failed to parse RPDB rule, ignoring: %s", a);
                                continue;
                        }
                        *b++ = '\0';

                        if (streq(a, "family")) {
                                r = af_from_name(b);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule family, ignoring: %s", b);
                                        continue;
                                }
                                if (rule->family != AF_UNSPEC && rule->family != r) {
                                        log_warning("RPDB rule family is already specified, ignoring assignment: %s", b);
                                        continue;
                                }
                                rule->family = r;
                        } else if (STR_IN_SET(a, "from", "to")) {
                                union in_addr_union *buffer;
                                uint8_t *prefixlen;

                                if (streq(a, "to")) {
                                        buffer = &rule->to;
                                        prefixlen = &rule->to_prefixlen;
                                } else {
                                        buffer = &rule->from;
                                        prefixlen = &rule->from_prefixlen;
                                }

                                if (rule->family == AF_UNSPEC)
                                        r = in_addr_prefix_from_string_auto(b, &rule->family, buffer, prefixlen);
                                else
                                        r = in_addr_prefix_from_string(b, rule->family, buffer, prefixlen);
                                if (r < 0) {
                                        log_warning_errno(r, "RPDB rule prefix is invalid, ignoring assignment: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "tos")) {
                                r = safe_atou8(b, &rule->tos);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule TOS, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "table")) {
                                r = safe_atou32(b, &rule->table);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule table, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "priority")) {
                                r = safe_atou32(b, &rule->priority);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule priority, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "fwmark")) {
                                r = parse_fwmark_fwmask(b, &rule->fwmark, &rule->fwmask);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule firewall mark or mask, ignoring: %s", a);
                                        continue;
                                }
                        } else if (streq(a, "iif")) {
                                if (free_and_strdup(&rule->iif, b) < 0)
                                        return log_oom();

                        } else if (streq(a, "oif")) {

                                if (free_and_strdup(&rule->oif, b) < 0)
                                        return log_oom();
                        } else if (streq(a, "protocol")) {
                                r = safe_atou8(b, &rule->protocol);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule protocol, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "sourceport")) {
                                uint16_t low, high;

                                r = parse_ip_port_range(b, &low, &high);
                                if (r < 0) {
                                        log_warning_errno(r, "Invalid routing policy rule source port range, ignoring assignment: '%s'", b);
                                        continue;
                                }

                                rule->sport.start = low;
                                rule->sport.end = high;
                        } else if (streq(a, "destinationport")) {
                                uint16_t low, high;

                                r = parse_ip_port_range(b, &low, &high);
                                if (r < 0) {
                                        log_warning_errno(r, "Invalid routing policy rule destination port range, ignoring assignment: '%s'", b);
                                        continue;
                                }

                                rule->dport.start = low;
                                rule->dport.end = high;
                        } else if (streq(a, "uidrange")) {
                                uid_t lower, upper;

                                r = parse_uid_range(b, &lower, &upper);
                                if (r < 0) {
                                        log_warning_errno(r, "Invalid routing policy rule uid range, ignoring assignment: '%s'", b);
                                        continue;
                                }

                                rule->uid_range.start = lower;
                                rule->uid_range.end = upper;
                        } else if (streq(a, "suppress_prefixlen")) {
                                r = parse_ip_prefix_length(b, &rule->suppress_prefixlen);
                                if (r == -ERANGE) {
                                        log_warning_errno(r, "Prefix length outside of valid range 0-128, ignoring: %s", b);
                                        continue;
                                }
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule suppress_prefixlen, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "invert_rule")) {
                                r = parse_boolean(b);
                                if (r < 0) {
                                        log_warning_errno(r, "Failed to parse RPDB rule invert_rule, ignoring: %s", b);
                                        continue;
                                }
                                rule->invert_rule = r;
                        } else
                                log_warning("Unknown RPDB rule, ignoring: %s", a);
                }

                r = set_ensure_put(rules, &routing_policy_rule_hash_ops, rule);
                if (r < 0) {
                        log_warning_errno(r, "Failed to add RPDB rule to saved DB, ignoring: %s", *i);
                        continue;
                }
                if (r > 0)
                        rule = NULL;
        }

        return 0;
}
