/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
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
#include "network-util.h"
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
        [FR_ACT_TO_TBL]      = "table",
        [FR_ACT_GOTO]        = "goto",
        [FR_ACT_NOP]         = "nop",
        [FR_ACT_BLACKHOLE]   = "blackhole",
        [FR_ACT_UNREACHABLE] = "unreachable",
        [FR_ACT_PROHIBIT]    = "prohibit",
};

assert_cc(__FR_ACT_MAX <= UINT8_MAX);
DEFINE_STRING_TABLE_LOOKUP(fr_act_type, int);

static RoutingPolicyRule* routing_policy_rule_detach_impl(RoutingPolicyRule *rule) {
        assert(rule);
        assert(!!rule->manager + !!rule->network <= 1);

        if (rule->network) {
                assert(rule->section);
                hashmap_remove(rule->network->rules_by_section, rule->section);
                rule->network = NULL;
                return rule;
        }

        if (rule->manager) {
                set_remove(rule->manager->rules, rule);
                rule->manager = NULL;
                return rule;
        }

        return NULL;
}

static void routing_policy_rule_detach(RoutingPolicyRule *rule) {
        assert(rule);
        routing_policy_rule_unref(routing_policy_rule_detach_impl(rule));
}

static RoutingPolicyRule* routing_policy_rule_free(RoutingPolicyRule *rule) {
        if (!rule)
                return NULL;

        routing_policy_rule_detach_impl(rule);

        config_section_free(rule->section);
        free(rule->iif);
        free(rule->oif);

        return mfree(rule);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(RoutingPolicyRule, routing_policy_rule, routing_policy_rule_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                routing_policy_rule_section_hash_ops,
                ConfigSection,
                config_section_hash_func,
                config_section_compare_func,
                RoutingPolicyRule,
                routing_policy_rule_detach);

static void routing_policy_rule_hash_func(const RoutingPolicyRule *rule, struct siphash *state);
static int routing_policy_rule_compare_func(const RoutingPolicyRule *a, const RoutingPolicyRule *b);

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                routing_policy_rule_hash_ops_detach,
                RoutingPolicyRule,
                routing_policy_rule_hash_func,
                routing_policy_rule_compare_func,
                routing_policy_rule_detach);

DEFINE_SECTION_CLEANUP_FUNCTIONS(RoutingPolicyRule, routing_policy_rule_unref);

static int routing_policy_rule_new(RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        rule = new(RoutingPolicyRule, 1);
        if (!rule)
                return -ENOMEM;

        *rule = (RoutingPolicyRule) {
                .n_ref = 1,
                .table = RT_TABLE_MAIN,
                .uid_range.start = UID_INVALID,
                .uid_range.end = UID_INVALID,
                .suppress_prefixlen = -1,
                .suppress_ifgroup = -1,
                .protocol = RTPROT_UNSPEC,
                .action = FR_ACT_TO_TBL,
        };

        *ret = rule;
        return 0;
}

static int routing_policy_rule_new_static(Network *network, const char *filename, unsigned section_line, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_unrefp) RoutingPolicyRule *rule = NULL;
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

        r = hashmap_ensure_put(&network->rules_by_section, &routing_policy_rule_section_hash_ops, rule->section, rule);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(rule);
        return 0;
}

static int routing_policy_rule_dup(const RoutingPolicyRule *src, int family, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_unrefp) RoutingPolicyRule *dest = NULL;

        assert(src);
        assert(ret);

        dest = newdup(RoutingPolicyRule, src, 1);
        if (!dest)
                return -ENOMEM;

        /* Clear the reference counter and all pointers. */
        dest->n_ref = 1;
        dest->manager = NULL;
        dest->network = NULL;
        dest->section = NULL;
        dest->iif = dest->oif = NULL;

        /* Set family. */
        dest->family = family;

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

        /* See rule_exists() in net/core/fib_rules.c of the kernel. */
        siphash24_compress_typesafe(rule->family, state);
        siphash24_compress_typesafe(rule->action, state);
        siphash24_compress_typesafe(rule->table, state);
        siphash24_compress_typesafe(rule->priority, state);
        siphash24_compress_string(rule->iif, state);
        siphash24_compress_string(rule->oif, state);
        siphash24_compress_typesafe(rule->fwmark, state);
        siphash24_compress_typesafe(rule->suppress_ifgroup, state);
        siphash24_compress_typesafe(rule->suppress_prefixlen, state);
        siphash24_compress_typesafe(rule->fwmask, state);
        siphash24_compress_typesafe(rule->tunnel_id, state);
        /* fr_net (network namespace) */
        siphash24_compress_typesafe(rule->l3mdev, state);
        siphash24_compress_typesafe(rule->uid_range, state);
        siphash24_compress_typesafe(rule->ipproto, state);
        siphash24_compress_typesafe(rule->protocol, state);
        siphash24_compress_typesafe(rule->sport, state);
        siphash24_compress_typesafe(rule->dport, state);

        /* See fib4_rule_compare() in net/ipv4/fib_rules.c, and fib6_rule_compare() in net/ipv6/fib6_rules.c. */
        siphash24_compress_typesafe(rule->from.prefixlen, state);
        siphash24_compress_typesafe(rule->to.prefixlen, state);
        siphash24_compress_typesafe(rule->tos, state);
        siphash24_compress_typesafe(rule->realms, state);
        in_addr_hash_func(&rule->from.address, rule->family, state);
        in_addr_hash_func(&rule->to.address, rule->family, state);
}

static int routing_policy_rule_compare_func_full(const RoutingPolicyRule *a, const RoutingPolicyRule *b, bool all) {
        int r;

        assert(a);
        assert(b);

        if (all) {
                r = CMP(a->family, b->family);
                if (r != 0)
                        return r;
        }

        r = CMP(a->action, b->action);
        if (r != 0)
                return r;

        r = CMP(a->table, b->table);
        if (r != 0)
                return r;

        if (all) {
                r = CMP(a->priority, b->priority);
                if (r != 0)
                        return r;
        }

        r = strcmp_ptr(a->iif, b->iif);
        if (r != 0)
                return r;

        r = strcmp_ptr(a->oif, b->oif);
        if (r != 0)
                return r;

        r = CMP(a->fwmark, b->fwmark);
        if (r != 0)
                return r;

        r = CMP(a->suppress_ifgroup, b->suppress_ifgroup);
        if (r != 0)
                return r;

        r = CMP(a->suppress_prefixlen, b->suppress_prefixlen);
        if (r != 0)
                return r;

        r = CMP(a->fwmask, b->fwmask);
        if (r != 0)
                return r;

        r = CMP(a->tunnel_id, b->tunnel_id);
        if (r != 0)
                return r;

        r = CMP(a->l3mdev, b->l3mdev);
        if (r != 0)
                return r;

        r = memcmp(&a->uid_range, &b->uid_range, sizeof(a->uid_range));
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

        r = CMP(a->from.prefixlen, b->from.prefixlen);
        if (r != 0)
                return r;

        r = CMP(a->to.prefixlen, b->to.prefixlen);
        if (r != 0)
                return r;

        r = CMP(a->tos, b->tos);
        if (r != 0)
                return r;

        r = CMP(a->realms, b->realms);
        if (r != 0)
                return r;

        if (all) {
                r = memcmp(&a->from.address, &b->from.address, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                r = memcmp(&a->to.address, &b->to.address, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;
        }

        return 0;
}

static int routing_policy_rule_compare_func(const RoutingPolicyRule *a, const RoutingPolicyRule *b) {
        return routing_policy_rule_compare_func_full(a, b, /* all = */ true);
}

static bool routing_policy_rule_equal(const RoutingPolicyRule *a, const RoutingPolicyRule *b, int family, uint32_t priority) {
        assert(a);
        assert(b);

        if (a->family != AF_UNSPEC && a->family != family)
                return false;
        if (b->family != AF_UNSPEC && b->family != family)
                return false;

        if (a->priority_set && a->priority != priority)
                return false;
        if (b->priority_set && b->priority != priority)
                return false;

        return routing_policy_rule_compare_func_full(a, b, /* all = */ false) == 0;
}

static bool routing_policy_rule_can_update(const RoutingPolicyRule *existing, const RoutingPolicyRule *requesting) {
        assert(existing);
        assert(IN_SET(existing->family, AF_INET, AF_INET6));
        assert(requesting);
        assert(IN_SET(requesting->family, AF_INET, AF_INET6) || requesting->address_family == ADDRESS_FAMILY_YES);

        if (!routing_policy_rule_equal(existing, requesting, existing->family, existing->priority))
                return false;

        /* These flags cannot be updated. */
        if ((existing->flags ^ requesting->flags) & (FIB_RULE_PERMANENT|FIB_RULE_INVERT))
                return false;

        /* GOTO target cannot be updated. */
        if (existing->action == FR_ACT_GOTO && existing->priority_goto != requesting->priority_goto)
                return false;

        return true;
}

static int routing_policy_rule_get(Manager *m, const RoutingPolicyRule *in, int family, RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        assert(m);
        assert(in);
        assert(in->family == AF_UNSPEC || in->family == family);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (in->priority_set && in->family != AF_UNSPEC) {
                rule = set_get(m->rules, in);
                if (!rule)
                        return -ENOENT;

                if (ret)
                        *ret = rule;
                return 0;
        }

        SET_FOREACH(rule, m->rules)
                if (routing_policy_rule_equal(in, rule, family, rule->priority)) {
                        if (ret)
                                *ret = rule;
                        return 0;
                }

        return -ENOENT;
}

static int routing_policy_rule_get_request(Manager *m, const RoutingPolicyRule *in, int family, Request **ret) {
        Request *req;

        assert(m);
        assert(in);
        assert(in->family == AF_UNSPEC || in->family == family);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (in->priority_set && in->family != AF_UNSPEC) {
                req = ordered_set_get(
                        m->request_queue,
                        &(Request) {
                                .type = REQUEST_TYPE_ROUTING_POLICY_RULE,
                                .userdata = (void*) in,
                                .hash_func = (hash_func_t) routing_policy_rule_hash_func,
                                .compare_func = (compare_func_t) routing_policy_rule_compare_func,
                        });
                if (!req)
                        return -ENOENT;

                if (ret)
                        *ret = req;
                return 0;
        }

        ORDERED_SET_FOREACH(req, m->request_queue) {

                if (req->type != REQUEST_TYPE_ROUTING_POLICY_RULE)
                        continue;

                RoutingPolicyRule *rule = ASSERT_PTR(req->userdata);
                if (routing_policy_rule_equal(in, rule, family, rule->priority)) {
                        if (ret)
                                *ret = req;
                        return 0;
                }
        }

        return -ENOENT;
}

static int routing_policy_rule_attach(Manager *m, RoutingPolicyRule *rule) {
        int r;

        assert(m);
        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));
        assert(!rule->manager);

        r = set_ensure_put(&m->rules, &routing_policy_rule_hash_ops_detach, rule);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        rule->manager = m;
        routing_policy_rule_ref(rule);
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

        Request *req;
        ORDERED_SET_FOREACH(req, manager->request_queue) {
                if (req->type != REQUEST_TYPE_ROUTING_POLICY_RULE)
                        continue;

                tmp = ASSERT_PTR(req->userdata);
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

        /* priority must be smaller than goto target */
        for (priority = rule->action == FR_ACT_GOTO ? rule->priority_goto - 1 : 32765; priority > 0; priority--)
                if (!set_contains(priorities, UINT32_TO_PTR(priority)))
                        break;

        rule->priority = priority;
        rule->priority_set = true;
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
                       IN_ADDR_PREFIX_TO_STRING(rule->family, &rule->from.address, rule->from.prefixlen),
                       IN_ADDR_PREFIX_TO_STRING(rule->family, &rule->to.address, rule->to.prefixlen),
                       strna(rule->iif), strna(rule->oif), strna(table));
}

static void routing_policy_rule_forget(Manager *manager, RoutingPolicyRule *rule, const char *msg) {
        assert(manager);
        assert(rule);
        assert(msg);

        Request *req;
        if (routing_policy_rule_get_request(manager, rule, rule->family, &req) >= 0)
                routing_policy_rule_enter_removed(req->userdata);

        if (!rule->manager && routing_policy_rule_get(manager, rule, rule->family, &rule) < 0)
                return;

        routing_policy_rule_enter_removed(rule);
        log_routing_policy_rule_debug(rule, "Forgetting", NULL, manager);
        routing_policy_rule_detach(rule);
}

static int routing_policy_rule_set_netlink_message(const RoutingPolicyRule *rule, sd_netlink_message *m) {
        int r;

        assert(rule);
        assert(m);

        if (rule->from.prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, FRA_SRC, rule->family, &rule->from.address);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_routing_policy_rule_set_src_prefixlen(m, rule->from.prefixlen);
                if (r < 0)
                        return r;
        }

        if (rule->to.prefixlen > 0) {
                r = netlink_message_append_in_addr_union(m, FRA_DST, rule->family, &rule->to.address);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_routing_policy_rule_set_dst_prefixlen(m, rule->to.prefixlen);
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

        if (rule->table < 256)
                r = sd_rtnl_message_routing_policy_rule_set_table(m, rule->table);
        else {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, RT_TABLE_UNSPEC);
                if (r < 0)
                        return r;

                r = sd_netlink_message_append_u32(m, FRA_TABLE, rule->table);
        }
        if (r < 0)
                return r;

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

        r = sd_rtnl_message_routing_policy_rule_set_flags(m, rule->flags);
        if (r < 0)
                return r;

        if (rule->l3mdev) {
                r = sd_netlink_message_append_u8(m, FRA_L3MDEV, 1);
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

        r = sd_rtnl_message_routing_policy_rule_set_action(m, rule->action);
        if (r < 0)
                return r;

        if (rule->action == FR_ACT_GOTO) {
                r = sd_netlink_message_append_u32(m, FRA_GOTO, rule->priority_goto);
                if (r < 0)
                        return r;
        }

        if (rule->realms > 0) {
                r = sd_netlink_message_append_u32(m, FRA_FLOW, rule->realms);
                if (r < 0)
                        return r;
        }

        if (rule->tunnel_id > 0) {
                r = sd_netlink_message_append_u64(m, FRA_TUN_ID, htobe64(rule->tunnel_id));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int routing_policy_rule_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, RemoveRequest *rreq) {
        int r;

        assert(m);
        assert(rreq);

        Manager *manager = ASSERT_PTR(rreq->manager);
        RoutingPolicyRule *rule = ASSERT_PTR(rreq->userdata);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_message_full_errno(m,
                                       (r == -ENOENT || !rule->manager) ? LOG_DEBUG : LOG_WARNING,
                                       r, "Could not drop routing policy rule, ignoring");

                /* If the rule cannot be removed, then assume the rule is already removed. */
                routing_policy_rule_forget(manager, rule, "Forgetting");
        }

        return 1;
}

static int routing_policy_rule_remove(RoutingPolicyRule *rule, Manager *manager) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(IN_SET(rule->family, AF_INET, AF_INET6));
        assert(manager);
        assert(manager->rtnl);

        /* If the rule is remembered, then use the remembered object. */
        (void) routing_policy_rule_get(manager, rule, rule->family, &rule);

        /* We cannot remove rules with the permanent flag. */
        if (FLAGS_SET(rule->flags, FIB_RULE_PERMANENT))
                return 0;

        log_routing_policy_rule_debug(rule, "Removing", NULL, manager);

        r = sd_rtnl_message_new_routing_policy_rule(manager->rtnl, &m, RTM_DELRULE, rule->family);
        if (r < 0)
                return log_warning_errno(r, "Could not allocate netlink message: %m");

        r = routing_policy_rule_set_netlink_message(rule, m);
        if (r < 0)
                return log_warning_errno(r, "Could not create netlink message: %m");

        r = manager_remove_request_add(manager, rule, routing_policy_rule,
                                       manager->rtnl, m, routing_policy_rule_remove_handler);
        if (r < 0)
                return log_warning_errno(r, "Could not queue rtnetlink message: %m");

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

        r = routing_policy_rule_set_netlink_message(rule, m);
        if (r < 0)
                return r;

        return request_call_netlink_async(link->manager->rtnl, m, req);
}

static void manager_unmark_routing_policy_rule(Manager *m, const RoutingPolicyRule *rule, int family) {
        RoutingPolicyRule *existing;

        assert(m);
        assert(rule);
        assert(rule->family == AF_UNSPEC || rule->family == family);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (routing_policy_rule_get(m, rule, family, &existing) < 0)
                return;

        if (!routing_policy_rule_can_update(existing, rule))
                return;

        routing_policy_rule_unmark(existing);
}

int link_drop_routing_policy_rules(Link *link, bool only_static) {
        RoutingPolicyRule *rule;
        int r = 0;

        assert(link);
        assert(link->manager);

        /* First, mark all existing rules. */
        SET_FOREACH(rule, link->manager->rules) {
                /* Do not touch rules managed by kernel. */
                if (rule->protocol == RTPROT_KERNEL)
                        continue;

                if (only_static) {
                        /* When 'only_static' is true, mark only static rules. */
                        if (rule->source != NETWORK_CONFIG_SOURCE_STATIC)
                                continue;
                } else {
                        /* Do not mark foreign rules when KeepConfiguration= is enabled. */
                        if (rule->source == NETWORK_CONFIG_SOURCE_FOREIGN &&
                            link->network &&
                            FLAGS_SET(link->network->keep_configuration, KEEP_CONFIGURATION_STATIC))
                                continue;
                }

                /* Ignore rules not assigned yet or already removing. */
                if (!routing_policy_rule_exists(rule))
                        continue;

                routing_policy_rule_mark(rule);
        }

        /* Then, unmark all rules requested by active links. */
        Link *other;
        HASHMAP_FOREACH(other, link->manager->links_by_index) {
                if (only_static && other == link)
                        continue;

                if (!IN_SET(other->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                        continue;

                HASHMAP_FOREACH(rule, other->network->rules_by_section) {
                        if (IN_SET(rule->family, AF_INET, AF_INET6))
                                manager_unmark_routing_policy_rule(link->manager, rule, rule->family);
                        else {
                                assert(rule->address_family == ADDRESS_FAMILY_YES);
                                manager_unmark_routing_policy_rule(link->manager, rule, AF_INET);
                                manager_unmark_routing_policy_rule(link->manager, rule, AF_INET6);
                        }
                }
        }

        /* Finally, remove all marked rules. */
        SET_FOREACH(rule, link->manager->rules) {
                if (!routing_policy_rule_is_marked(rule))
                        continue;

                RET_GATHER(r, routing_policy_rule_remove(rule, link->manager));
        }

        return r;
}

static int routing_policy_rule_process_request(Request *req, Link *link, RoutingPolicyRule *rule) {
        RoutingPolicyRule *existing;
        int r;

        assert(req);
        assert(link);
        assert(link->manager);
        assert(rule);

        if (!link_is_ready_to_configure(link, false))
                return 0;

        r = routing_policy_rule_configure(rule, link, req);
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to configure routing policy rule: %m");

        routing_policy_rule_enter_configuring(rule);
        if (routing_policy_rule_get(link->manager, rule, rule->family, &existing) >= 0)
                routing_policy_rule_enter_configuring(existing);

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
        assert(rule);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST) {
                RoutingPolicyRule *existing;

                if (routing_policy_rule_get(link->manager, rule, rule->family, &existing) >= 0) {
                        existing->source = rule->source;
                        routing_policy_rule_enter_configured(existing);
                }
        } else if (r < 0) {
                log_link_message_warning_errno(link, m, r, "Could not add routing policy rule");
                link_enter_failed(link);
                return 1;
        }

        if (link->static_routing_policy_rule_messages == 0) {
                log_link_debug(link, "Routing policy rule configured.");
                link->static_routing_policy_rules_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int link_request_routing_policy_rule(Link *link, const RoutingPolicyRule *rule, int family) {
        _cleanup_(routing_policy_rule_unrefp) RoutingPolicyRule *tmp = NULL;
        RoutingPolicyRule *existing = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(rule);
        assert(rule->source != NETWORK_CONFIG_SOURCE_FOREIGN);
        assert(rule->family == AF_UNSPEC || rule->family == family);
        assert(IN_SET(family, AF_INET, AF_INET6));

        if (routing_policy_rule_get_request(link->manager, rule, family, NULL) >= 0)
                return 0; /* already requested, skipping. */

        r = routing_policy_rule_dup(rule, family, &tmp);
        if (r < 0)
                return r;

        if (routing_policy_rule_get(link->manager, tmp, family, &existing) < 0) {
                r = routing_policy_rule_acquire_priority(link->manager, tmp);
                if (r < 0)
                        return r;
        } else {
                /* Copy priority from existing rule. */
                if (!tmp->priority_set) {
                        tmp->priority_set = true;
                        tmp->priority = existing->priority;
                }

                /* Copy state for logging below. */
                tmp->state = existing->state;
        }

        log_routing_policy_rule_debug(tmp, "Requesting", link, link->manager);
        r = link_queue_request_safe(link, REQUEST_TYPE_ROUTING_POLICY_RULE,
                                    tmp,
                                    routing_policy_rule_unref,
                                    routing_policy_rule_hash_func,
                                    routing_policy_rule_compare_func,
                                    routing_policy_rule_process_request,
                                    &link->static_routing_policy_rule_messages,
                                    static_routing_policy_rule_configure_handler,
                                    NULL);
        if (r <= 0)
                return r;

        routing_policy_rule_enter_requesting(tmp);
        if (existing)
                routing_policy_rule_enter_requesting(existing);

        TAKE_PTR(tmp);
        return 1;
}

static int link_request_static_routing_policy_rule(Link *link, const RoutingPolicyRule *rule) {
        int r;

        assert(link);
        assert(rule);

        if (IN_SET(rule->family, AF_INET, AF_INET6))
                return link_request_routing_policy_rule(link, rule, rule->family);

        assert(rule->address_family == ADDRESS_FAMILY_YES);

        r = link_request_routing_policy_rule(link, rule, AF_INET);
        if (r < 0)
                return r;

        r = link_request_routing_policy_rule(link, rule, AF_INET6);
        if (r < 0)
                return r;

        return 0;
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
                log_link_debug(link, "Requesting routing policy rules.");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static const RoutingPolicyRule kernel_rules[] = {
        { .family = AF_INET,  .priority_set = true, .priority = 0,     .table = RT_TABLE_LOCAL,   .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET,  .priority_set = true, .priority = 1000,  .table = RT_TABLE_UNSPEC,  .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, .l3mdev = true },
        { .family = AF_INET,  .priority_set = true, .priority = 32766, .table = RT_TABLE_MAIN,    .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET,  .priority_set = true, .priority = 32767, .table = RT_TABLE_DEFAULT, .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET6, .priority_set = true, .priority = 0,     .table = RT_TABLE_LOCAL,   .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
        { .family = AF_INET6, .priority_set = true, .priority = 1000,  .table = RT_TABLE_UNSPEC,  .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, .l3mdev = true },
        { .family = AF_INET6, .priority_set = true, .priority = 32766, .table = RT_TABLE_MAIN,    .action = FR_ACT_TO_TBL, .uid_range.start = UID_INVALID, .uid_range.end = UID_INVALID, .suppress_prefixlen = -1, .suppress_ifgroup = -1, },
};

static bool routing_policy_rule_is_created_by_kernel(const RoutingPolicyRule *rule) {
        assert(rule);

        FOREACH_ELEMENT(i, kernel_rules)
                if (routing_policy_rule_equal(rule, i, i->family, i->priority))
                        return true;

        return false;
}

int manager_rtnl_process_rule(sd_netlink *rtnl, sd_netlink_message *message, Manager *m) {
        int r;

        assert(rtnl);
        assert(message);

        if (sd_netlink_message_is_error(message)) {
                r = sd_netlink_message_get_errno(message);
                if (r < 0)
                        log_message_warning_errno(message, r, "rtnl: failed to receive rule message, ignoring");

                return 0;
        }

        uint16_t type;
        r = sd_netlink_message_get_type(message, &type);
        if (r < 0) {
                log_warning_errno(r, "rtnl: could not get message type, ignoring: %m");
                return 0;
        } else if (!IN_SET(type, RTM_NEWRULE, RTM_DELRULE)) {
                log_warning("rtnl: received unexpected message type %u when processing rule, ignoring.", type);
                return 0;
        }

        _cleanup_(routing_policy_rule_unrefp) RoutingPolicyRule *tmp = NULL;
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

        r = netlink_message_read_in_addr_union(message, FRA_SRC, tmp->family, &tmp->from.address);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_SRC attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = sd_rtnl_message_routing_policy_rule_get_src_prefixlen(message, &tmp->from.prefixlen);
                if (r < 0) {
                        log_warning_errno(r, "rtnl: received rule message without valid source prefix length, ignoring: %m");
                        return 0;
                }
        }

        r = netlink_message_read_in_addr_union(message, FRA_DST, tmp->family, &tmp->to.address);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_DST attribute, ignoring: %m");
                return 0;
        } else if (r >= 0) {
                r = sd_rtnl_message_routing_policy_rule_get_dst_prefixlen(message, &tmp->to.prefixlen);
                if (r < 0) {
                        log_warning_errno(r, "rtnl: received rule message without valid destination prefix length, ignoring: %m");
                        return 0;
                }
        }

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

        r = sd_rtnl_message_routing_policy_rule_get_action(message, &tmp->action);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FIB rule action, ignoring: %m");
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

        uint8_t l3mdev = 0;
        r = sd_netlink_message_read_u8(message, FRA_L3MDEV, &l3mdev);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_L3MDEV attribute, ignoring: %m");
                return 0;
        }
        tmp->l3mdev = l3mdev != 0;

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

        r = sd_netlink_message_read_u64(message, FRA_TUN_ID, &tmp->tunnel_id);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_TUN_ID attribute, ignoring: %m");
                return 0;
        }
        if (r >= 0)
                tmp->tunnel_id = be64toh(tmp->tunnel_id);

        r = sd_netlink_message_read_u32(message, FRA_FLOW, &tmp->realms);
        if (r < 0 && r != -ENODATA) {
                log_warning_errno(r, "rtnl: could not get FRA_FLOW attribute, ignoring: %m");
                return 0;
        }

        /* If FRA_PROTOCOL is supported by kernel, then the attribute is always appended. If the received
         * message does not have FRA_PROTOCOL, then we need to adjust the protocol of the rule. That requires
         * all properties compared in the routing_policy_rule_compare_func(), hence it must be done after
         * reading them. */
        r = sd_netlink_message_read_u8(message, FRA_PROTOCOL, &tmp->protocol);
        if (r == -ENODATA)
                /* As .network files does not have setting to specify protocol, we can assume the
                 * protocol of the received rule is RTPROT_KERNEL or RTPROT_STATIC. */
                tmp->protocol = routing_policy_rule_is_created_by_kernel(tmp) ? RTPROT_KERNEL : RTPROT_STATIC;
        else if (r < 0) {
                log_warning_errno(r, "rtnl: could not get FRA_PROTOCOL attribute, ignoring: %m");
                return 0;
        }

        RoutingPolicyRule *rule = NULL;
        (void) routing_policy_rule_get(m, tmp, tmp->family, &rule);

        if (type == RTM_DELRULE) {
                if (rule)
                        routing_policy_rule_forget(m, rule, "Forgetting removed");
                else
                        log_routing_policy_rule_debug(tmp, "Kernel removed unknown", NULL, m);
                return 0;
        }

        Request *req = NULL;
        (void) routing_policy_rule_get_request(m, tmp, tmp->family, &req);

        bool is_new = false;
        if (!rule) {
                if (!req && !m->manage_foreign_rules) {
                        routing_policy_rule_enter_configured(tmp);
                        log_routing_policy_rule_debug(tmp, "Ignoring received", NULL, m);
                        return 0;
                }

                /* If we did not know the rule, then save it. */
                r = routing_policy_rule_attach(m, tmp);
                if (r < 0) {
                        log_warning_errno(r, "Failed to save received routing policy rule, ignoring: %m");
                        return 0;
                }

                rule = tmp;
                is_new = true;
        }

        /* Also update information that cannot be obtained through netlink notification. */
        if (req && req->waiting_reply) {
                RoutingPolicyRule *req_rule = ASSERT_PTR(req->userdata);

                rule->source = req_rule->source;
        }

        /* Then, update miscellaneous info from netlink notification. */
        r = sd_rtnl_message_routing_policy_rule_get_flags(message, &rule->flags);
        if (r < 0)
                log_debug_errno(r, "rtnl: received rule message without valid flag, ignoring: %m");

        r = sd_netlink_message_read_u32(message, FRA_GOTO, &rule->priority_goto);
        if (r < 0 && r != -ENODATA)
                log_debug_errno(r, "rtnl: could not get FRA_GOTO attribute, ignoring: %m");

        routing_policy_rule_enter_configured(rule);
        if (req)
                routing_policy_rule_enter_configured(req->userdata);

        log_routing_policy_rule_debug(rule, is_new ? "Remembering" : "Received remembered", NULL, m);
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

static int config_parse_routing_policy_rule_priority(
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

        RoutingPolicyRule *rule = ASSERT_PTR(userdata);
        int r;

        if (isempty(rvalue)) {
                rule->priority = 0;
                rule->priority_set = false;
                return 1;
        }

        r = safe_atou32(rvalue, &rule->priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule priority, ignoring: %s", rvalue);
                return 0;
        }

        rule->priority_set = true;
        return 1;
}

static int config_parse_routing_policy_rule_goto(
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

        RoutingPolicyRule *rule = ASSERT_PTR(userdata);
        uint32_t priority;
        int r;

        assert(lvalue);
        assert(rvalue);

        r = safe_atou32(rvalue, &priority);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s=%s, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (priority <= 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid goto target priority, ignoring assignment.");
                return 0;
        }

        rule->action = FR_ACT_GOTO;
        rule->priority_goto = priority;
        return 1;
}

static int config_parse_routing_policy_rule_table(
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

        RoutingPolicyRule *rule = ASSERT_PTR(userdata);
        Manager *manager = ASSERT_PTR(ASSERT_PTR(rule->network)->manager);
        uint32_t *table = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = manager_get_route_table_from_string(manager, rvalue, table);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse RPDB rule route table \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        return 1;
}

static int config_parse_routing_policy_rule_fwmark(
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

        RoutingPolicyRule *rule = ASSERT_PTR(userdata);
        int r;

        assert(rvalue);

        r = parse_fwmark_fwmask(rvalue, &rule->fwmark, &rule->fwmask);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse RPDB rule firewall mark or mask, ignoring: %s", rvalue);
                return 0;
        }

        return 1;
}

static int config_parse_routing_policy_rule_port_range(
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

        struct fib_rule_port_range *p = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = parse_ip_port_range(rvalue, &p->start, &p->end, /* allow_zero = */ false);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse routing policy rule port range '%s'", rvalue);
                return 0;
        }

        return 1;
}

static int config_parse_routing_policy_rule_uid_range(
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

        struct fib_rule_uid_range *p = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (get_user_creds(&rvalue, &p->start, NULL, NULL, NULL, 0) >= 0) {
                p->end = p->start;
                return 1;
        }

        r = parse_uid_range(rvalue, &p->start, &p->end);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid uid or uid range '%s', ignoring: %m", rvalue);
                return 0;
        }

        return 1;
}

static int config_parse_routing_policy_rule_suppress(
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

        int32_t val, *p = ASSERT_PTR(data);
        int r;

        assert(lvalue);

        if (isempty(rvalue)) {
                *p = -1;
                return 1;
        }

        r = safe_atoi32(rvalue, &val);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=%s, ignoring assignment: %m", lvalue, rvalue);
                return 0;
        }
        if (val < 0 || val > ltype) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid value specified to %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        *p = val;
        return 1;
}

static int config_parse_routing_policy_rule_action(
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

        uint8_t *p = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = fr_act_type_from_string(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Could not parse FIB rule action \"%s\", ignoring assignment: %m", rvalue);
                return 0;
        }

        *p = (uint8_t) r;
        return 1;
}

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(
                config_parse_routing_policy_rule_family,
                routing_policy_rule_address_family,
                AddressFamily,
                ADDRESS_FAMILY_NO);

int config_parse_routing_policy_rule(
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

        static const ConfigSectionParser table[_ROUTING_POLICY_RULE_CONF_PARSER_MAX] = {
                [ROUTING_POLICY_RULE_IIF]                = { .parser = config_parse_ifname,                         .ltype = 0,               .offset = offsetof(RoutingPolicyRule, iif),                },
                [ROUTING_POLICY_RULE_OIF]                = { .parser = config_parse_ifname,                         .ltype = 0,               .offset = offsetof(RoutingPolicyRule, oif),                },
                [ROUTING_POLICY_RULE_FAMILY]             = { .parser = config_parse_routing_policy_rule_family,     .ltype = 0,               .offset = offsetof(RoutingPolicyRule, address_family),     },
                [ROUTING_POLICY_RULE_FWMARK]             = { .parser = config_parse_routing_policy_rule_fwmark,     .ltype = 0,               .offset = 0,                                               },
                [ROUTING_POLICY_RULE_GOTO]               = { .parser = config_parse_routing_policy_rule_goto,       .ltype = 0,               .offset = 0,                                               },
                [ROUTING_POLICY_RULE_INVERT]             = { .parser = config_parse_uint32_flag,                    .ltype = FIB_RULE_INVERT, .offset = offsetof(RoutingPolicyRule, flags),              },
                [ROUTING_POLICY_RULE_IP_PROTOCOL]        = { .parser = config_parse_ip_protocol,                    .ltype = 0,               .offset = offsetof(RoutingPolicyRule, ipproto),            },
                [ROUTING_POLICY_RULE_L3MDEV]             = { .parser = config_parse_bool,                           .ltype = 0,               .offset = offsetof(RoutingPolicyRule, l3mdev),             },
                [ROUTING_POLICY_RULE_SPORT]              = { .parser = config_parse_routing_policy_rule_port_range, .ltype = 0,               .offset = offsetof(RoutingPolicyRule, sport),              },
                [ROUTING_POLICY_RULE_DPORT]              = { .parser = config_parse_routing_policy_rule_port_range, .ltype = 0,               .offset = offsetof(RoutingPolicyRule, dport),              },
                [ROUTING_POLICY_RULE_FROM]               = { .parser = config_parse_in_addr_prefix,                 .ltype = 0,               .offset = offsetof(RoutingPolicyRule, from),               },
                [ROUTING_POLICY_RULE_TO]                 = { .parser = config_parse_in_addr_prefix,                 .ltype = 0,               .offset = offsetof(RoutingPolicyRule, to),                 },
                [ROUTING_POLICY_RULE_PRIORITY]           = { .parser = config_parse_routing_policy_rule_priority,   .ltype = 0,               .offset = 0,                                               },
                [ROUTING_POLICY_RULE_SUPPRESS_IFGROUP]   = { .parser = config_parse_routing_policy_rule_suppress,   .ltype = INT32_MAX,       .offset = offsetof(RoutingPolicyRule, suppress_ifgroup),   },
                [ROUTING_POLICY_RULE_SUPPRESS_PREFIXLEN] = { .parser = config_parse_routing_policy_rule_suppress,   .ltype = 128,             .offset = offsetof(RoutingPolicyRule, suppress_prefixlen), },
                [ROUTING_POLICY_RULE_TABLE]              = { .parser = config_parse_routing_policy_rule_table,      .ltype = 0,               .offset = offsetof(RoutingPolicyRule, table),              },
                [ROUTING_POLICY_RULE_TOS]                = { .parser = config_parse_uint8,                          .ltype = 0,               .offset = offsetof(RoutingPolicyRule, tos),                },
                [ROUTING_POLICY_RULE_ACTION]             = { .parser = config_parse_routing_policy_rule_action,     .ltype = 0,               .offset = offsetof(RoutingPolicyRule, action),             },
                [ROUTING_POLICY_RULE_UID_RANGE]          = { .parser = config_parse_routing_policy_rule_uid_range,  .ltype = 0,               .offset = offsetof(RoutingPolicyRule, uid_range),          },
        };

        _cleanup_(routing_policy_rule_unref_or_set_invalidp) RoutingPolicyRule *rule = NULL;
        Network *network = ASSERT_PTR(userdata);
        int r;

        assert(filename);

        r = routing_policy_rule_new_static(network, filename, section_line, &rule);
        if (r < 0)
                return log_oom();

        r = config_section_parse(table, ELEMENTSOF(table),
                                 unit, filename, line, section, section_line, lvalue, ltype, rvalue, rule);
        if (r <= 0) /* 0 means non-critical error, but the section will be ignored. */
                return r;

        TAKE_PTR(rule);
        return 0;
}

#define log_rule_section(rule, fmt, ...)                                \
        ({                                                              \
                const RoutingPolicyRule *_rule = (rule);                \
                log_section_warning_errno(                              \
                                _rule ? _rule->section : NULL,          \
                                SYNTHETIC_ERRNO(EINVAL),                \
                                fmt " Ignoring [RoutingPolicyRule] section.", \
                                ##__VA_ARGS__);                         \
        })

static int routing_policy_rule_section_verify(RoutingPolicyRule *rule) {
        assert(rule);

        if (section_is_invalid(rule->section))
                return -EINVAL;

        rule->family = rule->from.family;
        if (rule->family == AF_UNSPEC)
                rule->family = rule->to.family;
        else if (rule->to.family != AF_UNSPEC && rule->to.family != rule->family)
                return log_rule_section(rule, "From= and To= settings for routing policy rule contradict each other.");

        if ((rule->family == AF_INET && FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV6)) ||
            (rule->family == AF_INET6 && FLAGS_SET(rule->address_family, ADDRESS_FAMILY_IPV4)))
                return log_rule_section(rule, "Address family specified by Family= conflicts with To= and/or From=.");

        if (rule->family == AF_UNSPEC) {
                if (IN_SET(rule->address_family, ADDRESS_FAMILY_IPV4, ADDRESS_FAMILY_NO))
                        rule->family = AF_INET;
                else if (rule->address_family == ADDRESS_FAMILY_IPV6)
                        rule->family = AF_INET6;
                /* rule->family can be AF_UNSPEC only when Family=both. */
        }

        assert(IN_SET(rule->family, AF_INET, AF_INET6) || rule->address_family == ADDRESS_FAMILY_YES);

        if (rule->l3mdev)
                rule->table = RT_TABLE_UNSPEC;

        if (rule->action == FR_ACT_GOTO) {
                if (rule->priority_goto <= 0)
                        return log_rule_section(rule, "Type=goto is specified but the target priority GoTo= is unspecified.");

                if (rule->priority_set && rule->priority >= rule->priority_goto)
                        return log_rule_section(rule, "Goto target priority %"PRIu32" must be larger than the priority of this rule %"PRIu32".",
                                                rule->priority_goto, rule->priority);
        }

        return 0;
}

void network_drop_invalid_routing_policy_rules(Network *network) {
        RoutingPolicyRule *rule;

        assert(network);

        HASHMAP_FOREACH(rule, network->rules_by_section)
                if (routing_policy_rule_section_verify(rule) < 0)
                        routing_policy_rule_detach(rule);
}
