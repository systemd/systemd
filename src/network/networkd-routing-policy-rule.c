/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>
#include <linux/fib_rules.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "fileio.h"
#include "ip-protocol-list.h"
#include "networkd-routing-policy-rule.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"

int routing_policy_rule_new(RoutingPolicyRule **ret) {
        RoutingPolicyRule *rule;

        rule = new(RoutingPolicyRule, 1);
        if (!rule)
                return -ENOMEM;

        *rule = (RoutingPolicyRule) {
                .family = AF_INET,
                .table = RT_TABLE_MAIN,
        };

        *ret = rule;
        return 0;
}

void routing_policy_rule_free(RoutingPolicyRule *rule) {

        if (!rule)
                return;

        if (rule->network) {
                LIST_REMOVE(rules, rule->network->rules, rule);
                assert(rule->network->n_rules > 0);
                rule->network->n_rules--;

                if (rule->section)
                        hashmap_remove(rule->network->rules_by_section, rule->section);
        }

        if (rule->manager) {
                set_remove(rule->manager->rules, rule);
                set_remove(rule->manager->rules_foreign, rule);
        }

        network_config_section_free(rule->section);
        free(rule->iif);
        free(rule->oif);
        free(rule);
}

static void routing_policy_rule_hash_func(const void *b, struct siphash *state) {
        const RoutingPolicyRule *rule = b;

        assert(rule);

        siphash24_compress(&rule->family, sizeof(rule->family), state);

        switch (rule->family) {
        case AF_INET:
        case AF_INET6:

                siphash24_compress(&rule->from, FAMILY_ADDRESS_SIZE(rule->family), state);
                siphash24_compress(&rule->from_prefixlen, sizeof(rule->from_prefixlen), state);

                siphash24_compress(&rule->to, FAMILY_ADDRESS_SIZE(rule->family), state);
                siphash24_compress(&rule->to_prefixlen, sizeof(rule->to_prefixlen), state);

                siphash24_compress(&rule->tos, sizeof(rule->tos), state);
                siphash24_compress(&rule->fwmark, sizeof(rule->fwmark), state);
                siphash24_compress(&rule->table, sizeof(rule->table), state);

                siphash24_compress(&rule->protocol, sizeof(rule->protocol), state);
                siphash24_compress(&rule->sport, sizeof(rule->sport), state);
                siphash24_compress(&rule->dport, sizeof(rule->dport), state);

                if (rule->iif)
                        siphash24_compress(rule->iif, strlen(rule->iif), state);

                if (rule->oif)
                        siphash24_compress(rule->oif, strlen(rule->oif), state);

                break;
        default:
                /* treat any other address family as AF_UNSPEC */
                break;
        }
}

static int routing_policy_rule_compare_func(const void *_a, const void *_b) {
        const RoutingPolicyRule *a = _a, *b = _b;
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

                r = CMP(a->to_prefixlen, b->to_prefixlen);
                if (r != 0)
                        return r;

                r = CMP(a->tos, b->tos);
                if (r != 0)
                        return r;

                r = CMP(a->fwmask, b->fwmask);
                if (r != 0)
                        return r;

                r = CMP(a->table, b->table);
                if (r != 0)
                        return r;

                r = strcmp_ptr(a->iif, b->iif);
                if (!r)
                        return r;

                r = strcmp_ptr(a->oif, b->oif);
                if (!r)
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

                r = memcmp(&a->from, &b->from, FAMILY_ADDRESS_SIZE(a->family));
                if (r != 0)
                        return r;

                return memcmp(&a->to, &b->to, FAMILY_ADDRESS_SIZE(a->family));

        default:
                /* treat any other address family as AF_UNSPEC */
                return 0;
        }
}

const struct hash_ops routing_policy_rule_hash_ops = {
        .hash = routing_policy_rule_hash_func,
        .compare = routing_policy_rule_compare_func
};

int routing_policy_rule_get(Manager *m,
                            int family,
                            const union in_addr_union *from,
                            uint8_t from_prefixlen,
                            const union in_addr_union *to,
                            uint8_t to_prefixlen,
                            uint8_t tos,
                            uint32_t fwmark,
                            uint32_t table,
                            const char *iif,
                            const char *oif,
                            uint8_t protocol,
                            struct fib_rule_port_range *sport,
                            struct fib_rule_port_range *dport,
                            RoutingPolicyRule **ret) {

        RoutingPolicyRule rule, *existing;

        assert_return(m, -1);

        rule = (RoutingPolicyRule) {
                .family = family,
                .from = *from,
                .from_prefixlen = from_prefixlen,
                .to = *to,
                .to_prefixlen = to_prefixlen,
                .tos = tos,
                .fwmark = fwmark,
                .table = table,
                .iif = (char*) iif,
                .oif = (char*) oif,
                .protocol = protocol,
                .sport = *sport,
                .dport = *dport,
        };

        existing = set_get(m->rules, &rule);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 1;
        }

        existing = set_get(m->rules_foreign, &rule);
        if (existing) {
                if (ret)
                        *ret = existing;
                return 0;
        }

        return -ENOENT;
}

int routing_policy_rule_make_local(Manager *m, RoutingPolicyRule *rule) {
        int r;

        assert(m);

        if (set_contains(m->rules_foreign, rule)) {
                set_remove(m->rules_foreign, rule);

                r = set_ensure_allocated(&m->rules, &routing_policy_rule_hash_ops);
                if (r < 0)
                        return r;

                return set_put(m->rules, rule);
        }

        return -ENOENT;
}

static int routing_policy_rule_add_internal(Manager *m,
                                            Set **rules,
                                            int family,
                                            const union in_addr_union *from,
                                            uint8_t from_prefixlen,
                                            const union in_addr_union *to,
                                            uint8_t to_prefixlen,
                                            uint8_t tos,
                                            uint32_t fwmark,
                                            uint32_t table,
                                            const char *_iif,
                                            const char *_oif,
                                            uint8_t protocol,
                                            const struct fib_rule_port_range *sport,
                                            const struct fib_rule_port_range *dport,
                                            RoutingPolicyRule **ret) {

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        _cleanup_free_ char *iif = NULL, *oif = NULL;
        int r;

        assert_return(rules, -EINVAL);

        if (_iif) {
                iif = strdup(_iif);
                if (!iif)
                        return -ENOMEM;
        }

        if (_oif) {
                oif = strdup(_oif);
                if (!oif)
                        return -ENOMEM;
        }

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        rule->manager = m;
        rule->family = family;
        rule->from = *from;
        rule->from_prefixlen = from_prefixlen;
        rule->to = *to;
        rule->to_prefixlen = to_prefixlen;
        rule->tos = tos;
        rule->fwmark = fwmark;
        rule->table = table;
        rule->iif = iif;
        rule->oif = oif;
        rule->protocol = protocol;
        rule->sport = *sport;
        rule->dport = *dport;

        r = set_ensure_allocated(rules, &routing_policy_rule_hash_ops);
        if (r < 0)
                return r;

        r = set_put(*rules, rule);
        if (r < 0)
                return r;

        if (ret)
                *ret = rule;

        rule = NULL;
        iif = oif = NULL;

        return 0;
}

int routing_policy_rule_add(Manager *m,
                            int family,
                            const union in_addr_union *from,
                            uint8_t from_prefixlen,
                            const union in_addr_union *to,
                            uint8_t to_prefixlen,
                            uint8_t tos,
                            uint32_t fwmark,
                            uint32_t table,
                            const char *iif,
                            const char *oif,
                            uint8_t protocol,
                            const struct fib_rule_port_range *sport,
                            const struct fib_rule_port_range *dport,
                            RoutingPolicyRule **ret) {

        return routing_policy_rule_add_internal(m, &m->rules, family, from, from_prefixlen, to, to_prefixlen, tos, fwmark, table, iif, oif, protocol, sport, dport, ret);
}

int routing_policy_rule_add_foreign(Manager *m,
                                    int family,
                                    const union in_addr_union *from,
                                    uint8_t from_prefixlen,
                                    const union in_addr_union *to,
                                    uint8_t to_prefixlen,
                                    uint8_t tos,
                                    uint32_t fwmark,
                                    uint32_t table,
                                    const char *iif,
                                    const char *oif,
                                    uint8_t protocol,
                                    const struct fib_rule_port_range *sport,
                                    const struct fib_rule_port_range *dport,
                                    RoutingPolicyRule **ret) {
        return routing_policy_rule_add_internal(m, &m->rules_foreign, family, from, from_prefixlen, to, to_prefixlen, tos, fwmark, table, iif, oif, protocol, sport, dport, ret);
}

static int routing_policy_rule_remove_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(m);
        assert(link);
        assert(link->ifname);

        link->routing_policy_rule_remove_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0)
                log_link_warning_errno(link, r, "Could not drop routing policy rule: %m");

        return 1;
}

int routing_policy_rule_remove(RoutingPolicyRule *routing_policy_rule, Link *link, sd_netlink_message_handler_t callback) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(routing_policy_rule);
        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);
        assert(IN_SET(routing_policy_rule->family, AF_INET, AF_INET6));

        r = sd_rtnl_message_new_routing_policy_rule(link->manager->rtnl, &m, RTM_DELRULE, routing_policy_rule->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_DELRULE message: %m");

        if (!in_addr_is_null(routing_policy_rule->family, &routing_policy_rule->from)) {
                if (routing_policy_rule->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, FRA_SRC, &routing_policy_rule->from.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, FRA_SRC, &routing_policy_rule->from.in6);

                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_SRC attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_src_prefixlen(m, routing_policy_rule->from_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set source prefix length: %m");
        }

        if (!in_addr_is_null(routing_policy_rule->family, &routing_policy_rule->to)) {
                if (routing_policy_rule->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, FRA_DST, &routing_policy_rule->to.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, FRA_DST, &routing_policy_rule->to.in6);

                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_DST attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_dst_prefixlen(m, routing_policy_rule->to_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set destination prefix length: %m");
        }

        r = sd_netlink_call_async(link->manager->rtnl, NULL, m, callback,
                                  link_netlink_destroy_callback, link, 0, __func__);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

static int routing_policy_rule_new_static(Network *network, const char *filename, unsigned section_line, RoutingPolicyRule **ret) {
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                rule = hashmap_get(network->rules_by_section, n);
                if (rule) {
                        *ret = TAKE_PTR(rule);

                        return 0;
                }
        }

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        rule->network = network;
        LIST_APPEND(rules, network->rules, rule);
        network->n_rules++;

        if (filename) {
                rule->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->rules_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->rules_by_section, rule->section, rule);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(rule);

        return 0;
}

int link_routing_policy_rule_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        Link *link = userdata;
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
        if (r < 0 && r != -EEXIST)
                log_link_warning_errno(link, r, "Could not add routing policy rule: %m");

        if (link->routing_policy_rule_messages == 0) {
                log_link_debug(link, "Routing policy rule configured");
                link->routing_policy_rules_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int routing_policy_rule_configure(RoutingPolicyRule *rule, Link *link, sd_netlink_message_handler_t callback, bool update) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rule);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_routing_policy_rule(link->manager->rtnl, &m, RTM_NEWRULE, rule->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_NEWRULE message: %m");

        if (!in_addr_is_null(rule->family, &rule->from)) {
                if (rule->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, FRA_SRC, &rule->from.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, FRA_SRC, &rule->from.in6);

                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_SRC attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_src_prefixlen(m, rule->from_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set source prefix length: %m");
        }

        if (!in_addr_is_null(rule->family, &rule->to)) {
                if (rule->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, FRA_DST, &rule->to.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, FRA_DST, &rule->to.in6);

                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_DST attribute: %m");

                r = sd_rtnl_message_routing_policy_rule_set_rtm_dst_prefixlen(m, rule->to_prefixlen);
                if (r < 0)
                        return log_error_errno(r, "Could not set destination prefix length: %m");
        }

        r = sd_netlink_message_append_u32(m, FRA_PRIORITY, rule->priority);
        if (r < 0)
                return log_error_errno(r, "Could not append FRA_PRIORITY attribute: %m");

        if (rule->tos > 0) {
                r = sd_rtnl_message_routing_policy_rule_set_tos(m, rule->tos);
                if (r < 0)
                        return log_error_errno(r, "Could not set ip rule tos: %m");
        }

        if (rule->table < 256) {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, rule->table);
                if (r < 0)
                        return log_error_errno(r, "Could not set ip rule table: %m");
        } else {
                r = sd_rtnl_message_routing_policy_rule_set_table(m, RT_TABLE_UNSPEC);
                if (r < 0)
                        return log_error_errno(r, "Could not set ip rule table: %m");

                r = sd_netlink_message_append_u32(m, FRA_TABLE, rule->table);
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_TABLE attribute: %m");
        }

        if (rule->fwmark > 0) {
                r = sd_netlink_message_append_u32(m, FRA_FWMARK, rule->fwmark);
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_FWMARK attribute: %m");
        }

        if (rule->fwmask > 0) {
                r = sd_netlink_message_append_u32(m, FRA_FWMASK, rule->fwmask);
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_FWMASK attribute: %m");
        }

        if (rule->iif) {
                r = sd_netlink_message_append_string(m, FRA_IFNAME, rule->iif);
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_IFNAME attribute: %m");
        }

        if (rule->oif) {
                r = sd_netlink_message_append_string(m, FRA_OIFNAME, rule->oif);
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_OIFNAME attribute: %m");
        }

        r = sd_netlink_message_append_u8(m, FRA_IP_PROTO, rule->protocol);
        if (r < 0)
                return log_error_errno(r, "Could not append FRA_IP_PROTO attribute: %m");

        if (rule->sport.start != 0 || rule->sport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_SPORT_RANGE, &rule->sport, sizeof(rule->sport));
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_SPORT_RANGE attribute: %m");
        }

        if (rule->dport.start != 0 || rule->dport.end != 0) {
                r = sd_netlink_message_append_data(m, FRA_DPORT_RANGE, &rule->dport, sizeof(rule->dport));
                if (r < 0)
                        return log_error_errno(r, "Could not append FRA_DPORT_RANGE attribute: %m");
        }

        rule->link = link;

        r = sd_netlink_call_async(link->manager->rtnl, NULL, m, callback,
                                  link_netlink_destroy_callback, link, 0, __func__);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        r = routing_policy_rule_add(link->manager, rule->family, &rule->from, rule->from_prefixlen, &rule->to,
                                    rule->to_prefixlen, rule->tos, rule->fwmark, rule->table, rule->iif, rule->oif, rule->protocol, &rule->sport, &rule->dport, NULL);
        if (r < 0)
                return log_error_errno(r, "Could not add rule: %m");

        return 0;
}

static int parse_fwmark_fwmask(const char *s, uint32_t *fwmark, uint32_t *fwmask) {
        _cleanup_free_ char *f = NULL;
        char *p;
        int r;

        assert(s);

        f = strdup(s);
        if (!f)
                return -ENOMEM;

        p = strchr(f, '/');
        if (p)
                *p++ = '\0';

        r = safe_atou32(f, fwmark);
        if (r < 0)
                return log_error_errno(r, "Failed to parse RPDB rule firewall mark, ignoring: %s", f);

        if (p) {
                r = safe_atou32(p, fwmask);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse RPDB rule mask, ignoring: %s", f);
        }

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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = safe_atou8(rvalue, &n->tos);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse RPDB rule tos, ignoring: %s", rvalue);
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = safe_atou32(rvalue, &n->priority);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse RPDB rule priority, ignoring: %s", rvalue);
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = safe_atou32(rvalue, &n->table);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse RPDB rule table, ignoring: %s", rvalue);
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = parse_fwmark_fwmask(rvalue, &n->fwmark, &n->fwmask);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse RPDB rule firewall mark or mask, ignoring: %s", rvalue);
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        union in_addr_union buffer;
        uint8_t prefixlen;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_prefix_from_string(rvalue, AF_INET, &buffer, &prefixlen);
        if (r < 0) {
                r = in_addr_prefix_from_string(rvalue, AF_INET6, &buffer, &prefixlen);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r, "RPDB rule prefix is invalid, ignoring assignment: %s", rvalue);
                        return 0;
                }

                n->family = AF_INET6;
        } else
                n->family = AF_INET;

        if (streq(lvalue, "To")) {
                n->to = buffer;
                n->to_prefixlen = prefixlen;
        } else {
                n->from = buffer;
                n->from_prefixlen = prefixlen;
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse '%s' interface name, ignoring: %s", lvalue, rvalue);
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
        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
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
                return r;

        r = parse_ip_port_range(rvalue, &low, &high);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse routing policy rule port range '%s'", rvalue);
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

        _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *n = NULL;
        Network *network = userdata;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = routing_policy_rule_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = parse_ip_protocol(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse IP protocol '%s' for routing policy rule, ignoring: %m", rvalue);
                return 0;
        }

        n->protocol = r;

        n = NULL;

        return 0;
}

static int routing_policy_rule_read_full_file(const char *state_file, char **ret) {
        _cleanup_free_ char *s = NULL;
        size_t size;
        int r;

        assert(state_file);

        r = read_full_file(state_file, &s, &size);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (size <= 0)
                return -ENODATA;

        *ret = TAKE_PTR(s);

        return size;
}

int routing_policy_serialize_rules(Set *rules, FILE *f) {
        RoutingPolicyRule *rule = NULL;
        Iterator i;
        int r;

        assert(f);

        SET_FOREACH(rule, rules, i) {
                _cleanup_free_ char *from_str = NULL, *to_str = NULL;
                bool space = false;

                fputs("RULE=", f);

                if (!in_addr_is_null(rule->family, &rule->from)) {
                        r = in_addr_to_string(rule->family, &rule->from, &from_str);
                        if (r < 0)
                                return r;

                        fprintf(f, "from=%s/%hhu",
                                from_str, rule->from_prefixlen);
                        space = true;
                }

                if (!in_addr_is_null(rule->family, &rule->to)) {
                        r = in_addr_to_string(rule->family, &rule->to, &to_str);
                        if (r < 0)
                                return r;

                        fprintf(f, "%sto=%s/%hhu",
                                space ? " " : "",
                                to_str, rule->to_prefixlen);
                        space = true;
                }

                if (rule->tos != 0) {
                        fprintf(f, "%stos=%hhu",
                                space ? " " : "",
                                rule->tos);
                        space = true;
                }

                if (rule->fwmark != 0) {
                        fprintf(f, "%sfwmark=%"PRIu32"/%"PRIu32,
                                space ? " " : "",
                                rule->fwmark, rule->fwmask);
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

                fprintf(f, "%stable=%"PRIu32 "\n",
                        space ? " " : "",
                        rule->table);
        }

        return 0;
}

int routing_policy_load_rules(const char *state_file, Set **rules) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *data = NULL;
        uint16_t low = 0, high = 0;
        const char *p;
        char **i;
        int r;

        assert(state_file);
        assert(rules);

        r = routing_policy_rule_read_full_file(state_file, &data);
        if (r <= 0)
                return r;

        l = strv_split_newlines(data);
        if (!l)
                return -ENOMEM;

        r = set_ensure_allocated(rules, &routing_policy_rule_hash_ops);
        if (r < 0)
                return r;

        STRV_FOREACH(i, l) {
                _cleanup_(routing_policy_rule_freep) RoutingPolicyRule *rule = NULL;

                p = startswith(*i, "RULE=");
                if (!p)
                        continue;

                r = routing_policy_rule_new(&rule);
                if (r < 0)
                        return r;

                for (;;) {
                        _cleanup_free_ char *word = NULL, *a = NULL, *b = NULL;
                        union in_addr_union buffer;
                        uint8_t prefixlen;

                        r = extract_first_word(&p, &word, NULL, 0);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = split_pair(word, "=", &a, &b);
                        if (r < 0)
                                continue;

                        if (STR_IN_SET(a, "from", "to")) {

                                r = in_addr_prefix_from_string(b, AF_INET, &buffer, &prefixlen);
                                if (r < 0) {
                                        r = in_addr_prefix_from_string(b, AF_INET6, &buffer, &prefixlen);
                                        if (r < 0) {
                                                log_error_errno(r, "RPDB rule prefix is invalid, ignoring assignment: %s", b);
                                                continue;
                                        }

                                        rule->family = AF_INET6;
                                } else
                                        rule->family = AF_INET;

                                if (streq(a, "to")) {
                                        rule->to = buffer;
                                        rule->to_prefixlen = prefixlen;
                                } else {
                                        rule->from = buffer;
                                        rule->from_prefixlen = prefixlen;
                                }
                        } else if (streq(a, "tos")) {
                                r = safe_atou8(b, &rule->tos);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse RPDB rule tos, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "table")) {
                                r = safe_atou32(b, &rule->table);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse RPDB rule table, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "fwmark")) {

                                r = parse_fwmark_fwmask(b, &rule->fwmark, &rule->fwmask);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to parse RPDB rule firewall mark or mask, ignoring: %s", a);
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
                                        log_error_errno(r, "Failed to parse RPDB rule protocol, ignoring: %s", b);
                                        continue;
                                }
                        } else if (streq(a, "sourceport")) {

                                r = parse_ip_port_range(b, &low, &high);
                                if (r < 0) {
                                        log_error_errno(r, "Invalid routing policy rule source port range, ignoring assignment:'%s'", b);
                                        continue;
                                }

                                rule->sport.start = low;
                                rule->sport.end = high;

                        } else if (streq(a, "destinationport")) {

                                r = parse_ip_port_range(b, &low, &high);
                                if (r < 0) {
                                        log_error_errno(r, "Invalid routing policy rule destination port range, ignoring assignment:'%s'", b);
                                        continue;
                                }

                                rule->dport.start = low;
                                rule->dport.end = high;
                        }
                }

                r = set_put(*rules, rule);
                if (r < 0) {
                        log_warning_errno(r, "Failed to add RPDB rule to saved DB, ignoring: %s", p);
                        continue;
                }

                rule = NULL;
        }

        return 0;
}

void routing_policy_rule_purge(Manager *m, Link *link) {
        RoutingPolicyRule *rule, *existing;
        Iterator i;
        int r;

        assert(m);
        assert(link);

        SET_FOREACH(rule, m->rules_saved, i) {
                existing = set_get(m->rules_foreign, rule);
                if (existing) {

                        r = routing_policy_rule_remove(rule, link, routing_policy_rule_remove_handler);
                        if (r < 0) {
                                log_warning_errno(r, "Could not remove routing policy rules: %m");
                                continue;
                        }

                        link->routing_policy_rule_remove_messages++;
                }
        }
}
