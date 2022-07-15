/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "dns-domain.h"
#include "ip-protocol-list.h"
#include "netif-util.h"
#include "networkd-address.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-nexthop.h"
#include "networkd-network.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "sort-util.h"
#include "user-util.h"
#include "wifi-util.h"

static int address_build_json(Address *address, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *scope = NULL, *flags = NULL, *state = NULL;
        int r;

        assert(address);
        assert(ret);

        r = route_scope_to_string_alloc(address->scope, &scope);
        if (r < 0)
                return r;

        r = address_flags_to_string_alloc(address->flags, address->family, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(address->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", address->family),
                                JSON_BUILD_PAIR_IN_ADDR("Address", &address->in_addr, address->family),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Peer", &address->in_addr_peer, address->family),
                                JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("Broadcast", &address->broadcast),
                                JSON_BUILD_PAIR_UNSIGNED("PrefixLength", address->prefixlen),
                                JSON_BUILD_PAIR_UNSIGNED("Scope", address->scope),
                                JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", address->flags),
                                JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Label", address->label),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUsec", address->lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUsec", address->lifetime_valid_usec),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(address->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &address->provider, address->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int addresses_build_json(Set *addresses, JsonVariant **ret) {
        JsonVariant **elements;
        Address *address;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(addresses)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(addresses));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(address, addresses) {
                r = address_build_json(address, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("Addresses", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int neighbor_build_json(Neighbor *n, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *state = NULL;
        int r;

        assert(n);
        assert(ret);

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", n->family),
                                JSON_BUILD_PAIR_IN_ADDR("Destination", &n->in_addr, n->family),
                                JSON_BUILD_PAIR_HW_ADDR("LinkLayerAddress", &n->ll_addr),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int neighbors_build_json(Set *neighbors, JsonVariant **ret) {
        JsonVariant **elements;
        Neighbor *neighbor;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(neighbors)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(neighbors));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(neighbor, neighbors) {
                r = neighbor_build_json(neighbor, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("Neighbors", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nexthop_group_build_json(NextHop *nexthop, JsonVariant **ret) {
        JsonVariant **elements;
        struct nexthop_grp *g;
        size_t n = 0;
        int r;

        assert(nexthop);
        assert(ret);

        if (hashmap_isempty(nexthop->group)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, hashmap_size(nexthop->group));
        if (!elements)
                return -ENOMEM;

        HASHMAP_FOREACH(g, nexthop->group) {
                r = json_build(elements + n, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_UNSIGNED("ID", g->id),
                                        JSON_BUILD_PAIR_UNSIGNED("Weight", g->weight+1)));
                if (r < 0)
                        goto failure;

                n++;
        }

        r = json_variant_new_array(ret, elements, n);

failure:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nexthop_build_json(NextHop *n, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *group = NULL;
        _cleanup_free_ char *flags = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(n);
        assert(ret);

        r = route_flags_to_string_alloc(n->flags, &flags);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(n->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        r = nexthop_group_build_json(n, &group);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_UNSIGNED("ID", n->id),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Gateway", &n->gw, n->family),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", n->flags),
                                JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                JSON_BUILD_PAIR_UNSIGNED("Protocol", n->protocol),
                                JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                JSON_BUILD_PAIR_BOOLEAN("Blackhole", n->blackhole),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("Group", group),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int nexthops_build_json(Set *nexthops, JsonVariant **ret) {
        JsonVariant **elements;
        NextHop *nexthop;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(nexthops)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(nexthops));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(nexthop, nexthops) {
                r = nexthop_build_json(nexthop, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("NextHops", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int route_build_json(Route *route, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *flags = NULL, *state = NULL;
        Manager *manager;
        int r;

        assert(route);
        assert(ret);

        manager = route->link ? route->link->manager : route->manager;

        assert(manager);

        r = route_scope_to_string_alloc(route->scope, &scope);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(route->protocol, &protocol);
        if (r < 0)
                return r;

        r = manager_get_route_table_to_string(manager, route->table, &table);
        if (r < 0)
                return r;

        r = route_flags_to_string_alloc(route->flags, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(route->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", route->family),
                                JSON_BUILD_PAIR_IN_ADDR("Destination", &route->dst, route->family),
                                JSON_BUILD_PAIR_UNSIGNED("DestinationPrefixLength", route->dst_prefixlen),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Gateway", &route->gw, route->gw_family),
                                JSON_BUILD_PAIR_CONDITION(route->src_prefixlen > 0,
                                                          "Source", JSON_BUILD_IN_ADDR(&route->src, route->family)),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("SourcePrefixLength", route->src_prefixlen),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("PreferredSource", &route->prefsrc, route->family),
                                JSON_BUILD_PAIR_UNSIGNED("Scope", route->scope),
                                JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                JSON_BUILD_PAIR_UNSIGNED("Protocol", route->protocol),
                                JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                JSON_BUILD_PAIR_UNSIGNED("Type", route->type),
                                JSON_BUILD_PAIR_STRING("TypeString", route_type_to_string(route->type)),
                                JSON_BUILD_PAIR_UNSIGNED("Priority", route->priority),
                                JSON_BUILD_PAIR_UNSIGNED("Table", route->table),
                                JSON_BUILD_PAIR_STRING("TableString", table),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("MTU", route->mtu),
                                JSON_BUILD_PAIR_UNSIGNED("Preference", route->pref),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", route->flags),
                                JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                JSON_BUILD_PAIR_FINITE_USEC("LifetimeUSec", route->lifetime_usec),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(route->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &route->provider, route->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int routes_build_json(Set *routes, JsonVariant **ret) {
        JsonVariant **elements;
        Route *route;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(routes)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(routes));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(route, routes) {
                r = route_build_json(route, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("Routes", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int routing_policy_rule_build_json(RoutingPolicyRule *rule, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *table = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(rule);
        assert(rule->manager);
        assert(ret);

        r = manager_get_route_table_to_string(rule->manager, rule->table, &table);
        if (r < 0 && r != -EINVAL)
                return r;

        r = route_protocol_to_string_alloc(rule->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(rule->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", rule->family),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("FromPrefix", &rule->from, rule->family),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->from),
                                                          "FromPrefixLength", JSON_BUILD_UNSIGNED(rule->from_prefixlen)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ToPrefix", &rule->to, rule->family),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->to),
                                                          "ToPrefixLength", JSON_BUILD_UNSIGNED(rule->to_prefixlen)),
                                JSON_BUILD_PAIR_UNSIGNED("Protocol", rule->protocol),
                                JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                JSON_BUILD_PAIR_UNSIGNED("TOS", rule->tos),
                                JSON_BUILD_PAIR_UNSIGNED("Type", rule->type),
                                JSON_BUILD_PAIR_STRING("TypeString", fr_act_type_full_to_string(rule->type)),
                                JSON_BUILD_PAIR_UNSIGNED("IPProtocol", rule->ipproto),
                                JSON_BUILD_PAIR_STRING("IPProtocolString", ip_protocol_to_name(rule->ipproto)),
                                JSON_BUILD_PAIR_UNSIGNED("Priority", rule->priority),
                                JSON_BUILD_PAIR_UNSIGNED("FirewallMark", rule->fwmark),
                                JSON_BUILD_PAIR_UNSIGNED("FirewallMask", rule->fwmask),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Table", rule->table),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("TableString", table),
                                JSON_BUILD_PAIR_BOOLEAN("Invert", rule->invert_rule),
                                JSON_BUILD_PAIR_CONDITION(rule->suppress_prefixlen >= 0,
                                                          "SuppressPrefixLength", JSON_BUILD_UNSIGNED(rule->suppress_prefixlen)),
                                JSON_BUILD_PAIR_CONDITION(rule->suppress_ifgroup >= 0,
                                                          "SuppressInterfaceGroup", JSON_BUILD_UNSIGNED(rule->suppress_ifgroup)),
                                JSON_BUILD_PAIR_CONDITION(rule->sport.start != 0 || rule->sport.end != 0, "SourcePort",
                                                          JSON_BUILD_ARRAY(JSON_BUILD_UNSIGNED(rule->sport.start), JSON_BUILD_UNSIGNED(rule->sport.end))),
                                JSON_BUILD_PAIR_CONDITION(rule->dport.start != 0 || rule->dport.end != 0, "DestinationPort",
                                                          JSON_BUILD_ARRAY(JSON_BUILD_UNSIGNED(rule->dport.start), JSON_BUILD_UNSIGNED(rule->dport.end))),
                                JSON_BUILD_PAIR_CONDITION(rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID, "User",
                                                          JSON_BUILD_ARRAY(JSON_BUILD_UNSIGNED(rule->uid_range.start), JSON_BUILD_UNSIGNED(rule->uid_range.end))),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("IncomingInterface", rule->iif),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("OutgoingInterface", rule->oif),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(rule->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int routing_policy_rules_build_json(Set *rules, JsonVariant **ret) {
        JsonVariant **elements;
        RoutingPolicyRule *rule;
        size_t n = 0;
        int r;

        assert(ret);

        if (set_isempty(rules)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(rules));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(rule, rules) {
                r = routing_policy_rule_build_json(rule, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("RoutingPolicyRules", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int network_build_json(Network *network, JsonVariant **ret) {
        assert(ret);

        if (!network) {
                *ret = NULL;
                return 0;
        }

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("NetworkFile", network->filename),
                                JSON_BUILD_PAIR_BOOLEAN("RequiredForOnline", network->required_for_online),
                                JSON_BUILD_PAIR("RequiredOperationalStateForOnline",
                                                JSON_BUILD_ARRAY(JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.min)),
                                                                 JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.max)))),
                                JSON_BUILD_PAIR_STRING("RequiredFamilyForOnline",
                                                       link_required_address_family_to_string(network->required_family_for_online)),
                                JSON_BUILD_PAIR_STRING("ActivationPolicy",
                                                       activation_policy_to_string(network->activation_policy))));
}

static int device_build_json(sd_device *device, JsonVariant **ret) {
        const char *link = NULL, *path = NULL, *vendor = NULL, *model = NULL;

        assert(ret);

        if (!device) {
                *ret = NULL;
                return 0;
        }

        (void) sd_device_get_property_value(device, "ID_NET_LINK_FILE", &link);
        (void) sd_device_get_property_value(device, "ID_PATH", &path);

        if (sd_device_get_property_value(device, "ID_VENDOR_FROM_DATABASE", &vendor) < 0)
                (void) sd_device_get_property_value(device, "ID_VENDOR", &vendor);

        if (sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &model) < 0)
                (void) sd_device_get_property_value(device, "ID_MODEL", &model);

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("LinkFile", link),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Path", path),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Vendor", vendor),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Model", model)));
}

static int dns_build_json_one(Link *link, const struct in_addr_full *a, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(link);
        assert(a);
        assert(ret);

        if (a->ifindex != 0 && a->ifindex != link->ifindex) {
                *ret = NULL;
                return 0;
        }

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", a->family),
                                JSON_BUILD_PAIR_IN_ADDR("Address", &a->address, a->family),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", a->port),
                                JSON_BUILD_PAIR_CONDITION(a->ifindex != 0, "InterfaceIndex", JSON_BUILD_INTEGER(a->ifindex)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", a->server_name),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, a->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 1;
}

static int dns_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements = NULL;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        if (link->n_dns != UINT_MAX) {
                for (unsigned i = 0; i < link->n_dns; i++) {
                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                r = -ENOMEM;
                                goto finalize;
                        }

                        r = dns_build_json_one(link, link->dns[i], NETWORK_CONFIG_SOURCE_RUNTIME, NULL, elements + n);
                        if (r < 0)
                                goto finalize;
                        if (r > 0)
                                n++;
                }
        } else {
                for (unsigned i = 0; i < link->network->n_dns; i++) {
                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                r = -ENOMEM;
                                goto finalize;
                        }

                        r = dns_build_json_one(link, link->network->dns[i], NETWORK_CONFIG_SOURCE_STATIC, NULL, elements + n);
                        if (r < 0)
                                goto finalize;
                        if (r > 0)
                                n++;
                }

                if (link->dhcp_lease && link->network->dhcp_use_dns) {
                        const struct in_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        n_dns = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET, .address.in = dns[i], },
                                                       NETWORK_CONFIG_SOURCE_DHCP4,
                                                       &s,
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_dns) {
                        const struct in6_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        n_dns = sd_dhcp6_lease_get_dns(link->dhcp6_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET6, .address.in6 = dns[i], },
                                                       NETWORK_CONFIG_SOURCE_DHCP6,
                                                       &s,
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }

                if (link->network->ipv6_accept_ra_use_dns) {
                        NDiscRDNSS *a;

                        SET_FOREACH(a, link->ndisc_rdnss) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = dns_build_json_one(link,
                                                       &(struct in_addr_full) { .family = AF_INET6, .address.in6 = a->address, },
                                                       NETWORK_CONFIG_SOURCE_NDISC,
                                                       &(union in_addr_union) { .in6 = a->router },
                                                       elements + n);
                                if (r < 0)
                                        goto finalize;
                                if (r > 0)
                                        n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                r = 0;
                goto finalize;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("DNS", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int server_build_json_one_addr(int family, const union in_addr_union *a, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **ret) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(a);
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", family),
                                JSON_BUILD_PAIR_IN_ADDR("Address", a, family),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_build_json_one_fqdn(int family, const char *fqdn, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **ret) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(fqdn);
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Server", fqdn),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_build_json_one_string(const char *str, NetworkConfigSource s, JsonVariant **ret) {
        union in_addr_union a;
        int family;

        assert(str);
        assert(ret);

        if (in_addr_from_string_auto(str, &family, &a) >= 0)
                return server_build_json_one_addr(family, &a, s, NULL, ret);

        return server_build_json_one_fqdn(AF_UNSPEC, str, s, NULL, ret);
}

static int ntp_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements = NULL;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        STRV_FOREACH(p, link->ntp ?: link->network->ntp) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = server_build_json_one_string(*p, NETWORK_CONFIG_SOURCE_RUNTIME, elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (!link->ntp) {
                if (link->dhcp_lease && link->network->dhcp_use_ntp) {
                        const struct in_addr *ntp;
                        union in_addr_union s;
                        int n_ntp;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        n_ntp = sd_dhcp_lease_get_ntp(link->dhcp_lease, &ntp);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_addr(AF_INET,
                                                               &(union in_addr_union) { .in = ntp[i], },
                                                               NETWORK_CONFIG_SOURCE_DHCP4,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_ntp) {
                        const struct in6_addr *ntp_addr;
                        union in_addr_union s;
                        char **ntp_fqdn;
                        int n_ntp;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        n_ntp = sd_dhcp6_lease_get_ntp_addrs(link->dhcp6_lease, &ntp_addr);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_addr(AF_INET6,
                                                               &(union in_addr_union) { .in6 = ntp_addr[i], },
                                                               NETWORK_CONFIG_SOURCE_DHCP6,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }

                        n_ntp = sd_dhcp6_lease_get_ntp_fqdn(link->dhcp6_lease, &ntp_fqdn);
                        for (int i = 0; i < n_ntp; i++) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = server_build_json_one_fqdn(AF_INET6,
                                                               ntp_fqdn[i],
                                                               NETWORK_CONFIG_SOURCE_DHCP6,
                                                               &s,
                                                               elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("NTP", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int sip_build_json(Link *link, JsonVariant **ret) {
        const struct in_addr *sip;
        JsonVariant **elements;
        union in_addr_union s;
        size_t n = 0;
        int n_sip, r;

        assert(link);
        assert(ret);

        if (!link->network || !link->network->dhcp_use_sip || !link->dhcp_lease) {
                *ret = NULL;
                return 0;
        }

        n_sip = sd_dhcp_lease_get_sip(link->dhcp_lease, &sip);
        if (n_sip <= 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
        if (r < 0)
                return r;

        elements = new(JsonVariant*, n_sip);
        if (!elements)
                return -ENOMEM;

        for (int i = 0; i < n_sip; i++) {
                r = server_build_json_one_addr(AF_INET,
                                               &(union in_addr_union) { .in = sip[i], },
                                               NETWORK_CONFIG_SOURCE_DHCP4,
                                               &s,
                                               elements + n);
                if (r < 0)
                        goto finalize;
                if (r > 0)
                        n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("SIP", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int domain_build_json(int family, const char *domain, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **ret) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(domain);
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Domain", domain),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int domains_build_json(Link *link, bool is_route, JsonVariant **ret) {
        OrderedSet *link_domains, *network_domains;
        JsonVariant **elements = NULL;
        DHCPUseDomains use_domains;
        union in_addr_union s;
        char **domains;
        const char *domain;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        link_domains = is_route ? link->route_domains : link->search_domains;
        network_domains = is_route ? link->network->route_domains : link->network->search_domains;
        use_domains = is_route ? DHCP_USE_DOMAINS_ROUTE : DHCP_USE_DOMAINS_YES;

        ORDERED_SET_FOREACH(domain, link_domains ?: network_domains) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = domain_build_json(AF_UNSPEC, domain,
                                      link_domains ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                      NULL, elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (!link_domains) {
                if (link->dhcp_lease &&
                    link->network->dhcp_use_domains == use_domains) {
                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                goto finalize;

                        if (sd_dhcp_lease_get_domainname(link->dhcp_lease, &domain) >= 0) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = domain_build_json(AF_INET, domain, NETWORK_CONFIG_SOURCE_DHCP4, &s, elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }

                        if (sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains) >= 0) {
                                STRV_FOREACH(p, domains) {
                                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                                r = -ENOMEM;
                                                goto finalize;
                                        }

                                        r = domain_build_json(AF_INET, *p, NETWORK_CONFIG_SOURCE_DHCP4, &s, elements + n);
                                        if (r < 0)
                                                goto finalize;

                                        n++;
                                }
                        }
                }

                if (link->dhcp6_lease &&
                    link->network->dhcp6_use_domains == use_domains) {
                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                goto finalize;

                        if (sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains) >= 0) {
                                STRV_FOREACH(p, domains) {
                                        if (!GREEDY_REALLOC(elements, n + 1)) {
                                                r = -ENOMEM;
                                                goto finalize;
                                        }

                                        r = domain_build_json(AF_INET6, *p, NETWORK_CONFIG_SOURCE_DHCP6, &s, elements + n);
                                        if (r < 0)
                                                goto finalize;

                                        n++;
                                }
                        }
                }

                if (link->network->ipv6_accept_ra_use_domains == use_domains) {
                        NDiscDNSSL *a;

                        SET_FOREACH(a, link->ndisc_dnssl) {
                                if (!GREEDY_REALLOC(elements, n + 1)) {
                                        r = -ENOMEM;
                                        goto finalize;
                                }

                                r = domain_build_json(AF_INET6, NDISC_DNSSL_DOMAIN(a), NETWORK_CONFIG_SOURCE_NDISC,
                                                      &(union in_addr_union) { .in6 = a->router },
                                                      elements + n);
                                if (r < 0)
                                        goto finalize;

                                n++;
                        }
                }
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR(is_route ? "RouteDomains" : "SearchDomains",
                                                              JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int nta_build_json(const char *nta, NetworkConfigSource s, JsonVariant **ret) {
        assert(nta);
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("DNSSECNegativeTrustAnchor", nta),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s))));
}

static int ntas_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements = NULL;
        const char *nta;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        SET_FOREACH(nta, link->dnssec_negative_trust_anchors ?: link->network->dnssec_negative_trust_anchors) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = nta_build_json(nta,
                                   link->dnssec_negative_trust_anchors ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                   elements + n);
                if (r < 0)
                        goto finalize;

                n++;
        }

        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("DNSSECNegativeTrustAnchors",
                                                              JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

static int dns_misc_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements = NULL;
        ResolveSupport resolve_support;
        NetworkConfigSource source;
        DnsOverTlsMode mode;
        size_t n = 0;
        int t, r;

        assert(link);
        assert(ret);

        if (!link->network) {
                *ret = NULL;
                return 0;
        }

        resolve_support = link->llmnr >= 0 ? link->llmnr : link->network->llmnr;
        if (resolve_support >= 0) {
                source = link->llmnr >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = json_build(elements + n, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("LLMNR", resolve_support_to_string(resolve_support)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        resolve_support = link->mdns >= 0 ? link->mdns : link->network->mdns;
        if (resolve_support >= 0) {
                source = link->mdns >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = json_build(elements + n, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("MDNS", resolve_support_to_string(resolve_support)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        t = link->dns_default_route >= 0 ? link->dns_default_route : link->network->dns_default_route;
        if (t >= 0) {
                source = link->dns_default_route >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = json_build(elements + n, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_BOOLEAN("DNSDefaultRoute", t),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        mode = link->dns_over_tls_mode >= 0 ? link->dns_over_tls_mode : link->network->dns_over_tls_mode;
        if (mode >= 0) {
                source = link->dns_over_tls_mode >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = json_build(elements + n, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("DNSOverTLS", dns_over_tls_mode_to_string(mode)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        goto finalize;

                n++;
        }

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("DNSSettings",
                                                              JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

int link_build_json(Link *link, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        _cleanup_free_ char *type = NULL, *flags = NULL;
        int r;

        assert(link);
        assert(ret);

        r = net_get_type_string(link->sd_device, link->iftype, &type);
        if (r == -ENOMEM)
                return r;

        r = link_flags_to_string_alloc(link->flags, &flags);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                /* basic information */
                                JSON_BUILD_PAIR_INTEGER("Index", link->ifindex),
                                JSON_BUILD_PAIR_STRING("Name", link->ifname),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("AlternativeNames", link->alternative_names),
                                JSON_BUILD_PAIR_CONDITION(link->master_ifindex > 0,
                                                          "MasterInterfaceIndex", JSON_BUILD_INTEGER(link->master_ifindex)),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Kind", link->kind),
                                JSON_BUILD_PAIR_STRING("Type", type),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Driver", link->driver),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", link->flags),
                                JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                JSON_BUILD_PAIR_UNSIGNED("KernelOperationalState", link->kernel_operstate),
                                JSON_BUILD_PAIR_STRING("KernelOperationalStateString", kernel_operstate_to_string(link->kernel_operstate)),
                                JSON_BUILD_PAIR_UNSIGNED("MTU", link->mtu),
                                JSON_BUILD_PAIR_UNSIGNED("MinimumMTU", link->min_mtu),
                                JSON_BUILD_PAIR_UNSIGNED("MaximumMTU", link->max_mtu),
                                JSON_BUILD_PAIR_HW_ADDR_NON_NULL("HardwareAddress", &link->hw_addr),
                                JSON_BUILD_PAIR_HW_ADDR_NON_NULL("PermanentHardwareAddress", &link->permanent_hw_addr),
                                JSON_BUILD_PAIR_HW_ADDR_NON_NULL("BroadcastAddress", &link->bcast_addr),
                                JSON_BUILD_PAIR_IN6_ADDR_NON_NULL("IPv6LinkLocalAddress", &link->ipv6ll_address),
                                /* wlan information */
                                JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceType",
                                                          JSON_BUILD_UNSIGNED(link->wlan_iftype)),
                                JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceTypeString",
                                                          JSON_BUILD_STRING(nl80211_iftype_to_string(link->wlan_iftype))),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("SSID", link->ssid),
                                JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL("BSSID", &link->bssid),
                                /* link state */
                                JSON_BUILD_PAIR_STRING("AdministrativeState", link_state_to_string(link->state)),
                                JSON_BUILD_PAIR_STRING("OperationalState", link_operstate_to_string(link->operstate)),
                                JSON_BUILD_PAIR_STRING("CarrierState", link_carrier_state_to_string(link->carrier_state)),
                                JSON_BUILD_PAIR_STRING("AddressState", link_address_state_to_string(link->address_state)),
                                JSON_BUILD_PAIR_STRING("IPv4AddressState", link_address_state_to_string(link->ipv4_address_state)),
                                JSON_BUILD_PAIR_STRING("IPv6AddressState", link_address_state_to_string(link->ipv6_address_state)),
                                JSON_BUILD_PAIR_STRING("OnlineState", link_online_state_to_string(link->online_state))));
        if (r < 0)
                return r;

        r = network_build_json(link->network, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = device_build_json(link->sd_device, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = dns_build_json(link, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = ntp_build_json(link, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = sip_build_json(link, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = domains_build_json(link, /* is_route = */ false, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = domains_build_json(link, /* is_route = */ true, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = ntas_build_json(link, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = dns_misc_build_json(link, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = addresses_build_json(link->addresses, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = neighbors_build_json(link->neighbors, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = nexthops_build_json(link->nexthops, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = routes_build_json(link->routes, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int link_json_compare(JsonVariant * const *a, JsonVariant * const *b) {
        int64_t index_a, index_b;

        assert(a && *a);
        assert(b && *b);

        index_a = json_variant_integer(json_variant_by_key(*a, "Index"));
        index_b = json_variant_integer(json_variant_by_key(*b, "Index"));

        return CMP(index_a, index_b);
}

static int links_build_json(Manager *manager, JsonVariant **ret) {
        JsonVariant **elements;
        Link *link;
        size_t n = 0;
        int r;

        assert(manager);
        assert(ret);

        elements = new(JsonVariant*, hashmap_size(manager->links_by_index));
        if (!elements)
                return -ENOMEM;

        HASHMAP_FOREACH(link, manager->links_by_index) {
                r = link_build_json(link, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        typesafe_qsort(elements, n, link_json_compare);

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("Interfaces", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}

int manager_build_json(Manager *manager, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = links_build_json(manager, &v);
        if (r < 0)
                return r;

        r = nexthops_build_json(manager->nexthops, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = routes_build_json(manager->routes, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = routing_policy_rules_build_json(manager->rules, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}
