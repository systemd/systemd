/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

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
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Source", &route->src, route->family),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(route->family, &route->src),
                                                          "SourcePrefixLength", JSON_BUILD_UNSIGNED(route->src_prefixlen)),
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
                                JSON_BUILD_PAIR_STRING("NetworkFile", network->filename)));
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
                                JSON_BUILD_PAIR_STRING("SetupState", link_state_to_string(link->state)),
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
