/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "dhcp-server-lease-internal.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dns-domain.h"
#include "ip-protocol-list.h"
#include "netif-util.h"
#include "networkd-address.h"
#include "networkd-dhcp-common.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "sort-util.h"
#include "udev-util.h"
#include "user-util.h"
#include "wifi-util.h"

static int address_append_json(Address *address, JsonVariant **array) {
        _cleanup_free_ char *scope = NULL, *flags = NULL, *state = NULL;
        int r;

        assert(address);
        assert(array);

        r = route_scope_to_string_alloc(address->scope, &scope);
        if (r < 0)
                return r;

        r = address_flags_to_string_alloc(address->flags, address->family, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(address->state, &state);
        if (r < 0)
                return r;

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
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
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUSec", address->lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUsec", address->lifetime_preferred_usec), /* for backward compat */
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUSec", address->lifetime_valid_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUsec", address->lifetime_valid_usec), /* for backward compat */
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(address->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &address->provider, address->family)));
}

static int addresses_append_json(Set *addresses, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        Address *address;
        int r;

        assert(v);

        SET_FOREACH(address, addresses) {
                r = address_append_json(address, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Addresses", array);
}

static int neighbor_append_json(Neighbor *n, JsonVariant **array) {
        _cleanup_free_ char *state = NULL;
        int r;

        assert(n);
        assert(array);

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", n->family),
                                JSON_BUILD_PAIR_IN_ADDR("Destination", &n->in_addr, n->family),
                                JSON_BUILD_PAIR_HW_ADDR("LinkLayerAddress", &n->ll_addr),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
}

static int neighbors_append_json(Set *neighbors, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        Neighbor *neighbor;
        int r;

        assert(v);

        SET_FOREACH(neighbor, neighbors) {
                r = neighbor_append_json(neighbor, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Neighbors", array);
}

static int nexthop_group_build_json(NextHop *nexthop, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        struct nexthop_grp *g;
        int r;

        assert(nexthop);
        assert(ret);

        HASHMAP_FOREACH(g, nexthop->group) {
                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_UNSIGNED("ID", g->id),
                                                JSON_BUILD_PAIR_UNSIGNED("Weight", g->weight+1)));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

static int nexthop_append_json(NextHop *n, JsonVariant **array) {
        _cleanup_(json_variant_unrefp) JsonVariant *group = NULL;
        _cleanup_free_ char *flags = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(n);
        assert(array);

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

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
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
}

static int nexthops_append_json(Manager *manager, int ifindex, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        NextHop *nexthop;
        int r;

        assert(manager);
        assert(v);

        HASHMAP_FOREACH(nexthop, manager->nexthops_by_id) {
                if (nexthop->ifindex != ifindex)
                        continue;

                r = nexthop_append_json(nexthop, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "NextHops", array);
}

static int route_append_json(Route *route, JsonVariant **array) {
        _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *flags = NULL, *state = NULL;
        Manager *manager;
        int r;

        assert(route);
        assert(array);

        manager = route->link ? route->link->manager : route->manager;

        assert(manager);

        r = route_scope_to_string_alloc(route->scope, &scope);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(route->protocol, &protocol);
        if (r < 0)
                return r;

        r = manager_get_route_table_to_string(manager, route->table, /* append_num = */ false, &table);
        if (r < 0)
                return r;

        r = route_flags_to_string_alloc(route->flags, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(route->state, &state);
        if (r < 0)
                return r;

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
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
}

static int routes_append_json(Set *routes, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        Route *route;
        int r;

        assert(v);

        SET_FOREACH(route, routes) {
                r = route_append_json(route, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Routes", array);
}

static int routing_policy_rule_append_json(RoutingPolicyRule *rule, JsonVariant **array) {
        _cleanup_free_ char *table = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(rule);
        assert(rule->manager);
        assert(array);

        r = manager_get_route_table_to_string(rule->manager, rule->table, /* append_num = */ false, &table);
        if (r < 0 && r != -EINVAL)
                return r;

        r = route_protocol_to_string_alloc(rule->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(rule->state, &state);
        if (r < 0)
                return r;

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
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
}

static int routing_policy_rules_append_json(Set *rules, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        RoutingPolicyRule *rule;
        int r;

        assert(v);

        SET_FOREACH(rule, rules) {
                r = routing_policy_rule_append_json(rule, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "RoutingPolicyRules", array);
}

static int network_append_json(Network *network, JsonVariant **v) {
        assert(v);

        if (!network)
                return 0;

        return json_variant_merge_objectb(
                        v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("NetworkFile", network->filename),
                                JSON_BUILD_PAIR_STRV("NetworkFileDropins", network->dropins),
                                JSON_BUILD_PAIR_BOOLEAN("RequiredForOnline", network->required_for_online),
                                JSON_BUILD_PAIR("RequiredOperationalStateForOnline",
                                                JSON_BUILD_ARRAY(JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.min)),
                                                                 JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.max)))),
                                JSON_BUILD_PAIR_STRING("RequiredFamilyForOnline",
                                                       link_required_address_family_to_string(network->required_family_for_online)),
                                JSON_BUILD_PAIR_STRING("ActivationPolicy",
                                                       activation_policy_to_string(network->activation_policy))));
}

static int device_append_json(sd_device *device, JsonVariant **v) {
        _cleanup_strv_free_ char **link_dropins = NULL;
        const char *link = NULL, *path = NULL, *vendor = NULL, *model = NULL, *joined;
        int r;

        assert(v);

        if (!device)
                return 0;

        (void) sd_device_get_property_value(device, "ID_NET_LINK_FILE", &link);

        if (sd_device_get_property_value(device, "ID_NET_LINK_FILE_DROPINS", &joined) >= 0) {
                 r = strv_split_full(&link_dropins, joined, ":", EXTRACT_CUNESCAPE);
                 if (r < 0)
                        return r;
        }

        (void) sd_device_get_property_value(device, "ID_PATH", &path);

        (void) device_get_vendor_string(device, &vendor);
        (void) device_get_model_string(device, &model);

        return json_variant_merge_objectb(
                        v,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("LinkFile", link),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("LinkFileDropins", link_dropins),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Path", path),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Vendor", vendor),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Model", model)));
}

static int dns_append_json_one(Link *link, const struct in_addr_full *a, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **array) {
        assert(link);
        assert(a);
        assert(array);

        if (a->ifindex != 0 && a->ifindex != link->ifindex)
                return 0;

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_INTEGER("Family", a->family),
                                        JSON_BUILD_PAIR_IN_ADDR("Address", &a->address, a->family),
                                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", a->port),
                                        JSON_BUILD_PAIR_CONDITION(a->ifindex != 0, "InterfaceIndex", JSON_BUILD_INTEGER(a->ifindex)),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", a->server_name),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                        JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, a->family)));
}

static int dns_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        if (link->n_dns != UINT_MAX)
                for (unsigned i = 0; i < link->n_dns; i++) {
                        r = dns_append_json_one(link, link->dns[i], NETWORK_CONFIG_SOURCE_RUNTIME, NULL, &array);
                        if (r < 0)
                                return r;
                }
        else {
                for (unsigned i = 0; i < link->network->n_dns; i++) {
                        r = dns_append_json_one(link, link->network->dns[i], NETWORK_CONFIG_SOURCE_STATIC, NULL, &array);
                        if (r < 0)
                                return r;
                }

                if (link->dhcp_lease && link->network->dhcp_use_dns) {
                        const struct in_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                return r;

                        n_dns = sd_dhcp_lease_get_dns(link->dhcp_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                r = dns_append_json_one(link,
                                                        &(struct in_addr_full) { .family = AF_INET, .address.in = dns[i], },
                                                        NETWORK_CONFIG_SOURCE_DHCP4,
                                                        &s,
                                                        &array);
                                if (r < 0)
                                        return r;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_dns) {
                        const struct in6_addr *dns;
                        union in_addr_union s;
                        int n_dns;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                return r;

                        n_dns = sd_dhcp6_lease_get_dns(link->dhcp6_lease, &dns);
                        for (int i = 0; i < n_dns; i++) {
                                r = dns_append_json_one(link,
                                                        &(struct in_addr_full) { .family = AF_INET6, .address.in6 = dns[i], },
                                                        NETWORK_CONFIG_SOURCE_DHCP6,
                                                        &s,
                                                        &array);
                                if (r < 0)
                                        return r;
                        }
                }

                if (link->network->ipv6_accept_ra_use_dns) {
                        NDiscRDNSS *a;

                        SET_FOREACH(a, link->ndisc_rdnss) {
                                r = dns_append_json_one(link,
                                                        &(struct in_addr_full) { .family = AF_INET6, .address.in6 = a->address, },
                                                        NETWORK_CONFIG_SOURCE_NDISC,
                                                        &(union in_addr_union) { .in6 = a->router },
                                                        &array);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return json_variant_set_field_non_null(v, "DNS", array);
}

static int server_append_json_one_addr(int family, const union in_addr_union *a, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **array) {
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(a);
        assert(array);

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_INTEGER("Family", family),
                                JSON_BUILD_PAIR_IN_ADDR("Address", a, family),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_append_json_one_fqdn(int family, const char *fqdn, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **array) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(fqdn);
        assert(array);

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Server", fqdn),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int server_append_json_one_string(const char *str, NetworkConfigSource s, JsonVariant **array) {
        union in_addr_union a;
        int family;

        assert(str);

        if (in_addr_from_string_auto(str, &family, &a) >= 0)
                return server_append_json_one_addr(family, &a, s, NULL, array);

        return server_append_json_one_fqdn(AF_UNSPEC, str, s, NULL, array);
}

static int ntp_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        STRV_FOREACH(p, link->ntp ?: link->network->ntp) {
                r = server_append_json_one_string(*p, NETWORK_CONFIG_SOURCE_RUNTIME, &array);
                if (r < 0)
                        return r;
        }

        if (!link->ntp) {
                if (link->dhcp_lease && link->network->dhcp_use_ntp) {
                        const struct in_addr *ntp;
                        union in_addr_union s;
                        int n_ntp;

                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                return r;

                        n_ntp = sd_dhcp_lease_get_ntp(link->dhcp_lease, &ntp);
                        for (int i = 0; i < n_ntp; i++) {
                                r = server_append_json_one_addr(AF_INET,
                                                                &(union in_addr_union) { .in = ntp[i], },
                                                                NETWORK_CONFIG_SOURCE_DHCP4,
                                                                &s,
                                                                &array);
                                if (r < 0)
                                        return r;
                        }
                }

                if (link->dhcp6_lease && link->network->dhcp6_use_ntp) {
                        const struct in6_addr *ntp_addr;
                        union in_addr_union s;
                        char **ntp_fqdn;
                        int n_ntp;

                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                return r;

                        n_ntp = sd_dhcp6_lease_get_ntp_addrs(link->dhcp6_lease, &ntp_addr);
                        for (int i = 0; i < n_ntp; i++) {
                                r = server_append_json_one_addr(AF_INET6,
                                                                &(union in_addr_union) { .in6 = ntp_addr[i], },
                                                                NETWORK_CONFIG_SOURCE_DHCP6,
                                                                &s,
                                                                &array);
                                if (r < 0)
                                        return r;
                        }

                        n_ntp = sd_dhcp6_lease_get_ntp_fqdn(link->dhcp6_lease, &ntp_fqdn);
                        for (int i = 0; i < n_ntp; i++) {
                                r = server_append_json_one_fqdn(AF_INET6,
                                                                ntp_fqdn[i],
                                                                NETWORK_CONFIG_SOURCE_DHCP6,
                                                                &s,
                                                                &array);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return json_variant_set_field_non_null(v, "NTP", array);
}

static int sip_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        const struct in_addr *sip;
        union in_addr_union s;
        int n_sip, r;

        assert(link);
        assert(v);

        if (!link->network || !link->network->dhcp_use_sip || !link->dhcp_lease)
                return 0;

        n_sip = sd_dhcp_lease_get_sip(link->dhcp_lease, &sip);
        if (n_sip <= 0)
                return 0;

        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
        if (r < 0)
                return r;

        for (int i = 0; i < n_sip; i++) {
                r = server_append_json_one_addr(AF_INET,
                                                &(union in_addr_union) { .in = sip[i], },
                                                NETWORK_CONFIG_SOURCE_DHCP4,
                                                &s,
                                                &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "SIP", array);
}

static int domain_append_json(int family, const char *domain, NetworkConfigSource s, const union in_addr_union *p, JsonVariant **array) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(domain);
        assert(array);

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("Domain", domain),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, family)));
}

static int domains_append_json(Link *link, bool is_route, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        OrderedSet *link_domains, *network_domains;
        DHCPUseDomains use_domains;
        union in_addr_union s;
        char **domains;
        const char *domain;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        link_domains = is_route ? link->route_domains : link->search_domains;
        network_domains = is_route ? link->network->route_domains : link->network->search_domains;
        use_domains = is_route ? DHCP_USE_DOMAINS_ROUTE : DHCP_USE_DOMAINS_YES;

        ORDERED_SET_FOREACH(domain, link_domains ?: network_domains) {
                r = domain_append_json(AF_UNSPEC, domain,
                                       link_domains ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                       NULL, &array);
                if (r < 0)
                        return r;
        }

        if (!link_domains) {
                if (link->dhcp_lease &&
                    link->network->dhcp_use_domains == use_domains) {
                        r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                        if (r < 0)
                                return r;

                        if (sd_dhcp_lease_get_domainname(link->dhcp_lease, &domain) >= 0) {
                                r = domain_append_json(AF_INET, domain, NETWORK_CONFIG_SOURCE_DHCP4, &s, &array);
                                if (r < 0)
                                        return r;
                        }

                        if (sd_dhcp_lease_get_search_domains(link->dhcp_lease, &domains) >= 0)
                                STRV_FOREACH(p, domains) {
                                        r = domain_append_json(AF_INET, *p, NETWORK_CONFIG_SOURCE_DHCP4, &s, &array);
                                        if (r < 0)
                                                return r;
                                }
                }

                if (link->dhcp6_lease &&
                    link->network->dhcp6_use_domains == use_domains) {
                        r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                        if (r < 0)
                                return r;

                        if (sd_dhcp6_lease_get_domains(link->dhcp6_lease, &domains) >= 0)
                                STRV_FOREACH(p, domains) {
                                        r = domain_append_json(AF_INET6, *p, NETWORK_CONFIG_SOURCE_DHCP6, &s, &array);
                                        if (r < 0)
                                                return r;
                                }
                }

                if (link->network->ipv6_accept_ra_use_domains == use_domains) {
                        NDiscDNSSL *a;

                        SET_FOREACH(a, link->ndisc_dnssl) {
                                r = domain_append_json(AF_INET6, NDISC_DNSSL_DOMAIN(a), NETWORK_CONFIG_SOURCE_NDISC,
                                                       &(union in_addr_union) { .in6 = a->router },
                                                       &array);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return json_variant_set_field_non_null(v, is_route ? "RouteDomains" : "SearchDomains", array);
}

static int nta_append_json(const char *nta, NetworkConfigSource s, JsonVariant **array) {
        assert(nta);
        assert(array);

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_STRING("DNSSECNegativeTrustAnchor", nta),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s))));
}

static int ntas_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        const char *nta;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        SET_FOREACH(nta, link->dnssec_negative_trust_anchors ?: link->network->dnssec_negative_trust_anchors) {
                r = nta_append_json(nta,
                                   link->dnssec_negative_trust_anchors ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                   &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "DNSSECNegativeTrustAnchors", array);
}

static int dns_misc_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        ResolveSupport resolve_support;
        NetworkConfigSource source;
        DnsOverTlsMode mode;
        int t, r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        resolve_support = link->llmnr >= 0 ? link->llmnr : link->network->llmnr;
        if (resolve_support >= 0) {
                source = link->llmnr >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("LLMNR", resolve_support_to_string(resolve_support)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        return r;
        }

        resolve_support = link->mdns >= 0 ? link->mdns : link->network->mdns;
        if (resolve_support >= 0) {
                source = link->mdns >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("MDNS", resolve_support_to_string(resolve_support)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        return r;
        }

        t = link->dns_default_route >= 0 ? link->dns_default_route : link->network->dns_default_route;
        if (t >= 0) {
                source = link->dns_default_route >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_BOOLEAN("DNSDefaultRoute", t),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        return r;
        }

        mode = link->dns_over_tls_mode >= 0 ? link->dns_over_tls_mode : link->network->dns_over_tls_mode;
        if (mode >= 0) {
                source = link->dns_over_tls_mode >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_STRING("DNSOverTLS", dns_over_tls_mode_to_string(mode)),
                                        JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source))));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "DNSSettings", array);
}

static int captive_portal_append_json(Link *link, JsonVariant **v) {
        const char *captive_portal;
        int r;

        assert(link);
        assert(v);

        r = link_get_captive_portal(link, &captive_portal);
        if (r <= 0)
                return r;

        return json_variant_merge_objectb(v, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_STRING("CaptivePortal", captive_portal)));
}

static int pref64_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL, *w = NULL;
        NDiscPREF64 *i;
        int r;

        assert(link);
        assert(v);

        if (!link->network || !link->network->ipv6_accept_ra_use_pref64)
                return 0;

        SET_FOREACH(i, link->ndisc_pref64) {
                r = json_variant_append_arrayb(&array,
                                               JSON_BUILD_OBJECT(
                                                               JSON_BUILD_PAIR_IN6_ADDR_NON_NULL("Prefix", &i->prefix),
                                                               JSON_BUILD_PAIR_UNSIGNED("PrefixLength", i->prefix_len),
                                                               JSON_BUILD_PAIR_FINITE_USEC("LifetimeUSec", i->lifetime_usec),
                                                               JSON_BUILD_PAIR_IN6_ADDR_NON_NULL("ConfigProvider", &i->router)));
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&w, "PREF64", array);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "NDisc", w);
}

static int dhcp_server_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_server)
                return 0;

        r = json_build(&w,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR_UNSIGNED("PoolOffset", link->dhcp_server->pool_offset),
                                       JSON_BUILD_PAIR_UNSIGNED("PoolSize", link->dhcp_server->pool_size)));
        if (r < 0)
                return r;

        r = dhcp_server_bound_leases_append_json(link->dhcp_server, &w);
        if (r < 0)
                return r;

        r = dhcp_server_static_leases_append_json(link->dhcp_server, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "DHCPServer", w);
}

static int dhcp6_client_vendor_options_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        sd_dhcp6_option **options = NULL;
        int r, n_vendor_options;

        assert(link);
        assert(v);

        if (!link->dhcp6_lease)
                return 0;

        n_vendor_options = sd_dhcp6_lease_get_vendor_options(link->dhcp6_lease, &options);

        FOREACH_ARRAY(option, options, n_vendor_options) {
                r = json_variant_append_arrayb(&array,
                                            JSON_BUILD_OBJECT(
                                                            JSON_BUILD_PAIR_UNSIGNED("EnterpriseId", (*option)->enterprise_identifier),
                                                            JSON_BUILD_PAIR_UNSIGNED("SubOptionCode", (*option)->option),
                                                            JSON_BUILD_PAIR_HEX("SubOptionData", (*option)->data, (*option)->length)));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "VendorSpecificOptions", array);
}

static int dhcp6_client_lease_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        usec_t ts = USEC_INFINITY, t1 = USEC_INFINITY, t2 = USEC_INFINITY;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp6_lease)
                return 0;

        r = sd_dhcp6_lease_get_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME, &ts);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_dhcp6_lease_get_t1_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME, &t1);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_dhcp6_lease_get_t2_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME, &t2);
        if (r < 0 && r != -ENODATA)
                return r;

        r = json_build(&w, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_FINITE_USEC("Timeout1USec", t1),
                                JSON_BUILD_PAIR_FINITE_USEC("Timeout2USec", t2),
                                JSON_BUILD_PAIR_FINITE_USEC("LeaseTimestampUSec", ts)));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "Lease", w);
}

static int dhcp6_client_pd_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(v);

        if (!link->network->dhcp6_use_pd_prefix ||
            !sd_dhcp6_lease_has_pd_prefix(link->dhcp6_lease))
                return 0;

        FOREACH_DHCP6_PD_PREFIX(link->dhcp6_lease) {
                usec_t lifetime_preferred_usec, lifetime_valid_usec;
                struct in6_addr prefix;
                uint8_t prefix_len;

                r = sd_dhcp6_lease_get_pd_prefix(link->dhcp6_lease, &prefix, &prefix_len);
                if (r < 0)
                        return r;

                r = sd_dhcp6_lease_get_pd_lifetime_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME,
                                                             &lifetime_preferred_usec, &lifetime_valid_usec);
                if (r < 0)
                        return r;

                r = json_variant_append_arrayb(&array, JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR_IN6_ADDR("Prefix", &prefix),
                                               JSON_BUILD_PAIR_UNSIGNED("PrefixLength", prefix_len),
                                               JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUSec", lifetime_preferred_usec),
                                               JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUSec", lifetime_valid_usec)));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Prefixes", array);
}

static int dhcp6_client_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp6_client)
                return 0;

        r = dhcp6_client_lease_append_json(link, &w);
        if (r < 0)
                return r;

        r = dhcp6_client_pd_append_json(link, &w);
        if (r < 0)
                return r;

        r = dhcp6_client_vendor_options_append_json(link, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "DHCPv6Client", w);
}

static int dhcp_client_lease_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        usec_t lease_timestamp_usec = USEC_INFINITY, t1 = USEC_INFINITY, t2 = USEC_INFINITY;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_client || !link->dhcp_lease)
                return 0;

        r = sd_dhcp_lease_get_timestamp(link->dhcp_lease, CLOCK_BOOTTIME, &lease_timestamp_usec);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_dhcp_lease_get_t1_timestamp(link->dhcp_lease, CLOCK_BOOTTIME, &t1);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_dhcp_lease_get_t2_timestamp(link->dhcp_lease, CLOCK_BOOTTIME, &t2);
        if (r < 0 && r != -ENODATA)
                return r;

        r = json_build(&w, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR_FINITE_USEC("LeaseTimestampUSec", lease_timestamp_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("Timeout1USec", t1),
                                JSON_BUILD_PAIR_FINITE_USEC("Timeout2USec", t2)));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "Lease", w);
}

static int dhcp_client_pd_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *addresses = NULL, *array = NULL;
        uint8_t ipv4masklen, sixrd_prefixlen;
        struct in6_addr sixrd_prefix;
        const struct in_addr *br_addresses;
        size_t n_br_addresses = 0;
        int r;

        assert(link);
        assert(link->network);
        assert(v);

        if (!link->network->dhcp_use_6rd || !sd_dhcp_lease_has_6rd(link->dhcp_lease))
                return 0;

        r = sd_dhcp_lease_get_6rd(link->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, &br_addresses, &n_br_addresses);
        if (r < 0)
                return r;

        FOREACH_ARRAY(br_address, br_addresses, n_br_addresses) {
                r = json_variant_append_arrayb(&addresses, JSON_BUILD_IN4_ADDR(br_address));
                if (r < 0)
                        return r;
        }

        r = json_build(&array, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR_IN6_ADDR("Prefix", &sixrd_prefix),
                                       JSON_BUILD_PAIR_UNSIGNED("PrefixLength", sixrd_prefixlen),
                                       JSON_BUILD_PAIR_UNSIGNED("IPv4MaskLength", ipv4masklen),
                                       JSON_BUILD_PAIR_VARIANT_NON_NULL("BorderRouters", addresses)));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "6rdPrefix", array);
}

static int dhcp_client_append_json(Link *link, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_client)
                return 0;

        r = dhcp_client_lease_append_json(link, &w);
        if (r < 0)
                return r;

        r = dhcp_client_pd_append_json(link, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "DHCPv4Client", w);
}

int link_build_json(Link *link, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *type = NULL, *flags = NULL;
        int r;

        assert(link);
        assert(ret);

        r = net_get_type_string(link->dev, link->iftype, &type);
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

        r = network_append_json(link->network, &v);
        if (r < 0)
                return r;

        r = device_append_json(link->dev, &v);
        if (r < 0)
                return r;

        r = dns_append_json(link, &v);
        if (r < 0)
                return r;

        r = ntp_append_json(link, &v);
        if (r < 0)
                return r;

        r = sip_append_json(link, &v);
        if (r < 0)
                return r;

        r = domains_append_json(link, /* is_route = */ false, &v);
        if (r < 0)
                return r;

        r = domains_append_json(link, /* is_route = */ true, &v);
        if (r < 0)
                return r;

        r = ntas_append_json(link, &v);
        if (r < 0)
                return r;

        r = dns_misc_append_json(link, &v);
        if (r < 0)
                return r;

        r = captive_portal_append_json(link, &v);
        if (r < 0)
                return r;

        r = pref64_append_json(link, &v);
        if (r < 0)
                return r;

        r = addresses_append_json(link->addresses, &v);
        if (r < 0)
                return r;

        r = neighbors_append_json(link->neighbors, &v);
        if (r < 0)
                return r;

        r = nexthops_append_json(link->manager, link->ifindex, &v);
        if (r < 0)
                return r;

        r = routes_append_json(link->routes, &v);
        if (r < 0)
                return r;

        r = dhcp_server_append_json(link, &v);
        if (r < 0)
                return r;

        r = dhcp_client_append_json(link, &v);
        if (r < 0)
                return r;

        r = dhcp6_client_append_json(link, &v);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int links_append_json(Manager *manager, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_free_ Link **links = NULL;
        size_t n_links = 0;
        int r;

        assert(manager);
        assert(v);

        r = hashmap_dump_sorted(manager->links_by_index, (void***) &links, &n_links);
        if (r < 0)
                return r;

        FOREACH_ARRAY(link, links, n_links) {
                _cleanup_(json_variant_unrefp) JsonVariant *e = NULL;

                r = link_build_json(*link, &e);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, e);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Interfaces", array);
}

int manager_build_json(Manager *manager, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = links_append_json(manager, &v);
        if (r < 0)
                return r;

        r = nexthops_append_json(manager, /* ifindex = */ 0, &v);
        if (r < 0)
                return r;

        r = routes_append_json(manager->routes, &v);
        if (r < 0)
                return r;

        r = routing_policy_rules_append_json(manager->rules, &v);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}
