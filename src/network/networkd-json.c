/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "sd-device.h"
#include "sd-dhcp-client.h"
#include "sd-dhcp6-client.h"

#include "dhcp-lease-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp6-lease-internal.h"
#include "extract-word.h"
#include "in-addr-util.h"
#include "ip-protocol-list.h"
#include "json-util.h"
#include "netif-util.h"
#include "networkd-address.h"
#include "networkd-dhcp-common.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-nexthop.h"
#include "networkd-ntp.h"
#include "networkd-route.h"
#include "networkd-route-util.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-wwan.h"
#include "ordered-set.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "udev-util.h"
#include "wifi-util.h"

static int address_append_json(Address *address, bool serializing, sd_json_variant **array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(address);
        assert(array);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", address->family),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING("Address", address->family, &address->in_addr),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("Peer", address->family, &address->in_addr_peer),
                        SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength", address->prefixlen),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(address->source)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", address->family, &address->provider));
        if (r < 0)
                return r;

        if (!serializing) {
                _cleanup_free_ char *scope = NULL, *flags = NULL, *state = NULL;

                r = route_scope_to_string_alloc(address->scope, &scope);
                if (r < 0)
                        return r;

                r = address_flags_to_string_alloc(address->flags, address->family, &flags);
                if (r < 0)
                        return r;

                r = network_config_state_to_string_alloc(address->state, &state);
                if (r < 0)
                        return r;

                r = sd_json_variant_merge_objectbo(
                                &v,
                                JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL("Broadcast", &address->broadcast),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Scope", address->scope),
                                SD_JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", address->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Label", address->label),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUSec", address->lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUsec", address->lifetime_preferred_usec), /* for backward compat */
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUSec", address->lifetime_valid_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUsec", address->lifetime_valid_usec), /* for backward compat */
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state));
                if (r < 0)
                        return r;
        }

        return sd_json_variant_append_array(array, v);
}

int addresses_append_json(Link *link, bool serializing, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        Address *address;
        int r;

        assert(link);
        assert(v);

        SET_FOREACH(address, link->addresses) {
                if (serializing) {
                        if (address->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                                continue;
                        if (!address_is_ready(address))
                                continue;

                        log_address_debug(address, "Serializing", link);
                }

                r = address_append_json(address, serializing, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Addresses", array);
}

static int neighbor_append_json(Neighbor *n, sd_json_variant **array) {
        _cleanup_free_ char *state = NULL;
        int r;

        assert(n);
        assert(array);

        r = network_config_state_to_string_alloc(n->state, &state);
        if (r < 0)
                return r;

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", n->dst_addr.family),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING("Destination", n->dst_addr.family, &n->dst_addr.address),
                        JSON_BUILD_PAIR_HW_ADDR("LinkLayerAddress", &n->ll_addr),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                        SD_JSON_BUILD_PAIR_STRING("ConfigState", state));
}

static int neighbors_append_json(Set *neighbors, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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

static int nexthop_group_build_json(NextHop *nexthop, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        struct nexthop_grp *g;
        int r;

        assert(nexthop);
        assert(ret);

        HASHMAP_FOREACH(g, nexthop->group) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_UNSIGNED("ID", g->id),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Weight", g->weight+1));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

static int nexthop_append_json(NextHop *n, bool serializing, sd_json_variant **array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(n);
        assert(array);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_UNSIGNED("ID", n->id),
                        SD_JSON_BUILD_PAIR_INTEGER("Family", n->family),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", n->family, &n->provider));
        if (r < 0)
                return r;

        if (!serializing) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *group = NULL;
                _cleanup_free_ char *flags = NULL, *protocol = NULL, *state = NULL;

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

                r = sd_json_variant_merge_objectbo(
                                &v,
                                JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("Gateway", n->family, &n->gw.address),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Flags", n->flags),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", n->protocol),
                                SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                SD_JSON_BUILD_PAIR_BOOLEAN("Blackhole", n->blackhole),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("Group", group),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state));
        }

        return sd_json_variant_append_array(array, v);
}

int nexthops_append_json(Manager *manager, int ifindex, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        NextHop *nexthop;
        int r;

        assert(manager);
        assert(v);

        HASHMAP_FOREACH(nexthop, manager->nexthops_by_id) {
                if (ifindex >= 0) {
                        if (nexthop->ifindex != ifindex)
                                continue;
                } else {
                        /* negative ifindex means we are serializing now. */

                        if (nexthop->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                                continue;
                        if (!nexthop_exists(nexthop))
                                continue;

                        log_nexthop_debug(nexthop, "Serializing", manager);
                }

                r = nexthop_append_json(nexthop, /* serializing= */ ifindex < 0, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "NextHops", array);
}

static int route_append_json(Route *route, bool serializing, sd_json_variant **array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(route);
        assert(array);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", route->family),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING("Destination", route->family, &route->dst),
                        SD_JSON_BUILD_PAIR_UNSIGNED("DestinationPrefixLength", route->dst_prefixlen),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("Gateway", route->nexthop.family, &route->nexthop.gw),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("Source", route->family, route->src_prefixlen > 0 ? &route->src : NULL),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("SourcePrefixLength", route->src_prefixlen),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("PreferredSource", route->family, &route->prefsrc),
                        SD_JSON_BUILD_PAIR_UNSIGNED("TOS", route->tos),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Scope", route->scope),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", route->protocol),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Type", route->type),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Priority", route->priority),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Table", route->table),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Flags", route->flags),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("NextHopID", route->nexthop_id),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(route->source)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", route->family, &route->provider));
        if (r < 0)
                return r;

        if (serializing) {
                r = sd_json_variant_merge_objectbo(
                                &v,
                                SD_JSON_BUILD_PAIR_INTEGER("InterfaceIndex", route->nexthop.ifindex),
                                JSON_BUILD_PAIR_BYTE_ARRAY_NON_EMPTY("Metrics", route->metric.metrics, route->metric.n_metrics),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("TCPCongestionControlAlgorithm", route->metric.tcp_congestion_control_algo));
                if (r < 0)
                        return r;
        } else {
                _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *flags = NULL, *state = NULL;

                r = route_scope_to_string_alloc(route->scope, &scope);
                if (r < 0)
                        return r;

                r = route_protocol_to_string_alloc(route->protocol, &protocol);
                if (r < 0)
                        return r;

                r = manager_get_route_table_to_string(route->manager, route->table, /* append_num= */ false, &table);
                if (r < 0)
                        return r;

                r = route_flags_to_string_alloc(route->flags, &flags);
                if (r < 0)
                        return r;

                r = network_config_state_to_string_alloc(route->state, &state);
                if (r < 0)
                        return r;

                r = sd_json_variant_merge_objectbo(
                                &v,
                                SD_JSON_BUILD_PAIR_STRING("ScopeString", scope),
                                SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                                SD_JSON_BUILD_PAIR_STRING("TypeString", route_type_to_string(route->type)),
                                SD_JSON_BUILD_PAIR_STRING("TableString", table),
                                JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("MTU", route_metric_get(&route->metric, RTAX_MTU)),
                                SD_JSON_BUILD_PAIR_UNSIGNED("Preference", route->pref),
                                SD_JSON_BUILD_PAIR_STRING("FlagsString", strempty(flags)),
                                JSON_BUILD_PAIR_FINITE_USEC("LifetimeUSec", route->lifetime_usec),
                                SD_JSON_BUILD_PAIR_STRING("ConfigState", state));
                if (r < 0)
                        return r;
        }

        return sd_json_variant_append_array(array, v);
}

int routes_append_json(Manager *manager, int ifindex, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        Route *route;
        int r;

        assert(manager);
        assert(v);

        SET_FOREACH(route, manager->routes) {
                if (ifindex >= 0) {
                        if (route->nexthop.ifindex != ifindex)
                                continue;
                } else {
                        /* negative ifindex means we are serializing now. */

                        if (route->source == NETWORK_CONFIG_SOURCE_FOREIGN)
                                continue;
                        if (!route_exists(route))
                                continue;

                        log_route_debug(route, "Serializing", manager);
                }

                r = route_append_json(route, /* serializing= */ ifindex < 0, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Routes", array);
}

static int routing_policy_rule_append_json(RoutingPolicyRule *rule, sd_json_variant **array) {
        _cleanup_free_ char *table = NULL, *protocol = NULL, *state = NULL;
        int r;

        assert(rule);
        assert(rule->manager);
        assert(array);

        r = manager_get_route_table_to_string(rule->manager, rule->table, /* append_num= */ false, &table);
        if (r < 0 && r != -EINVAL)
                return r;

        r = route_protocol_to_string_alloc(rule->protocol, &protocol);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(rule->state, &state);
        if (r < 0)
                return r;

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", rule->family),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("FromPrefix", rule->family, &rule->from.address),
                        SD_JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->from.address),
                                                     "FromPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->from.prefixlen)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ToPrefix", rule->family, &rule->to.address),
                        SD_JSON_BUILD_PAIR_CONDITION(in_addr_is_set(rule->family, &rule->to.address),
                                                     "ToPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->to.prefixlen)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Protocol", rule->protocol),
                        SD_JSON_BUILD_PAIR_STRING("ProtocolString", protocol),
                        SD_JSON_BUILD_PAIR_UNSIGNED("TOS", rule->tos),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Type", rule->action),
                        SD_JSON_BUILD_PAIR_STRING("TypeString", fr_act_type_to_string(rule->action)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("IPProtocol", rule->ipproto),
                        SD_JSON_BUILD_PAIR_STRING("IPProtocolString", ip_protocol_to_name(rule->ipproto)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Priority", rule->priority),
                        SD_JSON_BUILD_PAIR_UNSIGNED("FirewallMark", rule->fwmark),
                        SD_JSON_BUILD_PAIR_UNSIGNED("FirewallMask", rule->fwmask),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Table", rule->table),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("TableString", table),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Invert", FLAGS_SET(rule->flags, FIB_RULE_INVERT)),
                        SD_JSON_BUILD_PAIR_CONDITION(rule->suppress_prefixlen >= 0,
                                                     "SuppressPrefixLength", SD_JSON_BUILD_UNSIGNED(rule->suppress_prefixlen)),
                        SD_JSON_BUILD_PAIR_CONDITION(rule->suppress_ifgroup >= 0,
                                                     "SuppressInterfaceGroup", SD_JSON_BUILD_UNSIGNED(rule->suppress_ifgroup)),
                        SD_JSON_BUILD_PAIR_CONDITION(rule->sport.start != 0 || rule->sport.end != 0, "SourcePort",
                                                     SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->sport.start), SD_JSON_BUILD_UNSIGNED(rule->sport.end))),
                        SD_JSON_BUILD_PAIR_CONDITION(rule->dport.start != 0 || rule->dport.end != 0, "DestinationPort",
                                                     SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->dport.start), SD_JSON_BUILD_UNSIGNED(rule->dport.end))),
                        SD_JSON_BUILD_PAIR_CONDITION(rule->uid_range.start != UID_INVALID && rule->uid_range.end != UID_INVALID, "User",
                                                     SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(rule->uid_range.start), SD_JSON_BUILD_UNSIGNED(rule->uid_range.end))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("IncomingInterface", rule->iif),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("OutgoingInterface", rule->oif),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(rule->source)),
                        SD_JSON_BUILD_PAIR_STRING("ConfigState", state));
}

static int routing_policy_rules_append_json(Set *rules, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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

static int network_append_json(Network *network, sd_json_variant **v) {
        assert(v);

        if (!network)
                return 0;

        return sd_json_variant_merge_objectbo(
                        v,
                        SD_JSON_BUILD_PAIR_STRING("NetworkFile", network->filename),
                        SD_JSON_BUILD_PAIR_STRV("NetworkFileDropins", network->dropins),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RequiredForOnline", network->required_for_online > 0),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        operational_state_range_is_valid(&network->required_operstate_for_online),
                                        "RequiredOperationalStateForOnline",
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.min)),
                                                SD_JSON_BUILD_STRING(link_operstate_to_string(network->required_operstate_for_online.max)))),
                        SD_JSON_BUILD_PAIR_STRING("RequiredFamilyForOnline", link_required_address_family_to_string(network->required_family_for_online)),
                        SD_JSON_BUILD_PAIR_STRING("ActivationPolicy", activation_policy_to_string(network->activation_policy)));
}

static int netdev_append_json(NetDev *netdev, sd_json_variant **v) {
        assert(v);

        if (!netdev)
                return 0;

        return sd_json_variant_merge_objectbo(
                        v,
                        SD_JSON_BUILD_PAIR_STRING("NetDevFile", netdev->filename),
                        SD_JSON_BUILD_PAIR_STRV("NetDevFileDropins", netdev->dropins));
}

static int device_append_json(sd_device *device, sd_json_variant **v) {
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

        return sd_json_variant_merge_objectbo(
                        v,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("LinkFile", link),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("LinkFileDropins", link_dropins),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Path", path),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Vendor", vendor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Model", model));
}

static int dns_append_json_one(Link *link, const struct in_addr_full *a, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **array) {
        assert(link);
        assert(a);
        assert(array);

        if (a->ifindex != 0 && a->ifindex != link->ifindex)
                return 0;

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", a->family),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING("Address", a->family, &a->address),
                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", a->port),
                        SD_JSON_BUILD_PAIR_CONDITION(a->ifindex != 0, "InterfaceIndex", SD_JSON_BUILD_INTEGER(a->ifindex)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", a->server_name),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", a->family, p));
}

static int dns_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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

                Bearer *b;

                if (link_get_bearer(link, &b) >= 0)
                        FOREACH_ARRAY(dns, b->dns, b->n_dns) {
                                r = dns_append_json_one(link, *dns, NETWORK_CONFIG_SOURCE_MODEM_MANAGER, NULL, &array);
                                if (r < 0)
                                        return r;
                        }

                if (link->dhcp_lease && link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
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

                if (link->dhcp6_lease && link_get_use_dns(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
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

                if (link_get_use_dns(link, NETWORK_CONFIG_SOURCE_NDISC)) {
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

static int dnr_append_json_one(Link *link, const struct sd_dns_resolver *res, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *addrs_array = NULL;
        _cleanup_strv_free_ char **transports = NULL;
        int r;

        assert(link);
        assert(res);
        assert(array);

        FOREACH_ARRAY(addr, res->addrs, res->n_addrs) {
                r = sd_json_variant_append_arrayb(
                                &addrs_array,
                                JSON_BUILD_IN_ADDR(addr, res->family));
                if (r < 0)
                        return r;
        }

        r = dns_resolver_transports_to_strv(res->transports, &transports);
        if (r < 0)
                return r;

        //FIXME ifindex?
        return sd_json_variant_append_arrayb(
                        array,
                        SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_INTEGER("Family", res->family),
                                        SD_JSON_BUILD_PAIR_INTEGER("Priority", res->priority),
                                        JSON_BUILD_PAIR_VARIANT_NON_NULL("Addresses", addrs_array),
                                        JSON_BUILD_PAIR_UNSIGNED_NON_ZERO("Port", res->port),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("ServerName", res->auth_name),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DoHPath", res->dohpath),
                                        JSON_BUILD_PAIR_STRV_NON_EMPTY("Transports", transports),
                                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                                        JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", p, res->family)));
}

static int dnr_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        if (link->dhcp_lease && link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
                struct sd_dns_resolver *dnr;
                union in_addr_union s;
                int n_dnr;

                r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                if (r < 0)
                        return r;

                n_dnr = sd_dhcp_lease_get_dnr(link->dhcp_lease, &dnr);
                if (n_dnr > 0)
                        FOREACH_ARRAY(res, dnr, n_dnr) {
                                r = dnr_append_json_one(link,
                                                        res,
                                                        NETWORK_CONFIG_SOURCE_DHCP4,
                                                        &s,
                                                        &array);
                                if (r < 0)
                                        return r;
                        }
        }

        if (link->dhcp6_lease && link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
                struct sd_dns_resolver *dnr;
                union in_addr_union s;
                int n_dnr;

                r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                if (r < 0)
                        return r;

                n_dnr = sd_dhcp6_lease_get_dnr(link->dhcp6_lease, &dnr);
                if (n_dnr > 0)
                        FOREACH_ARRAY(res, dnr, n_dnr) {
                                r = dnr_append_json_one(link,
                                                        res,
                                                        NETWORK_CONFIG_SOURCE_DHCP6,
                                                        &s,
                                                        &array);
                                if (r < 0)
                                        return r;
                        }
        }

        if (link_get_use_dnr(link, NETWORK_CONFIG_SOURCE_NDISC)) {
                NDiscDNR *a;

                SET_FOREACH(a, link->ndisc_dnr) {
                        r = dnr_append_json_one(link,
                                                &a->resolver,
                                                NETWORK_CONFIG_SOURCE_NDISC,
                                                &(union in_addr_union) { .in6 = a->router },
                                                &array);
                        if (r < 0)
                                return r;
                }
        }

        return json_variant_set_field_non_null(v, "DNR", array);
}

static int server_append_json_one_addr(int family, const union in_addr_union *a, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **array) {
        _cleanup_free_ char *address_str = NULL;
        int r;

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(a);
        assert(array);

        r = in_addr_to_string(family, a, &address_str);
        if (r < 0)
                return r;

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_INTEGER("Family", family),
                        JSON_BUILD_PAIR_IN_ADDR("Address", a, family),
                        SD_JSON_BUILD_PAIR_STRING("AddressString", address_str),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", family, p));
}

static int server_append_json_one_fqdn(int family, const char *fqdn, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **array) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(fqdn);
        assert(array);

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_STRING("Server", fqdn),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", family, p));
}

static int server_append_json_one_string(const char *str, NetworkConfigSource s, sd_json_variant **array) {
        union in_addr_union a;
        int family;

        assert(str);

        if (in_addr_from_string_auto(str, &family, &a) >= 0)
                return server_append_json_one_addr(family, &a, s, NULL, array);

        return server_append_json_one_fqdn(AF_UNSPEC, str, s, NULL, array);
}

static int ntp_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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
                if (link->dhcp_lease && link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP4)) {
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

                if (link->dhcp6_lease && link_get_use_ntp(link, NETWORK_CONFIG_SOURCE_DHCP6)) {
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

static int domain_append_json(int family, const char *domain, NetworkConfigSource s, const union in_addr_union *p, sd_json_variant **array) {
        assert(IN_SET(family, AF_UNSPEC, AF_INET, AF_INET6));
        assert(domain);
        assert(array);

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_STRING("Domain", domain),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)),
                        JSON_BUILD_PAIR_IN_ADDR_WITH_STRING_NON_NULL("ConfigProvider", family, p));
}

static int sip_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->network)
                return 0;

        if (link->dhcp_lease && link->network->dhcp_use_sip) {
                const struct in_addr *sip;
                union in_addr_union s;
                int n_sip;

                r = sd_dhcp_lease_get_server_identifier(link->dhcp_lease, &s.in);
                if (r < 0)
                        return r;

                n_sip = sd_dhcp_lease_get_sip(link->dhcp_lease, &sip);
                for (int i = 0; i < n_sip; i++) {
                        r = server_append_json_one_addr(AF_INET,
                                                        &(union in_addr_union) { .in = sip[i], },
                                                        NETWORK_CONFIG_SOURCE_DHCP4,
                                                        &s,
                                                        &array);
                        if (r < 0)
                                return r;
                }

        }

        if (link->dhcp6_lease && link->network->dhcp6_use_sip) {
                const struct in6_addr *sip_addr;
                union in_addr_union s;
                char **domains;
                int n_sip;

                r = sd_dhcp6_lease_get_server_address(link->dhcp6_lease, &s.in6);
                if (r < 0)
                        return r;

                n_sip = sd_dhcp6_lease_get_sip_addrs(link->dhcp6_lease, &sip_addr);
                for (int i = 0; i < n_sip; i++) {
                        r = server_append_json_one_addr(AF_INET6,
                                                        &(union in_addr_union) { .in6 = sip_addr[i], },
                                                        NETWORK_CONFIG_SOURCE_DHCP6,
                                                        &s,
                                                        &array);
                        if (r < 0)
                                return r;
                }

                if (sd_dhcp6_lease_get_sip_domains(link->dhcp6_lease, &domains) >= 0)
                        STRV_FOREACH(p, domains) {
                                r = domain_append_json(AF_INET6,
                                                       *p,
                                                       NETWORK_CONFIG_SOURCE_DHCP6,
                                                       &s,
                                                       &array);
                                if (r < 0)
                                        return r;
                        }

        }

        return json_variant_set_field_non_null(v, "SIP", array);
}

static int domains_append_json(Link *link, bool is_route, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        OrderedSet *link_domains, *network_domains;
        UseDomains use_domains;
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
        use_domains = is_route ? USE_DOMAINS_ROUTE : USE_DOMAINS_YES;

        ORDERED_SET_FOREACH(domain, link_domains ?: network_domains) {
                r = domain_append_json(AF_UNSPEC, domain,
                                       link_domains ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC,
                                       NULL, &array);
                if (r < 0)
                        return r;
        }

        if (!link_domains) {
                if (link->dhcp_lease &&
                    link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP4) == use_domains) {
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
                    link_get_use_domains(link, NETWORK_CONFIG_SOURCE_DHCP6) == use_domains) {
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

                if (link_get_use_domains(link, NETWORK_CONFIG_SOURCE_NDISC) == use_domains) {
                        NDiscDNSSL *a;

                        SET_FOREACH(a, link->ndisc_dnssl) {
                                r = domain_append_json(AF_INET6, ndisc_dnssl_domain(a), NETWORK_CONFIG_SOURCE_NDISC,
                                                       &(union in_addr_union) { .in6 = a->router },
                                                       &array);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        return json_variant_set_field_non_null(v, is_route ? "RouteDomains" : "SearchDomains", array);
}

static int nta_append_json(const char *nta, NetworkConfigSource s, sd_json_variant **array) {
        assert(nta);
        assert(array);

        return sd_json_variant_append_arraybo(
                        array,
                        SD_JSON_BUILD_PAIR_STRING("DNSSECNegativeTrustAnchor", nta),
                        SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(s)));
}

static int ntas_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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

static int dns_misc_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_STRING("LLMNR", resolve_support_to_string(resolve_support)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source)));
                if (r < 0)
                        return r;
        }

        resolve_support = link->mdns >= 0 ? link->mdns : link->network->mdns;
        if (resolve_support >= 0) {
                source = link->mdns >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_STRING("MDNS", resolve_support_to_string(resolve_support)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source)));
                if (r < 0)
                        return r;
        }

        t = link->dns_default_route >= 0 ? link->dns_default_route : link->network->dns_default_route;
        if (t >= 0) {
                source = link->dns_default_route >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_BOOLEAN("DNSDefaultRoute", t),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source)));
                if (r < 0)
                        return r;
        }

        mode = link->dns_over_tls_mode >= 0 ? link->dns_over_tls_mode : link->network->dns_over_tls_mode;
        if (mode >= 0) {
                source = link->dns_over_tls_mode >= 0 ? NETWORK_CONFIG_SOURCE_RUNTIME : NETWORK_CONFIG_SOURCE_STATIC;

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_STRING("DNSOverTLS", dns_over_tls_mode_to_string(mode)),
                                SD_JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(source)));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "DNSSettings", array);
}

static int captive_portal_append_json(Link *link, sd_json_variant **v) {
        const char *captive_portal;
        int r;

        assert(link);
        assert(v);

        r = link_get_captive_portal(link, &captive_portal);
        if (r <= 0)
                return r;

        return sd_json_variant_merge_objectbo(v, SD_JSON_BUILD_PAIR_STRING("CaptivePortal", captive_portal));
}

static int pref64_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL, *w = NULL;
        NDiscPREF64 *i;
        int r;

        assert(link);
        assert(v);

        if (!link->network || !link->network->ndisc_use_pref64)
                return 0;

        SET_FOREACH(i, link->ndisc_pref64) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                JSON_BUILD_PAIR_IN6_ADDR_WITH_STRING("Prefix", &i->prefix),
                                SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength", i->prefix_len),
                                JSON_BUILD_PAIR_FINITE_USEC("LifetimeUSec", i->lifetime_usec),
                                JSON_BUILD_PAIR_IN6_ADDR_WITH_STRING_NON_NULL("ConfigProvider", &i->router));
                if (r < 0)
                        return r;
        }

        r = json_variant_set_field_non_null(&w, "PREF64", array);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "NDisc", w);
}

static int dhcp_server_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_server)
                return 0;

        r = sd_json_buildo(
                        &w,
                        SD_JSON_BUILD_PAIR_UNSIGNED("PoolOffset", link->dhcp_server->pool_offset),
                        SD_JSON_BUILD_PAIR_UNSIGNED("PoolSize", link->dhcp_server->pool_size));
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

static int dhcp6_client_vendor_options_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        sd_dhcp6_option **options = NULL;
        int r, n_vendor_options;

        assert(link);
        assert(v);

        if (!link->dhcp6_lease)
                return 0;

        n_vendor_options = sd_dhcp6_lease_get_vendor_options(link->dhcp6_lease, &options);

        FOREACH_ARRAY(option, options, n_vendor_options) {
                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_UNSIGNED("EnterpriseId", (*option)->enterprise_identifier),
                                SD_JSON_BUILD_PAIR_UNSIGNED("SubOptionCode", (*option)->option),
                                SD_JSON_BUILD_PAIR_HEX("SubOptionData", (*option)->data, (*option)->length));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "VendorSpecificOptions", array);
}

static int dhcp6_client_lease_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
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

        r = sd_json_buildo(
                        &w,
                        JSON_BUILD_PAIR_FINITE_USEC("Timeout1USec", t1),
                        JSON_BUILD_PAIR_FINITE_USEC("Timeout2USec", t2),
                        JSON_BUILD_PAIR_FINITE_USEC("LeaseTimestampUSec", ts));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "Lease", w);
}

static int dhcp6_client_pd_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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
                _cleanup_free_ char *prefix_str = NULL;

                r = sd_dhcp6_lease_get_pd_prefix(link->dhcp6_lease, &prefix, &prefix_len);
                if (r < 0)
                        return r;

                r = sd_dhcp6_lease_get_pd_lifetime_timestamp(link->dhcp6_lease, CLOCK_BOOTTIME,
                                                             &lifetime_preferred_usec, &lifetime_valid_usec);
                if (r < 0)
                        return r;

                if (in6_addr_is_set(&prefix)) {
                        r = in6_addr_to_string(&prefix, &prefix_str);
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_append_arraybo(
                                &array,
                                JSON_BUILD_PAIR_IN6_ADDR("Prefix", &prefix),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("PrefixString", prefix_str),
                                SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength", prefix_len),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUSec", lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUSec", lifetime_valid_usec));
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Prefixes", array);
}

static int dhcp6_client_duid_append_json(Link *link, sd_json_variant **v) {
        const sd_dhcp_duid *duid;
        const void *data;
        size_t data_size;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp6_client)
                return 0;

        r = sd_dhcp6_client_get_duid(link->dhcp6_client, &duid);
        if (r < 0)
                return 0;

        r = sd_dhcp_duid_get_raw(duid, &data, &data_size);
        if (r < 0)
                return 0;

        return sd_json_variant_merge_objectbo(v, SD_JSON_BUILD_PAIR_BYTE_ARRAY("DUID", data, data_size));
}

static int dhcp6_client_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
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

        r = dhcp6_client_duid_append_json(link, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "DHCPv6Client", w);
}

static int dhcp_client_lease_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        usec_t lease_timestamp_usec = USEC_INFINITY, t1 = USEC_INFINITY, t2 = USEC_INFINITY;
        const char *hostname = NULL;
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

        r = sd_dhcp_lease_get_hostname(link->dhcp_lease, &hostname);
        if (r < 0 && r != -ENODATA)
                return r;

        r = sd_json_buildo(
                        &w,
                        JSON_BUILD_PAIR_FINITE_USEC("LeaseTimestampUSec", lease_timestamp_usec),
                        JSON_BUILD_PAIR_FINITE_USEC("Timeout1USec", t1),
                        JSON_BUILD_PAIR_FINITE_USEC("Timeout2USec", t2),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Hostname", hostname));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "Lease", w);
}

static int dhcp_client_pd_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *addresses = NULL, *array = NULL;
        uint8_t ipv4masklen, sixrd_prefixlen;
        struct in6_addr sixrd_prefix;
        const struct in_addr *br_addresses;
        size_t n_br_addresses = 0;
        _cleanup_free_ char *prefix_str = NULL;
        int r;

        assert(link);
        assert(link->network);
        assert(v);

        if (!link->network->dhcp_use_6rd || !sd_dhcp_lease_has_6rd(link->dhcp_lease))
                return 0;

        r = sd_dhcp_lease_get_6rd(link->dhcp_lease, &ipv4masklen, &sixrd_prefixlen, &sixrd_prefix, &br_addresses, &n_br_addresses);
        if (r < 0)
                return r;

        if (in6_addr_is_set(&sixrd_prefix)) {
                r = in6_addr_to_string(&sixrd_prefix, &prefix_str);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(br_address, br_addresses, n_br_addresses) {
                r = sd_json_variant_append_arrayb(&addresses, JSON_BUILD_IN4_ADDR(br_address));
                if (r < 0)
                        return r;
        }

        r = sd_json_buildo(
                        &array,
                        JSON_BUILD_PAIR_IN6_ADDR("Prefix", &sixrd_prefix),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("PrefixString", prefix_str),
                        SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength", sixrd_prefixlen),
                        SD_JSON_BUILD_PAIR_UNSIGNED("IPv4MaskLength", ipv4masklen),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("BorderRouters", addresses));
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "6rdPrefix", array);
}

static int dhcp_client_private_options_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_lease)
                return 0;

        LIST_FOREACH(options, option, link->dhcp_lease->private_options) {

                r = sd_json_variant_append_arraybo(
                                &array,
                                SD_JSON_BUILD_PAIR_UNSIGNED("Option", option->tag),
                                SD_JSON_BUILD_PAIR_HEX("PrivateOptionData", option->data, option->length));
                if (r < 0)
                        return 0;
        }
        return json_variant_set_field_non_null(v, "PrivateOptions", array);
}

static int dhcp_client_id_append_json(Link *link, sd_json_variant **v) {
        const sd_dhcp_client_id *client_id;
        const void *data;
        size_t l;
        int r;

        assert(link);
        assert(v);

        if (!link->dhcp_client)
                return 0;

        r = sd_dhcp_client_get_client_id(link->dhcp_client, &client_id);
        if (r < 0)
                return 0;

        r = sd_dhcp_client_id_get_raw(client_id, &data, &l);
        if (r < 0)
                return 0;

        return sd_json_variant_merge_objectbo(v, SD_JSON_BUILD_PAIR_BYTE_ARRAY("ClientIdentifier", data, l));
}

static int dhcp_client_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
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

        r = dhcp_client_private_options_append_json(link, &w);
        if (r < 0)
                return r;

        r = dhcp_client_id_append_json(link, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "DHCPv4Client", w);
}

static int lldp_tx_append_json(Link *link, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        int r;

        assert(link);
        assert(v);

        if (!link->lldp_tx)
                return 0;

        r = sd_lldp_tx_describe(link->lldp_tx, &w);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "LLDP", w);
}

int link_build_json(Link *link, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

        r = sd_json_buildo(
                        &v,
                        /* basic information */
                        SD_JSON_BUILD_PAIR_INTEGER("Index", link->ifindex),
                        SD_JSON_BUILD_PAIR_STRING("Name", link->ifname),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("AlternativeNames", link->alternative_names),
                        SD_JSON_BUILD_PAIR_CONDITION(link->master_ifindex > 0,
                                                     "MasterInterfaceIndex", SD_JSON_BUILD_INTEGER(link->master_ifindex)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Kind", link->kind),
                        SD_JSON_BUILD_PAIR_STRING("Type", type),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Driver", link->driver),
                        SD_JSON_BUILD_PAIR_UNSIGNED("Flags", link->flags),
                        SD_JSON_BUILD_PAIR_STRING("FlagsString", flags),
                        SD_JSON_BUILD_PAIR_UNSIGNED("KernelOperationalState", link->kernel_operstate),
                        SD_JSON_BUILD_PAIR_STRING("KernelOperationalStateString", kernel_operstate_to_string(link->kernel_operstate)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("MTU", link->mtu),
                        SD_JSON_BUILD_PAIR_UNSIGNED("MinimumMTU", link->min_mtu),
                        SD_JSON_BUILD_PAIR_UNSIGNED("MaximumMTU", link->max_mtu),
                        JSON_BUILD_PAIR_HW_ADDR_NON_NULL("HardwareAddress", &link->hw_addr),
                        JSON_BUILD_PAIR_HW_ADDR_NON_NULL("PermanentHardwareAddress", &link->permanent_hw_addr),
                        JSON_BUILD_PAIR_HW_ADDR_NON_NULL("BroadcastAddress", &link->bcast_addr),
                        JSON_BUILD_PAIR_IN6_ADDR_WITH_STRING_NON_NULL("IPv6LinkLocalAddress", &link->ipv6ll_address),
                        /* wlan information */
                        SD_JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceType",
                                                     SD_JSON_BUILD_UNSIGNED(link->wlan_iftype)),
                        SD_JSON_BUILD_PAIR_CONDITION(link->wlan_iftype > 0, "WirelessLanInterfaceTypeString",
                                                     SD_JSON_BUILD_STRING(nl80211_iftype_to_string(link->wlan_iftype))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("SSID", link->ssid),
                        JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL("BSSID", &link->bssid),
                        /* link state */
                        SD_JSON_BUILD_PAIR_STRING("AdministrativeState", link_state_to_string(link->state)),
                        SD_JSON_BUILD_PAIR_STRING("OperationalState", link_operstate_to_string(link->operstate)),
                        SD_JSON_BUILD_PAIR_STRING("CarrierState", link_carrier_state_to_string(link->carrier_state)),
                        SD_JSON_BUILD_PAIR_STRING("AddressState", link_address_state_to_string(link->address_state)),
                        SD_JSON_BUILD_PAIR_STRING("IPv4AddressState", link_address_state_to_string(link->ipv4_address_state)),
                        SD_JSON_BUILD_PAIR_STRING("IPv6AddressState", link_address_state_to_string(link->ipv6_address_state)),
                        SD_JSON_BUILD_PAIR_STRING("OnlineState", link_online_state_to_string(link->online_state)));
        if (r < 0)
                return r;

        r = network_append_json(link->network, &v);
        if (r < 0)
                return r;

        r = netdev_append_json(link->netdev, &v);
        if (r < 0)
                return r;

        r = device_append_json(link->dev, &v);
        if (r < 0)
                return r;

        r = dns_append_json(link, &v);
        if (r < 0)
                return r;

        r = dnr_append_json(link, &v);
        if (r < 0)
                return r;

        r = ntp_append_json(link, &v);
        if (r < 0)
                return r;

        r = sip_append_json(link, &v);
        if (r < 0)
                return r;

        r = domains_append_json(link, /* is_route= */ false, &v);
        if (r < 0)
                return r;

        r = domains_append_json(link, /* is_route= */ true, &v);
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

        r = addresses_append_json(link, /* serializing= */ false, &v);
        if (r < 0)
                return r;

        r = neighbors_append_json(link->neighbors, &v);
        if (r < 0)
                return r;

        r = nexthops_append_json(link->manager, link->ifindex, &v);
        if (r < 0)
                return r;

        r = routes_append_json(link->manager, link->ifindex, &v);
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

        r = lldp_tx_append_json(link, &v);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

static int links_append_json(Manager *manager, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        _cleanup_free_ Link **links = NULL;
        size_t n_links = 0;
        int r;

        assert(manager);
        assert(v);

        r = hashmap_dump_sorted(manager->links_by_index, (void***) &links, &n_links);
        if (r < 0)
                return r;

        FOREACH_ARRAY(link, links, n_links) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;

                r = link_build_json(*link, &e);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&array, e);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Interfaces", array);
}

int manager_build_json(Manager *manager, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = links_append_json(manager, &v);
        if (r < 0)
                return r;

        r = nexthops_append_json(manager, /* ifindex= */ 0, &v);
        if (r < 0)
                return r;

        r = routes_append_json(manager, /* ifindex= */ 0, &v);
        if (r < 0)
                return r;

        r = routing_policy_rules_append_json(manager->rules, &v);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}
