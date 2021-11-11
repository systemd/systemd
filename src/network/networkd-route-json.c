/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-route-json.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-link.h"
#include "networkd-util.h"

static int route_build_json(Route *route, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *state = NULL;
        int r;

        assert(route);
        assert(ret);

        r = route_scope_to_string_alloc(route->scope, &scope);
        if (r < 0)
                return r;

        r = route_protocol_to_string_alloc(route->protocol, &protocol);
        if (r < 0)
                return r;

        r = manager_get_route_table_to_string(route->link ? route->link->manager : route->manager,
                                              route->table, &table);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(route->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("Family", JSON_BUILD_INTEGER(route->family)),
                                JSON_BUILD_PAIR("Destination", JSON_BUILD_IN_ADDR_UNION(&route->dst, route->family)),
                                JSON_BUILD_PAIR("DestinationPrefixLength", JSON_BUILD_UNSIGNED(route->dst_prefixlen)),
                                JSON_BUILD_PAIR("GatewayFamily", JSON_BUILD_INTEGER(route->gw_family)),
                                JSON_BUILD_PAIR("Gateway", JSON_BUILD_IN_ADDR_UNION(&route->gw, route->gw_family)),
                                JSON_BUILD_PAIR("Source", JSON_BUILD_IN_ADDR_UNION(&route->src, route->family)),
                                JSON_BUILD_PAIR("SourcePrefixLength", JSON_BUILD_UNSIGNED(route->src_prefixlen)),
                                JSON_BUILD_PAIR("Scope", JSON_BUILD_UNSIGNED(route->scope)),
                                JSON_BUILD_PAIR("ScopeString", JSON_BUILD_STRING(scope)),
                                JSON_BUILD_PAIR("Protocol", JSON_BUILD_UNSIGNED(route->protocol)),
                                JSON_BUILD_PAIR("ProtocolString", JSON_BUILD_STRING(protocol)),
                                JSON_BUILD_PAIR("Type", JSON_BUILD_UNSIGNED(route->type)),
                                JSON_BUILD_PAIR("TypeString", JSON_BUILD_STRING(route_type_to_string(route->type))),
                                JSON_BUILD_PAIR("PreferredSource", JSON_BUILD_IN_ADDR_UNION(&route->prefsrc, route->family)),
                                JSON_BUILD_PAIR("Priority", JSON_BUILD_UNSIGNED(route->priority)),
                                JSON_BUILD_PAIR("Table", JSON_BUILD_UNSIGNED(route->table)),
                                JSON_BUILD_PAIR("TableString", JSON_BUILD_STRING(table)),
                                JSON_BUILD_PAIR("MTU", JSON_BUILD_UNSIGNED(route->mtu)),
                                JSON_BUILD_PAIR("Preference", JSON_BUILD_UNSIGNED(route->pref)),
                                JSON_BUILD_PAIR("Flags", JSON_BUILD_UNSIGNED(route->flags)),
                                JSON_BUILD_PAIR("LifetimeUSec", JSON_BUILD_UNSIGNED(route->lifetime_usec)),
                                JSON_BUILD_PAIR("ConfigSource", JSON_BUILD_STRING(network_config_source_to_string(route->source))),
                                JSON_BUILD_PAIR("ConfigState", JSON_BUILD_STRING(state)),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(route->family, &route->provider), "ConfigProvider",
                                                          JSON_BUILD_IN_ADDR_UNION(&route->provider, route->family))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int link_routes_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements;
        Route *route;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (set_isempty(link->routes)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(link->routes));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(route, link->routes) {
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
