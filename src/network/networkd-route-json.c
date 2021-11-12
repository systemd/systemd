/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-route-json.h"
#include "networkd-route-util.h"
#include "networkd-route.h"
#include "networkd-link.h"
#include "networkd-util.h"

static int route_build_json(Route *route, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *scope = NULL, *protocol = NULL, *table = NULL, *flags = NULL, *state = NULL;
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
                                JSON_BUILD_PAIR_FINITE_TIMESTAMP("LifetimeString", route->lifetime_usec),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(route->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &route->provider, route->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int routes_build_json(Set *routes, JsonVariant **ret) {
        JsonVariant **elements;
        Route *route;
        size_t n = 0;
        int r;

        assert(routes);
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
