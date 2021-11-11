/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nexthop.h>

#include "networkd-nexthop-json.h"
#include "networkd-nexthop.h"
#include "networkd-link.h"
#include "networkd-route-util.h"
#include "networkd-util.h"

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
        _cleanup_free_ char *flags = NULL, *state = NULL;
        int r;

        assert(n);
        assert(ret);

        r = route_flags_to_string_alloc(n->flags, &flags);
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
                                JSON_BUILD_PAIR_BOOLEAN("Blackhole", n->blackhole),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("Group", group),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(n->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int nexthops_build_json(Set *nexthops, JsonVariant **ret) {
        JsonVariant **elements;
        NextHop *nexthop;
        size_t n = 0;
        int r;

        assert(nexthops);
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
