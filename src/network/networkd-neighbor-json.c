/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-neighbor-json.h"
#include "networkd-neighbor.h"
#include "networkd-link.h"
#include "networkd-util.h"

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

int neighbors_build_json(Set *neighbors, JsonVariant **ret) {
        JsonVariant **elements;
        Neighbor *neighbor;
        size_t n = 0;
        int r;

        assert(neighbors);
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
