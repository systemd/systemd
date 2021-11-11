/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-link-json.h"
#include "networkd-manager-json.h"
#include "networkd-manager.h"
#include "networkd-nexthop-json.h"
#include "networkd-route-json.h"
#include "networkd-routing-policy-rule-json.h"

int manager_build_json(Manager *manager, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *w = NULL;
        int r;

        assert(manager);
        assert(ret);

        r = links_build_json(manager, &v);
        if (r < 0)
                return r;

        r = routes_build_json(manager->routes, &w);
        if (r < 0)
                return r;

        r = json_variant_merge(&v, w);
        if (r < 0)
                return r;

        w = json_variant_unref(w);

        r = nexthops_build_json(manager->nexthops, &w);
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
