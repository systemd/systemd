/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-link.h"
#include "networkd-route-util.h"
#include "networkd-routing-policy-rule-json.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-util.h"

static int routing_policy_rule_build_json(RoutingPolicyRule *rule, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *table = NULL, *state = NULL;
        int r;

        assert(rule);
        assert(ret);

        r = manager_get_route_table_to_string(rule->manager, rule->table, &table);
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
                                JSON_BUILD_PAIR_UNSIGNED("Priority", rule->priority),
                                JSON_BUILD_PAIR_UNSIGNED("Table", rule->table),
                                JSON_BUILD_PAIR_STRING("TableString", table),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("IncomingInterface", rule->iif),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("OutgoingInterface", rule->oif),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(rule->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int routing_policy_rules_build_json(Set *rules, JsonVariant **ret) {
        JsonVariant **elements;
        RoutingPolicyRule *rule;
        size_t n = 0;
        int r;

        assert(rules);
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
