/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "networkd-address-json.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-util.h"

static int address_build_json(Address *address, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *flags = NULL, *state = NULL;
        int r;

        assert(address);
        assert(ret);

        r = address_flags_to_string_alloc(address->flags, address->family, &flags);
        if (r < 0)
                return r;

        r = network_config_state_to_string_alloc(address->state, &state);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                JSON_BUILD_PAIR("Family", JSON_BUILD_INTEGER(address->family)),
                                JSON_BUILD_PAIR("Address", JSON_BUILD_IN_ADDR_UNION(&address->in_addr, address->family)),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(address->family, &address->in_addr_peer), "Peer",
                                                          JSON_BUILD_IN_ADDR_UNION(&address->in_addr_peer, address->family)),
                                JSON_BUILD_PAIR_CONDITION(address->family == AF_INET && in4_addr_is_set(&address->broadcast), "Broadcast",
                                                          JSON_BUILD_IN_ADDR(&address->broadcast)),
                                JSON_BUILD_PAIR("PrefixLength", JSON_BUILD_UNSIGNED(address->prefixlen)),
                                JSON_BUILD_PAIR("Scope", JSON_BUILD_UNSIGNED(address->scope)),
                                JSON_BUILD_PAIR("Flags", JSON_BUILD_STRING(flags)),
                                JSON_BUILD_PAIR_CONDITION(address->family == AF_INET, "Label",
                                                          JSON_BUILD_STRING(address->label)),
                                JSON_BUILD_PAIR("PreferredLifetimeUsec", JSON_BUILD_UNSIGNED(address->lifetime_preferred_usec)),
                                JSON_BUILD_PAIR("ValidLifetimeUsec", JSON_BUILD_UNSIGNED(address->lifetime_valid_usec)),
                                JSON_BUILD_PAIR("ConfigSource", JSON_BUILD_STRING(network_config_source_to_string(address->source))),
                                JSON_BUILD_PAIR("ConfigState", JSON_BUILD_STRING(state)),
                                JSON_BUILD_PAIR_CONDITION(in_addr_is_set(address->family, &address->provider), "ConfigProvider",
                                                          JSON_BUILD_IN_ADDR_UNION(&address->provider, address->family))));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int link_addresses_build_json(Link *link, JsonVariant **ret) {
        JsonVariant **elements;
        Address *address;
        size_t n = 0;
        int r;

        assert(link);
        assert(ret);

        if (set_isempty(link->addresses)) {
                *ret = NULL;
                return 0;
        }

        elements = new(JsonVariant*, set_size(link->addresses));
        if (!elements)
                return -ENOMEM;

        SET_FOREACH(address, link->addresses) {
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
