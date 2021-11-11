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
                                JSON_BUILD_PAIR_INTEGER("Family", address->family),
                                JSON_BUILD_PAIR_IN_ADDR("Address", &address->in_addr, address->family),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("Peer", &address->in_addr_peer, address->family),
                                JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("Broadcast", &address->broadcast),
                                JSON_BUILD_PAIR_UNSIGNED("PrefixLength", address->prefixlen),
                                JSON_BUILD_PAIR_UNSIGNED("Scope", address->scope),
                                JSON_BUILD_PAIR_UNSIGNED("Flags", address->flags),
                                JSON_BUILD_PAIR_STRING("FlagsString", flags),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("Label", address->label),
                                JSON_BUILD_PAIR_FINITE_USEC("PreferredLifetimeUsec", address->lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_TIMESTAMP("PreferredLifetimeString", address->lifetime_preferred_usec),
                                JSON_BUILD_PAIR_FINITE_USEC("ValidLifetimeUsec", address->lifetime_valid_usec),
                                JSON_BUILD_PAIR_FINITE_TIMESTAMP("ValidLifetimeString", address->lifetime_valid_usec),
                                JSON_BUILD_PAIR_STRING("ConfigSource", network_config_source_to_string(address->source)),
                                JSON_BUILD_PAIR_STRING("ConfigState", state),
                                JSON_BUILD_PAIR_IN_ADDR_NON_NULL("ConfigProvider", &address->provider, address->family)));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(v);
        return 0;
}

int addresses_build_json(Set *addresses, JsonVariant **ret) {
        JsonVariant **elements;
        Address *address;
        size_t n = 0;
        int r;

        assert(addresses);
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
