/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-util.h"
#include "networkd-json.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "sort-util.h"

static int network_build_json(Network *network, JsonVariant **ret) {
        assert(network);
        assert(ret);

        return json_build(ret, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("NetworkFile", JSON_BUILD_STRING(network->filename))));
}

static int device_build_json(sd_device *device, JsonVariant **ret) {
        const char *link = NULL, *path = NULL, *vendor = NULL, *model = NULL;

        assert(device);
        assert(ret);

        (void) sd_device_get_property_value(device, "ID_NET_LINK_FILE", &link);
        (void) sd_device_get_property_value(device, "ID_PATH", &path);

        if (sd_device_get_property_value(device, "ID_VENDOR_FROM_DATABASE", &vendor) < 0)
                (void) sd_device_get_property_value(device, "ID_VENDOR", &vendor);

        if (sd_device_get_property_value(device, "ID_MODEL_FROM_DATABASE", &model) < 0)
                (void) sd_device_get_property_value(device, "ID_MODEL", &model);

        return json_build(ret, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("LinkFile", JSON_BUILD_STRING(link)),
                                        JSON_BUILD_PAIR("Path", JSON_BUILD_STRING(path)),
                                        JSON_BUILD_PAIR("Vendor", JSON_BUILD_STRING(vendor)),
                                        JSON_BUILD_PAIR("Model", JSON_BUILD_STRING(model))));
}

int link_build_json(Link *link, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *type = NULL;
        int r;

        assert(link);
        assert(ret);

        r = net_get_type_string(link->sd_device, link->iftype, &type);
        if (r == -ENOMEM)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("Index", JSON_BUILD_INTEGER(link->ifindex)),
                                        JSON_BUILD_PAIR("Name", JSON_BUILD_STRING(link->ifname)),
                                        JSON_BUILD_PAIR("AlternativeNames", JSON_BUILD_STRV(link->alternative_names)),
                                        JSON_BUILD_PAIR("Type", JSON_BUILD_STRING(type)),
                                        JSON_BUILD_PAIR("Driver", JSON_BUILD_STRING(link->driver)),
                                        JSON_BUILD_PAIR("SetupState", JSON_BUILD_STRING(link_state_to_string(link->state))),
                                        JSON_BUILD_PAIR("OperationalState", JSON_BUILD_STRING(link_operstate_to_string(link->operstate))),
                                        JSON_BUILD_PAIR("CarrierState", JSON_BUILD_STRING(link_carrier_state_to_string(link->carrier_state))),
                                        JSON_BUILD_PAIR("AddressState", JSON_BUILD_STRING(link_address_state_to_string(link->address_state))),
                                        JSON_BUILD_PAIR("IPv4AddressState", JSON_BUILD_STRING(link_address_state_to_string(link->ipv4_address_state))),
                                        JSON_BUILD_PAIR("IPv6AddressState", JSON_BUILD_STRING(link_address_state_to_string(link->ipv6_address_state))),
                                        JSON_BUILD_PAIR("OnlineState", JSON_BUILD_STRING(link_online_state_to_string(link->online_state)))));
        if (r < 0)
                return r;

        if (link->network) {
                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

                r = network_build_json(link->network, &w);
                if (r < 0)
                        return r;

                r = json_variant_merge(&v, w);
                if (r < 0)
                        return r;
        }

        if (link->sd_device) {
                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

                r = device_build_json(link->sd_device, &w);
                if (r < 0)
                        return r;

                r = json_variant_merge(&v, w);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int link_json_compare(JsonVariant * const *a, JsonVariant * const *b) {
        intmax_t index_a, index_b;

        assert(a && *a);
        assert(b && *b);

        index_a = json_variant_integer(json_variant_by_key(*a, "Index"));
        index_b = json_variant_integer(json_variant_by_key(*b, "Index"));

        return CMP(index_a, index_b);
}

int manager_build_json(Manager *manager, JsonVariant **ret) {
        JsonVariant **elements;
        Link *link;
        size_t n = 0;
        int r;

        assert(manager);
        assert(ret);

        elements = new(JsonVariant*, hashmap_size(manager->links_by_index));
        if (!elements)
                return -ENOMEM;

        HASHMAP_FOREACH(link, manager->links_by_index) {
                r = link_build_json(link, elements + n);
                if (r < 0)
                        goto finalize;
                n++;
        }

        typesafe_qsort(elements, n, link_json_compare);

        r = json_build(ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("Interfaces", JSON_BUILD_VARIANT_ARRAY(elements, n))));

finalize:
        json_variant_unref_many(elements, n);
        free(elements);
        return r;
}
