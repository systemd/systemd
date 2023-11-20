/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-server-lease-internal.h"

static sd_dhcp_server_lease* dhcp_server_lease_free(sd_dhcp_server_lease *lease) {
        if (!lease)
                return NULL;

        if (lease->server) {
                hashmap_remove_value(lease->server->bound_leases_by_address, UINT32_TO_PTR(lease->address), lease);
                hashmap_remove_value(lease->server->bound_leases_by_client_id, &lease->client_id, lease);
                hashmap_remove_value(lease->server->static_leases_by_address, UINT32_TO_PTR(lease->address), lease);
                hashmap_remove_value(lease->server->static_leases_by_client_id, &lease->client_id, lease);
        }

        free(lease->hostname);
        return mfree(lease);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_server_lease, sd_dhcp_server_lease, dhcp_server_lease_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        dhcp_server_lease_hash_ops,
        sd_dhcp_client_id,
        client_id_hash_func,
        client_id_compare_func,
        sd_dhcp_server_lease,
        sd_dhcp_server_lease_unref);

int dhcp_server_add_lease(sd_dhcp_server *server, sd_dhcp_server_lease *lease, bool is_static) {
        int r;

        assert(server);
        assert(lease);

        lease->server = server; /* This must be set before hashmap_put(). */

        r = hashmap_ensure_put(is_static ? &server->static_leases_by_client_id : &server->bound_leases_by_client_id,
                               &dhcp_server_lease_hash_ops, &lease->client_id, lease);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(is_static ? &server->static_leases_by_address : &server->bound_leases_by_address,
                               NULL, UINT32_TO_PTR(lease->address), lease);
        if (r < 0)
                return r;

        return 0;
}

static int dhcp_server_lease_append_json(sd_dhcp_server_lease *lease, JsonVariant **array) {
        assert(lease);
        assert(array);

        return json_variant_append_arrayb(
                        array,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR_BYTE_ARRAY(
                                                        "ClientId",
                                                        lease->client_id.raw,
                                                        lease->client_id.size),
                                        JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("Address", &(struct in_addr) { .s_addr = lease->address }),
                                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Hostname", lease->hostname),
                                        JSON_BUILD_PAIR_FINITE_USEC(
                                                        "ExpirationUSec", lease->expiration)));
}

static int dhcp_server_bound_leases_build_json(sd_dhcp_server *server, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        sd_dhcp_server_lease *lease;
        int r;

        assert(server);
        assert(ret);

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id) {
                r = dhcp_server_lease_append_json(lease, &array);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

int dhcp_server_bound_leases_append_json(sd_dhcp_server *server, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        int r;

        assert(server);
        assert(v);

        r = dhcp_server_bound_leases_build_json(server, &array);
        if (r < 0)
                return r;

        return json_variant_set_field_non_null(v, "Leases", array);
}

int dhcp_server_static_leases_append_json(sd_dhcp_server *server, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        sd_dhcp_server_lease *lease;
        int r;

        assert(server);
        assert(v);

        HASHMAP_FOREACH(lease, server->static_leases_by_client_id) {
                r = dhcp_server_lease_append_json(lease, &array);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "StaticLeases", array);
}
