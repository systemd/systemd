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

int dhcp_server_put_lease(sd_dhcp_server *server, sd_dhcp_server_lease *lease, bool is_static) {
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

int dhcp_server_set_lease(sd_dhcp_server *server, be32_t address, DHCPRequest *req, usec_t expiration) {
        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = NULL;
        int r;

        assert(server);
        assert(address != 0);
        assert(req);
        assert(expiration != 0);

        /* If a lease for the host already exists, update it. */
        lease = hashmap_get(server->bound_leases_by_client_id, &req->client_id);
        if (lease) {
                if (lease->address != address) {
                        hashmap_remove_value(server->bound_leases_by_address, UINT32_TO_PTR(lease->address), lease);
                        lease->address = address;

                        r = hashmap_ensure_put(&server->bound_leases_by_address, NULL, UINT32_TO_PTR(lease->address), lease);
                        if (r < 0)
                                return r;
                }

                lease->expiration = expiration;

                TAKE_PTR(lease);
                return 0;
        }

        /* Otherwise, add a new lease. */

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
                .address = address,
                .client_id = req->client_id,
                .htype = req->message->htype,
                .hlen = req->message->hlen,
                .gateway = req->message->giaddr,
                .expiration = expiration,
        };

        memcpy(lease->chaddr, req->message->chaddr, req->message->hlen);

        if (req->hostname) {
                lease->hostname = strdup(req->hostname);
                if (!lease->hostname)
                        return -ENOMEM;
        }

        r = dhcp_server_put_lease(server, lease, /* is_static = */ false);
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

int dhcp_server_cleanup_expired_leases(sd_dhcp_server *server) {
        sd_dhcp_server_lease *lease;
        usec_t time_now;
        int r;

        assert(server);

        r = sd_event_now(server->event, CLOCK_BOOTTIME, &time_now);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id)
                if (lease->expiration < time_now) {
                        log_dhcp_server(server, "CLEAN (0x%x)", be32toh(lease->address));
                        sd_dhcp_server_lease_unref(lease);
                }

        return 0;
}

sd_dhcp_server_lease* dhcp_server_get_static_lease(sd_dhcp_server *server, const DHCPRequest *req) {
        sd_dhcp_server_lease *static_lease;
        sd_dhcp_client_id client_id;

        assert(server);
        assert(req);

        static_lease = hashmap_get(server->static_leases_by_client_id, &req->client_id);
        if (static_lease)
                goto verify;

        /* when no lease is found based on the client id fall back to chaddr */
        if (!client_id_data_size_is_valid(req->message->hlen))
                return NULL;

        if (sd_dhcp_client_id_set(&client_id, /* type = */ 1, req->message->chaddr, req->message->hlen) < 0)
                return NULL;

        static_lease = hashmap_get(server->static_leases_by_client_id, &client_id);
        if (!static_lease)
                return NULL;

verify:
        /* Check if the address is in the same subnet. */
        if ((static_lease->address & server->netmask) != server->subnet)
                return NULL;

        /* Check if the address is different from the server address. */
        if (static_lease->address == server->address)
                return NULL;

        return static_lease;
}

int sd_dhcp_server_set_static_lease(
                sd_dhcp_server *server,
                const struct in_addr *address,
                uint8_t *client_id_raw,
                size_t client_id_size) {

        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = NULL;
        sd_dhcp_client_id client_id;
        int r;

        assert_return(server, -EINVAL);
        assert_return(client_id_raw, -EINVAL);
        assert_return(client_id_size_is_valid(client_id_size), -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        r = sd_dhcp_client_id_set_raw(&client_id, client_id_raw, client_id_size);
        if (r < 0)
                return r;

        /* Static lease with an empty or omitted address is a valid entry,
         * the server removes any static lease with the specified mac address. */
        if (!address || address->s_addr == 0) {
                sd_dhcp_server_lease_unref(hashmap_get(server->static_leases_by_client_id, &client_id));
                return 0;
        }

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
                .address = address->s_addr,
                .client_id = client_id,
        };

        r = dhcp_server_put_lease(server, lease, /* is_static = */ true);
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}
