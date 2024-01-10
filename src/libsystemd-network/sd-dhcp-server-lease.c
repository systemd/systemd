/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-server-lease-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "path-util.h"
#include "tmpfile-util.h"

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

int dhcp_server_save_leases(sd_dhcp_server *server, const char *path) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(server);
        assert(path);

        if (!path_is_safe(path))
                return -EINVAL;

        r = dhcp_server_bound_leases_build_json(server, &v);
        if (r < 0)
                return r;

        if (!v) {
                if (unlink(path) < 0 && errno != -ENOENT)
                        return -errno;

                return 0;
        }

        r = fopen_temporary(path, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        r = json_variant_dump(v, JSON_FORMAT_NEWLINE | JSON_FORMAT_FLUSH, f, /* prefix = */ NULL);
        if (r < 0)
                return r;

        r = conservative_rename(temp_path, path);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path);
        return 0;
}

static int json_dispatch_client_id(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        sd_dhcp_client_id *client_id = ASSERT_PTR(userdata);
        return json_dispatch_byte_array(name, variant, flags, client_id->raw, MIN_CLIENT_ID_LEN, MAX_CLIENT_ID_LEN, &client_id->size);
}

static int json_dispatch_address(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        be32_t *address = ASSERT_PTR(userdata);
        union in_addr_union u;
        int r;

        r = json_dispatch_byte_array(name, variant, flags, u.bytes, sizeof(be32_t), sizeof(be32_t), NULL);
        if (r < 0)
                return r;

        *address = u.in.s_addr;
        return 0;
}

static int json_dispatch_dhcp_lease(sd_dhcp_server *server, JsonVariant *v) {
        static const JsonDispatch dispatch_table[] = {
                { "ClientId",        JSON_VARIANT_ARRAY,         json_dispatch_client_id, offsetof(sd_dhcp_server_lease, client_id),  JSON_MANDATORY },
                { "Address",         JSON_VARIANT_ARRAY,         json_dispatch_address,   offsetof(sd_dhcp_server_lease, address),    JSON_MANDATORY },
                { "Hostname",        JSON_VARIANT_STRING,        json_dispatch_string,    offsetof(sd_dhcp_server_lease, hostname),   0              },
                { "ExpirationUSec",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,    offsetof(sd_dhcp_server_lease, expiration), 0              },
                {}
        };

        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = NULL;
        int r;

        assert(server);
        assert(v);

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
        };

        r = json_dispatch(v, dispatch_table, /* flags = */ 0, lease);
        if (r < 0)
                return r;

        r = dhcp_server_put_lease(server, lease, /* is_static = */ false);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 1;
}

int dhcp_server_load_leases(sd_dhcp_server *server, const char *path) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        int r;

        assert(server);
        assert(path);

        if (!path_is_safe(path))
                return -EINVAL;

        r = json_parse_file(
                        /* f = */ NULL,
                        path,
                        /* flags = */ 0,
                        &v,
                        /* ret_line = */ NULL,
                        /* ret_column = */ NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        r = 0;
        JsonVariant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, v)
                RET_GATHER(r, json_dispatch_dhcp_lease(server, i));

        return r;
}
