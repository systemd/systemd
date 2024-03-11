/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-server-lease-internal.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
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

static int dhcp_server_lease_append_json(sd_dhcp_server_lease *lease, JsonVariant **ret) {
        assert(lease);
        assert(ret);

        return json_build(ret,
                        JSON_BUILD_OBJECT(
                                 JSON_BUILD_PAIR_BYTE_ARRAY("ClientId", lease->client_id.raw, lease->client_id.size),
                                 JSON_BUILD_PAIR_IN4_ADDR_NON_NULL("Address", &(struct in_addr) { .s_addr = lease->address }),
                                 JSON_BUILD_PAIR_STRING_NON_EMPTY("Hostname", lease->hostname)));
}

int dhcp_server_bound_leases_append_json(sd_dhcp_server *server, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        sd_dhcp_server_lease *lease;
        usec_t now_b, now_r;
        int r;

        assert(server);
        assert(v);

        r = sd_event_now(server->event, CLOCK_BOOTTIME, &now_b);
        if (r < 0)
                return r;

        r = sd_event_now(server->event, CLOCK_REALTIME, &now_r);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id) {
                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

                r = dhcp_server_lease_append_json(lease, &w);
                if (r < 0)
                        return r;

                usec_t exp_r = map_clock_usec_raw(lease->expiration, now_b, now_r);

                r = json_variant_merge_objectb(&w,
                                 JSON_BUILD_OBJECT(
                                         JSON_BUILD_PAIR_UNSIGNED("ExpirationUSec", lease->expiration),
                                         JSON_BUILD_PAIR_UNSIGNED("ExpirationRealtimeUSec", exp_r)));
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, w);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Leases", array);
}

int dhcp_server_static_leases_append_json(sd_dhcp_server *server, JsonVariant **v) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        sd_dhcp_server_lease *lease;
        int r;

        assert(server);
        assert(v);

        HASHMAP_FOREACH(lease, server->static_leases_by_client_id) {
                _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;

                r = dhcp_server_lease_append_json(lease, &w);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, w);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "StaticLeases", array);
}

int dhcp_server_save_leases(sd_dhcp_server *server) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sd_id128_t boot_id;
        int r;

        assert(server);

        if (!server->lease_file)
                return 0;

        if (hashmap_isempty(server->bound_leases_by_client_id)) {
                if (unlink(server->lease_file) < 0 && errno != ENOENT)
                        return -errno;

                return 0;
        }

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        r = json_build(&v, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_ID128("BootID", boot_id)));
        if (r < 0)
                return r;

        r = dhcp_server_bound_leases_append_json(server, &v);
        if (r < 0)
                return r;

        r = mkdir_parents(server->lease_file, 0755);
        if (r < 0)
                return r;

        r = fopen_temporary(server->lease_file, &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        r = json_variant_dump(v, JSON_FORMAT_NEWLINE | JSON_FORMAT_FLUSH, f, /* prefix = */ NULL);
        if (r < 0)
                return r;

        r = conservative_rename(temp_path, server->lease_file);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path);
        return 0;
}

static int json_dispatch_dhcp_lease(sd_dhcp_server *server, JsonVariant *v, bool use_boottime) {
        static const JsonDispatch dispatch_table_boottime[] = {
                { "ClientId",               JSON_VARIANT_ARRAY,         json_dispatch_client_id, offsetof(sd_dhcp_server_lease, client_id),  JSON_MANDATORY },
                { "Address",                JSON_VARIANT_ARRAY,         json_dispatch_in_addr,   offsetof(sd_dhcp_server_lease, address),    JSON_MANDATORY },
                { "Hostname",               JSON_VARIANT_STRING,        json_dispatch_string,    offsetof(sd_dhcp_server_lease, hostname),   0              },
                { "ExpirationUSec",         _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,    offsetof(sd_dhcp_server_lease, expiration), JSON_MANDATORY },
                { "ExpirationRealtimeUSec", _JSON_VARIANT_TYPE_INVALID, NULL,                    0,                                          JSON_MANDATORY },
                {}
        }, dispatch_table_realtime[] = {
                { "ClientId",               JSON_VARIANT_ARRAY,         json_dispatch_client_id, offsetof(sd_dhcp_server_lease, client_id),  JSON_MANDATORY },
                { "Address",                JSON_VARIANT_ARRAY,         json_dispatch_in_addr,   offsetof(sd_dhcp_server_lease, address),    JSON_MANDATORY },
                { "Hostname",               JSON_VARIANT_STRING,        json_dispatch_string,    offsetof(sd_dhcp_server_lease, hostname),   0              },
                { "ExpirationUSec",         _JSON_VARIANT_TYPE_INVALID, NULL,                    0,                                          JSON_MANDATORY },
                { "ExpirationRealtimeUSec", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,    offsetof(sd_dhcp_server_lease, expiration), JSON_MANDATORY },
                {}
        };

        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = NULL;
        usec_t now_b;
        int r;

        assert(server);
        assert(v);

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
        };

        r = json_dispatch(v, use_boottime ? dispatch_table_boottime : dispatch_table_realtime, JSON_ALLOW_EXTENSIONS, lease);
        if (r < 0)
                return r;

        r = sd_event_now(server->event, CLOCK_BOOTTIME, &now_b);
        if (r < 0)
                return r;

        if (use_boottime) {
                if (lease->expiration < now_b)
                        return 0; /* already expired */
        } else {
                usec_t now_r;

                r = sd_event_now(server->event, CLOCK_REALTIME, &now_r);
                if (r < 0)
                        return r;

                if (lease->expiration < now_r)
                        return 0; /* already expired */

                lease->expiration = map_clock_usec_raw(lease->expiration, now_r, now_b);
        }

        r = dhcp_server_put_lease(server, lease, /* is_static = */ false);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

typedef struct SavedInfo {
        sd_id128_t boot_id;
        JsonVariant *leases;
} SavedInfo;

static int dhcp_server_dispatch_leases(sd_dhcp_server *server, JsonVariant *v) {
        static const JsonDispatch dispatch_table[] = {
                { "BootID", JSON_VARIANT_STRING, json_dispatch_id128,         offsetof(SavedInfo, boot_id), JSON_MANDATORY },
                { "Leases", JSON_VARIANT_ARRAY,  json_dispatch_variant_noref, offsetof(SavedInfo, leases),  JSON_MANDATORY },
                {}
        };

        SavedInfo info = {};
        sd_id128_t boot_id;
        int r;

        r = json_dispatch(v, dispatch_table, JSON_ALLOW_EXTENSIONS, &info);
        if (r < 0)
                return r;

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        JsonVariant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, info.leases)
                RET_GATHER(r, json_dispatch_dhcp_lease(server, i, /* use_boottime = */ sd_id128_equal(info.boot_id, boot_id)));

        return r;
}

int dhcp_server_load_leases(sd_dhcp_server *server) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        size_t n, m;
        int r;

        assert(server);
        assert(server->event);

        if (!server->lease_file)
                return 0;

        r = json_parse_file(
                        /* f = */ NULL,
                        server->lease_file,
                        /* flags = */ 0,
                        &v,
                        /* ret_line = */ NULL,
                        /* ret_column = */ NULL);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        n = hashmap_size(server->bound_leases_by_client_id);

        r = dhcp_server_dispatch_leases(server, v);

        m = hashmap_size(server->bound_leases_by_client_id);
        assert(m >= n);
        log_dhcp_server(server, "Loaded %zu lease(s) from %s.", m - n, server->lease_file);

        return r;
}
