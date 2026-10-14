/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-request.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
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

int dhcp_server_set_lease(sd_dhcp_server *server, DHCPRequest *req) {
        int r;

        assert(server);
        assert(req);
        assert(req->message);
        assert(req->address != INADDR_ANY);

        usec_t expiration;
        r = dhcp_request_get_lifetime_timestamp(req, CLOCK_BOOTTIME, &expiration);
        if (r < 0)
                return r;

        /* If a bound lease for the static address with another client ID exists, it was acquired by the same
         * host before it changed its client ID. Drop it, as the address is now assigned with the new client
         * ID. */
        if (req->static_lease) {
                sd_dhcp_server_lease *old;

                if (dhcp_server_get_bound_lease(server, req, req->address, &old) > 0 &&
                    !client_id_equal(&old->client_id, &req->client_id))
                        sd_dhcp_server_lease_unref(old);
        }

        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease =
                hashmap_get(server->bound_leases_by_client_id, &req->client_id);
        if (lease) {
                /* If a lease for the host already exists, update it. */
                if (lease->address != req->address) {
                        hashmap_remove_value(server->bound_leases_by_address, UINT32_TO_PTR(lease->address), lease);
                        lease->address = req->address;

                        r = hashmap_ensure_put(&server->bound_leases_by_address, NULL, UINT32_TO_PTR(lease->address), lease);
                        if (r < 0)
                                return r;
                }

                lease->htype = req->message->header.htype;
                lease->hw_addr = req->hw_addr;
                lease->gateway = req->message->header.giaddr;
                lease->expiration = expiration;
        } else {
                /* Otherwise, add a new lease. */
                lease = new(sd_dhcp_server_lease, 1);
                if (!lease)
                        return -ENOMEM;

                *lease = (sd_dhcp_server_lease) {
                        .n_ref = 1,
                        .client_id = req->client_id,
                        .htype = req->message->header.htype,
                        .hw_addr = req->hw_addr,
                        .address = req->address,
                        .gateway = req->message->header.giaddr,
                        .expiration = expiration,
                };

                r = dhcp_server_put_lease(server, lease, /* is_static= */ false);
                if (r < 0)
                        return r;
        }

        char *hostname = NULL;
        (void) dhcp_message_get_option_hostname(req->message, &hostname);
        free_and_replace(lease->hostname, hostname);

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

        assert(server);
        assert(req);

        static_lease = hashmap_get(server->static_leases_by_client_id, &req->client_id);
        if (!static_lease && sd_dhcp_client_id_is_set(&req->client_id_by_header))
                /* when no lease is found, fall back to use the fake client ID generated from the header. */
                static_lease = hashmap_get(server->static_leases_by_client_id, &req->client_id_by_header);
        if (!static_lease)
                return NULL;

        /* Check if the address is in the same subnet. */
        if ((static_lease->address & server->netmask) != server->subnet)
                return NULL;

        /* Check if the address is different from the server address. */
        if (static_lease->address == server->address)
                return NULL;

        return static_lease;
}

/* An address of a static lease is never assigned from the pool, hence a bound lease for the address can only
 * be acquired by the host the static lease is configured for. When the host changes its client ID, e.g. when
 * it is dual-booted or its DHCP client is reconfigured to send a DUID, the bound lease still has the old
 * client ID. This checks if the bound lease was acquired by the host that sent the request. Hosts sharing a
 * hardware address that send different node-specific client IDs, e.g. ipvlan L2 children, are considered
 * as different hosts. */
static bool dhcp_server_lease_is_same_host(const sd_dhcp_server_lease *lease, const DHCPRequest *req) {
        assert(lease);
        assert(req);
        assert(req->message);

        if (sd_dhcp_client_id_is_set(&req->client_id) &&
            client_id_equal(&lease->client_id, &req->client_id))
                return true;

        /* The remaining cases need the client ID generated from the hardware address in the request. */
        if (!sd_dhcp_client_id_is_set(&req->client_id_by_header))
                return false;

        /* The lease was acquired with the client ID generated from the hardware address of this host, e.g.
         * by dhclient without -i, or by a client that did not send the Client Identifier option. Now the
         * host sends another client ID, e.g. a DUID. */
        if (client_id_equal(&lease->client_id, &req->client_id_by_header))
                return true;

        /* The other way around: the lease was acquired with another client ID, e.g. a DUID sent by
         * systemd-networkd, and now the request does not identify the host more precisely than its hardware
         * address, hence compare the hardware addresses. That is, the request either does not have the
         * Client Identifier option, in which case req->client_id is set to the client ID generated from the
         * hardware address, or has the option with the client ID generated from the hardware address, e.g.
         * sent by Windows in a dual-boot setup. */
        if (!client_id_equal(&req->client_id, &req->client_id_by_header))
                return false;

        if (hw_addr_is_null(&req->hw_addr))
                return false;

        return lease->htype == req->message->header.htype && hw_addr_equal(&lease->hw_addr, &req->hw_addr);
}

/* Returns 1 and the lease bound to the address when it is acquired by the host that sent the request,
 * 0 when the address is not assigned to any host, and -EADDRINUSE when the address is already assigned to
 * another host. */
int dhcp_server_get_bound_lease(
                sd_dhcp_server *server,
                const DHCPRequest *req,
                be32_t address,
                sd_dhcp_server_lease **ret) {

        sd_dhcp_server_lease *lease, *static_lease;

        assert(server);
        assert(req);

        lease = hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(address));
        if (!lease) {
                if (ret)
                        *ret = NULL;
                return 0;
        }

        if (!client_id_equal(&lease->client_id, &req->client_id)) {
                /* The lease has another client ID. It is still acquired by the host, if the address is the
                 * static address of the host, and the host changed its client ID. */
                static_lease = dhcp_server_get_static_lease(server, req);
                if (!static_lease || static_lease->address != address ||
                    !dhcp_server_lease_is_same_host(lease, req))
                        return -EADDRINUSE;
        }

        if (ret)
                *ret = lease;
        return 1;
}

int sd_dhcp_server_set_static_lease(
                sd_dhcp_server *server,
                const struct in_addr *address,
                uint8_t *client_id_raw,
                size_t client_id_size,
                const char *hostname) {

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

        if (hostname) {
                r = dns_name_is_valid_ldh(hostname);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,
                .address = address->s_addr,
                .client_id = client_id,
        };

        if (hostname) {
                lease->hostname = strdup(hostname);
                if (!lease->hostname)
                        return -ENOMEM;
        }

        r = dhcp_server_put_lease(server, lease, /* is_static= */ true);
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

static int dhcp_server_lease_build_json(sd_dhcp_server_lease *lease, sd_json_variant **ret) {
        assert(lease);
        assert(ret);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_BYTE_ARRAY("ClientId", lease->client_id.raw, lease->client_id.size),
                        JSON_BUILD_PAIR_IN4_ADDR_WITH_STRING_NON_NULL("Address", &(struct in_addr) { .s_addr = lease->address }),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("Hostname", lease->hostname),
                        SD_JSON_BUILD_PAIR_UNSIGNED("HardwareAddressType", lease->htype),
                        SD_JSON_BUILD_PAIR_UNSIGNED("HardwareAddressLength", lease->hw_addr.length),
                        SD_JSON_BUILD_PAIR_BYTE_ARRAY("HardwareAddress", lease->hw_addr.bytes, lease->hw_addr.length));
}

int dhcp_server_bound_leases_append_json(sd_dhcp_server *server, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
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
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                r = dhcp_server_lease_build_json(lease, &w);
                if (r < 0)
                        return r;

                usec_t exp_r = map_clock_usec_raw(lease->expiration, now_b, now_r);

                r = sd_json_variant_merge_objectbo(
                                &w,
                                SD_JSON_BUILD_PAIR_UNSIGNED("ExpirationUSec", lease->expiration),
                                SD_JSON_BUILD_PAIR_UNSIGNED("ExpirationRealtimeUSec", exp_r));
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&array, w);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "Leases", array);
}

int dhcp_server_static_leases_append_json(sd_dhcp_server *server, sd_json_variant **v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        sd_dhcp_server_lease *lease;
        int r;

        assert(server);
        assert(v);

        HASHMAP_FOREACH(lease, server->static_leases_by_client_id) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                r = dhcp_server_lease_build_json(lease, &w);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&array, w);
                if (r < 0)
                        return r;
        }

        return json_variant_set_field_non_null(v, "StaticLeases", array);
}

int dhcp_server_save_leases(sd_dhcp_server *server) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
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

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_ID128("BootID", boot_id),
                        JSON_BUILD_PAIR_IN4_ADDR("Address", &(struct in_addr) { .s_addr = server->address }),
                        SD_JSON_BUILD_PAIR_UNSIGNED("PrefixLength",
                                                    in4_addr_netmask_to_prefixlen(&(struct in_addr) { .s_addr = server->netmask })));
        if (r < 0)
                return r;

        r = dhcp_server_bound_leases_append_json(server, &v);
        if (r < 0)
                return r;

        r = mkdirat_parents(server->lease_dir_fd, server->lease_file, 0755);
        if (r < 0)
                return r;

        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        r = fopen_temporary_at(server->lease_dir_fd, server->lease_file, &f, &temp_path);
        if (r < 0)
                return r;

        CLEANUP_TMPFILE_AT(server->lease_dir_fd, temp_path);

        (void) fchmod(fileno(f), 0644);

        r = sd_json_variant_dump(v, SD_JSON_FORMAT_NEWLINE | SD_JSON_FORMAT_FLUSH, f, /* prefix= */ NULL);
        if (r < 0)
                return r;

        r = conservative_renameat(server->lease_dir_fd, temp_path, server->lease_dir_fd, server->lease_file);
        if (r < 0)
                return r;

        temp_path = mfree(temp_path); /* disarm CLEANUP_TMPFILE_AT() */
        return 0;
}

typedef struct LeaseParam {
        sd_dhcp_client_id client_id;
        uint8_t htype;
        uint8_t hlen;
        struct iovec hw_addr;
        struct in_addr address;
        usec_t exp_b;
        usec_t exp_r;
        char *hostname;
} LeaseParam;

static void lease_param_done(LeaseParam *p) {
        assert(p);

        iovec_done(&p->hw_addr);
        free(p->hostname);
}

static int json_dispatch_dhcp_lease(sd_dhcp_server *server, sd_json_variant *v, bool use_boottime) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ClientId",               SD_JSON_VARIANT_ARRAY,         json_dispatch_client_id,        offsetof(LeaseParam, client_id),  SD_JSON_MANDATORY },
                { "HardwareAddressType",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,         offsetof(LeaseParam, htype),      0                 },
                { "HardwareAddressLength",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,         offsetof(LeaseParam, hlen),       0                 },
                { "HardwareAddress",        SD_JSON_VARIANT_ARRAY,         json_dispatch_byte_array_iovec, offsetof(LeaseParam, hw_addr),    0                 },
                { "Address",                SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,          offsetof(LeaseParam, address),    SD_JSON_MANDATORY },
                { "AddressString",          SD_JSON_VARIANT_STRING,        NULL,                           0,                                0                 },
                { "ExpirationUSec",         _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(LeaseParam, exp_b),      SD_JSON_MANDATORY },
                { "ExpirationRealtimeUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(LeaseParam, exp_r),      SD_JSON_MANDATORY },
                { "Hostname",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        offsetof(LeaseParam, hostname),   0                 },
                {}
        };

        int r;

        assert(server);
        assert(v);

        _cleanup_(lease_param_done) LeaseParam p = {};
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return r;

        if (p.hlen > HW_ADDR_MAX_SIZE)
                return -EINVAL;

        if (p.hlen > p.hw_addr.iov_len)
                return -EINVAL;

        if (!in4_addr_is_set(&p.address))
                return -EINVAL;

        if (!sd_dhcp_client_id_is_set(&p.client_id))
                return -EINVAL;

        usec_t now_b;
        r = sd_event_now(server->event, CLOCK_BOOTTIME, &now_b);
        if (r < 0)
                return r;

        if (use_boottime) {
                if (p.exp_b < now_b)
                        return 0; /* already expired */
        } else {
                usec_t now_r;

                r = sd_event_now(server->event, CLOCK_REALTIME, &now_r);
                if (r < 0)
                        return r;

                if (p.exp_r < now_r)
                        return 0; /* already expired */

                p.exp_b = map_clock_usec_raw(p.exp_r, now_r, now_b);
        }

        _cleanup_(sd_dhcp_server_lease_unrefp) sd_dhcp_server_lease *lease = new(sd_dhcp_server_lease, 1);
        if (!lease)
                return -ENOMEM;

        *lease = (sd_dhcp_server_lease) {
                .n_ref = 1,

                .client_id = p.client_id,
                .htype = p.htype,
                .hw_addr.length = p.hlen,
                .address = p.address.s_addr,
                .expiration = p.exp_b,
                .hostname = TAKE_PTR(p.hostname),
        };

        memcpy_safe(lease->hw_addr.bytes, p.hw_addr.iov_base, p.hlen);

        r = dhcp_server_put_lease(server, lease, /* is_static= */ false);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        TAKE_PTR(lease);
        return 0;
}

typedef struct SavedInfo {
        sd_id128_t boot_id;
        struct in_addr address;
        uint8_t prefixlen;
        sd_json_variant *leases;
} SavedInfo;

static void saved_info_done(SavedInfo *info) {
        if (!info)
                return;

        sd_json_variant_unref(info->leases);
}

static int load_leases_file(int dir_fd, const char *path, SavedInfo *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);
        assert(ret);

        r = sd_json_parse_file_at(
                        /* f= */ NULL,
                        dir_fd,
                        path,
                        /* flags= */ SD_JSON_PARSE_MUST_BE_OBJECT,
                        &v,
                        /* reterr_line= */ NULL,
                        /* ret_column= */ NULL);
        if (r < 0)
                return r;

        static const sd_json_dispatch_field dispatch_lease_file_table[] = {
                { "BootID",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,   offsetof(SavedInfo, boot_id),   SD_JSON_MANDATORY },
                { "Address",      SD_JSON_VARIANT_ARRAY,         json_dispatch_in_addr,    offsetof(SavedInfo, address),   SD_JSON_MANDATORY },
                { "PrefixLength", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint8,   offsetof(SavedInfo, prefixlen), SD_JSON_MANDATORY },
                { "Leases",       SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant, offsetof(SavedInfo, leases),    SD_JSON_MANDATORY },
                {}
        };

        return sd_json_dispatch(v, dispatch_lease_file_table, SD_JSON_ALLOW_EXTENSIONS, ret);
}

int dhcp_server_load_leases(sd_dhcp_server *server) {
        _cleanup_(saved_info_done) SavedInfo info = {};
        sd_id128_t boot_id;
        size_t n, m;
        int r;

        assert(server);
        assert(server->event);

        if (!server->lease_file)
                return 0;

        r = load_leases_file(server->lease_dir_fd, server->lease_file, &info);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        n = hashmap_size(server->bound_leases_by_client_id);

        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, info.leases)
                RET_GATHER(r, json_dispatch_dhcp_lease(server, i, /* use_boottime= */ sd_id128_equal(info.boot_id, boot_id)));

        m = hashmap_size(server->bound_leases_by_client_id);
        assert(m >= n);
        log_dhcp_server(server, "Loaded %zu lease(s) from %s.", m - n, server->lease_file);

        return r;
}

int dhcp_server_leases_file_get_server_address(
                int dir_fd,
                const char *path,
                struct in_addr *ret_address,
                uint8_t *ret_prefixlen) {

        _cleanup_(saved_info_done) SavedInfo info = {};
        int r;

        if (!ret_address && !ret_prefixlen)
                return 0;

        r = load_leases_file(dir_fd, path, &info);
        if (r < 0)
                return r;

        if (ret_address)
                *ret_address = info.address;
        if (ret_prefixlen)
                *ret_prefixlen = info.prefixlen;
        return 0;
}
