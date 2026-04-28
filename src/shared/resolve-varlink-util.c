/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "alloc-util.h"
#include "hash-funcs.h"
#include "iovec-util.h"
#include "json-util.h"
#include "ordered-set.h"
#include "resolve-varlink-util.h"

ResolvedAddress* resolved_address_free(ResolvedAddress *address) {
        if (!address)
                return NULL;

        return mfree(address);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        resolved_address_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        ResolvedAddress,
        resolved_address_free);

static int dispatch_resolved_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_address_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(ResolvedAddress, ifindex), SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,   offsetof(ResolvedAddress, family),  SD_JSON_MANDATORY },
                { "address", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                           0,                                  0                 },
                {},
        };
        ResolvedAddress **ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_address_freep) ResolvedAddress *address = new0(ResolvedAddress, 1);
        if (!address)
                return log_oom();

        r = sd_json_dispatch(variant, resolved_address_dispatch_table, flags & ~SD_JSON_MANDATORY, address);
        if (r < 0)
                return r;

        sd_json_variant *v = sd_json_variant_by_key(variant, "address");
        if (!v)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "resolved address is missing 'address' field");

        _cleanup_(iovec_done) struct iovec bytes = {};
        r = json_dispatch_byte_array_iovec("address", v, flags, &bytes);
        if (r < 0)
                return r;

        if (bytes.iov_len != FAMILY_ADDRESS_SIZE_SAFE(address->family))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Dispatched address size (%zu) is incompatible with the family (%s).",
                                bytes.iov_len, af_to_ipv4_ipv6(address->family));
        memcpy_safe(&address->in_addr, bytes.iov_base, bytes.iov_len);

        *ret = TAKE_PTR(address);

        return 0;
}

static int dispatch_resolved_address_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        OrderedSet **ret = ASSERT_PTR(userdata);
        _cleanup_ordered_set_free_ OrderedSet *resolved_addresses = NULL;
        sd_json_variant *v;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(resolved_address_freep) ResolvedAddress *address = NULL;

                r = dispatch_resolved_address(name, v, flags, &address);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedAddress.");

                r = ordered_set_ensure_put(&resolved_addresses, &resolved_address_hash_ops, address);
                if (r < 0)
                        return r;
                TAKE_PTR(address);
        }

        free_and_replace_full(*ret, resolved_addresses, ordered_set_free);

        return 0;
}

ResolveHostnameReply* resolve_hostname_reply_free(ResolveHostnameReply *reply) {
        if (!reply)
                return NULL;

        free(reply->name);
        ordered_set_free(reply->addresses);

        return mfree(reply);
}

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_hostname_reply_dispatch_table[] = {
                { "name",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,         offsetof(ResolveHostnameReply, name),      SD_JSON_MANDATORY },
                { "flags",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,         offsetof(ResolveHostnameReply, flags),     SD_JSON_MANDATORY },
                { "addresses", SD_JSON_VARIANT_ARRAY,         dispatch_resolved_address_array, offsetof(ResolveHostnameReply, addresses), SD_JSON_MANDATORY },
                {},
        };
        ResolveHostnameReply **ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_hostname_reply_freep) ResolveHostnameReply *reply = new0(ResolveHostnameReply, 1);
        if (!reply)
                return log_oom();

        r = sd_json_dispatch(variant, resolve_hostname_reply_dispatch_table, flags, reply);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(reply);

        return 0;
}

ResolvedName* resolved_name_free(ResolvedName *name) {
        if (!name)
                return NULL;

        free(name->name);

        return mfree(name);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        resolved_name_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        ResolvedName,
        resolved_name_free);

static int dispatch_resolved_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_name_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(ResolvedName, ifindex), SD_JSON_RELAX     },
                { "name",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolvedName, name),    SD_JSON_MANDATORY },
                {},
        };
        ResolvedName **ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_name_freep) ResolvedName *resolved_name = new0(ResolvedName, 1);
        if (!resolved_name)
                return log_oom();

        r = sd_json_dispatch(variant, resolved_name_dispatch_table, flags & ~SD_JSON_MANDATORY, resolved_name);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(resolved_name);

        return 0;
}

static int dispatch_resolved_name_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        OrderedSet **ret = ASSERT_PTR(userdata);
        _cleanup_ordered_set_free_ OrderedSet *resolved_names = NULL;
        sd_json_variant *v;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(resolved_name_freep) ResolvedName *resolved_name = NULL;

                r = dispatch_resolved_name(name, v, flags, &resolved_name);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedName.");

                r = ordered_set_ensure_put(&resolved_names, &resolved_name_hash_ops, resolved_name);
                if (r < 0)
                        return r;
                TAKE_PTR(resolved_name);
        }

        free_and_replace_full(*ret, resolved_names, ordered_set_free);

        return 0;
}

ResolveAddressReply* resolve_address_reply_free(ResolveAddressReply *reply) {
        if (!reply)
                return NULL;

        ordered_set_free(reply->names);

        return mfree(reply);
}

int dispatch_resolve_address_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_address_reply_dispatch_table[] = {
                { "flags", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,      offsetof(ResolveAddressReply, flags), SD_JSON_MANDATORY },
                { "names", SD_JSON_VARIANT_ARRAY,         dispatch_resolved_name_array, offsetof(ResolveAddressReply, names), SD_JSON_MANDATORY },
                {},
        };
        ResolveAddressReply **ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_address_reply_freep) ResolveAddressReply *reply = new0(ResolveAddressReply, 1);
        if (!reply)
                return log_oom();

        r = sd_json_dispatch(variant, resolve_address_reply_dispatch_table, flags, reply);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(reply);

        return 0;
}
