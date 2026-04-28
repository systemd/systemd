/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "iovec-util.h"
#include "json-util.h"
#include "resolve-varlink-util.h"

static int dispatch_resolved_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_address_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(ResolvedAddress, ifindex), SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,   offsetof(ResolvedAddress, family),  SD_JSON_MANDATORY },
                { "address", _SD_JSON_VARIANT_TYPE_INVALID, NULL,                           0,                                  0                 },
                {},
        };
        ResolvedAddress *ret = ASSERT_PTR(userdata);
        int r;

        ResolvedAddress address = {};
        r = sd_json_dispatch(variant, resolved_address_dispatch_table, flags & ~SD_JSON_MANDATORY, &address);
        if (r < 0)
                return r;

        sd_json_variant *v = sd_json_variant_by_key(variant, "address");
        if (!v)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "resolved address is missing 'address' field");

        _cleanup_(iovec_done) struct iovec bytes = {};
        r = json_dispatch_byte_array_iovec("address", v, flags, &bytes);
        if (r < 0)
                return r;

        if (bytes.iov_len != FAMILY_ADDRESS_SIZE_SAFE(address.family))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Dispatched address size (%zu) is incompatible with the family (%s).",
                                bytes.iov_len, af_to_ipv4_ipv6(address.family));

        ret->ifindex = address.ifindex;
        ret->family = address.family;
        memcpy_safe(&ret->in_addr, bytes.iov_base, bytes.iov_len);

        return 0;
}

static int dispatch_resolved_address_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveHostnameReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->addresses, reply->n_addresses + 1))
                        return log_oom();

                r = dispatch_resolved_address(name, v, flags, &reply->addresses[reply->n_addresses]);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedAddress.");

                reply->n_addresses++;
        }

        return 0;
}

void resolve_hostname_reply_done(ResolveHostnameReply *reply) {
        if (!reply)
                return;

        reply->name = mfree(reply->name);
        reply->addresses = mfree(reply->addresses);
        reply->n_addresses = 0;
}

int dispatch_resolve_hostname_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_hostname_reply_dispatch_table[] = {
                { "name",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,         offsetof(ResolveHostnameReply, name),  SD_JSON_MANDATORY },
                { "flags",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,         offsetof(ResolveHostnameReply, flags), SD_JSON_MANDATORY },
                { "addresses", SD_JSON_VARIANT_ARRAY,         dispatch_resolved_address_array, 0                                    , SD_JSON_MANDATORY },
                {},
        };
        ResolveHostnameReply *ret = ASSERT_PTR(userdata);

        return sd_json_dispatch(variant, resolve_hostname_reply_dispatch_table, flags, ret);
}

static void resolved_name_done(ResolvedName *name) {
        if (!name)
                return;

        name->name = mfree(name->name);
}

static int dispatch_resolved_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_name_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(ResolvedName, ifindex), SD_JSON_RELAX     },
                { "name",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolvedName, name),    SD_JSON_MANDATORY },
                {},
        };
        ResolvedName *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_name_done) ResolvedName resolved_name = {};
        r = sd_json_dispatch(variant, resolved_name_dispatch_table, flags & ~SD_JSON_MANDATORY, &resolved_name);
        if (r < 0)
                return r;

        ret->ifindex = resolved_name.ifindex;
        r = free_and_strdup(&ret->name, resolved_name.name);
        if (r < 0)
                return log_oom();

        return 0;
}

static int dispatch_resolved_name_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveAddressReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->names, reply->n_names + 1))
                        return log_oom();

                r = dispatch_resolved_name(name, v, flags, &reply->names[reply->n_names]);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedName.");

                reply->n_names++;
        }

        return 0;
}

void resolve_address_reply_done(ResolveAddressReply *reply) {
        if (!reply)
                return;

        FOREACH_ARRAY(n, reply->names, reply->n_names)
                resolved_name_done(n);
        reply->names = mfree(reply->names);
        reply->n_names = 0;
}

int dispatch_resolve_address_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_address_reply_dispatch_table[] = {
                { "flags", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,      offsetof(ResolveAddressReply, flags), SD_JSON_MANDATORY },
                { "names", SD_JSON_VARIANT_ARRAY,         dispatch_resolved_name_array, 0,                                    SD_JSON_MANDATORY },
                {},
        };
        ResolveAddressReply *ret = ASSERT_PTR(userdata);

        return sd_json_dispatch(variant, resolve_address_reply_dispatch_table, flags, ret);
}
