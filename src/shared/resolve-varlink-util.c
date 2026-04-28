/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "dns-packet.h"
#include "iovec-util.h"
#include "json-util.h"
#include "resolve-varlink-util.h"

void resolve_error_done(ResolveError *error) {
        if (!error)
                return;

        error->ede_msg = mfree(error->ede_msg);
}

int dispatch_resolve_error(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_error_dispatch_table[] = {
                { "rcode",                _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(ResolveError, rcode),     0 },
                { "extendedDNSErrorCode", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(ResolveError, ede_rcode), 0 },
                { "extendedDNSErrorCode", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolveError, ede_msg),   0 },
                {},
        };
        ResolveError *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_error_done) ResolveError error = {
                .rcode = _DNS_RCODE_INVALID,
                .ede_rcode = _DNS_EDE_RCODE_INVALID,
        };
        r = sd_json_dispatch(variant, resolve_error_dispatch_table, flags | SD_JSON_ALLOW_EXTENSIONS, &error);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(error);
        return 0;
}

static void resolved_address_done(ResolvedAddress *address) {
        if (!address)
                return;

        iovec_done(&address->bytes);
}

static int dispatch_resolved_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_address_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(ResolvedAddress, ifindex),    SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family,   offsetof(ResolvedAddress, family),     SD_JSON_MANDATORY },
                { "address", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_byte_array_iovec, offsetof(ResolvedAddress, bytes),      SD_JSON_MANDATORY },
                {},
        };
        ResolvedAddress *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_address_done) ResolvedAddress address = {};
        r = sd_json_dispatch(variant, resolved_address_dispatch_table, flags & ~SD_JSON_MANDATORY, &address);
        if (r < 0)
                return r;

        if (address.bytes.iov_len != FAMILY_ADDRESS_SIZE_SAFE(address.family))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Dispatched address size (%zu) is incompatible with the family (%s).",
                                address.bytes.iov_len, af_to_ipv4_ipv6(address.family));

        memcpy_safe(&address.in_addr, address.bytes.iov_base, address.bytes.iov_len);

        *ret = TAKE_STRUCT(address);
        return 0;
}

static int dispatch_resolved_address_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveHostnameReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->addresses, reply->n_addresses + 1))
                        return log_oom();

                r = dispatch_resolved_address(name, v, flags, &reply->addresses[reply->n_addresses++]);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedAddress.");
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
                { "addresses", SD_JSON_VARIANT_ARRAY,         dispatch_resolved_address_array, 0,                                     SD_JSON_MANDATORY },
                {},
        };
        ResolveHostnameReply *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_hostname_reply_done) ResolveHostnameReply reply = {};
        r = sd_json_dispatch(variant, resolve_hostname_reply_dispatch_table, flags, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
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

        *ret = TAKE_STRUCT(resolved_name);
        return 0;
}

static int dispatch_resolved_name_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveAddressReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->names, reply->n_names + 1))
                        return log_oom();

                r = dispatch_resolved_name(name, v, flags, &reply->names[reply->n_names++]);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedName.");
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
        int r;

        _cleanup_(resolve_address_reply_done) ResolveAddressReply reply = {};
        r = sd_json_dispatch(variant, resolve_address_reply_dispatch_table, flags, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
}

static void resolved_record_done(ResolvedRecord *record) {
        if (!record)
                return;

        record->raw = mfree(record->raw);
}

static int dispatch_resolved_record(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_record_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,   offsetof(ResolvedRecord, ifindex), SD_JSON_RELAX     },
                { "raw",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolvedRecord, raw),     SD_JSON_MANDATORY },
                { "rr",      _SD_JSON_VARIANT_TYPE_INVALID, NULL,                    0,                                 0                 },
                {},
        };
        ResolvedRecord *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_record_done) ResolvedRecord record = {};
        r = sd_json_dispatch(variant, resolved_record_dispatch_table, flags & ~SD_JSON_MANDATORY, &record);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(record);
        return 0;
}

static int dispatch_resolved_record_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveRecordReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->records, reply->n_records + 1))
                        return log_oom();

                r = dispatch_resolved_record(name, v, flags, &reply->records[reply->n_records++]);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid ResolvedRecord.");
        }

        return 0;
}

void resolve_record_reply_done(ResolveRecordReply *reply) {
        if (!reply)
                return;

        FOREACH_ARRAY(record, reply->records, reply->n_records)
                resolved_record_done(record);
        reply->records = mfree(reply->records);
        reply->n_records = 0;
}

int dispatch_resolve_record_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_record_reply_dispatch_table[] = {
                { "flags", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(ResolveRecordReply, flags),   SD_JSON_MANDATORY },
                { "rrs",   SD_JSON_VARIANT_ARRAY,         dispatch_resolved_record_array, 0,                                     SD_JSON_MANDATORY },
                {},
        };
        ResolveRecordReply *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_record_reply_done) ResolveRecordReply reply = {};
        r = sd_json_dispatch(variant, resolve_record_reply_dispatch_table, flags, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
}
