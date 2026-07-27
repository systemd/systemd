/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "bus-polkit.h"
#include "dns-packet.h"
#include "iovec-util.h"
#include "json-util.h"
#include "netlink-util.h"
#include "resolve-util.h"
#include "resolve-varlink-util.h"
#include "socket-netlink.h"
#include "strv.h"

void resolve_error_done(ResolveError *error) {
        if (!error)
                return;

        error->ede_msg = mfree(error->ede_msg);
        error->query_string = mfree(error->query_string);
        error->result = mfree(error->result);
}

int dispatch_resolve_error(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_error_dispatch_table[] = {
                { "rcode",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(ResolveError, rcode),        0 },
                { "extendedDNSErrorCode",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(ResolveError, ede_rcode),    0 },
                { "extendedDNSErrorMessage", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolveError, ede_msg),      0 },
                { "queryString",             SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolveError, query_string), 0 },
                { "result",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ResolveError, result),       0 },
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

static int dispatch_resolved_address(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_address_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,        offsetof(ResolvedAddress, ifindex), SD_JSON_RELAX     },
                { "family",  _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_address_family, offsetof(ResolvedAddress, family),  SD_JSON_MANDATORY },
                { "address", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_in_addr_data,   offsetof(ResolvedAddress, in_addr), SD_JSON_MANDATORY },
                {},
        };
        ResolvedAddress *ret = ASSERT_PTR(userdata);
        int r;

        ResolvedAddress address = {};
        r = sd_json_dispatch(variant, resolved_address_dispatch_table, flags & ~SD_JSON_MANDATORY, &address);
        if (r < 0)
                return r;

        if (address.family != address.in_addr.family)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "'%s' address and family are inconsistent.", strna(name));

        *ret = TAKE_STRUCT(address);
        return 0;
}

static int dispatch_resolved_address_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveHostnameReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->addresses, reply->n_addresses + 1))
                        return json_log_oom(variant, flags);

                r = dispatch_resolved_address(name, v, flags, &reply->addresses[reply->n_addresses++]);
                if (r < 0)
                        return r;
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
        r = sd_json_dispatch(variant, resolve_hostname_reply_dispatch_table, flags | SD_JSON_ALLOW_EXTENSIONS, &reply);
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
                        return json_log_oom(variant, flags);

                r = dispatch_resolved_name(name, v, flags, &reply->names[reply->n_names++]);
                if (r < 0)
                        return r;
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
        r = sd_json_dispatch(variant, resolve_address_reply_dispatch_table, flags | SD_JSON_ALLOW_EXTENSIONS, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
}

static void resolved_record_done(ResolvedRecord *record) {
        if (!record)
                return;

        iovec_done(&record->raw);
}

static int dispatch_resolved_record(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_record_dispatch_table[] = {
                { "ifindex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,        offsetof(ResolvedRecord, ifindex), SD_JSON_RELAX     },
                { "raw",     _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_unbase64_iovec, offsetof(ResolvedRecord, raw),     SD_JSON_MANDATORY },
                { "rr",      _SD_JSON_VARIANT_TYPE_INVALID, NULL,                         0,                                 0                 },
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
                        return json_log_oom(variant, flags);

                r = dispatch_resolved_record(name, v, flags, &reply->records[reply->n_records++]);
                if (r < 0)
                        return r;
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
                { "flags", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(ResolveRecordReply, flags), SD_JSON_MANDATORY },
                { "rrs",   SD_JSON_VARIANT_ARRAY,         dispatch_resolved_record_array, 0,                                   SD_JSON_MANDATORY },
                {},
        };
        ResolveRecordReply *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_record_reply_done) ResolveRecordReply reply = {};
        r = sd_json_dispatch(variant, resolve_record_reply_dispatch_table, flags | SD_JSON_ALLOW_EXTENSIONS, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
}

static void resolved_service_done(ResolvedService *service) {
        if (!service)
                return;

        service->hostname = mfree(service->hostname);
        service->canonical_name = mfree(service->canonical_name);
        service->addresses = mfree(service->addresses);
        service->n_addresses = 0;
}

static int dispatch_resolved_service_address_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolvedService *service = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(service->addresses, service->n_addresses + 1))
                        return json_log_oom(variant, flags);

                r = dispatch_resolved_address(name, v, flags, &service->addresses[service->n_addresses++]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dispatch_resolved_service(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_service_dispatch_table[] = {
                { "priority",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,                 offsetof(ResolvedService, priority),       SD_JSON_MANDATORY },
                { "weight",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,                 offsetof(ResolvedService, weight),         SD_JSON_MANDATORY },
                { "port",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint16,                 offsetof(ResolvedService, port),           SD_JSON_MANDATORY },
                { "hostname",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,                 offsetof(ResolvedService, hostname),       SD_JSON_MANDATORY },
                { "canonicalName", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,                 offsetof(ResolvedService, canonical_name), SD_JSON_NULLABLE  },
                { "addresses",     SD_JSON_VARIANT_ARRAY,         dispatch_resolved_service_address_array, 0,                                         SD_JSON_NULLABLE  },
                {},
        };
        ResolvedService *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_service_done) ResolvedService service = {};
        r = sd_json_dispatch(variant, resolved_service_dispatch_table, flags & ~SD_JSON_MANDATORY, &service);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(service);
        return 0;
}

static int dispatch_resolved_service_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        ResolveServiceReply *reply = ASSERT_PTR(userdata);
        int r;

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(reply->services, reply->n_services + 1))
                        return json_log_oom(variant, flags);

                r = dispatch_resolved_service(name, v, flags, &reply->services[reply->n_services++]);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void resolved_canonical_done(ResolvedCanonical *canonical) {
        if (!canonical)
                return;

        canonical->name = mfree(canonical->name);
        canonical->type = mfree(canonical->type);
        canonical->domain = mfree(canonical->domain);
}

static int dispatch_resolved_canonical(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolved_canonical_dispatch_table[] = {
                { "name",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(ResolvedCanonical, name),   SD_JSON_NULLABLE  },
                { "type",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(ResolvedCanonical, type),   SD_JSON_MANDATORY },
                { "domain", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(ResolvedCanonical, domain), SD_JSON_MANDATORY },
                {},
        };
        ResolvedCanonical *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolved_canonical_done) ResolvedCanonical canonical = {};
        r = sd_json_dispatch(variant, resolved_canonical_dispatch_table, flags & ~SD_JSON_MANDATORY, &canonical);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(canonical);
        return 0;
}

void resolve_service_reply_done(ResolveServiceReply *reply) {
        if (!reply)
                return;

        FOREACH_ARRAY(service, reply->services, reply->n_services)
                resolved_service_done(service);
        reply->services = mfree(reply->services);
        reply->n_services = 0;
        reply->txt = strv_free(reply->txt);
        resolved_canonical_done(&reply->canonical);
}

int dispatch_resolve_service_reply(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field resolve_service_reply_dispatch_table[] = {
                { "services",  SD_JSON_VARIANT_ARRAY,         dispatch_resolved_service_array, 0,                                        SD_JSON_MANDATORY },
                { "txt",       SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,           offsetof(ResolveServiceReply, txt),       SD_JSON_NULLABLE  },
                { "canonical", SD_JSON_VARIANT_OBJECT,        dispatch_resolved_canonical,     offsetof(ResolveServiceReply, canonical), SD_JSON_MANDATORY },
                { "flags",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,         offsetof(ResolveServiceReply, flags),     SD_JSON_MANDATORY },
                {},
        };
        ResolveServiceReply *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(resolve_service_reply_done) ResolveServiceReply reply = {};
        r = sd_json_dispatch(variant, resolve_service_reply_dispatch_table, flags | SD_JSON_ALLOW_EXTENSIONS, &reply);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(reply);
        return 0;
}

static int dispatch_in_addr_full(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Family",         SD_JSON_VARIANT_INTEGER,       json_dispatch_address_family, offsetof(struct in_addr_full, family),      SD_JSON_MANDATORY },
                { "Address",        SD_JSON_VARIANT_ARRAY,         NULL,                         0,                                          SD_JSON_MANDATORY },
                { "Port",           SD_JSON_VARIANT_UNSIGNED,      sd_json_dispatch_uint16,      offsetof(struct in_addr_full, port),        SD_JSON_NULLABLE  },
                { "ServerName",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,      offsetof(struct in_addr_full, server_name), SD_JSON_NULLABLE  },
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,        offsetof(struct in_addr_full, ifindex),     SD_JSON_RELAX     },
                {},
        };
        struct in_addr_full **ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(in_addr_full_freep) struct in_addr_full *server = new0(struct in_addr_full, 1);
        if (!server)
                return json_log_oom(variant, flags);

        r = sd_json_dispatch(variant, dispatch_table, flags & ~SD_JSON_MANDATORY, server);
        if (r < 0)
                return r;

        struct in_addr_data data = {};
        r = json_dispatch_in_addr_data("Address", sd_json_variant_by_key(variant, "Address"), flags, &data);
        if (r < 0)
                return r;

        if (data.family != server->family)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Address and family are inconsistent.");

        server->address = data.address;
        if (!dns_server_address_valid(server->family, &server->address))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid DNS server address.");

        r = dns_name_is_valid_ldh(server->server_name);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to verify DNS server name: %m");
        if (r == 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid DNS server name.");

        if (IN_SET(server->port, 53, 853))
                server->port = 0;

        *ret = TAKE_PTR(server);
        return 0;
}

static int dispatch_in_addr_full_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        LinkSetDNSParameters *p = ASSERT_PTR(userdata);
        int r;

        if (sd_json_variant_elements(variant) > LINK_DNS_SERVERS_MAX)
                return json_log(variant, flags, SYNTHETIC_ERRNO(E2BIG), "Too many DNS servers for one link.");

        sd_json_variant *v;
        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                if (!GREEDY_REALLOC0(p->servers, p->n_servers + 1))
                        return json_log_oom(variant, flags);

                r = dispatch_in_addr_full(name, v, flags, &p->servers[p->n_servers++]);
                if (r < 0)
                        return r;
        }

        return 0;
}

void link_set_dns_parameters_done(LinkSetDNSParameters *p) {
        if (!p)
                return;

        FOREACH_ARRAY(d, p->servers, p->n_servers)
                in_addr_full_free(*d);
        p->servers = mfree(p->servers);
        p->n_servers = 0;
}

static int ensure_ifindex(int ifindex, const char *ifname, int *ret) {
        int r;

        if (ifindex <= 0 && isempty(ifname))
                return -EINVAL;

        if (ifname) {
                r = rtnl_resolve_interface_or_warn(/* rtnl= */ NULL, ifname);
                if (r < 0)
                        return r;

                if (ifindex != 0 && r != ifindex)
                        return -EINVAL;

                *ret = r;
        } else
                *ret = ifindex;

        return 0;
}

int dispatch_link_set_dns_parameters(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "Servers",        SD_JSON_VARIANT_ARRAY,         dispatch_in_addr_full_array,    0,                                       SD_JSON_MANDATORY },
                { "InterfaceIndex", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_ifindex,          offsetof(LinkSetDNSParameters, ifindex), SD_JSON_RELAX     },
                { "InterfaceName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  offsetof(LinkSetDNSParameters, ifname),  SD_JSON_NULLABLE  },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        LinkSetDNSParameters *ret = ASSERT_PTR(userdata);
        int r;

        _cleanup_(link_set_dns_parameters_done) LinkSetDNSParameters p = {};
        r = sd_json_dispatch(variant, dispatch_table, flags, &p);
        if (r < 0)
                return r;

        int ifindex;
        r = ensure_ifindex(p.ifindex, p.ifname, &ifindex);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to verify interface index: %m");
        p.ifindex = ifindex;

        FOREACH_ARRAY(s, p.servers, p.n_servers)
                if ((*s)->ifindex != 0 && (*s)->ifindex != p.ifindex)
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Invalid DNS server interface index.");

        *ret = TAKE_STRUCT(p);
        return 0;
}
