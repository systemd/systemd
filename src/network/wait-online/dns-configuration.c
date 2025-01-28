/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "af-list.h"
#include "alloc-util.h"
#include "dns-configuration.h"
#include "hash-funcs.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "set.h"
#include "strv.h"

DNSServer* dns_server_free(DNSServer *s) {
        if (!s)
                return NULL;

        free(s->server_name);
        iovec_done(&s->addr);

        return mfree(s);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        dns_server_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        DNSServer,
        dns_server_free);

static int dispatch_dns_server(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_server_dispatch_table[] = {
                { "address",    SD_JSON_VARIANT_ARRAY,    json_dispatch_byte_array_iovec, offsetof(DNSServer, addr),        SD_JSON_MANDATORY },
                { "family",     SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,          offsetof(DNSServer, family),      SD_JSON_MANDATORY },
                { "port",       SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint16,        offsetof(DNSServer, port),        0                 },
                { "ifindex",    SD_JSON_VARIANT_UNSIGNED, json_dispatch_ifindex,          offsetof(DNSServer, ifindex),     SD_JSON_RELAX     },
                { "name",       SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,        offsetof(DNSServer, server_name), 0                 },
                { "accessible", SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool,       offsetof(DNSServer, accessible),  SD_JSON_MANDATORY },
                {},
        };
        DNSServer **ret = ASSERT_PTR(userdata);
        _cleanup_(dns_server_freep) DNSServer *s = NULL;
        int r;

        s = new0(DNSServer, 1);
        if (!s)
                return log_oom();

        r = sd_json_dispatch(variant, dns_server_dispatch_table, flags, s);
        if (r < 0)
                return r;

        if (s->addr.iov_len != FAMILY_ADDRESS_SIZE_SAFE(s->family))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "Dispatched address size (%zu) is incompatible with the family (%s).",
                                s->addr.iov_len, af_to_ipv4_ipv6(s->family));

        *ret = TAKE_PTR(s);

        return 0;
}

static int dispatch_dns_server_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Set **ret = ASSERT_PTR(userdata);
        _cleanup_set_free_ Set *dns_servers = NULL;
        sd_json_variant *v;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(dns_server_freep) DNSServer *s = NULL;

                r = dispatch_dns_server(name, v, flags, &s);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid DNSServer.");

                r = set_ensure_consume(&dns_servers, &dns_server_hash_ops, TAKE_PTR(s));
                if (r < 0)
                        return r;
        }

        set_free_and_replace(*ret, dns_servers);

        return 0;
}

SearchDomain* search_domain_free(SearchDomain *d) {
        if (!d)
                return NULL;

        free(d->name);

        return mfree(d);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        search_domain_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        SearchDomain,
        search_domain_free);

static int dispatch_search_domain(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field search_domain_dispatch_table[] = {
                { "name",      SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,  offsetof(SearchDomain, name),       SD_JSON_MANDATORY },
                { "routeOnly", SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool, offsetof(SearchDomain, route_only), SD_JSON_MANDATORY },
                { "ifindex",   SD_JSON_VARIANT_UNSIGNED, json_dispatch_ifindex,    offsetof(SearchDomain, ifindex),    SD_JSON_RELAX     },
                {},
        };
        SearchDomain **ret = ASSERT_PTR(userdata);
        _cleanup_(search_domain_freep) SearchDomain *d = NULL;
        int r;

        d = new0(SearchDomain, 1);
        if (!d)
                return log_oom();

        r = sd_json_dispatch(variant, search_domain_dispatch_table, flags, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);

        return 0;
}

static int dispatch_search_domain_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Set **ret = ASSERT_PTR(userdata);
        _cleanup_set_free_ Set *search_domains = NULL;
        sd_json_variant *v;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(search_domain_freep) SearchDomain *d = NULL;

                r = dispatch_search_domain(name, v, flags, &d);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid SearchDomain.");

                r = set_ensure_consume(&search_domains, &search_domain_hash_ops, TAKE_PTR(d));
                if (r < 0)
                        return r;
        }

        set_free_and_replace(*ret, search_domains);

        return 0;
}

DNSConfiguration* dns_configuration_free(DNSConfiguration *c) {
        if (!c)
                return NULL;

        dns_server_free(c->current_dns_server);
        set_free(c->dns_servers);
        set_free(c->search_domains);
        free(c->ifname);

        return mfree(c);
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        dns_configuration_hash_ops,
        void,
        trivial_hash_func,
        trivial_compare_func,
        DNSConfiguration,
        dns_configuration_free);

static int dispatch_dns_configuration(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_configuration_dispatch_table[] = {
                { "ifname",        SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,      offsetof(DNSConfiguration, ifname),             0             },
                { "ifindex",       SD_JSON_VARIANT_UNSIGNED, json_dispatch_ifindex,        offsetof(DNSConfiguration, ifindex),            SD_JSON_RELAX },
                { "defaultRoute",  SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool,     offsetof(DNSConfiguration, default_route),      0             },
                { "currentServer", SD_JSON_VARIANT_OBJECT,   dispatch_dns_server,          offsetof(DNSConfiguration, current_dns_server), 0             },
                { "servers",       SD_JSON_VARIANT_ARRAY,    dispatch_dns_server_array,    offsetof(DNSConfiguration, dns_servers),        0             },
                { "searchDomains", SD_JSON_VARIANT_ARRAY,    dispatch_search_domain_array, offsetof(DNSConfiguration, search_domains),     0             },
                {},

        };
        DNSConfiguration **ret = ASSERT_PTR(userdata);
        _cleanup_(dns_configuration_freep) DNSConfiguration *c = NULL;
        int r;

        c = new0(DNSConfiguration, 1);
        if (!c)
                return log_oom();

        r = sd_json_dispatch(variant, dns_configuration_dispatch_table, flags, c);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);

        return 0;
}

int dns_configuration_from_json(sd_json_variant *variant, DNSConfiguration **ret) {
        return dispatch_dns_configuration(NULL, variant, SD_JSON_LOG, ret);
}

bool dns_is_accessible(DNSConfiguration *c) {
        DNSServer *s = NULL;

        if (!c)
                return false;

        if (c->current_dns_server && c->current_dns_server->accessible)
                return true;

        SET_FOREACH(s, c->dns_servers)
                if (s->accessible)
                        return true;

        return false;
}

bool dns_configuration_contains_search_domain(DNSConfiguration *c, const char *domain) {
        SearchDomain *d = NULL;

        assert(domain);

        if (!c)
                return false;

        SET_FOREACH(d, c->search_domains)
                if (streq(d->name, domain))
                        return true;

        return false;
}
