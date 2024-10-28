/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "dns-configuration.h"
#include "json-util.h"
#include "set.h"
#include "strv.h"

DNSServer *dns_server_free(DNSServer *s) {
        if (!s)
                return NULL;

        free(s->server_name);

        return mfree(s);
}

static int dispatch_dns_server(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_server_dispatch_table[] = {
                { "address",            SD_JSON_VARIANT_ARRAY,    json_dispatch_in_addr_union, offsetof(DNSServer, addr),        SD_JSON_MANDATORY },
                { "addressFamily",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,       offsetof(DNSServer, family),      SD_JSON_MANDATORY },
                { "port",               SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint16,     offsetof(DNSServer, port),        0                 },
                { "interfaceSpecifier", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,       offsetof(DNSServer, ifindex),     0                 },
                { "serverName",         SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,     offsetof(DNSServer, server_name), 0                 },
                { "accessible",         SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool,    offsetof(DNSServer, accessible),  SD_JSON_MANDATORY },
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

        *ret = TAKE_PTR(s);

        return 0;
}

static int dispatch_dns_server_array(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        Set **ret = ASSERT_PTR(userdata);
        Set *dns_servers = set_new(NULL);
        sd_json_variant *v = NULL;
        int r;

        JSON_VARIANT_ARRAY_FOREACH(v, variant) {
                _cleanup_(dns_server_freep) DNSServer *s = NULL;

                s = new0(DNSServer, 1);
                if (!s)
                        return log_oom();

                r = dispatch_dns_server(name, v, flags, &s);
                if (r < 0)
                        return json_log(v, flags, r, "JSON array element is not a valid DNSServer.");

                r = set_put(dns_servers, TAKE_PTR(s));
                if (r < 0)
                        return log_oom();
        }

        set_free_and_replace(*ret, dns_servers);

        return 0;
}

DNSConfiguration *dns_configuration_free(DNSConfiguration *c) {
        if (!c)
                return NULL;

        dns_server_free(c->current_dns_server);
        set_free_with_destructor(c->dns_servers, dns_server_free);
        free(c->ifname);
        strv_free(c->search_domains);

        return mfree(c);
}

static int dispatch_dns_configuration(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dns_configuration_dispatch_table[] = {
                { "interface",        SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,   offsetof(DNSConfiguration, ifname),             0 },
                { "interfaceIndex",   SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,     offsetof(DNSConfiguration, ifindex),            0 },
                { "currentDNSServer", SD_JSON_VARIANT_OBJECT,   dispatch_dns_server,       offsetof(DNSConfiguration, current_dns_server), 0 },
                { "dnsServers",       SD_JSON_VARIANT_ARRAY,    dispatch_dns_server_array, offsetof(DNSConfiguration, dns_servers),        0 },
                { "searchDomains",    SD_JSON_VARIANT_ARRAY,    sd_json_dispatch_strv,     offsetof(DNSConfiguration, search_domains),     0 },
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
