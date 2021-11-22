/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "resolve-util.h"
#include "string-table.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_resolve_support, resolve_support, ResolveSupport, "Failed to parse resolve support setting");
DEFINE_CONFIG_PARSE_ENUM(config_parse_dnssec_mode, dnssec_mode, DnssecMode, "Failed to parse DNSSEC mode setting");
DEFINE_CONFIG_PARSE_ENUM(config_parse_dns_over_tls_mode, dns_over_tls_mode, DnsOverTlsMode, "Failed to parse DNS-over-TLS mode setting");

static const char* const resolve_support_table[_RESOLVE_SUPPORT_MAX] = {
        [RESOLVE_SUPPORT_NO] = "no",
        [RESOLVE_SUPPORT_YES] = "yes",
        [RESOLVE_SUPPORT_RESOLVE] = "resolve",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(resolve_support, ResolveSupport, RESOLVE_SUPPORT_YES);

static const char* const dnssec_mode_table[_DNSSEC_MODE_MAX] = {
        [DNSSEC_NO] = "no",
        [DNSSEC_ALLOW_DOWNGRADE] = "allow-downgrade",
        [DNSSEC_YES] = "yes",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dnssec_mode, DnssecMode, DNSSEC_YES);

static const char* const dns_over_tls_mode_table[_DNS_OVER_TLS_MODE_MAX] = {
        [DNS_OVER_TLS_NO] = "no",
        [DNS_OVER_TLS_OPPORTUNISTIC] = "opportunistic",
        [DNS_OVER_TLS_YES] = "yes",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dns_over_tls_mode, DnsOverTlsMode, DNS_OVER_TLS_YES);

bool dns_server_address_valid(int family, const union in_addr_union *sa) {

        /* Refuses the 0 IP addresses as well as 127.0.0.53/127.0.0.54 (which is our own DNS stub) */

        if (!in_addr_is_set(family, sa))
                return false;

        if (family == AF_INET && IN_SET(be32toh(sa->in.s_addr), INADDR_DNS_STUB, INADDR_DNS_PROXY_STUB))
                return false;

        return true;
}

DEFINE_CONFIG_PARSE_ENUM(config_parse_dns_cache_mode, dns_cache_mode, DnsCacheMode, "Failed to parse DNS cache mode setting")

static const char* const dns_cache_mode_table[_DNS_CACHE_MODE_MAX] = {
        [DNS_CACHE_MODE_YES] = "yes",
        [DNS_CACHE_MODE_NO] = "no",
        [DNS_CACHE_MODE_NO_NEGATIVE] = "no-negative",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(dns_cache_mode, DnsCacheMode, DNS_CACHE_MODE_YES);
