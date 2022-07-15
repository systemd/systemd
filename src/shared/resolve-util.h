/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"
#include "macro.h"

/* 127.0.0.53 in native endian (The IP address we listen on with the full DNS stub, i.e. that does LLMNR/mDNS, and stuff) */
#define INADDR_DNS_STUB ((in_addr_t) 0x7f000035U)

/* 127.0.0.54 in native endian (The IP address we listen on we only implement "proxy" mode) */
#define INADDR_DNS_PROXY_STUB ((in_addr_t) 0x7f000036U)

typedef enum DnsCacheMode DnsCacheMode;

enum DnsCacheMode {
        DNS_CACHE_MODE_NO,
        DNS_CACHE_MODE_YES,
        DNS_CACHE_MODE_NO_NEGATIVE,
        _DNS_CACHE_MODE_MAX,
        _DNS_CACHE_MODE_INVALID = -EINVAL,
};

typedef enum ResolveSupport ResolveSupport;
typedef enum DnssecMode DnssecMode;
typedef enum DnsOverTlsMode DnsOverTlsMode;

enum ResolveSupport {
        RESOLVE_SUPPORT_NO,
        RESOLVE_SUPPORT_YES,
        RESOLVE_SUPPORT_RESOLVE,
        _RESOLVE_SUPPORT_MAX,
        _RESOLVE_SUPPORT_INVALID = -EINVAL,
};

enum DnssecMode {
        /* No DNSSEC validation is done */
        DNSSEC_NO,

        /* Validate locally, if the server knows DO, but if not,
         * don't. Don't trust the AD bit. If the server doesn't do
         * DNSSEC properly, downgrade to non-DNSSEC operation. Of
         * course, we then are vulnerable to a downgrade attack, but
         * that's life and what is configured. */
        DNSSEC_ALLOW_DOWNGRADE,

        /* Insist on DNSSEC server support, and rather fail than downgrading. */
        DNSSEC_YES,

        _DNSSEC_MODE_MAX,
        _DNSSEC_MODE_INVALID = -EINVAL,
};

enum DnsOverTlsMode {
        /* No connection is made for DNS-over-TLS */
        DNS_OVER_TLS_NO,

        /* Try to connect using DNS-over-TLS, but if connection fails,
         * fall back to using an unencrypted connection */
        DNS_OVER_TLS_OPPORTUNISTIC,

        /* Enforce DNS-over-TLS and require valid server certificates */
        DNS_OVER_TLS_YES,

        _DNS_OVER_TLS_MODE_MAX,
        _DNS_OVER_TLS_MODE_INVALID = -EINVAL,
};

CONFIG_PARSER_PROTOTYPE(config_parse_resolve_support);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssec_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_over_tls_mode);
CONFIG_PARSER_PROTOTYPE(config_parse_dns_cache_mode);

const char* resolve_support_to_string(ResolveSupport p) _const_;
ResolveSupport resolve_support_from_string(const char *s) _pure_;

const char* dnssec_mode_to_string(DnssecMode p) _const_;
DnssecMode dnssec_mode_from_string(const char *s) _pure_;

const char* dns_over_tls_mode_to_string(DnsOverTlsMode p) _const_;
DnsOverTlsMode dns_over_tls_mode_from_string(const char *s) _pure_;

bool dns_server_address_valid(int family, const union in_addr_union *sa);

const char* dns_cache_mode_to_string(DnsCacheMode p) _const_;
DnsCacheMode dns_cache_mode_from_string(const char *s) _pure_;

/* A resolv.conf file containing the DNS server and domain data we learnt from uplink, i.e. the full uplink data */
#define PRIVATE_UPLINK_RESOLV_CONF "/run/systemd/resolve/resolv.conf"

/* A resolv.conf file containing the domain data we learnt from uplink, but our own DNS server address. */
#define PRIVATE_STUB_RESOLV_CONF "/run/systemd/resolve/stub-resolv.conf"

/* A static resolv.conf file containing no domains, but only our own DNS server address */
#define PRIVATE_STATIC_RESOLV_CONF ROOTLIBEXECDIR "/resolv.conf"
