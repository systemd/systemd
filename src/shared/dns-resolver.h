/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "macro.h"
#include "list.h"
#include "socket-netlink.h"

/* https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml#dns-svcparamkeys */
enum {
        DNS_SVC_PARAM_KEY_MANDATORY       = 0, /* RFC 9460 § 8 */
        DNS_SVC_PARAM_KEY_ALPN            = 1, /* RFC 9460 § 7.1 */
        DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN = 2, /* RFC 9460 § 7.1 */
        DNS_SVC_PARAM_KEY_PORT            = 3, /* RFC 9460 § 7.2 */
        DNS_SVC_PARAM_KEY_IPV4HINT        = 4, /* RFC 9460 § 7.3 */
        DNS_SVC_PARAM_KEY_ECH             = 5, /* RFC 9460 */
        DNS_SVC_PARAM_KEY_IPV6HINT        = 6, /* RFC 9460 § 7.3  */
        DNS_SVC_PARAM_KEY_DOHPATH         = 7, /* RFC 9461 */
        DNS_SVC_PARAM_KEY_OHTTP           = 8,
        _DNS_SVC_PARAM_KEY_MAX_DEFINED,
        DNS_SVC_PARAM_KEY_INVALID         = 65535 /* RFC 9460 */
};

const char *dns_svc_param_key_to_string(int i) _const_;
const char *format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]);
#define FORMAT_DNS_SVC_PARAM_KEY(i) format_dns_svc_param_key(i, (char [DECIMAL_STR_MAX(uint16_t)+3]) {})

/* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
typedef enum DNSALPNFlags {
        /* There isn't really an alpn reserved for Do53 service, but designated resolvers may or may not offer
         * Do53 service, so we should probably have a flag to represent this capability. Unfortunately DNR
         * does not indicate the status to us.*/
        SD_DNS_ALPN_DO53           = 1 << 0,
        /* SD_DNS_ALPN_HTTP_1_1,                "http/1.1" [RFC9112] */
        SD_DNS_ALPN_HTTP_2_TLS     = 1 << 1, /* "h2"  [RFC9113] [RFC9461] */
        /* SD_DNS_ALPN_HTTP_2_TCP,              "h2c" [RFC9113] */
        SD_DNS_ALPN_HTTP_3         = 1 << 2, /* "h3"  [RFC9114] [RFC9461] */
        SD_DNS_ALPN_DOT            = 1 << 3, /* "dot" [RFC7858] [RFC9461] */
        SD_DNS_ALPN_DOQ            = 1 << 4  /* "doq" [RFC9250] [RFC9461] */
} DNSALPNFlags;

/* const char *dns_alpn_flag_to_string(DNSALPNFlags alpn); */
/* DNSALPNFlags dns_alpn_flag_from_string(const char *s); */

/* Represents a "designated resolver" */
typedef struct ResolverData ResolverData;
struct ResolverData {
        uint16_t priority;
        char *auth_name;
        int family;
        union in_addr_union *addrs;
        size_t n_addrs;
        DNSALPNFlags transports;
        uint16_t port;
        char *dohpath;
        usec_t lifetime_usec; /* ndisc ra lifetime */
        LIST_FIELDS(ResolverData, resolvers);
};

ResolverData *dnr_resolver_data_free_all(ResolverData *first);
DEFINE_TRIVIAL_CLEANUP_FUNC(ResolverData *, dnr_resolver_data_free_all);

int dnr_parse_svc_params(const uint8_t *option, size_t len, ResolverData *resolver);

int dns_resolvers_to_dot_addrs(const ResolverData *resolvers, struct in_addr_full ***ret_addrs, size_t *ret_n_addrs);
int dns_resolvers_to_dot_strv(const ResolverData *resolvers, char ***ret_names);
