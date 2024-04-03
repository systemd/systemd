/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "sd-dns-resolver.h"

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

const char* dns_svc_param_key_to_string(int i) _const_;
const char* format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]);
#define FORMAT_DNS_SVC_PARAM_KEY(i) format_dns_svc_param_key(i, (char [DECIMAL_STR_MAX(uint16_t)+3]) {})

/* Represents a "designated resolver" */
/* typedef struct sd_dns_resolver sd_dns_resolver; */
struct sd_dns_resolver {
        uint16_t priority;
        char *auth_name;
        int family;
        union in_addr_union *addrs;
        size_t n_addrs;
        sd_dns_alpn_flags transports;
        uint16_t port;
        char *dohpath;
};

void siphash24_compress_resolver(const sd_dns_resolver *res, struct siphash *state);

int dns_resolver_transports_to_strv(sd_dns_alpn_flags transports, char ***ret);

int dns_resolvers_to_dot_addrs(const sd_dns_resolver *resolvers, size_t n_resolvers,
                struct in_addr_full ***ret_addrs, size_t *ret_n_addrs);

int dns_resolver_prio_compare(const sd_dns_resolver *a, const sd_dns_resolver *b);

int dnr_parse_svc_params(const uint8_t *option, size_t len, sd_dns_resolver *resolver);

int dns_resolvers_to_dot_strv(const sd_dns_resolver *resolvers, size_t n_resolvers, char ***ret_names);

void sd_dns_resolver_done(sd_dns_resolver *res);

void dns_resolver_done_many(sd_dns_resolver *resolvers, size_t n);
