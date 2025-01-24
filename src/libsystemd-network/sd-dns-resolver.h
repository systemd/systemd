#ifndef SD_DNS_RESOLVER_H
#define SD_DNS_RESOLVER_H

#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dns_resolver sd_dns_resolver;

/* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids */
typedef enum sd_dns_alpn_flags {
        /* There isn't really an alpn reserved for Do53 service, but designated resolvers may or may not offer
         * Do53 service, so we should probably have a flag to represent this capability. Unfortunately DNR
         * does not indicate the status to us. */
        SD_DNS_ALPN_DO53           = 1 << 0,
        /* SD_DNS_ALPN_HTTP_1_1,                "http/1.1" [RFC9112] */
        SD_DNS_ALPN_HTTP_2_TLS     = 1 << 1, /* "h2"  [RFC9113] [RFC9461] */
        /* SD_DNS_ALPN_HTTP_2_TCP,              "h2c" [RFC9113] */
        SD_DNS_ALPN_HTTP_3         = 1 << 2, /* "h3"  [RFC9114] [RFC9461] */
        SD_DNS_ALPN_DOT            = 1 << 3, /* "dot" [RFC7858] [RFC9461] */
        SD_DNS_ALPN_DOQ            = 1 << 4, /* "doq" [RFC9250] [RFC9461] */

        _SD_ENUM_FORCE_S64(SD_DNS_ALPN)
} sd_dns_alpn_flags;

int sd_dns_resolver_get_priority(sd_dns_resolver *res, uint16_t *ret_priority);
int sd_dns_resolver_get_adn(sd_dns_resolver *res, const char **ret_adn);
int sd_dns_resolver_get_inet_addresses(sd_dns_resolver *res, const struct in_addr **ret_addrs, size_t *n);
int sd_dns_resolver_get_inet6_addresses(sd_dns_resolver *res, const struct in6_addr **ret_addrs, size_t *n);
int sd_dns_resolver_get_alpn(sd_dns_resolver *res, sd_dns_alpn_flags *ret_alpn);
int sd_dns_resolver_get_port(sd_dns_resolver *res, uint16_t *ret_port);
int sd_dns_resolver_get_dohpath(sd_dns_resolver *res, const char **ret_dohpath);

sd_dns_resolver *sd_dns_resolver_unref(sd_dns_resolver *res);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dns_resolver, sd_dns_resolver_unref);

_SD_END_DECLARATIONS;

#endif /* SD_DNS_RESOLVER_H */
