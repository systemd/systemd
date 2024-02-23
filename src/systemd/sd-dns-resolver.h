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

int sd_dns_resolver_get_priority(const sd_dns_resolver *res, uint16_t *priority);
int sd_dns_resolver_get_adn(const sd_dns_resolver *res, const char **adn);
int sd_dns_resolver_get_addrs(const sd_dns_resolver *res, int *family, const struct in6_addr **addrs, size_t *n);
//FIXME in_addr_union?
int sd_dns_resolver_get_transports(const sd_dns_resolver *res, DNSALPNFlags *transports);
int sd_dns_resolver_get_port(const sd_dns_resolver *res, uint16_t *port);
int sd_dns_resolver_get_dohpath(const sd_dns_resolver *res, const char **dohpath);

void sd_dns_resolver_done(sd_dns_resolver *res);
void sd_dns_resolver_clear(sd_dns_resolver *res);
sd_dns_resolver *sd_dns_resolver_free(sd_dns_resolver *res);
_SD_DEFINE_POINTER_CLEANUP_FUNC (sd_dns_resolver, sd_dns_resolver_free);
void sd_dns_resolver_array_free(sd_dns_resolver *resolvers, size_t n);

int sd_dns_resolver_prio_compare(const sd_dns_resolver *a, const sd_dns_resolver *b);

int dnr_parse_svc_params(const uint8_t *option, size_t len, sd_dns_resolver *resolver);

int sd_dns_resolvers_to_dot_strv(const sd_dns_resolver *resolvers, size_t n_resolvers, char ***ret_names);

_SD_END_DECLARATIONS;

#endif /* SD_DNS_RESOLVER_H */
