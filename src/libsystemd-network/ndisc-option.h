/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/uio.h>

#include "sd-ndisc-protocol.h"
#include "sd-dns-resolver.h"

#include "icmp6-packet.h"
#include "macro.h"
#include "set.h"
#include "time-util.h"

typedef struct sd_ndisc_raw {
        uint8_t *bytes;
        size_t length;
} sd_ndisc_raw;

/* Mostly equivalent to struct nd_opt_prefix_info, but using usec_t. */
typedef struct sd_ndisc_prefix {
        uint8_t flags;
        uint8_t prefixlen;
        struct in6_addr address;
        usec_t valid_lifetime;
        usec_t preferred_lifetime;
        /* timestamp in CLOCK_BOOTTIME, used when sending option for adjusting lifetime. */
        usec_t valid_until;
        usec_t preferred_until;
} sd_ndisc_prefix;

typedef struct sd_ndisc_home_agent {
        uint16_t preference;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_home_agent;

typedef struct sd_ndisc_route {
        uint8_t preference;
        uint8_t prefixlen;
        struct in6_addr address;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_route;

typedef struct sd_ndisc_rdnss {
        size_t n_addresses;
        struct in6_addr *addresses;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_rdnss;

typedef struct sd_ndisc_dnssl {
        char **domains;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_dnssl;

typedef struct sd_ndisc_prefix64 {
        uint8_t prefixlen;
        struct in6_addr prefix;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_prefix64;

typedef struct sd_ndisc_dnr {
        sd_dns_resolver *resolver;
        usec_t lifetime;
        usec_t valid_until;
} sd_ndisc_dnr;

typedef struct sd_ndisc_option {
        uint8_t type;
        size_t offset;

        union {
                sd_ndisc_raw raw;               /* for testing or unsupported options */
                struct ether_addr mac;          /* SD_NDISC_OPTION_SOURCE_LL_ADDRESS or SD_NDISC_OPTION_TARGET_LL_ADDRESS */
                sd_ndisc_prefix prefix;         /* SD_NDISC_OPTION_PREFIX_INFORMATION */
                struct ip6_hdr hdr;             /* SD_NDISC_OPTION_REDIRECTED_HEADER */
                uint32_t mtu;                   /* SD_NDISC_OPTION_MTU */
                sd_ndisc_home_agent home_agent; /* SD_NDISC_OPTION_HOME_AGENT */
                sd_ndisc_route route;           /* SD_NDISC_OPTION_ROUTE_INFORMATION */
                sd_ndisc_rdnss rdnss;           /* SD_NDISC_OPTION_RDNSS */
                uint64_t extended_flags;        /* SD_NDISC_OPTION_FLAGS_EXTENSION */
                sd_ndisc_dnssl dnssl;           /* SD_NDISC_OPTION_DNSSL */
                char *captive_portal;           /* SD_NDISC_OPTION_CAPTIVE_PORTAL */
                sd_ndisc_prefix64 prefix64;     /* SD_NDISC_OPTION_PREF64 */
                sd_ndisc_dnr encrypted_dns;     /* SD_NDISC_OPTION_ENCRYPTED_DNS */
        };
} sd_ndisc_option;

/* RFC 8781: PREF64 or (NAT64 prefix) */
#define PREF64_SCALED_LIFETIME_MASK      0xfff8
#define PREF64_PLC_MASK                  0x0007
#define PREF64_MAX_LIFETIME_USEC         (65528 * USEC_PER_SEC)

typedef enum PrefixLengthCode {
        PREFIX_LENGTH_CODE_96,
        PREFIX_LENGTH_CODE_64,
        PREFIX_LENGTH_CODE_56,
        PREFIX_LENGTH_CODE_48,
        PREFIX_LENGTH_CODE_40,
        PREFIX_LENGTH_CODE_32,
        _PREFIX_LENGTH_CODE_MAX,
        _PREFIX_LENGTH_CODE_INVALID = -EINVAL,
} PrefixLengthCode;

/* rfc8781: section 4 - Scaled Lifetime: 13-bit unsigned integer. PREFIX_LEN (Prefix Length Code): 3-bit unsigned integer */
struct nd_opt_prefix64_info {
        uint8_t type;
        uint8_t length;
        uint16_t lifetime_and_plc;
        uint8_t prefix[12];
} _packed_;

int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret);

sd_ndisc_option* ndisc_option_free(sd_ndisc_option *option);

int ndisc_option_parse(
                ICMP6Packet *p,
                size_t offset,
                uint8_t *ret_type,
                size_t *ret_len,
                const uint8_t **ret_opt);

int ndisc_parse_options(ICMP6Packet *p, Set **ret_options);

static inline sd_ndisc_option* ndisc_option_get(Set *options, const sd_ndisc_option *p) {
        return set_get(options, ASSERT_PTR(p));
}
static inline sd_ndisc_option* ndisc_option_get_by_type(Set *options, uint8_t type) {
        return ndisc_option_get(options, &(const sd_ndisc_option) { .type = type });
}
int ndisc_option_get_mac(Set *options, uint8_t type, struct ether_addr *ret);

static inline void ndisc_option_remove(Set *options, const sd_ndisc_option *p) {
        ndisc_option_free(set_remove(options, ASSERT_PTR(p)));
}
static inline void ndisc_option_remove_by_type(Set *options, uint8_t type) {
        ndisc_option_remove(options, &(const sd_ndisc_option) { .type = type });
}

int ndisc_option_set_raw(
                Set **options,
                size_t length,
                const uint8_t *bytes);
int ndisc_option_add_link_layer_address(
                Set **options,
                uint8_t type,
                size_t offset,
                const struct ether_addr *mac);
static inline int ndisc_option_set_link_layer_address(
                Set **options,
                uint8_t type,
                const struct ether_addr *mac) {
        return ndisc_option_add_link_layer_address(options, type, 0, mac);
}
int ndisc_option_add_prefix_internal(
                Set **options,
                size_t offset,
                uint8_t flags,
                uint8_t prefixlen,
                const struct in6_addr *address,
                usec_t valid_lifetime,
                usec_t preferred_lifetime,
                usec_t valid_until,
                usec_t preferred_until);
static inline int ndisc_option_add_prefix(
                Set **options,
                size_t offset,
                uint8_t flags,
                uint8_t prefixlen,
                const struct in6_addr *address,
                usec_t valid_lifetime,
                usec_t preferred_lifetime) {
        return ndisc_option_add_prefix_internal(options, offset, flags, prefixlen, address,
                                                valid_lifetime, preferred_lifetime,
                                                USEC_INFINITY, USEC_INFINITY);
}
static inline int ndisc_option_set_prefix(
                Set **options,
                uint8_t flags,
                uint8_t prefixlen,
                const struct in6_addr *address,
                usec_t valid_lifetime,
                usec_t preferred_lifetime,
                usec_t valid_until,
                usec_t preferred_until) {
        return ndisc_option_add_prefix_internal(options, 0, flags, prefixlen, address,
                                                valid_lifetime, preferred_lifetime,
                                                valid_until, preferred_until);
}
int ndisc_option_add_redirected_header(
                Set **options,
                size_t offset,
                const struct ip6_hdr *hdr);
int ndisc_option_add_mtu(
                Set **options,
                size_t offset,
                uint32_t mtu);
static inline int ndisc_option_set_mtu(
                Set **options,
                uint32_t mtu) {
        return ndisc_option_add_mtu(options, 0, mtu);
}
int ndisc_option_add_home_agent_internal(
                Set **options,
                size_t offset,
                uint16_t preference,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_home_agent(
                Set **options,
                size_t offset,
                uint16_t preference,
                usec_t lifetime) {
        return ndisc_option_add_home_agent_internal(options, offset, preference, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_home_agent(
                Set **options,
                uint16_t preference,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_home_agent_internal(options, 0, preference, lifetime, valid_until);
}
int ndisc_option_add_route_internal(
                Set **options,
                size_t offset,
                uint8_t preference,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_route(
                Set **options,
                size_t offset,
                uint8_t preference,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime) {
        return ndisc_option_add_route_internal(options, offset, preference, prefixlen, prefix, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_route(
                Set **options,
                uint8_t preference,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_route_internal(options, 0, preference, prefixlen, prefix, lifetime, valid_until);
}
int ndisc_option_add_rdnss_internal(
                Set **options,
                size_t offset,
                size_t n_addresses,
                const struct in6_addr *addresses,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_rdnss(
                Set **options,
                size_t offset,
                size_t n_addresses,
                const struct in6_addr *addresses,
                usec_t lifetime) {
        return ndisc_option_add_rdnss_internal(options, offset, n_addresses, addresses, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_rdnss(
                Set **options,
                size_t n_addresses,
                const struct in6_addr *addresses,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_rdnss_internal(options, 0, n_addresses, addresses, lifetime, valid_until);
}
int ndisc_option_add_flags_extension(
                Set **options,
                size_t offset,
                uint64_t flags);
int ndisc_option_add_dnssl_internal(
                Set **options,
                size_t offset,
                char * const *domains,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_dnssl(
                Set **options,
                size_t offset,
                char * const *domains,
                usec_t lifetime) {
        return ndisc_option_add_dnssl_internal(options, offset, domains, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_dnssl(
                Set **options,
                char * const *domains,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_dnssl_internal(options, 0, domains, lifetime, valid_until);
}
int ndisc_option_add_captive_portal(
                Set **options,
                size_t offset,
                const char *portal);
static inline int ndisc_option_set_captive_portal(
                Set **options,
                const char *portal) {
        return ndisc_option_add_captive_portal(options, 0, portal);
}
int ndisc_option_add_prefix64_internal(
                Set **options,
                size_t offset,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_prefix64(
                Set **options,
                size_t offset,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime) {
        return ndisc_option_add_prefix64_internal(options, offset, prefixlen, prefix, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_prefix64(
                Set **options,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_prefix64_internal(options, 0, prefixlen, prefix, lifetime, valid_until);
}

int ndisc_option_add_encrypted_dns_internal(
                Set **options,
                size_t offset,
                sd_dns_resolver *res,
                usec_t lifetime,
                usec_t valid_until);
static inline int ndisc_option_add_encrypted_dns(
                Set **options,
                size_t offset,
                sd_dns_resolver *res,
                usec_t lifetime) {
        return ndisc_option_add_encrypted_dns_internal(options, offset, res, lifetime, USEC_INFINITY);
}
static inline int ndisc_option_set_encrypted_dns(
                Set **options,
                size_t offset,
                sd_dns_resolver *res,
                usec_t lifetime,
                usec_t valid_until) {
        return ndisc_option_add_encrypted_dns_internal(options, 0, res, lifetime, valid_until);
}

int ndisc_send(int fd, const struct in6_addr *dst, const struct icmp6_hdr *hdr, Set *options, usec_t timestamp);
