/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "sd-ndisc-protocol.h"

#include "icmp6-packet.h"
#include "macro.h"
#include "set.h"
#include "time-util.h"

/* Mostly equivalent to struct nd_opt_prefix_info, but using usec_t. */
typedef struct sd_ndisc_prefix {
        uint8_t flags;
        uint8_t prefixlen;
        struct in6_addr address;
        usec_t valid_lifetime;
        usec_t preferred_lifetime;
} sd_ndisc_prefix;

typedef struct sd_ndisc_route {
        uint8_t preference;
        uint8_t prefixlen;
        struct in6_addr address;
        usec_t lifetime;
} sd_ndisc_route;

typedef struct sd_ndisc_rdnss {
        size_t n_addresses;
        struct in6_addr *addresses;
        usec_t lifetime;
} sd_ndisc_rdnss;

typedef struct sd_ndisc_dnssl {
        char **domains;
        usec_t lifetime;
} sd_ndisc_dnssl;

typedef struct sd_ndisc_prefix64 {
        uint8_t prefixlen;
        struct in6_addr prefix;
        usec_t lifetime;
} sd_ndisc_prefix64;

typedef struct sd_ndisc_option {
        uint8_t type;
        size_t offset;

        union {
                struct ether_addr mac;      /* SD_NDISC_OPTION_SOURCE_LL_ADDRESS or SD_NDISC_OPTION_TARGET_LL_ADDRESS */
                sd_ndisc_prefix prefix;     /* SD_NDISC_OPTION_PREFIX_INFORMATION */
                struct ip6_hdr hdr;         /* SD_NDISC_OPTION_REDIRECTED_HEADER */
                uint32_t mtu;               /* SD_NDISC_OPTION_MTU */
                sd_ndisc_route route;       /* SD_NDISC_OPTION_ROUTE_INFORMATION */
                sd_ndisc_rdnss rdnss;       /* SD_NDISC_OPTION_RDNSS */
                uint64_t extended_flags;    /* SD_NDISC_OPTION_FLAGS_EXTENSION */
                sd_ndisc_dnssl dnssl;       /* SD_NDISC_OPTION_DNSSL */
                char *captive_portal;       /* SD_NDISC_OPTION_CAPTIVE_PORTAL */
                sd_ndisc_prefix64 prefix64; /* SD_NDISC_OPTION_PREF64 */
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

static inline sd_ndisc_option* ndisc_option_get(Set *options, uint8_t type) {
        return set_get(options, &(sd_ndisc_option) { .type = type, });
}

int ndisc_option_get_mac(Set *options, uint8_t type, struct ether_addr *ret);

int ndisc_option_add_link_layer_address(
                Set **options,
                uint8_t opt,
                size_t offset,
                const struct ether_addr *mac);
int ndisc_option_add_prefix(
                Set **options,
                size_t offset,
                uint8_t flags,
                uint8_t prefixlen,
                const struct in6_addr *address,
                usec_t valid_lifetime,
                usec_t preferred_lifetime);
int ndisc_option_add_redirected_header(
                Set **options,
                size_t offset,
                const struct ip6_hdr *hdr);
int ndisc_option_add_mtu(
                Set **options,
                size_t offset,
                uint32_t mtu);
int ndisc_option_add_route(
                Set **options,
                size_t offset,
                uint8_t preference,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime);
int ndisc_option_add_rdnss(
                Set **options,
                size_t offset,
                size_t n_addresses,
                const struct in6_addr *addresses,
                usec_t lifetime);
int ndisc_option_add_flags_extension(
                Set **options,
                size_t offset,
                uint64_t flags);
int ndisc_option_add_dnssl(
                Set **options,
                size_t offset,
                char * const *domains,
                usec_t lifetime);
int ndisc_option_add_captive_portal(
                Set **options,
                size_t offset,
                const char *portal);
int ndisc_option_add_prefix64(
                Set **options,
                size_t offset,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime);
