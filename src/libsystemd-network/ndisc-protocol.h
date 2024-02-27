/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "sd-ndisc-protocol.h"

#include "icmp6-packet.h"
#include "macro.h"
#include "time-util.h"

/* Mostly equivalent to struct nd_opt_prefix_info, but using usec_t. */
typedef struct sd_ndisc_prefix {
        uint8_t flags;
        uint8_t prefixlen;
        struct in6_addr prefix;
        usec_t valid_lifetime;
        usec_t preferred_lifetime;
} sd_ndisc_prefix;

typedef struct sd_ndisc_route {
        uint8_t preference;
        uint8_t prefixlen;
        struct in6_addr prefix;
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

typedef struct sd_ndisc_pref64 {
        uint8_t prefixlen;
        struct in6_addr prefix;
        usec_t lifetime;
} sd_ndisc_pref64;

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

int pref64_plc_to_prefix_length(uint16_t plc, uint8_t *ret);
int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret);

int ndisc_option_parse(
                ICMP6Packet *p,
                size_t offset,
                uint8_t *ret_type,
                size_t *ret_len,
                const uint8_t **ret_opt);

int ndisc_option_parse_link_layer_address(const uint8_t *opt, size_t len, struct ether_addr *ret);
int ndisc_option_parse_prefix(const uint8_t *opt, size_t len, sd_ndisc_prefix *ret);
int ndisc_option_parse_redirected_header(const uint8_t *opt, size_t len, struct ip6_hdr *ret);
int ndisc_option_parse_mtu(const uint8_t *opt, size_t len, uint32_t *ret);
int ndisc_option_parse_route(const uint8_t *opt, size_t len, sd_ndisc_route *ret);
int ndisc_option_parse_rdnss(const uint8_t *opt, size_t len, sd_ndisc_rdnss *ret);
int ndisc_option_parse_flags_extension(const uint8_t *opt, size_t len, uint8_t basic_flags, uint64_t *ret);
int ndisc_option_parse_dnssl(const uint8_t *opt, size_t len, sd_ndisc_dnssl *ret);
int ndisc_option_parse_captive_portal(const uint8_t *opt, size_t len, char **ret);
int ndisc_option_parse_pref64(const uint8_t *opt, size_t len, sd_ndisc_pref64 *ret);

int pref64_lifetime_and_plc_parse(uint16_t lifetime_and_plc, uint8_t *ret_prefixlen, usec_t *ret_lifetime);
int pref64_lifetime_and_plc_generate(uint8_t prefixlen, usec_t lifetime, uint16_t *ret);
