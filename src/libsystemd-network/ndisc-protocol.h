/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

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
} __attribute__((__packed__));

int pref64_plc_to_prefix_length(uint16_t plc, uint8_t *ret);
int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret);
