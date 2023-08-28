/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-ndisc.h"

#include "network-common.h"
#include "time-util.h"

/* RFC 8781: PREF64 or (NAT64 prefix) */
#define PREF64_SCALED_LIFETIME_MASK      0xfff8
#define PREF64_PLC_MASK                  0x0007
#define PREF64_MAX_LIFETIME              (65528 * USEC_PER_SEC)

#define PREF64_PLC_32                    5
#define PREF64_PLC_40                    4
#define PREF64_PLC_48                    3
#define PREF64_PLC_56                    2
#define PREF64_PLC_64                    1
#define PREF64_PLC_96                    0

#define PREF64_PREFIX_LEN_32             32
#define PREF64_PREFIX_LEN_40             40
#define PREF64_PREFIX_LEN_48             48
#define PREF64_PREFIX_LEN_56             56
#define PREF64_PREFIX_LEN_64             64
#define PREF64_PREFIX_LEN_96             96

/* rfc8781: section 4 - Scaled Lifetime: 13-bit unsigned integer. PREFIX_LEN (Prefix Length Code): 3-bit unsigned integer */
struct nd_opt_prefix64_info {
        uint8_t type;
        uint8_t length;
        uint16_t lifetime_and_plc;
        uint8_t prefix[12];
} __attribute__((__packed__));

 int pref64_plc_to_prefix_length(uint8_t plc, uint8_t *ret);
