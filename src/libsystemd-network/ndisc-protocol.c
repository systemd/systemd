/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "ndisc-protocol.h"

int pref64_plc_to_prefix_length(uint8_t plc, uint8_t *ret) {
        switch (plc) {
        case PREF64_PLC_32:
                *ret = PREF64_PREFIX_LEN_32;
                return 0;
        case PREF64_PLC_40:
                *ret = PREF64_PREFIX_LEN_40;
                return 0;
        case PREF64_PLC_48:
                *ret = PREF64_PREFIX_LEN_48;
                return 0;
        case PREF64_PLC_56:
                *ret = PREF64_PREFIX_LEN_56;
                return 0;
        case PREF64_PLC_64:
                *ret = PREF64_PREFIX_LEN_64;
                return 0;
        case PREF64_PLC_96:
                *ret = PREF64_PREFIX_LEN_96;
                return 0;
        default:
                return -EINVAL;
        }

        return 0;
}
