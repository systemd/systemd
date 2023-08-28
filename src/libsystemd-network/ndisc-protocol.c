/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ndisc-protocol.h"

static const uint8_t prefix_length_code_to_prefix_length[_PREFIX_LENGTH_CODE_MAX] = {
        [PREFIX_LENGTH_CODE_96] = 96,
        [PREFIX_LENGTH_CODE_64] = 64,
        [PREFIX_LENGTH_CODE_56] = 56,
        [PREFIX_LENGTH_CODE_48] = 48,
        [PREFIX_LENGTH_CODE_40] = 40,
        [PREFIX_LENGTH_CODE_32] = 32,
};

int pref64_plc_to_prefix_length(uint16_t plc, uint8_t *ret) {
        plc &= PREF64_PLC_MASK;
        if (plc >= _PREFIX_LENGTH_CODE_MAX)
                return -EINVAL;

        if (ret)
                *ret = prefix_length_code_to_prefix_length[plc];
        return 0;
}

int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret) {
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(prefix_length_code_to_prefix_length); i++)
                if (prefix_length_code_to_prefix_length[i] == prefixlen) {
                        *ret = i;
                        return 0;
                }

        return -EINVAL;
}
