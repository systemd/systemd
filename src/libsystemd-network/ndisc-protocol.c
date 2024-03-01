/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "ndisc-protocol.h"

int ndisc_option_parse(
                ICMP6Packet *p,
                size_t offset,
                uint8_t *ret_type,
                size_t *ret_len,
                const uint8_t **ret_opt) {

        assert(p);

        if (offset == p->raw_size)
                return -ESPIPE; /* end of the packet */

        if (offset > p->raw_size)
                return -EBADMSG;

        if (p->raw_size - offset < sizeof(struct nd_opt_hdr))
                return -EBADMSG;

        assert_cc(alignof(struct nd_opt_hdr) == 1);
        const struct nd_opt_hdr *hdr = (const struct nd_opt_hdr*) (p->raw_packet + offset);
        if (hdr->nd_opt_len == 0)
                return -EBADMSG;

        size_t len = hdr->nd_opt_len * 8;
        if (p->raw_size - offset < len)
                return -EBADMSG;

        if (ret_type)
                *ret_type = hdr->nd_opt_type;
        if (ret_len)
                *ret_len = len;
        if (ret_opt)
                *ret_opt = p->raw_packet + offset;

        return 0;
}

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
