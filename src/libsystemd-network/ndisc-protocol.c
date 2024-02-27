/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "dns-domain.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "missing_network.h"
#include "ndisc-protocol.h"
#include "network-common.h"
#include "strv.h"
#include "unaligned.h"

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

int ndisc_option_parse_link_layer_address(const uint8_t *opt, size_t len, struct ether_addr *ret) {
        assert(opt);
        assert(ret);

        if (len != sizeof(struct ether_addr) + 2)
                return -EBADMSG;

        if (!IN_SET(opt[0], SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS))
                return -EBADMSG;

        memcpy(ret, opt + 2, sizeof(struct ether_addr));
        return 0;
}

int ndisc_option_parse_prefix(const uint8_t *opt, size_t len, sd_ndisc_prefix *ret) {
        const struct nd_opt_prefix_info *p = (const struct nd_opt_prefix_info*) ASSERT_PTR(opt);

        assert(ret);

        if (len != sizeof(struct nd_opt_prefix_info))
                return -EBADMSG;

        if (p->nd_opt_pi_type != SD_NDISC_OPTION_PREFIX_INFORMATION)
                return -EBADMSG;

        if (p->nd_opt_pi_prefix_len > 128)
                return -EBADMSG;

        if (in6_addr_is_link_local(&p->nd_opt_pi_prefix))
                return -EBADMSG;

        usec_t valid = be32_sec_to_usec(p->nd_opt_pi_valid_time, /* max_as_infinity = */ true);
        usec_t pref = be32_sec_to_usec(p->nd_opt_pi_preferred_time, /* max_as_infinity = */ true);
        if (pref > valid)
                return -EBADMSG;

        /* We only support 64 bits interface identifier for addrconf. */
        uint8_t flags = p->nd_opt_pi_flags_reserved;
        if (FLAGS_SET(flags, ND_OPT_PI_FLAG_AUTO) && p->nd_opt_pi_prefix_len != 64)
                flags &= ~ND_OPT_PI_FLAG_AUTO;

        *ret = (sd_ndisc_prefix) {
                .flags = flags,
                .prefixlen = p->nd_opt_pi_prefix_len,
                .prefix = p->nd_opt_pi_prefix,
                .valid_lifetime = valid,
                .preferred_lifetime = pref,
        };
        return 0;
}

int ndisc_option_parse_redirected_header(const uint8_t *opt, size_t len, struct ip6_hdr *ret) {
        assert(opt);
        assert(ret);

        if (len < sizeof(struct nd_opt_rd_hdr) + sizeof(struct ip6_hdr))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_REDIRECTED_HEADER)
                return -EBADMSG;

        /* For safety, here we copy only IPv6 header. */
        memcpy(ret, opt + sizeof(struct nd_opt_rd_hdr), sizeof(struct ip6_hdr));
        return 0;
}

int ndisc_option_parse_mtu(const uint8_t *opt, size_t len, uint32_t *ret) {
        const struct nd_opt_mtu *p = (const struct nd_opt_mtu*) ASSERT_PTR(opt);

        assert(ret);

        if (len != sizeof(struct nd_opt_mtu))
                return -EBADMSG;

        if (p->nd_opt_mtu_type != SD_NDISC_OPTION_MTU)
                return -EBADMSG;

        uint32_t mtu = be32toh(p->nd_opt_mtu_mtu);
        if (mtu < IPV6_MIN_MTU) /* ignore invalidly small MTUs */
                return -EINVAL;

        *ret = mtu;
        return 0;
}

int ndisc_option_parse_route(const uint8_t *opt, size_t len, sd_ndisc_route *ret) {
        assert(opt);
        assert(ret);

        if (!IN_SET(len, 1*8, 2*8, 3*8))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_ROUTE_INFORMATION)
                return -EBADMSG;

        uint8_t prefixlen = opt[2];
        if (prefixlen > 128)
                return -EBADMSG;

        if (len != (size_t) (DIV_ROUND_UP(prefixlen, 128) + 1) * 8)
                return -EBADMSG;

        uint8_t preference = (opt[3] >> 3) & 0x07;
        if (!IN_SET(preference, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_MEDIUM, SD_NDISC_PREFERENCE_HIGH))
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        struct in6_addr prefix;
        memcpy(&prefix, opt + 8, len - 8);
        in6_addr_mask(&prefix, prefixlen);

        *ret = (sd_ndisc_route) {
                .preference = preference,
                .prefixlen = prefixlen,
                .prefix = prefix,
                .lifetime = lifetime,
        };
        return 0;
}

int ndisc_option_parse_rdnss(const uint8_t *opt, size_t len, sd_ndisc_rdnss *ret) {
        assert(opt);
        assert(ret);

        if (len < 3*8 || (len % (2*8)) != 1*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_RDNSS)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        size_t n = (len - 8) / (2*8);
        struct in6_addr *addrs = newdup(struct in6_addr, (struct in6_addr*) (opt + 8), n);
        if (!addrs)
                return -ENOMEM;

        *ret = (sd_ndisc_rdnss) {
                .lifetime = lifetime,
                .n_addresses = n,
                .addresses = addrs,
        };
        return 0;
}

int ndisc_option_parse_flags_extension(const uint8_t *opt, size_t len, uint8_t basic_flags, uint64_t *ret) {
        assert(opt);
        assert(ret);

        if (len != 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_FLAGS_EXTENSION)
                return -EBADMSG;

        uint64_t extended_flags = (unaligned_read_be64(opt) & 0xffffffffffff0000) >> 8;

        *ret = basic_flags | extended_flags;
        return 0;
}

int ndisc_option_parse_dnssl(const uint8_t *opt, size_t len, sd_ndisc_dnssl *ret) {
        int r;

        assert(opt);
        assert(ret);

        if (len < 2*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_DNSSL)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *e = NULL;
        size_t n = 0;
        for (size_t c, pos = 8; pos < len; pos += c) {

                c = opt[pos];
                pos++;

                if (c == 0) {
                        /* Found NUL termination */

                        if (n > 0) {
                                _cleanup_free_ char *normalized = NULL;

                                e[n] = 0;
                                r = dns_name_normalize(e, 0, &normalized);
                                if (r < 0)
                                        return r;

                                /* Ignore the root domain name or "localhost" and friends */
                                if (!is_localhost(normalized) && !dns_name_is_root(normalized)) {
                                        r = strv_consume(&l, TAKE_PTR(normalized));
                                        if (r < 0)
                                                return r;
                                }
                        }

                        n = 0;
                        continue;
                }

                /* Check for compression (which is not allowed) */
                if (c > 63)
                        return -EBADMSG;

                if (pos + c >= len)
                        return -EBADMSG;

                if (!GREEDY_REALLOC(e, n + (n != 0) + DNS_LABEL_ESCAPED_MAX + 1U))
                        return -ENOMEM;

                if (n != 0)
                        e[n++] = '.';

                r = dns_label_escape((const char*) (opt + pos), c, e + n, DNS_LABEL_ESCAPED_MAX);
                if (r < 0)
                        return r;

                n += r;
        }

        if (n > 0) /* Not properly NUL terminated */
                return -EBADMSG;

        if (strv_isempty(l))
                return -EBADMSG; /* No valid domain? */

        *ret = (sd_ndisc_dnssl) {
                .lifetime = lifetime,
                .domains = TAKE_PTR(l),
        };
        return 0;
}

int ndisc_option_parse_captive_portal(const uint8_t *opt, size_t len, char **ret) {
        assert(opt);
        assert(ret);

        if (len < 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_CAPTIVE_PORTAL)
                return -EBADMSG;

        /* Check that the message is not truncated by an embedded NUL.
         * NUL padding to a multiple of 8 is expected. */
        size_t size = strnlen((const char*) opt + 2, len - 2);
        if (DIV_ROUND_UP(size + 2, 8) * 8 != len)
                return -EBADMSG;

        if (size == 0)
                return -EBADMSG;

        char *p = memdup_suffix0(opt + 2, size);
        if (!p)
                return -ENOMEM;

        *ret = TAKE_PTR(p);
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

int pref64_lifetime_and_plc_parse(uint16_t lifetime_and_plc, uint8_t *ret_prefixlen, usec_t *ret_lifetime) {
        uint16_t plc = lifetime_and_plc & PREF64_PLC_MASK;
        if (plc >= _PREFIX_LENGTH_CODE_MAX)
                return -EINVAL;

        if (ret_prefixlen)
                *ret_prefixlen = prefix_length_code_to_prefix_length[plc];
        if (ret_lifetime)
                *ret_lifetime = (lifetime_and_plc & PREF64_SCALED_LIFETIME_MASK) * USEC_PER_SEC;
        return 0;
}

int pref64_lifetime_and_plc_generate(uint8_t prefixlen, usec_t lifetime, uint16_t *ret) {
        assert(ret);

        if (lifetime > PREF64_MAX_LIFETIME_USEC)
                return -EINVAL;

        uint16_t scaled_lifetime = (uint16_t) DIV_ROUND_UP(lifetime, 8 * USEC_PER_SEC);

        for (size_t i = 0; i < ELEMENTSOF(prefix_length_code_to_prefix_length); i++)
                if (prefix_length_code_to_prefix_length[i] == prefixlen) {
                        *ret = i | scaled_lifetime;
                        return 0;
                }

        return -EINVAL;
}

int ndisc_option_parse_pref64(const uint8_t *opt, size_t len, sd_ndisc_pref64 *ret) {
        int r;

        assert(opt);
        assert(ret);

        if (len != 2*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_PREF64)
                return -EBADMSG;

        uint8_t prefixlen;
        usec_t lifetime;
        r = pref64_lifetime_and_plc_parse(unaligned_read_be16(opt + 2), &prefixlen, &lifetime);
        if (r < 0)
                return r;

        struct in6_addr prefix;
        memcpy(&prefix, opt + 4, len - 4);
        in6_addr_mask(&prefix, prefixlen);

        *ret = (sd_ndisc_pref64) {
                .prefixlen = prefixlen,
                .prefix = prefix,
                .lifetime = lifetime,
        };
        return 0;
}
