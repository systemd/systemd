/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ipv6.h>
#include <netinet/icmp6.h>

#include "dns-resolver-internal.h"
#include "dns-domain.h"
#include "ether-addr-util.h"
#include "hostname-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "missing_network.h"
#include "ndisc-option.h"
#include "network-common.h"
#include "strv.h"
#include "unaligned.h"

/* RFC does not say anything about the maximum number of options, but let's limit the number of options for
 * safety. Typically, the number of options in an ICMPv6 message should be only a few. */
#define MAX_OPTIONS 128

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

static sd_ndisc_option* ndisc_option_new(uint8_t type, size_t offset) {
        sd_ndisc_option *p = new0(sd_ndisc_option, 1); /* use new0() here to make the fuzzers silent. */
        if (!p)
                return NULL;

        /* As the same reason in the above, do not use the structured initializer here. */
        p->type = type;
        p->offset = offset;

        return p;
}

static void ndisc_raw_done(sd_ndisc_raw *raw) {
        if (!raw)
                return;

        free(raw->bytes);
}

static void ndisc_rdnss_done(sd_ndisc_rdnss *rdnss) {
        if (!rdnss)
                return;

        free(rdnss->addresses);
}

static void ndisc_dnssl_done(sd_ndisc_dnssl *dnssl) {
        if (!dnssl)
                return;

        strv_free(dnssl->domains);
}

static void ndisc_dnr_done(sd_ndisc_dnr *dnr) {
        if (!dnr)
                return;

        sd_dns_resolver_unref(dnr->resolver);
}

sd_ndisc_option* ndisc_option_free(sd_ndisc_option *option) {
        if (!option)
                return NULL;

        switch (option->type) {
        case 0:
                ndisc_raw_done(&option->raw);
                break;

        case SD_NDISC_OPTION_RDNSS:
                ndisc_rdnss_done(&option->rdnss);
                break;

        case SD_NDISC_OPTION_DNSSL:
                ndisc_dnssl_done(&option->dnssl);
                break;

        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                free(option->captive_portal);
                break;

        case SD_NDISC_OPTION_ENCRYPTED_DNS:
                ndisc_dnr_done(&option->encrypted_dns);
                break;
        }

        return mfree(option);
}

static int ndisc_option_compare_func(const sd_ndisc_option *x, const sd_ndisc_option *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->type, y->type);
        if (r != 0)
                return r;

        switch (x->type) {
        case 0:
                return memcmp_nn(x->raw.bytes, x->raw.length, y->raw.bytes, y->raw.length);

        case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
        case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
        case SD_NDISC_OPTION_REDIRECTED_HEADER:
        case SD_NDISC_OPTION_MTU:
        case SD_NDISC_OPTION_HOME_AGENT:
        case SD_NDISC_OPTION_FLAGS_EXTENSION:
        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                /* These options cannot be specified multiple times. */
                return 0;

        case SD_NDISC_OPTION_PREFIX_INFORMATION:
                /* Should not specify the same prefix multiple times. */
                r = CMP(x->prefix.prefixlen, y->prefix.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->prefix.address, &y->prefix.address, sizeof(struct in6_addr));

        case SD_NDISC_OPTION_ROUTE_INFORMATION:
                r = CMP(x->route.prefixlen, y->route.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->route.address, &y->route.address, sizeof(struct in6_addr));

        case SD_NDISC_OPTION_PREF64:
                r = CMP(x->prefix64.prefixlen, y->prefix64.prefixlen);
                if (r != 0)
                        return r;

                return memcmp(&x->prefix64.prefix, &y->prefix64.prefix, sizeof(struct in6_addr));

        default:
                /* DNSSL, RDNSS, and other unsupported options can be specified multiple times. */
                return trivial_compare_func(x, y);
        }
}

static void ndisc_option_hash_func(const sd_ndisc_option *option, struct siphash *state) {
        assert(option);
        assert(state);

        siphash24_compress_typesafe(option->type, state);

        switch (option->type) {
        case 0:
                siphash24_compress(option->raw.bytes, option->raw.length, state);
                break;

        case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
        case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
        case SD_NDISC_OPTION_REDIRECTED_HEADER:
        case SD_NDISC_OPTION_MTU:
        case SD_NDISC_OPTION_HOME_AGENT:
        case SD_NDISC_OPTION_FLAGS_EXTENSION:
        case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                break;

        case SD_NDISC_OPTION_PREFIX_INFORMATION:
                siphash24_compress_typesafe(option->prefix.prefixlen, state);
                siphash24_compress_typesafe(option->prefix.address, state);
                break;

        case SD_NDISC_OPTION_ROUTE_INFORMATION:
                siphash24_compress_typesafe(option->route.prefixlen, state);
                siphash24_compress_typesafe(option->route.address, state);
                break;

        case SD_NDISC_OPTION_PREF64:
                siphash24_compress_typesafe(option->prefix64.prefixlen, state);
                siphash24_compress_typesafe(option->prefix64.prefix, state);
                break;

        default:
                trivial_hash_func(option, state);
        }
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                ndisc_option_hash_ops,
                sd_ndisc_option,
                ndisc_option_hash_func,
                ndisc_option_compare_func,
                ndisc_option_free);

static int ndisc_option_consume(Set **options, sd_ndisc_option *p) {
        assert(options);
        assert(p);

        if (set_size(*options) >= MAX_OPTIONS) {
                ndisc_option_free(p);
                return -ETOOMANYREFS; /* recognizable error code */
        }

        return set_ensure_consume(options, &ndisc_option_hash_ops, p);
}

int ndisc_option_set_raw(Set **options, size_t length, const uint8_t *bytes) {
        _cleanup_free_ uint8_t *copy = NULL;

        assert(options);
        assert(bytes);

        if (length == 0)
                return -EINVAL;

        copy = newdup(uint8_t, bytes, length);
        if (!copy)
                return -ENOMEM;

        sd_ndisc_option *p = ndisc_option_new(/* type = */ 0, /* offset = */ 0);
        if (!p)
                return -ENOMEM;

        p->raw = (sd_ndisc_raw) {
                .bytes = TAKE_PTR(copy),
                .length = length,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_build_raw(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(option->type == 0);
        assert(ret);

        _cleanup_free_ uint8_t *buf = newdup(uint8_t, option->raw.bytes, option->raw.length);
        if (!buf)
                return -ENOMEM;

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_link_layer_address(Set **options, uint8_t type, size_t offset, const struct ether_addr *mac) {
        assert(options);
        assert(IN_SET(type, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS));

        if (!mac || ether_addr_is_null(mac)) {
                ndisc_option_remove_by_type(*options, type);
                return 0;
        }

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, type);
        if (p) {
                /* offset == 0 means that we are now building a packet to be sent, and in that case we allow
                 * to override the option we previously set.
                 * offset != 0 means that we are now parsing a received packet, and we refuse to override
                 * conflicting options. */
                if (offset != 0)
                        return -EEXIST;

                p->mac = *mac;
                return 0;
        }

        p = ndisc_option_new(type, offset);
        if (!p)
                return -ENOMEM;

        p->mac = *mac;

        return set_ensure_consume(options, &ndisc_option_hash_ops, p);
}

static int ndisc_option_parse_link_layer_address(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (len != sizeof(struct ether_addr) + 2)
                return -EBADMSG;

        if (!IN_SET(opt[0], SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS))
                return -EBADMSG;

        struct ether_addr mac;
        memcpy(&mac, opt + 2, sizeof(struct ether_addr));

        if (ether_addr_is_null(&mac))
                return -EBADMSG;

        return ndisc_option_add_link_layer_address(options, opt[0], offset, &mac);
}

static int ndisc_option_build_link_layer_address(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(IN_SET(option->type, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS));
        assert(ret);

        assert_cc(2 + sizeof(struct ether_addr) == 8);

        _cleanup_free_ uint8_t *buf = new(uint8_t, 2 + sizeof(struct ether_addr));
        if (!buf)
                return -ENOMEM;

        buf[0] = option->type;
        buf[1] = 1;
        memcpy(buf + 2, &option->mac, sizeof(struct ether_addr));

        *ret = TAKE_PTR(buf);
        return 0;
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
                usec_t preferred_until) {

        assert(options);
        assert(address);

        if (prefixlen > 128)
                return -EINVAL;

        struct in6_addr addr = *address;
        in6_addr_mask(&addr, prefixlen);

        /* RFC 4861 and 4862 only state that link-local prefix should be ignored.
         * But here we also ignore null and multicast addresses. */
        if (in6_addr_is_link_local(&addr) || in6_addr_is_null(&addr) || in6_addr_is_multicast(&addr))
                return -EINVAL;

        if (preferred_lifetime > valid_lifetime)
                return -EINVAL;

        if (preferred_until > valid_until)
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_get(
                                *options,
                                &(const sd_ndisc_option) {
                                        .type = SD_NDISC_OPTION_PREFIX_INFORMATION,
                                        .prefix.prefixlen = prefixlen,
                                        .prefix.address = addr,
                                });
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->prefix.flags = flags;
                p->prefix.valid_lifetime = valid_lifetime;
                p->prefix.preferred_lifetime = preferred_lifetime;
                p->prefix.valid_until = valid_until;
                p->prefix.preferred_until = preferred_until;
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_PREFIX_INFORMATION, offset);
        if (!p)
                return -ENOMEM;

        p->prefix = (sd_ndisc_prefix) {
                .flags = flags,
                .prefixlen = prefixlen,
                .address = addr,
                .valid_lifetime = valid_lifetime,
                .preferred_lifetime = preferred_lifetime,
                .valid_until = valid_until,
                .preferred_until = preferred_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_prefix(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        const struct nd_opt_prefix_info *pi = (const struct nd_opt_prefix_info*) ASSERT_PTR(opt);

        assert(options);

        if (len != sizeof(struct nd_opt_prefix_info))
                return -EBADMSG;

        if (pi->nd_opt_pi_type != SD_NDISC_OPTION_PREFIX_INFORMATION)
                return -EBADMSG;

        usec_t valid = be32_sec_to_usec(pi->nd_opt_pi_valid_time, /* max_as_infinity = */ true);
        usec_t pref = be32_sec_to_usec(pi->nd_opt_pi_preferred_time, /* max_as_infinity = */ true);

        /* We only support 64 bits interface identifier for addrconf. */
        uint8_t flags = pi->nd_opt_pi_flags_reserved;
        if (FLAGS_SET(flags, ND_OPT_PI_FLAG_AUTO) && pi->nd_opt_pi_prefix_len != 64)
                flags &= ~ND_OPT_PI_FLAG_AUTO;

        return ndisc_option_add_prefix(options, offset, flags,
                                       pi->nd_opt_pi_prefix_len, &pi->nd_opt_pi_prefix,
                                       valid, pref);
}

static int ndisc_option_build_prefix(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_PREFIX_INFORMATION);
        assert(ret);

        assert_cc(sizeof(struct nd_opt_prefix_info) % 8 == 0);

        _cleanup_free_ struct nd_opt_prefix_info *buf = new(struct nd_opt_prefix_info, 1);
        if (!buf)
                return -ENOMEM;

        usec_t valid = MIN(option->prefix.valid_lifetime,
                           usec_sub_unsigned(option->prefix.valid_until, timestamp));
        usec_t pref = MIN3(valid,
                           option->prefix.preferred_lifetime,
                           usec_sub_unsigned(option->prefix.preferred_until, timestamp));

        *buf = (struct nd_opt_prefix_info) {
                .nd_opt_pi_type = SD_NDISC_OPTION_PREFIX_INFORMATION,
                .nd_opt_pi_len = sizeof(struct nd_opt_prefix_info) / 8,
                .nd_opt_pi_prefix_len = option->prefix.prefixlen,
                .nd_opt_pi_flags_reserved = option->prefix.flags,
                .nd_opt_pi_valid_time = usec_to_be32_sec(valid),
                .nd_opt_pi_preferred_time = usec_to_be32_sec(pref),
                .nd_opt_pi_prefix = option->prefix.address,
        };

        *ret = (uint8_t*) TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_redirected_header(Set **options, size_t offset, const struct ip6_hdr *hdr) {
        assert(options);

        if (!hdr) {
                ndisc_option_remove_by_type(*options, SD_NDISC_OPTION_REDIRECTED_HEADER);
                return 0;
        }

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, SD_NDISC_OPTION_REDIRECTED_HEADER);
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                memcpy(&p->hdr, hdr, sizeof(struct ip6_hdr));
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_REDIRECTED_HEADER, offset);
        if (!p)
                return -ENOMEM;

        /* For safety, here we copy only IPv6 header. */
        memcpy(&p->hdr, hdr, sizeof(struct ip6_hdr));

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_redirected_header(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (len < sizeof(struct nd_opt_rd_hdr) + sizeof(struct ip6_hdr))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_REDIRECTED_HEADER)
                return -EBADMSG;

        return ndisc_option_add_redirected_header(options, offset, (const struct ip6_hdr*) (opt + sizeof(struct nd_opt_rd_hdr)));
}

static int ndisc_option_build_redirected_header(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_REDIRECTED_HEADER);
        assert(ret);

        assert_cc((sizeof(struct nd_opt_rd_hdr) + sizeof(struct ip6_hdr)) % 8 == 0);

        size_t len = DIV_ROUND_UP(sizeof(struct nd_opt_rd_hdr) + sizeof(struct ip6_hdr), 8);

        _cleanup_free_ uint8_t *buf = new(uint8_t, len * 8);
        if (!buf)
                return -ENOMEM;

        uint8_t *p;
        p = mempcpy(buf,
                    &(const struct nd_opt_rd_hdr) {
                            .nd_opt_rh_type = SD_NDISC_OPTION_REDIRECTED_HEADER,
                            .nd_opt_rh_len = len,
                    },
                    sizeof(struct nd_opt_rd_hdr));
        memcpy(p, &option->hdr, sizeof(struct ip6_hdr));

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_mtu(Set **options, size_t offset, uint32_t mtu) {
        assert(options);

        if (mtu < IPV6_MIN_MTU)
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, SD_NDISC_OPTION_MTU);
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->mtu = mtu;
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_MTU, offset);
        if (!p)
                return -ENOMEM;

        p->mtu = mtu;

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_mtu(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        const struct nd_opt_mtu *pm = (const struct nd_opt_mtu*) ASSERT_PTR(opt);

        assert(options);

        if (len != sizeof(struct nd_opt_mtu))
                return -EBADMSG;

        if (pm->nd_opt_mtu_type != SD_NDISC_OPTION_MTU)
                return -EBADMSG;

        return ndisc_option_add_mtu(options, offset, be32toh(pm->nd_opt_mtu_mtu));
}

static int ndisc_option_build_mtu(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_MTU);
        assert(ret);

        assert_cc(sizeof(struct nd_opt_mtu) % 8 == 0);

        _cleanup_free_ struct nd_opt_mtu *buf = new(struct nd_opt_mtu, 1);
        if (!buf)
                return -ENOMEM;

        *buf = (struct nd_opt_mtu) {
                .nd_opt_mtu_type = SD_NDISC_OPTION_MTU,
                .nd_opt_mtu_len = sizeof(struct nd_opt_mtu) / 8,
                .nd_opt_mtu_mtu = htobe32(option->mtu),
        };

        *ret = (uint8_t*) TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_home_agent_internal(
                Set **options,
                size_t offset,
                uint16_t preference,
                usec_t lifetime,
                usec_t valid_until) {

        assert(options);

        if (lifetime > UINT16_MAX * USEC_PER_SEC)
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, SD_NDISC_OPTION_HOME_AGENT);
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->home_agent = (sd_ndisc_home_agent) {
                        .preference = preference,
                        .lifetime = lifetime,
                        .valid_until = valid_until,
                };
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_HOME_AGENT, offset);
        if (!p)
                return -ENOMEM;

        p->home_agent = (sd_ndisc_home_agent) {
                .preference = preference,
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_home_agent(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        const struct nd_opt_home_agent_info *p = (const struct nd_opt_home_agent_info*) ASSERT_PTR(opt);

        assert(options);

        if (len != sizeof(struct nd_opt_home_agent_info))
                return -EBADMSG;

        if (p->nd_opt_home_agent_info_type != SD_NDISC_OPTION_HOME_AGENT)
                return -EBADMSG;

        return ndisc_option_add_home_agent(
                        options, offset,
                        be16toh(p->nd_opt_home_agent_info_preference),
                        be16_sec_to_usec(p->nd_opt_home_agent_info_lifetime, /* max_as_infinity = */ false));
}

static int ndisc_option_build_home_agent(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_HOME_AGENT);
        assert(ret);

        assert_cc(sizeof(struct nd_opt_home_agent_info) % 8 == 0);

        usec_t lifetime = MIN(option->home_agent.lifetime,
                              usec_sub_unsigned(option->home_agent.valid_until, timestamp));

        _cleanup_free_ struct nd_opt_home_agent_info *buf = new(struct nd_opt_home_agent_info, 1);
        if (!buf)
                return -ENOMEM;

        *buf = (struct nd_opt_home_agent_info) {
                .nd_opt_home_agent_info_type = SD_NDISC_OPTION_HOME_AGENT,
                .nd_opt_home_agent_info_len = sizeof(struct nd_opt_home_agent_info) / 8,
                .nd_opt_home_agent_info_preference = htobe16(option->home_agent.preference),
                .nd_opt_home_agent_info_lifetime = usec_to_be16_sec(lifetime),
        };

        *ret = (uint8_t*) TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_route_internal(
                Set **options,
                size_t offset,
                uint8_t preference,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until) {

        assert(options);
        assert(prefix);

        if (prefixlen > 128)
                return -EINVAL;

        /* RFC 4191 section 2.3
         * Prf (Route Preference)
         * 2-bit signed integer. The Route Preference indicates whether to prefer the router associated with
         * this prefix over others, when multiple identical prefixes (for different routers) have been
         * received. If the Reserved (10) value is received, the Route Information Option MUST be ignored. */
        if (!IN_SET(preference, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_MEDIUM, SD_NDISC_PREFERENCE_HIGH))
                return -EINVAL;

        struct in6_addr addr = *prefix;
        in6_addr_mask(&addr, prefixlen);

        sd_ndisc_option *p = ndisc_option_get(
                                *options,
                                &(const sd_ndisc_option) {
                                        .type = SD_NDISC_OPTION_ROUTE_INFORMATION,
                                        .route.prefixlen = prefixlen,
                                        .route.address = addr,
                                });
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->route.preference = preference;
                p->route.lifetime = lifetime;
                p->route.valid_until = valid_until;
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_ROUTE_INFORMATION, offset);
        if (!p)
                return -ENOMEM;

        p->route = (sd_ndisc_route) {
                .preference = preference,
                .prefixlen = prefixlen,
                .address = addr,
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_route(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (!IN_SET(len, 1*8, 2*8, 3*8))
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_ROUTE_INFORMATION)
                return -EBADMSG;

        uint8_t prefixlen = opt[2];
        if (prefixlen > 128)
                return -EBADMSG;

        if (len < (size_t) (DIV_ROUND_UP(prefixlen, 64) + 1) * 8)
                return -EBADMSG;

        uint8_t preference = (opt[3] >> 3) & 0x03;
        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);

        struct in6_addr prefix;
        memcpy_safe(&prefix, opt + 8, len - 8);
        in6_addr_mask(&prefix, prefixlen);

        return ndisc_option_add_route(options, offset, preference, prefixlen, &prefix, lifetime);
}

static int ndisc_option_build_route(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_ROUTE_INFORMATION);
        assert(option->route.prefixlen <= 128);
        assert(ret);

        size_t len = 1 + DIV_ROUND_UP(option->route.prefixlen, 64);
        be32_t lifetime = usec_to_be32_sec(MIN(option->route.lifetime,
                                               usec_sub_unsigned(option->route.valid_until, timestamp)));

        _cleanup_free_ uint8_t *buf = new(uint8_t, len * 8);
        if (!buf)
                return -ENOMEM;

        buf[0] = SD_NDISC_OPTION_ROUTE_INFORMATION;
        buf[1] = len;
        buf[2] = option->route.prefixlen;
        buf[3] = option->route.preference << 3;
        memcpy(buf + 4, &lifetime, sizeof(be32_t));
        memcpy_safe(buf + 8, &option->route.address, (len - 1) * 8);

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_rdnss_internal(
                Set **options,
                size_t offset,
                size_t n_addresses,
                const struct in6_addr *addresses,
                usec_t lifetime,
                usec_t valid_until) {

        assert(options);
        assert(addresses);

        if (n_addresses == 0)
                return -EINVAL;

        _cleanup_free_ struct in6_addr *addrs = newdup(struct in6_addr, addresses, n_addresses);
        if (!addrs)
                return -ENOMEM;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_RDNSS, offset);
        if (!p)
                return -ENOMEM;

        p->rdnss = (sd_ndisc_rdnss) {
                .n_addresses = n_addresses,
                .addresses = TAKE_PTR(addrs),
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_rdnss(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (len < 8 + sizeof(struct in6_addr) || (len % sizeof(struct in6_addr)) != 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_RDNSS)
                return -EBADMSG;

        usec_t lifetime = unaligned_be32_sec_to_usec(opt + 4, /* max_as_infinity = */ true);
        size_t n_addrs = len / sizeof(struct in6_addr);

        return ndisc_option_add_rdnss(options, offset, n_addrs, (const struct in6_addr*) (opt + 8), lifetime);
}

static int ndisc_option_build_rdnss(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_RDNSS);
        assert(ret);

        size_t len = option->rdnss.n_addresses * 2 + 1;
        be32_t lifetime = usec_to_be32_sec(MIN(option->rdnss.lifetime,
                                               usec_sub_unsigned(option->rdnss.valid_until, timestamp)));

        _cleanup_free_ uint8_t *buf = new(uint8_t, len * 8);
        if (!buf)
                return -ENOMEM;

        buf[0] = SD_NDISC_OPTION_RDNSS;
        buf[1] = len;
        buf[2] = 0;
        buf[3] = 0;
        memcpy(buf + 4, &lifetime, sizeof(be32_t));
        memcpy(buf + 8, option->rdnss.addresses, sizeof(struct in6_addr) * option->rdnss.n_addresses);

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_flags_extension(Set **options, size_t offset, uint64_t flags) {
        assert(options);

        if ((flags & UINT64_C(0x00ffffffffffff00)) != flags)
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, SD_NDISC_OPTION_FLAGS_EXTENSION);
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->extended_flags = flags;
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_FLAGS_EXTENSION, offset);
        if (!p)
                return -ENOMEM;

        p->extended_flags = flags;

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_flags_extension(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (len != 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_FLAGS_EXTENSION)
                return -EBADMSG;

        uint64_t flags = (unaligned_read_be64(opt) & UINT64_C(0xffffffffffff0000)) >> 8;
        return ndisc_option_add_flags_extension(options, offset, flags);
}

static int ndisc_option_build_flags_extension(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_FLAGS_EXTENSION);
        assert(ret);

        _cleanup_free_ uint8_t *buf = new(uint8_t, 8);
        if (!buf)
                return 0;

        unaligned_write_be64(buf, (option->extended_flags & UINT64_C(0x00ffffffffffff00)) << 8);
        buf[0] = SD_NDISC_OPTION_FLAGS_EXTENSION;
        buf[1] = 1;

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_dnssl_internal(
                Set **options,
                size_t offset, char *
                const *domains,
                usec_t lifetime,
                usec_t valid_until) {

        int r;

        assert(options);

        if (strv_isempty(domains))
                return -EINVAL;

        STRV_FOREACH(s, domains) {
                r = dns_name_is_valid(*s);
                if (r < 0)
                        return r;

                if (is_localhost(*s) || dns_name_is_root(*s))
                        return -EINVAL;
        }

        _cleanup_strv_free_ char **copy = strv_copy(domains);
        if (!copy)
                return -ENOMEM;

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_DNSSL, offset);
        if (!p)
                return -ENOMEM;

        p->dnssl = (sd_ndisc_dnssl) {
                .domains = TAKE_PTR(copy),
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_dnssl(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        int r;

        assert(options);
        assert(opt);

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

        return ndisc_option_add_dnssl(options, offset, l, lifetime);
}

 static int ndisc_option_build_dnssl(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        int r;

        assert(option);
        assert(option->type == SD_NDISC_OPTION_DNSSL);
        assert(ret);

        size_t len = 8;
        STRV_FOREACH(s, option->dnssl.domains)
                len += strlen(*s) + 2;
        len = DIV_ROUND_UP(len, 8);

        be32_t lifetime = usec_to_be32_sec(MIN(option->dnssl.lifetime,
                                               usec_sub_unsigned(option->dnssl.valid_until, timestamp)));

        _cleanup_free_ uint8_t *buf = new(uint8_t, len * 8);
        if (!buf)
                return -ENOMEM;

        buf[0] = SD_NDISC_OPTION_DNSSL;
        buf[1] = len;
        buf[2] = 0;
        buf[3] = 0;
        memcpy(buf + 4, &lifetime, sizeof(be32_t));

        size_t remaining = len * 8 - 8;
        uint8_t *p = buf + 8;

        STRV_FOREACH(s, option->dnssl.domains) {
                r = dns_name_to_wire_format(*s, p, remaining, /* canonical = */ false);
                if (r < 0)
                        return r;

                assert(remaining >= (size_t) r);
                p += r;
                remaining -= r;
        }

        memzero(p, remaining);

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_captive_portal(Set **options, size_t offset, const char *portal) {
        assert(options);

        if (isempty(portal))
                return -EINVAL;

        if (!in_charset(portal, URI_VALID))
                return -EINVAL;

        sd_ndisc_option *p = ndisc_option_get_by_type(*options, SD_NDISC_OPTION_CAPTIVE_PORTAL);
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                return free_and_strdup(&p->captive_portal, portal);
        }

        _cleanup_free_ char *copy = strdup(portal);
        if (!copy)
                return -ENOMEM;

        p = ndisc_option_new(SD_NDISC_OPTION_CAPTIVE_PORTAL, offset);
        if (!p)
                return -ENOMEM;

        p->captive_portal = TAKE_PTR(copy);

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_captive_portal(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);

        if (len < 8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_CAPTIVE_PORTAL)
                return -EBADMSG;

        _cleanup_free_ char *portal = memdup_suffix0(opt + 2, len - 2);
        if (!portal)
                return -ENOMEM;

        size_t size = strlen(portal);
        if (size == 0)
                return -EBADMSG;

        /* Check that the message is not truncated by an embedded NUL.
         * NUL padding to a multiple of 8 is expected. */
        if (DIV_ROUND_UP(size + 2, 8) * 8 != len && DIV_ROUND_UP(size + 3, 8) * 8 != len)
                return -EBADMSG;

        return ndisc_option_add_captive_portal(options, offset, portal);
}

static int ndisc_option_build_captive_portal(const sd_ndisc_option *option, uint8_t **ret) {
        assert(option);
        assert(option->type == SD_NDISC_OPTION_CAPTIVE_PORTAL);
        assert(ret);

        size_t len_portal = strlen(option->captive_portal);
        size_t len = DIV_ROUND_UP(len_portal + 1 + 2, 8);

        _cleanup_free_ uint8_t *buf = new(uint8_t, len * 8);
        if (!buf)
                return -ENOMEM;

        buf[0] = SD_NDISC_OPTION_CAPTIVE_PORTAL;
        buf[1] = len;

        uint8_t *p = mempcpy(buf + 2, option->captive_portal, len_portal);
        size_t remaining = len * 8 - 2 - len_portal;

        memzero(p, remaining);

        *ret = TAKE_PTR(buf);
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

int pref64_prefix_length_to_plc(uint8_t prefixlen, uint8_t *ret) {
        for (size_t i = 0; i < ELEMENTSOF(prefix_length_code_to_prefix_length); i++)
                if (prefix_length_code_to_prefix_length[i] == prefixlen) {
                        if (ret)
                                *ret = i;
                        return 0;
                }

        return -EINVAL;
}

static int pref64_lifetime_and_plc_parse(uint16_t lifetime_and_plc, uint8_t *ret_prefixlen, usec_t *ret_lifetime) {
        uint16_t plc = lifetime_and_plc & PREF64_PLC_MASK;
        if (plc >= _PREFIX_LENGTH_CODE_MAX)
                return -EINVAL;

        if (ret_prefixlen)
                *ret_prefixlen = prefix_length_code_to_prefix_length[plc];
        if (ret_lifetime)
                *ret_lifetime = (lifetime_and_plc & PREF64_SCALED_LIFETIME_MASK) * USEC_PER_SEC;
        return 0;
}

int ndisc_option_add_prefix64_internal(
                Set **options,
                size_t offset,
                uint8_t prefixlen,
                const struct in6_addr *prefix,
                usec_t lifetime,
                usec_t valid_until) {

        int r;

        assert(options);
        assert(prefix);

        r = pref64_prefix_length_to_plc(prefixlen, NULL);
        if (r < 0)
                return r;

        if (lifetime > PREF64_MAX_LIFETIME_USEC)
                return -EINVAL;

        struct in6_addr addr = *prefix;
        in6_addr_mask(&addr, prefixlen);

        sd_ndisc_option *p = ndisc_option_get(
                                *options,
                                &(const sd_ndisc_option) {
                                        .type = SD_NDISC_OPTION_PREF64,
                                        .prefix64.prefixlen = prefixlen,
                                        .prefix64.prefix = addr,
                                });
        if (p) {
                if (offset != 0)
                        return -EEXIST;

                p->prefix64.lifetime = lifetime;
                p->prefix64.valid_until = valid_until;
                return 0;
        }

        p = ndisc_option_new(SD_NDISC_OPTION_PREF64, offset);
        if (!p)
                return -ENOMEM;

        p->prefix64 = (sd_ndisc_prefix64) {
                .prefixlen = prefixlen,
                .prefix = addr,
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_option_parse_prefix64(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        int r;

        assert(options);
        assert(opt);

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

        return ndisc_option_add_prefix64(options, offset, prefixlen, &prefix, lifetime);
}

static int ndisc_option_build_prefix64(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        int r;

        assert(option);
        assert(option->type == SD_NDISC_OPTION_PREF64);
        assert(ret);

        uint8_t code;
        r = pref64_prefix_length_to_plc(option->prefix64.prefixlen, &code);
        if (r < 0)
                return r;

        uint16_t lifetime = (uint16_t) DIV_ROUND_UP(MIN(option->prefix64.lifetime,
                                                        usec_sub_unsigned(option->prefix64.valid_until, timestamp)),
                                                    USEC_PER_SEC) & PREF64_SCALED_LIFETIME_MASK;

        _cleanup_free_ uint8_t *buf = new(uint8_t, 2 * 8);
        if (!buf)
                return -ENOMEM;

        buf[0] = SD_NDISC_OPTION_PREF64;
        buf[1] = 2;
        unaligned_write_be16(buf + 2, lifetime | code);
        memcpy(buf + 4, &option->prefix64.prefix, 12);

        *ret = TAKE_PTR(buf);
        return 0;
}

int ndisc_option_add_encrypted_dns_internal(
                Set **options,
                size_t offset,
                sd_dns_resolver *res,
                usec_t lifetime,
                usec_t valid_until) {
        assert(options);

        sd_ndisc_option *p = ndisc_option_new(SD_NDISC_OPTION_ENCRYPTED_DNS, offset);
        if (!p)
                return -ENOMEM;

        p->encrypted_dns = (sd_ndisc_dnr) {
                .resolver = res,
                .lifetime = lifetime,
                .valid_until = valid_until,
        };

        return ndisc_option_consume(options, p);
}

static int ndisc_get_dns_name(const uint8_t *optval, size_t optlen, char **ret) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(optval || optlen == 0);
        assert(ret);

        r = dns_name_from_wire_format(&optval, &optlen, &name);
        if (r < 0)
                return r;
        if (r == 0 || optlen != 0)
                return -EBADMSG;

        *ret = TAKE_PTR(name);
        return r;
}

static int ndisc_option_parse_encrypted_dns(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        int r;

        assert(options);
        assert(opt);
        _cleanup_(sd_dns_resolver_done) sd_dns_resolver res = {};
        usec_t lifetime;
        size_t ilen;

        /* Every field up to and including adn must be present */
        if (len < 2*8)
                return -EBADMSG;

        if (opt[0] != SD_NDISC_OPTION_ENCRYPTED_DNS)
                return -EBADMSG;

        size_t off = 2;

        /* Priority */
        res.priority = unaligned_read_be16(opt + off);
        /* Alias mode is not allowed */
        if (res.priority == 0)
                return -EBADMSG;
        off += sizeof(uint16_t);

        /* Lifetime */
        lifetime = unaligned_be32_sec_to_usec(opt + off, /* max_as_infinity = */ true);
        off += sizeof(uint32_t);

        /* adn field (length + dns-name) */
        ilen = unaligned_read_be16(opt + off);
        off += sizeof(uint16_t);
        if (off + ilen > len)
                return -EBADMSG;

        r = ndisc_get_dns_name(opt + off, ilen, &res.auth_name);
        if (r < 0)
                return r;
        r = dns_name_is_valid_ldh(res.auth_name);
        if (r < 0)
                return r;
        if (!r)
                return -EBADMSG;
        if (dns_name_is_root(res.auth_name))
                return -EBADMSG;
        off += ilen;

        /* This is the last field in adn-only mode, sans padding */
        if (8 * DIV_ROUND_UP(off, 8) == len && memeqzero(opt + off, len - off))
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Received ADN-only encrypted DNS option, ignoring.");

        /* Fields following the variable (octets) length adn field are no longer certain to be aligned. */

        /* addrs (length + packed struct in6_addr) */
        if (off + sizeof(uint16_t) > len)
                return -EBADMSG;
        ilen = unaligned_read_be16(opt + off);
        off += sizeof(uint16_t);
        if (off + ilen > len || ilen % (sizeof(struct in6_addr)) != 0)
                return -EBADMSG;

        size_t n_addrs = ilen / (sizeof(struct in6_addr));
        if (n_addrs == 0)
                return -EBADMSG;
        res.addrs = new(union in_addr_union, n_addrs);
        if (!res.addrs)
                return -ENOMEM;

        for (size_t i = 0; i < n_addrs; i++) {
                union in_addr_union addr;
                memcpy(&addr.in6, opt + off, sizeof(struct in6_addr));
                if (in_addr_is_multicast(AF_INET6, &addr) ||
                    in_addr_is_localhost(AF_INET, &addr))
                        return -EBADMSG;
                res.addrs[i] = addr;
                off += sizeof(struct in6_addr);
        }
        res.n_addrs = n_addrs;
        res.family = AF_INET6;

        /* SvcParam field. (length + SvcParams) */
        if (off + sizeof(uint16_t) > len)
                return -EBADMSG;
        ilen = unaligned_read_be16(opt + off);
        off += sizeof(uint16_t);
        if (off + ilen > len)
                return -EBADMSG;

        r = dnr_parse_svc_params(opt + off, ilen, &res);
        if (r < 0)
                return r;
        if (r == 0) /* This indicates a valid message we don't support */
                return -EOPNOTSUPP;
        off += ilen;

        /* the remaining padding bytes must be zeroed */
        if (len - off >= 8 || !memeqzero(opt + off, len - off))
                return -EBADMSG;

        sd_dns_resolver *new_res = new(sd_dns_resolver, 1);
        if (!new_res)
                return -ENOMEM;

        *new_res = TAKE_STRUCT(res);

        return ndisc_option_add_encrypted_dns(options, offset, new_res, lifetime);
}

static int ndisc_option_build_encrypted_dns(const sd_ndisc_option *option, usec_t timestamp, uint8_t **ret) {
        int r;

        assert(option);
        assert(option->type == SD_NDISC_OPTION_ENCRYPTED_DNS);
        assert(ret);

        size_t off, len, ilen, plen, poff;

        /* Everything up to adn field is required, so we need at least 2*8 bytes */
        _cleanup_free_ uint8_t *buf = new(uint8_t, 2 * 8);
        if (!buf)
                return -ENOMEM;

        _cleanup_strv_free_ char **alpns = NULL;
        const sd_dns_resolver *res = option->encrypted_dns.resolver;
        be32_t lifetime = usec_to_be32_sec(MIN(option->encrypted_dns.lifetime,
                                               usec_sub_unsigned(option->encrypted_dns.valid_until, timestamp)));

        /* Type (Length field filled in last) */
        buf[0] = option->type;

        /* Priority */
        off = 2;
        unaligned_write_be16(buf + off, res->priority);
        off += sizeof(be16_t);

        /* Lifetime */
        memcpy(buf + off, &lifetime, sizeof(be32_t));
        off += sizeof(be32_t);

        /* ADN */
        //FIXME can the wire format be longer than this?
        ilen = strlen(res->auth_name) + 2;

        /* From now on, there isn't guaranteed to be enough space to put each field */
        if (!GREEDY_REALLOC(buf, off + sizeof(uint16_t) + ilen))
                return -ENOMEM;

        r = dns_name_to_wire_format(res->auth_name, buf + off + sizeof(uint16_t), ilen, /* canonical = */ false);
        if (r < 0)
                return r;
        unaligned_write_be16(buf + off, (uint16_t) r);
        off += sizeof(uint16_t) + r;

        /* ADN-only mode */
        if (res->n_addrs == 0)
                goto padding;

        /* addrs */
        if (size_multiply_overflow(sizeof(struct in6_addr), res->n_addrs))
                return -ENOMEM;

        ilen = res->n_addrs * sizeof(struct in6_addr);
        if (!GREEDY_REALLOC(buf, off + sizeof(uint16_t) + ilen))
                return -ENOMEM;

        unaligned_write_be16(buf + off, ilen);
        off += sizeof(uint16_t);

        FOREACH_ARRAY(addr, res->addrs, res->n_addrs) {
                memcpy(buf + off, &addr->in6, sizeof(struct in6_addr));
                off += sizeof(struct in6_addr);
        }

        /* SvcParam, MUST appear in order */
        poff = off + sizeof(uint16_t);

        /* ALPN */
        dns_resolver_transports_to_strv(res->transports, &alpns);

        /* res needs to have at least one valid transport */
        if (strv_isempty(alpns))
                return -EINVAL;

        plen = 0;
        STRV_FOREACH(alpn, alpns)
                plen += sizeof(uint8_t) + strlen(*alpn);

        if (!GREEDY_REALLOC(buf, poff + 2 * sizeof(uint16_t) + plen))
                return -ENOMEM;

        unaligned_write_be16(buf + poff, (uint16_t) DNS_SVC_PARAM_KEY_ALPN);
        poff += sizeof(uint16_t);
        unaligned_write_be16(buf + poff, plen);
        poff += sizeof(uint16_t);

        STRV_FOREACH(alpn, alpns) {
                size_t alen = strlen(*alpn);
                buf[poff++] = alen;
                memcpy(buf + poff, *alpn, alen);
                poff += alen;
        }

        /* port */
        if (res->port > 0) {
                plen = 2;
                if (!GREEDY_REALLOC(buf, poff + 2 * sizeof(uint16_t) + plen))
                        return -ENOMEM;

                unaligned_write_be16(buf + poff, (uint16_t) DNS_SVC_PARAM_KEY_PORT);
                poff += sizeof(uint16_t);
                unaligned_write_be16(buf + poff, plen);
                poff += sizeof(uint16_t);
                unaligned_write_be16(buf + poff, res->port);
                poff += sizeof(uint16_t);
        }

        /* dohpath */
        if (res->dohpath) {
                plen = strlen(res->dohpath);
                if (!GREEDY_REALLOC(buf, poff + 2 * sizeof(uint16_t) + plen))
                        return -ENOMEM;

                unaligned_write_be16(buf + poff, (uint16_t) DNS_SVC_PARAM_KEY_DOHPATH);
                poff += sizeof(uint16_t);
                unaligned_write_be16(buf + poff, plen);
                poff += sizeof(uint16_t);
                memcpy(buf + poff, res->dohpath, plen);
                poff += plen;
        }

        unaligned_write_be16(buf + off, LESS_BY(poff, off));
        off = poff;

padding:
        len = DIV_ROUND_UP(off, 8);
        if (!GREEDY_REALLOC(buf, 8*len))
                return -ENOMEM;
        memzero(buf + off, 8*len - off);

        buf[1] = len;
        *ret = TAKE_PTR(buf);
        return 0;
}

static int ndisc_option_parse_default(Set **options, size_t offset, size_t len, const uint8_t *opt) {
        assert(options);
        assert(opt);
        assert(len > 0);

        sd_ndisc_option *p = ndisc_option_new(opt[0], offset);
        if (!p)
                return -ENOMEM;

        return ndisc_option_consume(options, p);
}

static int ndisc_header_size(uint8_t icmp6_type) {
        switch (icmp6_type) {
        case ND_ROUTER_SOLICIT:
                return sizeof(struct nd_router_solicit);
        case ND_ROUTER_ADVERT:
                return sizeof(struct nd_router_advert);
        case ND_NEIGHBOR_SOLICIT:
                return sizeof(struct nd_neighbor_solicit);
        case ND_NEIGHBOR_ADVERT:
                return sizeof(struct nd_neighbor_advert);
        case ND_REDIRECT:
                return sizeof(struct nd_redirect);
        default:
                return -EINVAL;
        }
}

int ndisc_parse_options(ICMP6Packet *packet, Set **ret_options) {
        _cleanup_set_free_ Set *options = NULL;
        int r;

        assert(packet);
        assert(ret_options);

        r = icmp6_packet_get_type(packet);
        if (r < 0)
                return r;

        r = ndisc_header_size(r);
        if (r < 0)
                return -EBADMSG;
        size_t header_size = r;

        if (packet->raw_size < header_size)
                return -EBADMSG;

        for (size_t length, offset = header_size; offset < packet->raw_size; offset += length) {
                uint8_t type;
                const uint8_t *opt;

                r = ndisc_option_parse(packet, offset, &type, &length, &opt);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse NDisc option header: %m");

                switch (type) {
                case 0:
                        r = -EBADMSG;
                        break;

                case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
                case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
                        r = ndisc_option_parse_link_layer_address(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_PREFIX_INFORMATION:
                        r = ndisc_option_parse_prefix(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_REDIRECTED_HEADER:
                        r = ndisc_option_parse_redirected_header(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_MTU:
                        r = ndisc_option_parse_mtu(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_HOME_AGENT:
                        r = ndisc_option_parse_home_agent(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_option_parse_route(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        r = ndisc_option_parse_rdnss(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_FLAGS_EXTENSION:
                        r = ndisc_option_parse_flags_extension(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        r = ndisc_option_parse_dnssl(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                        r = ndisc_option_parse_captive_portal(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_PREF64:
                        r = ndisc_option_parse_prefix64(&options, offset, length, opt);
                        break;

                case SD_NDISC_OPTION_ENCRYPTED_DNS:
                        r = ndisc_option_parse_encrypted_dns(&options, offset, length, opt);
                        break;

                default:
                        r = ndisc_option_parse_default(&options, offset, length, opt);
                }
                if (r == -ENOMEM)
                        return log_oom_debug();
                if (r < 0)
                        log_debug_errno(r, "Failed to parse NDisc option %u, ignoring: %m", type);
        }

        *ret_options = TAKE_PTR(options);
        return 0;
}

int ndisc_option_get_mac(Set *options, uint8_t type, struct ether_addr *ret) {
        assert(IN_SET(type, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, SD_NDISC_OPTION_TARGET_LL_ADDRESS));

        sd_ndisc_option *p = ndisc_option_get_by_type(options, type);
        if (!p)
                return -ENODATA;

        if (ret)
                *ret = p->mac;
        return 0;
}

int ndisc_send(int fd, const struct in6_addr *dst, const struct icmp6_hdr *hdr, Set *options, usec_t timestamp) {
        int r;

        assert(fd >= 0);
        assert(dst);
        assert(hdr);

        size_t n;
        _cleanup_free_ sd_ndisc_option **list = NULL;
        r = set_dump_sorted(options, (void***) &list, &n);
        if (r < 0)
                return r;

        struct iovec *iov = NULL;
        size_t n_iov = 0;
        CLEANUP_ARRAY(iov, n_iov, iovec_array_free);

        iov = new(struct iovec, 1 + n);
        if (!iov)
                return -ENOMEM;

        r = ndisc_header_size(hdr->icmp6_type);
        if (r < 0)
                return r;
        size_t hdr_size = r;

        _cleanup_free_ uint8_t *copy = newdup(uint8_t, hdr, hdr_size);
        if (!copy)
                return -ENOMEM;

        iov[n_iov++] = IOVEC_MAKE(TAKE_PTR(copy), hdr_size);

        FOREACH_ARRAY(p, list, n) {
                _cleanup_free_ uint8_t *buf = NULL;
                sd_ndisc_option *option = *p;

                switch (option->type) {
                case 0:
                        r = ndisc_option_build_raw(option, &buf);
                        break;

                case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
                case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
                        r = ndisc_option_build_link_layer_address(option, &buf);
                        break;

                case SD_NDISC_OPTION_PREFIX_INFORMATION:
                        r = ndisc_option_build_prefix(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_REDIRECTED_HEADER:
                        r = ndisc_option_build_redirected_header(option, &buf);
                        break;

                case SD_NDISC_OPTION_MTU:
                        r = ndisc_option_build_mtu(option, &buf);
                        break;

                case SD_NDISC_OPTION_HOME_AGENT:
                        r = ndisc_option_build_home_agent(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        r = ndisc_option_build_route(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_RDNSS:
                        r = ndisc_option_build_rdnss(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_FLAGS_EXTENSION:
                        r = ndisc_option_build_flags_extension(option, &buf);
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        r = ndisc_option_build_dnssl(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_CAPTIVE_PORTAL:
                        r = ndisc_option_build_captive_portal(option, &buf);
                        break;

                case SD_NDISC_OPTION_PREF64:
                        r = ndisc_option_build_prefix64(option, timestamp, &buf);
                        break;

                case SD_NDISC_OPTION_ENCRYPTED_DNS:
                        r = ndisc_option_build_encrypted_dns(option, timestamp, &buf);
                        break;

                default:
                        continue;
                }
                if (r == -ENOMEM)
                        return log_oom_debug();
                if (r < 0)
                        log_debug_errno(r, "Failed to build NDisc option %u, ignoring: %m", option->type);

                iov[n_iov++] = IOVEC_MAKE(buf, buf[1] * 8);
                TAKE_PTR(buf);
        }

        return icmp6_send(fd, dst, iov, n_iov);
}
