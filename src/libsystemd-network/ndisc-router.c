/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "hostname-util.h"
#include "memory-util.h"
#include "missing_network.h"
#include "ndisc-internal.h"
#include "ndisc-router.h"
#include "strv.h"

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_router, sd_ndisc_router, mfree);

sd_ndisc_router *ndisc_router_new(size_t raw_size) {
        sd_ndisc_router *rt;

        if (raw_size > SIZE_MAX - ALIGN(sizeof(sd_ndisc_router)))
                return NULL;

        rt = malloc0(ALIGN(sizeof(sd_ndisc_router)) + raw_size);
        if (!rt)
                return NULL;

        rt->raw_size = raw_size;
        rt->n_ref = 1;

        return rt;
}

int sd_ndisc_router_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr) {
        assert_return(rt, -EINVAL);
        assert_return(ret_addr, -EINVAL);

        if (in6_addr_is_null(&rt->address))
                return -ENODATA;

        *ret_addr = rt->address;
        return 0;
}

int sd_ndisc_router_get_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(TRIPLE_TIMESTAMP_HAS_CLOCK(clock), -EOPNOTSUPP);
        assert_return(clock_supported(clock), -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        if (!triple_timestamp_is_set(&rt->timestamp))
                return -ENODATA;

        *ret = triple_timestamp_by_clock(&rt->timestamp, clock);
        return 0;
}

int sd_ndisc_router_get_raw(sd_ndisc_router *rt, const void **ret, size_t *size) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        *ret = NDISC_ROUTER_RAW(rt);
        *size = rt->raw_size;

        return 0;
}

int ndisc_router_parse(sd_ndisc *nd, sd_ndisc_router *rt) {
        struct nd_router_advert *a;
        const uint8_t *p;
        bool has_mtu = false, has_flag_extension = false;
        size_t left;

        assert(rt);

        if (rt->raw_size < sizeof(struct nd_router_advert))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Too small to be a router advertisement, ignoring.");

        /* Router advertisement packets are neatly aligned to 64bit boundaries, hence we can access them directly */
        a = NDISC_ROUTER_RAW(rt);

        if (a->nd_ra_type != ND_ROUTER_ADVERT)
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received ND packet that is not a router advertisement, ignoring.");

        if (a->nd_ra_code != 0)
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received ND packet with wrong RA code, ignoring.");

        rt->hop_limit = a->nd_ra_curhoplimit;
        rt->flags = a->nd_ra_flags_reserved; /* the first 8bit */
        rt->lifetime = be16toh(a->nd_ra_router_lifetime);

        rt->preference = (rt->flags >> 3) & 3;
        if (!IN_SET(rt->preference, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_HIGH))
                rt->preference = SD_NDISC_PREFERENCE_MEDIUM;

        p = (const uint8_t*) NDISC_ROUTER_RAW(rt) + sizeof(struct nd_router_advert);
        left = rt->raw_size - sizeof(struct nd_router_advert);

        for (;;) {
                uint8_t type;
                size_t length;

                if (left == 0)
                        break;

                if (left < 2)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Option lacks header, ignoring datagram.");

                type = p[0];
                length = p[1] * 8;

                if (length == 0)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Zero-length option, ignoring datagram.");
                if (left < length)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Option truncated, ignoring datagram.");

                switch (type) {

                case SD_NDISC_OPTION_PREFIX_INFORMATION:

                        if (length != 4*8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Prefix option of invalid size, ignoring datagram.");

                        if (p[2] > 128)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Bad prefix length, ignoring datagram.");

                        break;

                case SD_NDISC_OPTION_MTU: {
                        uint32_t m;

                        if (has_mtu) {
                                log_ndisc(nd, "MTU option specified twice, ignoring.");
                                break;
                        }

                        if (length != 8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "MTU option of invalid size, ignoring datagram.");

                        m = be32toh(*(uint32_t*) (p + 4));
                        if (m >= IPV6_MIN_MTU) /* ignore invalidly small MTUs */
                                rt->mtu = m;

                        has_mtu = true;
                        break;
                }

                case SD_NDISC_OPTION_ROUTE_INFORMATION:
                        if (length < 1*8 || length > 3*8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Route information option of invalid size, ignoring datagram.");

                        if (p[2] > 128)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Bad route prefix length, ignoring datagram.");

                        break;

                case SD_NDISC_OPTION_RDNSS:
                        if (length < 3*8 || (length % (2*8)) != 1*8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG), "RDNSS option has invalid size.");

                        break;

                case SD_NDISC_OPTION_FLAGS_EXTENSION:

                        if (has_flag_extension) {
                                log_ndisc(nd, "Flags extension option specified twice, ignoring.");
                                break;
                        }

                        if (length < 1*8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Flags extension option has invalid size.");

                        /* Add in the additional flags bits */
                        rt->flags |=
                                ((uint64_t) p[2] << 8) |
                                ((uint64_t) p[3] << 16) |
                                ((uint64_t) p[4] << 24) |
                                ((uint64_t) p[5] << 32) |
                                ((uint64_t) p[6] << 40) |
                                ((uint64_t) p[7] << 48);

                        has_flag_extension = true;
                        break;

                case SD_NDISC_OPTION_DNSSL:
                        if (length < 2*8)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "DNSSL option has invalid size.");

                        break;
                }

                p += length, left -= length;
        }

        rt->rindex = sizeof(struct nd_router_advert);
        return 0;
}

int sd_ndisc_router_get_hop_limit(sd_ndisc_router *rt, uint8_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->hop_limit;
        return 0;
}

int sd_ndisc_router_get_flags(sd_ndisc_router *rt, uint64_t *ret_flags) {
        assert_return(rt, -EINVAL);
        assert_return(ret_flags, -EINVAL);

        *ret_flags = rt->flags;
        return 0;
}

int sd_ndisc_router_get_lifetime(sd_ndisc_router *rt, uint16_t *ret_lifetime) {
        assert_return(rt, -EINVAL);
        assert_return(ret_lifetime, -EINVAL);

        *ret_lifetime = rt->lifetime;
        return 0;
}

int sd_ndisc_router_get_preference(sd_ndisc_router *rt, unsigned *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->preference;
        return 0;
}

int sd_ndisc_router_get_mtu(sd_ndisc_router *rt, uint32_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        if (rt->mtu <= 0)
                return -ENODATA;

        *ret = rt->mtu;
        return 0;
}

int sd_ndisc_router_option_rewind(sd_ndisc_router *rt) {
        assert_return(rt, -EINVAL);

        assert(rt->raw_size >= sizeof(struct nd_router_advert));
        rt->rindex = sizeof(struct nd_router_advert);

        return rt->rindex < rt->raw_size;
}

int sd_ndisc_router_option_next(sd_ndisc_router *rt) {
        size_t length;

        assert_return(rt, -EINVAL);

        if (rt->rindex == rt->raw_size) /* EOF */
                return -ESPIPE;

        if (rt->rindex + 2 > rt->raw_size) /* Truncated message */
                return -EBADMSG;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (rt->rindex + length > rt->raw_size)
                return -EBADMSG;

        rt->rindex += length;
        return rt->rindex < rt->raw_size;
}

int sd_ndisc_router_option_get_type(sd_ndisc_router *rt, uint8_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        if (rt->rindex == rt->raw_size) /* EOF */
                return -ESPIPE;

        if (rt->rindex + 2 > rt->raw_size) /* Truncated message */
                return -EBADMSG;

        *ret = NDISC_ROUTER_OPTION_TYPE(rt);
        return 0;
}

int sd_ndisc_router_option_is_type(sd_ndisc_router *rt, uint8_t type) {
        uint8_t k;
        int r;

        assert_return(rt, -EINVAL);

        r = sd_ndisc_router_option_get_type(rt, &k);
        if (r < 0)
                return r;

        return type == k;
}

int sd_ndisc_router_option_get_raw(sd_ndisc_router *rt, const void **ret, size_t *size) {
        size_t length;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        /* Note that this returns the full option, including the option header */

        if (rt->rindex + 2 > rt->raw_size)
                return -EBADMSG;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (rt->rindex + length > rt->raw_size)
                return -EBADMSG;

        *ret = (uint8_t*) NDISC_ROUTER_RAW(rt) + rt->rindex;
        *size = length;

        return 0;
}

static int get_prefix_info(sd_ndisc_router *rt, struct nd_opt_prefix_info **ret) {
        struct nd_opt_prefix_info *ri;
        size_t length;
        int r;

        assert(rt);
        assert(ret);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_PREFIX_INFORMATION);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (length != sizeof(struct nd_opt_prefix_info))
                return -EBADMSG;

        ri = (struct nd_opt_prefix_info*) ((uint8_t*) NDISC_ROUTER_RAW(rt) + rt->rindex);
        if (ri->nd_opt_pi_prefix_len > 128)
                return -EBADMSG;

        *ret = ri;
        return 0;
}

int sd_ndisc_router_prefix_get_valid_lifetime(sd_ndisc_router *rt, uint32_t *ret) {
        struct nd_opt_prefix_info *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_prefix_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = be32toh(ri->nd_opt_pi_valid_time);
        return 0;
}

int sd_ndisc_router_prefix_get_preferred_lifetime(sd_ndisc_router *rt, uint32_t *ret) {
        struct nd_opt_prefix_info *pi;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_prefix_info(rt, &pi);
        if (r < 0)
                return r;

        *ret = be32toh(pi->nd_opt_pi_preferred_time);
        return 0;
}

int sd_ndisc_router_prefix_get_flags(sd_ndisc_router *rt, uint8_t *ret) {
        struct nd_opt_prefix_info *pi;
        uint8_t flags;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_prefix_info(rt, &pi);
        if (r < 0)
                return r;

        flags = pi->nd_opt_pi_flags_reserved;

        if ((flags & ND_OPT_PI_FLAG_AUTO) && (pi->nd_opt_pi_prefix_len != 64)) {
                log_ndisc(NULL, "Invalid prefix length, ignoring prefix for stateless autoconfiguration.");
                flags &= ~ND_OPT_PI_FLAG_AUTO;
        }

        *ret = flags;
        return 0;
}

int sd_ndisc_router_prefix_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr) {
        struct nd_opt_prefix_info *pi;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret_addr, -EINVAL);

        r = get_prefix_info(rt, &pi);
        if (r < 0)
                return r;

        *ret_addr = pi->nd_opt_pi_prefix;
        return 0;
}

int sd_ndisc_router_prefix_get_prefixlen(sd_ndisc_router *rt, unsigned *ret) {
        struct nd_opt_prefix_info *pi;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_prefix_info(rt, &pi);
        if (r < 0)
                return r;

        if (pi->nd_opt_pi_prefix_len > 128)
                return -EBADMSG;

        *ret = pi->nd_opt_pi_prefix_len;
        return 0;
}

static int get_route_info(sd_ndisc_router *rt, uint8_t **ret) {
        uint8_t *ri;
        size_t length;
        int r;

        assert(rt);
        assert(ret);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_ROUTE_INFORMATION);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (length < 1*8 || length > 3*8)
                return -EBADMSG;

        ri = (uint8_t*) NDISC_ROUTER_RAW(rt) + rt->rindex;

        if (ri[2] > 128)
                return -EBADMSG;

        *ret = ri;
        return 0;
}

int sd_ndisc_router_route_get_lifetime(sd_ndisc_router *rt, uint32_t *ret) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_route_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = be32toh(*(uint32_t*) (ri + 4));
        return 0;
}

int sd_ndisc_router_route_get_address(sd_ndisc_router *rt, struct in6_addr *ret_addr) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret_addr, -EINVAL);

        r = get_route_info(rt, &ri);
        if (r < 0)
                return r;

        zero(*ret_addr);
        memcpy(ret_addr, ri + 8, NDISC_ROUTER_OPTION_LENGTH(rt) - 8);

        return 0;
}

int sd_ndisc_router_route_get_prefixlen(sd_ndisc_router *rt, unsigned *ret) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_route_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = ri[2];
        return 0;
}

int sd_ndisc_router_route_get_preference(sd_ndisc_router *rt, unsigned *ret) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_route_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = (ri[3] >> 3) & 3;
        if (!IN_SET(*ret, SD_NDISC_PREFERENCE_LOW, SD_NDISC_PREFERENCE_HIGH))
                *ret = SD_NDISC_PREFERENCE_MEDIUM;

        return 0;
}

static int get_rdnss_info(sd_ndisc_router *rt, uint8_t **ret) {
        size_t length;
        int r;

        assert(rt);
        assert(ret);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_RDNSS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (length < 3*8 || (length % (2*8)) != 1*8)
                return -EBADMSG;

        *ret = (uint8_t*) NDISC_ROUTER_RAW(rt) + rt->rindex;
        return 0;
}

int sd_ndisc_router_rdnss_get_addresses(sd_ndisc_router *rt, const struct in6_addr **ret) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_rdnss_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = (const struct in6_addr*) (ri + 8);
        return (NDISC_ROUTER_OPTION_LENGTH(rt) - 8) / 16;
}

int sd_ndisc_router_rdnss_get_lifetime(sd_ndisc_router *rt, uint32_t *ret) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_rdnss_info(rt, &ri);
        if (r < 0)
                return r;

        *ret = be32toh(*(uint32_t*) (ri + 4));
        return 0;
}

static int get_dnssl_info(sd_ndisc_router *rt, uint8_t **ret) {
        size_t length;
        int r;

        assert(rt);
        assert(ret);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_DNSSL);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        length = NDISC_ROUTER_OPTION_LENGTH(rt);
        if (length < 2*8)
                return -EBADMSG;

        *ret = (uint8_t*) NDISC_ROUTER_RAW(rt) + rt->rindex;
        return 0;
}

int sd_ndisc_router_dnssl_get_domains(sd_ndisc_router *rt, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *e = NULL;
        size_t n = 0, left;
        uint8_t *ri, *p;
        bool first = true;
        int r;
        unsigned k = 0;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = get_dnssl_info(rt, &ri);
        if (r < 0)
                return r;

        p = ri + 8;
        left = NDISC_ROUTER_OPTION_LENGTH(rt) - 8;

        for (;;) {
                if (left == 0) {

                        if (n > 0) /* Not properly NUL terminated */
                                return -EBADMSG;

                        break;
                }

                if (*p == 0) {
                        /* Found NUL termination */

                        if (n > 0) {
                                _cleanup_free_ char *normalized = NULL;

                                e[n] = 0;
                                r = dns_name_normalize(e, 0, &normalized);
                                if (r < 0)
                                        return r;

                                /* Ignore the root domain name or "localhost" and friends */
                                if (!is_localhost(normalized) &&
                                    !dns_name_is_root(normalized)) {

                                        if (strv_push(&l, normalized) < 0)
                                                return -ENOMEM;

                                        normalized = NULL;
                                        k++;
                                }
                        }

                        n = 0;
                        first = true;
                        p++, left--;
                        continue;
                }

                /* Check for compression (which is not allowed) */
                if (*p > 63)
                        return -EBADMSG;

                if (1U + *p + 1U > left)
                        return -EBADMSG;

                if (!GREEDY_REALLOC(e, n + !first + DNS_LABEL_ESCAPED_MAX + 1U))
                        return -ENOMEM;

                if (first)
                        first = false;
                else
                        e[n++] = '.';

                r = dns_label_escape((char*) p+1, *p, e + n, DNS_LABEL_ESCAPED_MAX);
                if (r < 0)
                        return r;

                n += r;

                left -= 1 + *p;
                p += 1 + *p;
        }

        if (strv_isempty(l)) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(l);

        return k;
}

int sd_ndisc_router_dnssl_get_lifetime(sd_ndisc_router *rt, uint32_t *ret_sec) {
        uint8_t *ri;
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret_sec, -EINVAL);

        r = get_dnssl_info(rt, &ri);
        if (r < 0)
                return r;

        *ret_sec = be32toh(*(uint32_t*) (ri + 4));
        return 0;
}
