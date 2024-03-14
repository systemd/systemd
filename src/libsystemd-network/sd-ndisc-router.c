/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>

#include "dns-resolver-internal.h"
#include "sd-ndisc.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "ndisc-internal.h"
#include "ndisc-router-internal.h"
#include "unaligned.h"

static sd_ndisc_router* ndisc_router_free(sd_ndisc_router *rt) {
        if (!rt)
                return NULL;

        icmp6_packet_unref(rt->packet);
        set_free(rt->options);
        return mfree(rt);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_router, sd_ndisc_router, ndisc_router_free);

sd_ndisc_router* ndisc_router_new(ICMP6Packet *packet) {
        sd_ndisc_router *rt;

        assert(packet);

        rt = new(sd_ndisc_router, 1);
        if (!rt)
                return NULL;

        *rt = (sd_ndisc_router) {
                .n_ref = 1,
                .packet = icmp6_packet_ref(packet),
                .iterator = ITERATOR_FIRST,
        };

        return rt;
}

int sd_ndisc_router_get_sender_address(sd_ndisc_router *rt, struct in6_addr *ret) {
        assert_return(rt, -EINVAL);

        return icmp6_packet_get_sender_address(rt->packet, ret);
}

int sd_ndisc_router_get_timestamp(sd_ndisc_router *rt, clockid_t clock, uint64_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        return icmp6_packet_get_timestamp(rt->packet, clock, ret);
}

#define DEFINE_GET_TIMESTAMP(name)                                      \
        int sd_ndisc_router_##name##_timestamp(                         \
                        sd_ndisc_router *rt,                            \
                        clockid_t clock,                                \
                        uint64_t *ret) {                                \
                                                                        \
                usec_t s, t;                                            \
                int r;                                                  \
                                                                        \
                assert_return(rt, -EINVAL);                             \
                assert_return(ret, -EINVAL);                            \
                                                                        \
                r = sd_ndisc_router_##name(rt, &s);                     \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = sd_ndisc_router_get_timestamp(rt, clock, &t);       \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                *ret = time_span_to_stamp(s, t);                        \
                return 0;                                               \
        }

DEFINE_GET_TIMESTAMP(get_lifetime);
DEFINE_GET_TIMESTAMP(prefix_get_valid_lifetime);
DEFINE_GET_TIMESTAMP(prefix_get_preferred_lifetime);
DEFINE_GET_TIMESTAMP(route_get_lifetime);
DEFINE_GET_TIMESTAMP(rdnss_get_lifetime);
DEFINE_GET_TIMESTAMP(dnssl_get_lifetime);
DEFINE_GET_TIMESTAMP(prefix64_get_lifetime);
DEFINE_GET_TIMESTAMP(encrypted_dns_get_lifetime);

int ndisc_router_parse(sd_ndisc *nd, sd_ndisc_router *rt) {
        const struct nd_router_advert *a;
        int r;

        assert(rt);
        assert(rt->packet);

        if (rt->packet->raw_size < sizeof(struct nd_router_advert))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Too small to be a router advertisement, ignoring.");

        a = (const struct nd_router_advert*) rt->packet->raw_packet;
        assert(a->nd_ra_type == ND_ROUTER_ADVERT);
        assert(a->nd_ra_code == 0);

        rt->hop_limit = a->nd_ra_curhoplimit;
        rt->flags = a->nd_ra_flags_reserved; /* the first 8 bits */
        rt->lifetime_usec = be16_sec_to_usec(a->nd_ra_router_lifetime, /* max_as_infinity = */ false);
        rt->reachable_time_usec = be32_msec_to_usec(a->nd_ra_reachable, /* mas_as_infinity = */ false);
        rt->retransmission_time_usec = be32_msec_to_usec(a->nd_ra_retransmit, /* max_as_infinity = */ false);

        /* RFC 4191 section 2.2
         * Prf (Default Router Preference)
         * 2-bit signed integer. Indicates whether to prefer this router over other default routers. If the
         * Router Lifetime is zero, the preference value MUST be set to (00) by the sender and MUST be
         * ignored by the receiver. If the Reserved (10) value is received, the receiver MUST treat the value
         * as if it were (00). */
        rt->preference = (rt->flags >> 3) & 3;
        if (rt->preference == SD_NDISC_PREFERENCE_RESERVED)
                rt->preference = SD_NDISC_PREFERENCE_MEDIUM;

        r = ndisc_parse_options(rt->packet, &rt->options);
        if (r < 0)
                return log_ndisc_errno(nd, r, "Failed to parse NDisc options in router advertisement message, ignoring: %m");

        return 0;
}

int sd_ndisc_router_get_hop_limit(sd_ndisc_router *rt, uint8_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->hop_limit;
        return 0;
}

int sd_ndisc_router_get_reachable_time(sd_ndisc_router *rt, uint64_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->reachable_time_usec;
        return 0;
}

int sd_ndisc_router_get_retransmission_time(sd_ndisc_router *rt, uint64_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->retransmission_time_usec;
        return 0;
}

int sd_ndisc_router_get_flags(sd_ndisc_router *rt, uint64_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_ndisc_option *p = ndisc_option_get(rt->options, SD_NDISC_OPTION_FLAGS_EXTENSION);

        *ret = rt->flags | (p ? p->extended_flags : 0);
        return 0;
}

int sd_ndisc_router_get_lifetime(sd_ndisc_router *rt, uint64_t *ret) {
        assert_return(rt, -EINVAL);

        if (ret)
                *ret = rt->lifetime_usec;

        return rt->lifetime_usec > 0; /* Indicate if the router is still valid or not. */
}

int sd_ndisc_router_get_preference(sd_ndisc_router *rt, uint8_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = rt->preference;
        return 0;
}

int sd_ndisc_router_get_sender_mac(sd_ndisc_router *rt, struct ether_addr *ret) {
        assert_return(rt, -EINVAL);

        return ndisc_option_get_mac(rt->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, ret);
}

int sd_ndisc_router_get_mtu(sd_ndisc_router *rt, uint32_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_ndisc_option *p = ndisc_option_get(rt->options, SD_NDISC_OPTION_MTU);
        if (!p)
                return -ENODATA;

        *ret = p->mtu;
        return 0;
}

int sd_ndisc_router_get_captive_portal(sd_ndisc_router *rt, const char **ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        sd_ndisc_option *p = ndisc_option_get(rt->options, SD_NDISC_OPTION_CAPTIVE_PORTAL);
        if (!p)
                return -ENODATA;

        *ret = p->captive_portal;
        return 0;
}

static int ndisc_get_dns_name(const uint8_t *optval, size_t optlen, char **ret) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(optval || optlen == 0);
        assert(ret);

        r = dns_name_from_wire_format(&optval, &optlen, &name);
        if (r < 0)
                return -EBADMSG; /* ndisc doesn't handle other errcodes atm */
        if (r == 0 || optlen != 0)
                return -EBADMSG;

        *ret = TAKE_PTR(name);
        return r;
}

int sd_ndisc_router_encrypted_dns_get_dnr(sd_ndisc_router *rt, sd_dns_resolver *ret) {
        uint8_t *nd_opt_encrypted_dns = NULL;
        size_t length;
        int r;

        _cleanup_(sd_dns_resolver_done) sd_dns_resolver res = {};

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_ENCRYPTED_DNS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        r = sd_ndisc_router_option_get_raw(rt, (void *)&nd_opt_encrypted_dns, &length);
        if (r < 0)
                return r;

        assert(length % 8 == 0);
        if (length == 0)
                return -EBADMSG;

        uint8_t *optval = &nd_opt_encrypted_dns[2];
        size_t optlen = 8 * length - 2; /* units of octets */
        size_t offset = 0;

        res.priority = unaligned_read_be16(&optval[offset]);
        offset += sizeof(uint16_t);
        offset += sizeof(uint32_t); /* Lifetime field. Accessed with *lifetime_timestamp functions. */

        if (offset + sizeof(uint16_t) > optlen)
                return -EBADMSG;

        /* adn field (length + dns-name) */
        size_t ilen = unaligned_read_be16(&optval[offset]);
        offset += sizeof(uint16_t);
        if (offset + ilen > optlen)
                return -EBADMSG;

        r = ndisc_get_dns_name(&optval[offset], ilen, &res.auth_name);
        if (r < 0)
                return r;
        if (dns_name_is_root(res.auth_name))
                return -EBADMSG;
        offset += ilen;

        if (offset == optlen) /* adn-only mode */
                return 0;

        /* Fields following the variable (octets) length adn field are no longer certain to be aligned. */

        if (offset + sizeof(uint16_t) > optlen)
                return -EBADMSG;
        ilen = unaligned_read_be16(&optval[offset]);
        if (offset + ilen > optlen)
                return -EBADMSG;
        if (ilen % (sizeof(struct in6_addr)) != 0)
                return -EBADMSG;

        size_t n_addrs = ilen / (sizeof(struct in6_addr));
        if (n_addrs == 0)
                return -EBADMSG;
        res.addrs = new(union in_addr_union, n_addrs);
        if (!res.addrs)
                return -ENOMEM;

        for (size_t i = 0; i < n_addrs; i++) {
                union in_addr_union addr;
                memcpy(&addr.in6, &optval[offset], sizeof(struct in6_addr));
                if (in_addr_is_multicast(AF_INET6, &addr) ||
                    in_addr_is_localhost(AF_INET, &addr))
                        return -EBADMSG;
                res.addrs[i] = addr;
                offset += sizeof(struct in6_addr);
        }

        /* find the real size of the svc params field */
        size_t splen = 0;
        while (ilen != 0 && offset + splen + sizeof(uint16_t) <= optlen) {
                ilen = unaligned_read_be16(&optval[offset]);
                if (offset + splen + ilen > optlen)
                        return -EBADMSG;
                splen += ilen;
        }

        /* the remaining padding bytes must be zeroed */
        for (uint8_t *b = &optval[offset + splen]; b < optval + optlen; b++)
                if (*b != '\0')
                        return -EBADMSG;

        r = dnr_parse_svc_params(&optval[offset], splen, &res);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(res);
        return 1;
}

int sd_ndisc_router_option_rewind(sd_ndisc_router *rt) {
        assert_return(rt, -EINVAL);

        rt->iterator = ITERATOR_FIRST;
        return sd_ndisc_router_option_next(rt);
}

int sd_ndisc_router_option_next(sd_ndisc_router *rt) {
        assert_return(rt, -EINVAL);

        return set_iterate(rt->options, &rt->iterator, (void**) &rt->current_option);
}

int sd_ndisc_router_option_get_type(sd_ndisc_router *rt, uint8_t *ret) {
        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!rt->current_option)
                return -ENODATA;

        *ret = rt->current_option->type;
        return 0;
}

int sd_ndisc_router_option_is_type(sd_ndisc_router *rt, uint8_t type) {
        uint8_t t;
        int r;

        assert_return(rt, -EINVAL);

        r = sd_ndisc_router_option_get_type(rt, &t);
        if (r < 0)
                return r;

        return t == type;
}

int sd_ndisc_router_option_get_raw(sd_ndisc_router *rt, const uint8_t **ret, size_t *ret_size) {
        assert_return(rt, -EINVAL);

        if (!rt->current_option)
                return -ENODATA;

        return ndisc_option_parse(rt->packet, rt->current_option->offset, NULL, ret_size, ret);
}

#define DEFINE_GETTER(name, type, element, element_type)                \
        int sd_ndisc_router_##name##_get_##element(                     \
                        sd_ndisc_router *rt,                            \
                        element_type *ret) {                            \
                                                                        \
                int r;                                                  \
                                                                        \
                assert_return(rt, -EINVAL);                             \
                assert_return(ret, -EINVAL);                            \
                                                                        \
                r = sd_ndisc_router_option_is_type(rt, type);           \
                if (r < 0)                                              \
                        return r;                                       \
                if (r == 0)                                             \
                        return -EMEDIUMTYPE;                            \
                                                                        \
                *ret = rt->current_option->name.element;                \
                return 0;                                               \
        }

DEFINE_GETTER(prefix, SD_NDISC_OPTION_PREFIX_INFORMATION, flags, uint8_t);
DEFINE_GETTER(prefix, SD_NDISC_OPTION_PREFIX_INFORMATION, prefixlen, uint8_t);
DEFINE_GETTER(prefix, SD_NDISC_OPTION_PREFIX_INFORMATION, address, struct in6_addr);
DEFINE_GETTER(prefix, SD_NDISC_OPTION_PREFIX_INFORMATION, valid_lifetime, uint64_t);
DEFINE_GETTER(prefix, SD_NDISC_OPTION_PREFIX_INFORMATION, preferred_lifetime, uint64_t);

DEFINE_GETTER(route, SD_NDISC_OPTION_ROUTE_INFORMATION, preference, uint8_t);
DEFINE_GETTER(route, SD_NDISC_OPTION_ROUTE_INFORMATION, prefixlen, uint8_t);
DEFINE_GETTER(route, SD_NDISC_OPTION_ROUTE_INFORMATION, address, struct in6_addr);
DEFINE_GETTER(route, SD_NDISC_OPTION_ROUTE_INFORMATION, lifetime, uint64_t);

DEFINE_GETTER(rdnss, SD_NDISC_OPTION_RDNSS, lifetime, uint64_t);

int sd_ndisc_router_rdnss_get_addresses(sd_ndisc_router *rt, const struct in6_addr **ret) {
        int r;

        assert_return(rt, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_ndisc_router_option_is_type(rt, SD_NDISC_OPTION_RDNSS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EMEDIUMTYPE;

        *ret = rt->current_option->rdnss.addresses;
        return (int) rt->current_option->rdnss.n_addresses;
}

DEFINE_GETTER(dnssl, SD_NDISC_OPTION_DNSSL, domains, char**);
DEFINE_GETTER(dnssl, SD_NDISC_OPTION_DNSSL, lifetime, uint64_t);

DEFINE_GETTER(prefix64, SD_NDISC_OPTION_PREF64, prefixlen, uint8_t);
DEFINE_GETTER(prefix64, SD_NDISC_OPTION_PREF64, prefix, struct in6_addr);
DEFINE_GETTER(prefix64, SD_NDISC_OPTION_PREF64, lifetime, uint64_t);

DEFINE_GETTER(encrypted_dns, SD_NDISC_OPTION_ENCRYPTED_DNS, lifetime, uint64_t);
