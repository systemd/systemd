/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "escape.h"
#include "hostname-util.h"
#include "memory-util.h"
#include "missing_network.h"
#include "ndisc-internal.h"
#include "ndisc-protocol.h"
#include "ndisc-neighbor-internal.h"
#include "strv.h"

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_neighbor, sd_ndisc_neighbor, mfree);

sd_ndisc_neighbor *ndisc_neighbor_new(size_t raw_size) {
        sd_ndisc_neighbor *na;

        if (raw_size > SIZE_MAX - ALIGN(sizeof(sd_ndisc_neighbor)))
                return NULL;

        na = malloc0(ALIGN(sizeof(sd_ndisc_neighbor)) + raw_size);
        if (!na)
                return NULL;

        na->raw_size = raw_size;
        na->n_ref = 1;

        return na;
}

int sd_ndisc_neighbor_get_address(sd_ndisc_neighbor *na, struct in6_addr *ret) {
        assert_return(na, -EINVAL);
        assert_return(ret, -EINVAL);

        if (in6_addr_is_null(&na->address))
                return -ENODATA;

        *ret = na->address;
        return 0;
}

int sd_ndisc_neighbor_get_raw(sd_ndisc_neighbor *na, const void **ret, size_t *ret_size) {
        assert_return(na, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(ret_size, -EINVAL);

        *ret = NDISC_NEIGHBOR_RAW(na);
        *ret_size = na->raw_size;
        return 0;
}

int ndisc_neighbor_parse(sd_ndisc *nd, sd_ndisc_neighbor *na) {
        struct nd_neighbor_advert *a;

        assert(na);

        if (na->raw_size < sizeof(struct nd_neighbor_advert))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Too small to be a neighbor advertisement, ignoring.");

        /* Neighbor advertisement packets are neatly aligned to 64-bit boundaries, hence we can access them directly */
        a = NDISC_NEIGHBOR_RAW(na);

        if (a->nd_na_type != ND_NEIGHBOR_ADVERT)
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received ND packet that is not a neighbor advertisement, ignoring.");

        if (a->nd_na_code != 0)
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received ND packet with wrong NA code, ignoring.");

        na->flags = a->nd_na_flags_reserved; /* the first 3 bits */

        na->target_address = a->nd_na_target;
        /* RFC 4861 section 4.4:
         * For solicited advertisements, the Target Address field in the Neighbor Solicitation message that
         * prompted this advertisement. For an unsolicited advertisement, the address whose link-layer
         * address has changed. The Target Address MUST NOT be a multicast address.
         *
         * Here, we only check if the target address is a link-layer address (or a null address, for safety)
         * when the message is an unsolicited neighbor advertisement. */
        if (!FLAGS_SET(na->flags, ND_NA_FLAG_SOLICITED)) {
                if (!in6_addr_is_link_local(&na->target_address) && !in6_addr_is_null(&na->target_address))
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Received ND packet with wrond NA target address (%s), ignoring.",
                                               IN6_ADDR_TO_STRING(&na->target_address));
        }

        const uint8_t *p = (const uint8_t*) NDISC_NEIGHBOR_RAW(na) + sizeof(struct nd_neighbor_advert);
        size_t left = na->raw_size - sizeof(struct nd_neighbor_advert);

        for (;;) {
                uint8_t type;
                size_t length;

                if (left == 0)
                        break;

                if (left < 2)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Neighbor advertisement option lacks header, ignoring datagram.");

                type = p[0];
                length = p[1] * 8;

                if (length == 0)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Neighbor advertisement option with zero length, ignoring datagram.");
                if (left < length)
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Neighbor advertisement option is truncated, ignoring datagram.");

                switch (type) {

                case SD_NDISC_OPTION_TARGET_LL_ADDRESS:
                        assert(length >= 2);
                        if (length != sizeof(struct ether_addr) + 2)
                                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                                       "Neighbor advertisement target link-layer address option with invalid length, ignoring datagram.");
                        break;
                }

                p += length, left -= length;
        }

        return 0;
}

int sd_ndisc_neighbor_get_flags(sd_ndisc_neighbor *na, uint32_t *ret) {
        assert_return(na, -EINVAL);
        assert_return(ret, -EINVAL);

        *ret = na->flags;
        return 0;
}

int sd_ndisc_neighbor_is_router(sd_ndisc_neighbor *na) {
        assert_return(na, -EINVAL);

        return FLAGS_SET(na->flags, ND_NA_FLAG_ROUTER);
}

int sd_ndisc_neighbor_is_solicited(sd_ndisc_neighbor *na) {
        assert_return(na, -EINVAL);

        return FLAGS_SET(na->flags, ND_NA_FLAG_SOLICITED);
}

int sd_ndisc_neighbor_is_override(sd_ndisc_neighbor *na) {
        assert_return(na, -EINVAL);

        return FLAGS_SET(na->flags, ND_NA_FLAG_OVERRIDE);
}

int sd_ndisc_neighbor_get_target_address(sd_ndisc_neighbor *na, struct in6_addr *ret) {
        assert_return(na, -EINVAL);
        assert_return(ret, -EINVAL);

        if (in6_addr_is_null(&na->target_address))
                return sd_ndisc_neighbor_get_address(na, ret); /* fall back to the sender address, for safety. */

        *ret = na->target_address;
        return 0;
}
