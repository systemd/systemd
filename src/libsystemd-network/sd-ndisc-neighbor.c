/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "icmp6-packet.h"
#include "in-addr-util.h"
#include "ndisc-internal.h"
#include "ndisc-neighbor-internal.h"
#include "ndisc-option.h"
#include "set.h"

static sd_ndisc_neighbor* ndisc_neighbor_free(sd_ndisc_neighbor *na) {
        if (!na)
                return NULL;

        icmp6_packet_unref(na->packet);
        set_free(na->options);
        return mfree(na);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_neighbor, sd_ndisc_neighbor, ndisc_neighbor_free);

sd_ndisc_neighbor* ndisc_neighbor_new(ICMP6Packet *packet) {
        sd_ndisc_neighbor *na;

        assert(packet);

        na = new(sd_ndisc_neighbor, 1);
        if (!na)
                return NULL;

        *na = (sd_ndisc_neighbor) {
                .n_ref = 1,
                .packet = icmp6_packet_ref(packet),
        };

        return na;
}

int ndisc_neighbor_parse(sd_ndisc *nd, sd_ndisc_neighbor *na) {
        int r;

        assert(na);

        if (na->packet->raw_size < sizeof(struct nd_neighbor_advert))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Too small to be a neighbor advertisement, ignoring datagram.");

        /* Neighbor advertisement packets are neatly aligned to 64-bit boundaries, hence we can access them directly */
        const struct nd_neighbor_advert *a = (const struct nd_neighbor_advert*) na->packet->raw_packet;
        assert(a->nd_na_type == ND_NEIGHBOR_ADVERT);
        assert(a->nd_na_code == 0);

        na->flags = a->nd_na_flags_reserved; /* the first 3 bits */
        na->target_address = a->nd_na_target;

        /* RFC 4861 section 4.4:
         * For solicited advertisements, the Target Address field in the Neighbor Solicitation message that
         * prompted this advertisement. For an unsolicited advertisement, the address whose link-layer
         * address has changed. The Target Address MUST NOT be a multicast address.
         *
         * Here, we only check if the target address is a link-layer address (or a null address, for safety)
         * when the message is an unsolicited neighbor advertisement. */
        if (!FLAGS_SET(na->flags, ND_NA_FLAG_SOLICITED))
                if (!in6_addr_is_link_local(&na->target_address) && !in6_addr_is_null(&na->target_address))
                        return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                               "Received ND packet with an invalid target address (%s), ignoring datagram.",
                                               IN6_ADDR_TO_STRING(&na->target_address));

        r = ndisc_parse_options(na->packet, &na->options);
        if (r < 0)
                return log_ndisc_errno(nd, r, "Failed to parse NDisc options in neighbor advertisement message, ignoring: %m");

        return 0;
}

int sd_ndisc_neighbor_get_sender_address(sd_ndisc_neighbor *na, struct in6_addr *ret) {
        assert_return(na, -EINVAL);

        return icmp6_packet_get_sender_address(na->packet, ret);
}

int sd_ndisc_neighbor_get_target_address(sd_ndisc_neighbor *na, struct in6_addr *ret) {
        assert_return(na, -EINVAL);

        if (in6_addr_is_null(&na->target_address))
                /* fall back to the sender address, for safety. */
                return sd_ndisc_neighbor_get_sender_address(na, ret);

        if (ret)
                *ret = na->target_address;
        return 0;
}

int sd_ndisc_neighbor_get_target_mac(sd_ndisc_neighbor *na, struct ether_addr *ret) {
        assert_return(na, -EINVAL);

        return ndisc_option_get_mac(na->options, SD_NDISC_OPTION_TARGET_LL_ADDRESS, ret);
}

int sd_ndisc_neighbor_get_flags(sd_ndisc_neighbor *na, uint32_t *ret) {
        assert_return(na, -EINVAL);

        if (ret)
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
