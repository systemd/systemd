/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "in-addr-util.h"
#include "ndisc-option.h"
#include "ndisc-router-solicit-internal.h"
#include "radv-internal.h"

static sd_ndisc_router_solicit* ndisc_router_solicit_free(sd_ndisc_router_solicit *rs) {
        if (!rs)
                return NULL;

        icmp6_packet_unref(rs->packet);
        set_free(rs->options);
        return mfree(rs);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_router_solicit, sd_ndisc_router_solicit, ndisc_router_solicit_free);

sd_ndisc_router_solicit* ndisc_router_solicit_new(ICMP6Packet *packet) {
        sd_ndisc_router_solicit *rs;

        assert(packet);

        rs = new(sd_ndisc_router_solicit, 1);
        if (!rs)
                return NULL;

        *rs = (sd_ndisc_router_solicit) {
                .n_ref = 1,
                .packet = icmp6_packet_ref(packet),
        };

        return rs;
}

int ndisc_router_solicit_parse(sd_radv *ra, sd_ndisc_router_solicit *rs) {
        int r;

        assert(rs);
        assert(rs->packet);

        if (rs->packet->raw_size < sizeof(struct nd_router_solicit))
                return log_radv_errno(ra, SYNTHETIC_ERRNO(EBADMSG),
                                      "Too small to be a router solicit, ignoring.");

        const struct nd_router_solicit *a = (const struct nd_router_solicit*) rs->packet->raw_packet;
        assert(a);
        assert(a->nd_rs_type == ND_ROUTER_SOLICIT);
        assert(a->nd_rs_code == 0);

        r = ndisc_parse_options(rs->packet, &rs->options);
        if (r < 0)
                return log_radv_errno(ra, r, "Failed to parse NDisc options in router solicit, ignoring datagram: %m");

        /* RFC 4861 section 4.1.
         * Source link-layer address:
         * The link-layer address of the sender, if known. MUST NOT be included if the Source
         * Address is the unspecified address. Otherwise, it SHOULD be included on link
         * layers that have addresses. */
        if (ndisc_option_get_mac(rs->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, NULL) >= 0&&
            sd_ndisc_router_solicit_get_sender_address(rs, NULL) == -ENODATA)
                return log_radv_errno(ra, SYNTHETIC_ERRNO(EBADMSG),
                                      "Router Solicitation message from null address unexpectedly contains source link-layer address option, ignoring datagaram.");

        return 0;
}

int sd_ndisc_router_solicit_get_sender_address(sd_ndisc_router_solicit *rs, struct in6_addr *ret) {
        assert_return(rs, -EINVAL);

        return icmp6_packet_get_sender_address(rs->packet, ret);
}

int sd_ndisc_router_solicit_get_sender_mac(sd_ndisc_router_solicit *rs, struct ether_addr *ret) {
        assert_return(rs, -EINVAL);

        return ndisc_option_get_mac(rs->options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, ret);
}
