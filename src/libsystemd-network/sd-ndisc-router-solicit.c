/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "sd-radv.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "ndisc-protocol.h"
#include "ndisc-router-solicit-internal.h"
#include "radv-internal.h"

static sd_ndisc_router_solicit* ndisc_router_solicit_free(sd_ndisc_router_solicit *rs) {
        if (!rs)
                return NULL;

        icmp6_packet_unref(rs->packet);
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

        if (rs->packet->raw_size < sizeof(struct nd_router_solicit))
                return log_radv_errno(ra, SYNTHETIC_ERRNO(EBADMSG),
                                      "Too small to be a router solicit, ignoring.");

        const struct nd_router_solicit *a = (const struct nd_router_solicit*) rs->packet->raw_packet;
        assert(a->nd_rs_type == ND_ROUTER_SOLICIT);
        assert(a->nd_rs_code == 0);

        for (size_t offset = sizeof(struct nd_router_solicit), length; offset < rs->packet->raw_size; offset += length) {
                uint8_t type;
                const uint8_t *p;

                r = ndisc_option_parse(rs->packet, offset, &type, &length, &p);
                if (r < 0)
                        return log_radv_errno(ra, r, "Failed to parse NDisc option header, ignoring datagram: %m");

                switch (type) {

                case SD_NDISC_OPTION_SOURCE_LL_ADDRESS:
                        if (length != sizeof(struct ether_addr) + 2) {
                                log_radv(ra, "Router Solicitation message has source link-layer address option with invalid length, ignoring the option.");
                                continue;
                        }

                        if (!ether_addr_is_null(&rs->sender_mac)) {
                                log_radv(ra, "Router Solicitation message has multiple source link-layer address options, ignoring the option.");
                                continue;
                        }

                        /* RFC 4861 section 4.1.
                         * Source link-layer address:
                         * The link-layer address of the sender, if known. MUST NOT be included if the Source
                         * Address is the unspecified address. Otherwise, it SHOULD be included on link
                         * layers that have addresses. */
                        if (sd_ndisc_router_solicit_get_sender_address(rs, NULL) == -ENODATA)
                                return log_radv_errno(ra, SYNTHETIC_ERRNO(EBADMSG),
                                                      "Router Solicitation message from null address unexpectedly contains source link-layer address option, ignoring datagaram.");

                        memcpy(&rs->sender_mac, p + 2, sizeof(struct ether_addr));
                        break;
                }
        }

        return 0;
}

int sd_ndisc_router_solicit_get_sender_address(sd_ndisc_router_solicit *rs, struct in6_addr *ret) {
        assert_return(rs, -EINVAL);

        return icmp6_packet_get_sender_address(rs->packet, ret);
}

int sd_ndisc_router_solicit_get_sender_mac(sd_ndisc_router_solicit *rs, struct ether_addr *ret) {
        assert_return(rs, -EINVAL);

        if (!ether_addr_is_null(&rs->sender_mac))
                return -ENODATA;

        if (ret)
                *ret = rs->sender_mac;
        return 0;
}
