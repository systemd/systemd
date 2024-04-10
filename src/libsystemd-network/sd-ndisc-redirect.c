/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "in-addr-util.h"
#include "ndisc-internal.h"
#include "ndisc-option.h"
#include "ndisc-redirect-internal.h"

static sd_ndisc_redirect* ndisc_redirect_free(sd_ndisc_redirect *rd) {
        if (!rd)
                return NULL;

        icmp6_packet_unref(rd->packet);
        set_free(rd->options);
        return mfree(rd);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc_redirect, sd_ndisc_redirect, ndisc_redirect_free);

sd_ndisc_redirect* ndisc_redirect_new(ICMP6Packet *packet) {
        sd_ndisc_redirect *rd;

        assert(packet);

        rd = new(sd_ndisc_redirect, 1);
        if (!rd)
                return NULL;

        *rd = (sd_ndisc_redirect) {
                .n_ref = 1,
                .packet = icmp6_packet_ref(packet),
        };

        return rd;
}

int ndisc_redirect_parse(sd_ndisc *nd, sd_ndisc_redirect *rd) {
        int r;

        assert(rd);
        assert(rd->packet);

        if (rd->packet->raw_size < sizeof(struct nd_redirect))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Too small to be a redirect message, ignoring.");

        const struct nd_redirect *a = (const struct nd_redirect*) rd->packet->raw_packet;
        assert(a->nd_rd_type == ND_REDIRECT);
        assert(a->nd_rd_code == 0);

        rd->target_address = a->nd_rd_target;
        rd->destination_address = a->nd_rd_dst;

        /* RFC 4861 section 8.1
         * The ICMP Destination Address field in the redirect message does not contain a multicast address. */
        if (in6_addr_is_null(&rd->destination_address) || in6_addr_is_multicast(&rd->destination_address))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received Redirect message with an invalid destination address, ignoring datagram: %m");

        /* RFC 4861 section 8.1
         * The ICMP Target Address is either a link-local address (when redirected to a router) or the same
         * as the ICMP Destination Address (when redirected to the on-link destination). */
        if (!in6_addr_is_link_local(&rd->target_address) && !in6_addr_equal(&rd->target_address, &rd->destination_address))
                return log_ndisc_errno(nd, SYNTHETIC_ERRNO(EBADMSG),
                                       "Received Redirect message with an invalid target address, ignoring datagram: %m");

        r = ndisc_parse_options(rd->packet, &rd->options);
        if (r < 0)
                return log_ndisc_errno(nd, r, "Failed to parse NDisc options in Redirect message, ignoring datagram: %m");

        return 0;
}

int sd_ndisc_redirect_set_sender_address(sd_ndisc_redirect *rd, const struct in6_addr *addr) {
        assert_return(rd, -EINVAL);

        return icmp6_packet_set_sender_address(rd->packet, addr);
}

int sd_ndisc_redirect_get_sender_address(sd_ndisc_redirect *rd, struct in6_addr *ret) {
        assert_return(rd, -EINVAL);

        return icmp6_packet_get_sender_address(rd->packet, ret);
}

int sd_ndisc_redirect_get_target_address(sd_ndisc_redirect *rd, struct in6_addr *ret) {
        assert_return(rd, -EINVAL);

        if (in6_addr_is_null(&rd->target_address))
                return -ENODATA;

        if (ret)
                *ret = rd->target_address;
        return 0;
}

int sd_ndisc_redirect_get_destination_address(sd_ndisc_redirect *rd, struct in6_addr *ret) {
        assert_return(rd, -EINVAL);

        if (in6_addr_is_null(&rd->destination_address))
                return -ENODATA;

        if (ret)
                *ret = rd->destination_address;
        return 0;
}

int sd_ndisc_redirect_get_target_mac(sd_ndisc_redirect *rd, struct ether_addr *ret) {
        assert_return(rd, -EINVAL);

        return ndisc_option_get_mac(rd->options, SD_NDISC_OPTION_TARGET_LL_ADDRESS, ret);
}

int sd_ndisc_redirect_get_redirected_header(sd_ndisc_redirect *rd, struct ip6_hdr *ret) {
        assert_return(rd, -EINVAL);

        sd_ndisc_option *p = ndisc_option_get_by_type(rd->options, SD_NDISC_OPTION_REDIRECTED_HEADER);
        if (!p)
                return -ENODATA;

        if (ret)
                *ret = p->hdr;
        return 0;
}
