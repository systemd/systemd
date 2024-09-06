/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/icmp6.h>

#include "icmp6-packet.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "network-common.h"
#include "socket-util.h"

DEFINE_TRIVIAL_REF_UNREF_FUNC(ICMP6Packet, icmp6_packet, mfree);

static ICMP6Packet* icmp6_packet_new(size_t size) {
        ICMP6Packet *p;

        if (size > SIZE_MAX - offsetof(ICMP6Packet, raw_packet))
                return NULL;

        p = malloc0(offsetof(ICMP6Packet, raw_packet) + size);
        if (!p)
                return NULL;

        p->raw_size = size;
        p->n_ref = 1;

        return p;
}

int icmp6_packet_set_sender_address(ICMP6Packet *p, const struct in6_addr *addr) {
        assert(p);

        if (addr)
                p->sender_address = *addr;
        else
                p->sender_address = (const struct in6_addr) {};

        return 0;
}

int icmp6_packet_get_sender_address(ICMP6Packet *p, struct in6_addr *ret) {
        assert(p);

        if (in6_addr_is_null(&p->sender_address))
                return -ENODATA;

        if (ret)
                *ret = p->sender_address;
        return 0;
}

int icmp6_packet_get_timestamp(ICMP6Packet *p, clockid_t clock, usec_t *ret) {
        assert(p);
        assert(ret);

        if (!TRIPLE_TIMESTAMP_HAS_CLOCK(clock) || !clock_supported(clock))
                return -EOPNOTSUPP;

        if (!triple_timestamp_is_set(&p->timestamp))
                return -ENODATA;

        *ret = triple_timestamp_by_clock(&p->timestamp, clock);
        return 0;
}

const struct icmp6_hdr* icmp6_packet_get_header(ICMP6Packet *p) {
        assert(p);

        if (p->raw_size < sizeof(struct icmp6_hdr))
                return NULL;

        return (const struct icmp6_hdr*) p->raw_packet;
}

int icmp6_packet_get_type(ICMP6Packet *p) {
        const struct icmp6_hdr *hdr = icmp6_packet_get_header(p);
        if (!hdr)
                return -EBADMSG;

        return hdr->icmp6_type;
}

static int icmp6_packet_verify(ICMP6Packet *p) {
        const struct icmp6_hdr *hdr = icmp6_packet_get_header(p);
        if (!hdr)
                return -EBADMSG;

        if (hdr->icmp6_code != 0)
                return -EBADMSG;

        /* Drop any overly large packets early. We are not interested in jumbograms,
         * which could cause excessive processing. */
        if (p->raw_size > ICMP6_MAX_NORMAL_PAYLOAD_SIZE)
                return -EMSGSIZE;

        return 0;
}

int icmp6_packet_receive(int fd, ICMP6Packet **ret) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *p = NULL;
        ssize_t len;
        int r;

        assert(fd >= 0);
        assert(ret);

        len = next_datagram_size_fd(fd);
        if (len < 0)
                return (int) len;

        p = icmp6_packet_new(len);
        if (!p)
                return -ENOMEM;

        r = icmp6_receive(fd, p->raw_packet, p->raw_size, &p->sender_address, &p->timestamp);
        if (r == -EADDRNOTAVAIL)
                return log_debug_errno(r, "ICMPv6: Received a packet from neither link-local nor null address.");
        if (r == -EMULTIHOP)
                return log_debug_errno(r, "ICMPv6: Received a packet with an invalid hop limit.");
        if (r == -EPFNOSUPPORT)
                return log_debug_errno(r, "ICMPv6: Received a packet with an invalid source address.");
        if (r < 0)
                return log_debug_errno(r, "ICMPv6: Unexpected error while receiving a packet: %m");

        r = icmp6_packet_verify(p);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(p);
        return 0;
}
