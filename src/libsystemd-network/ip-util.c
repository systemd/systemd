/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "log.h"

union iphdr_union {
        struct iphdr ip;
        uint8_t buf[15 * 4]; /* ip->ihl is 4 bits, hence max length is 15 * 4 */
};

struct udp_pseudo_header {
        be32_t saddr;
        be32_t daddr;
        uint8_t unused;
        uint8_t protocol;
        uint16_t len;
} _packed_;

static uint64_t complement_sum(uint64_t a, uint64_t b) {
        if (a < UINT64_MAX - b)
                return a + b;

        return a - (UINT64_MAX - b);
}

static uint64_t checksum_buffer(uint64_t sum, const void *buf, size_t len) {
        const uint64_t *p = ASSERT_PTR(buf);

        while (len >= sizeof(uint64_t)) {
                sum = complement_sum(sum, *p);
                len -= sizeof(uint64_t);
                p++;
        }

        if (len > 0) {
                uint64_t t = 0;
                memcpy(&t, p, len);
                sum = complement_sum(sum, t);
        }

        return sum;
}

static uint16_t checksum_finalize(uint64_t sum) {
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

uint16_t ip_checksum(const void *buf, size_t len) {
        /* See RFC1071 */
        return checksum_finalize(checksum_buffer(0, buf, len));
}

static uint16_t iphdr_checksum(const union iphdr_union *ip) {
        assert(ip);
        return ip_checksum(ip, ip->ip.ihl * 4);
}

static uint16_t udphdr_checksum(be32_t saddr, be32_t daddr, const struct udphdr *udp, const struct iovec *payload) {
        assert(udp);
        assert(iovec_is_set(payload));

        /* RFC 768 */

        struct udp_pseudo_header pseudo = {
                .saddr = saddr,
                .daddr = daddr,
                .protocol = IPPROTO_UDP,
                .len = udp->len,
        };

        uint64_t sum = 0;
        sum = checksum_buffer(sum, &pseudo, sizeof(struct udp_pseudo_header));
        sum = checksum_buffer(sum, udp, sizeof(struct udphdr));
        sum = checksum_buffer(sum, payload->iov_base, payload->iov_len);

        return checksum_finalize(sum);
}

int udp_packet_build(
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                const struct iovec *payload,
                struct iovec_wrapper *ret) {

        int r;

        assert(iovec_is_set(payload));
        assert(ret);

        /* This takes the buffer in the payload on success. */

        /* iphdr.tot_len is uint16_t, hence the total length must be <= UINT16_MAX. */
        size_t len = payload->iov_len;
        if (len >= UINT16_MAX - sizeof(struct iphdr) - sizeof(struct udphdr))
                return -E2BIG;

        union iphdr_union ip = {
                .ip.version = IPVERSION,
                .ip.ihl = sizeof(struct iphdr) / 4,
                .ip.tos = ip_service_type >= 0 ? ip_service_type : IPTOS_CLASS_CS6,
                .ip.tot_len = htobe16(sizeof(struct iphdr) + sizeof(struct udphdr) + len),
                .ip.ttl = IPDEFTTL,
                .ip.protocol = IPPROTO_UDP,
                .ip.saddr = source_addr,
                .ip.daddr = destination_addr,
        };

        ip.ip.check = iphdr_checksum(&ip);

        struct udphdr udp = {
                .source = htobe16(source_port),
                .dest = htobe16(destination_port),
                .len = htobe16(sizeof(struct udphdr) + len),
        };

        udp.check = udphdr_checksum(source_addr, destination_addr, &udp, payload);

        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        r = iovw_extend(&iovw, &ip.ip, sizeof(struct iphdr));
        if (r < 0)
                return r;

        r = iovw_extend(&iovw, &udp, sizeof(struct udphdr));
        if (r < 0)
                return r;

        r = iovw_put_iov(&iovw, payload);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(iovw);
        return 0;
}

int udp_packet_verify(
                const uint8_t *packet,
                size_t len,
                uint16_t port,
                bool checksum,
                struct iovec *ret_payload) {

        assert(packet);

        /* This verifies IP and UDP packet headers and optionally returns the UDP payload. */

        /* IP */
        if (len < sizeof(struct iphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet (%zu bytes) smaller than minimum IP header (%zu bytes), ignoring packet.",
                                       len, sizeof(struct iphdr));

        const union iphdr_union *ip = (const union iphdr_union*) packet;
        if (ip->ip.version != IPVERSION)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet is not IPv4, ignoring packet.");

        size_t iphdrlen = ip->ip.ihl * 4;
        if (iphdrlen < sizeof(struct iphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: IP header size (%zu bytes) smaller than minimum (%zu bytes), ignoring packet.",
                                       iphdrlen, sizeof(struct iphdr));

        if (len < iphdrlen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet (%zu bytes) smaller than expected (%zu) by IP header, ignoring packet.",
                                       len, iphdrlen);

        if (be16toh(ip->ip.tot_len) != len)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet length (%zu bytes) does not match expected (%zu) by IP header, ignoring packet.",
                                       len, be16toh(ip->ip.tot_len));

        if (ip->ip.protocol != IPPROTO_UDP)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: not UDP, ignoring packet.");

        if (iphdr_checksum(ip) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: invalid IP checksum, ignoring packet.");

        /* UDP */
        if (len < iphdrlen + sizeof(struct udphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: packet (%zu bytes) smaller than IP header + UDP header, ignoring packet.",
                                       len);

        const struct udphdr *udp = (const struct udphdr*) (packet + iphdrlen);
        size_t udplen = be16toh(udp->len);
        if (udplen < sizeof(struct udphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: UDP datagram (%zu bytes) smaller than UDP header (%zu bytes), ignoring packet.",
                                       udplen, sizeof(struct udphdr));

        if (len < iphdrlen + udplen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: packet (%zu bytes) smaller than expected (%zu) by UDP header, ignoring packet.",
                                       len, iphdrlen + udplen);

        if (be16toh(udp->dest) != port)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: to port %u, which is not the expected port (%u), ignoring packet.",
                                       be16toh(udp->dest), port);

        /* Calculate UDP payload length from the UDP header. Do not use the total length in IP header.
         * The packet may contain garbage at the end. */
        struct iovec payload = IOVEC_MAKE(packet + iphdrlen + sizeof(struct udphdr), udplen - sizeof(struct udphdr));
        if (checksum && udp->check != 0 && udphdr_checksum(ip->ip.saddr, ip->ip.daddr, udp, &payload) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: invalid UDP checksum, ignoring packet.");

        if (ret_payload)
                *ret_payload = payload;
        return 0;
}
