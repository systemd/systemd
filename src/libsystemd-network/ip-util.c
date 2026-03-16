/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
        be16_t len;
} _packed_;

static uint64_t complement_sum(uint64_t a, uint64_t b) {
        /* This performs one's complement addition (end-around carry). See RFC1071. */
        if (a <= UINT64_MAX - b)
                return a + b;

        return a - (UINT64_MAX - b);
}

static uint64_t checksum_iov(uint64_t sum, const struct iovec *iov) {
        assert(iov);

        for (struct iovec i = *iov; iovec_is_set(&i); iovec_inc(&i, sizeof(uint64_t))) {
                uint64_t t = 0;
                memcpy(&t, i.iov_base, MIN(i.iov_len, sizeof(uint64_t)));
                sum = complement_sum(sum, t);
        }

        return sum;
}

static uint16_t checksum_finalize(uint64_t sum) {
        while ((sum >> 16) != 0)
                sum = (sum & 0xffffu) + (sum >> 16);

        return ~sum;
}

uint16_t ip_checksum(const void *buf, size_t len) {
        /* See RFC1071 */
        return checksum_finalize(checksum_iov(0, &IOVEC_MAKE(buf, len)));
}

static uint16_t iphdr_checksum(const union iphdr_union *ip) {
        assert(ip);
        return ip_checksum(ip, ip->ip.ihl * 4);
}

static uint16_t udphdr_checksum(
                be32_t saddr,
                be32_t daddr,
                const struct udphdr *udp,
                const struct iovec_wrapper *payload) {

        assert(udp);
        assert(payload);

        /* RFC 768 */

        struct udp_pseudo_header pseudo = {
                .saddr = saddr,
                .daddr = daddr,
                .protocol = IPPROTO_UDP,
                .len = udp->len,
        };

        uint64_t sum = 0;
        sum = checksum_iov(sum, &IOVEC_MAKE(&pseudo, sizeof(struct udp_pseudo_header)));
        sum = checksum_iov(sum, &IOVEC_MAKE(udp, sizeof(struct udphdr)));

        uint8_t buf[2] = {};
        bool odd = false;
        FOREACH_ARRAY(i, payload->iovec, payload->count) {
                if (!iovec_is_set(i))
                        continue;

                struct iovec v = *i;
                if (odd) {
                        buf[1] = *(uint8_t*) v.iov_base;
                        sum = checksum_iov(sum, &IOVEC_MAKE(buf, 2));
                        iovec_inc(&v, 1);
                }

                odd = v.iov_len % 2;
                if (odd) {
                        buf[0] = ((uint8_t*) v.iov_base)[v.iov_len - 1];
                        v.iov_len--;
                }
                sum = checksum_iov(sum, &v);
        }
        if (odd) {
                buf[1] = 0;
                sum = checksum_iov(sum, &IOVEC_MAKE(buf, 2));
        }

        return checksum_finalize(sum);
}

int udp_packet_build(
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                const struct iovec_wrapper *payload,
                struct iphdr *ret_iphdr,
                struct udphdr *ret_udphdr) {

        assert(payload);
        assert(ret_iphdr);
        assert(ret_udphdr);

        /* When ip_service_type is negative, IPTOS_CLASS_CS6 will be used. Otherwise, it must be a valid TOS,
         * hence must be in 0…255. Here, we only check its range. */
        if (ip_service_type > UINT8_MAX)
                return -EINVAL;

        /* iphdr.tot_len is uint16_t, hence the total length must be <= UINT16_MAX. */
        size_t len = iovw_size(payload);
        if (len > UDP_PAYLOAD_MAX_SIZE)
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

        *ret_iphdr = ip.ip;
        *ret_udphdr = udp;
        return 0;
}

int udp_packet_verify(
                const struct iovec *packet,
                uint16_t port,
                bool checksum,
                struct iovec *ret_payload) {

        assert(packet);

        /* This verifies IP and UDP packet headers and optionally returns the UDP payload. */

        /* IP */
        if (packet->iov_len < sizeof(struct iphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet (%zu bytes) smaller than minimum IP header (%zu bytes), ignoring packet.",
                                       packet->iov_len, sizeof(struct iphdr));

        const union iphdr_union *ip = (const union iphdr_union*) packet->iov_base;
        if (ip->ip.version != IPVERSION)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet is not IPv4, ignoring packet.");

        size_t iphdrlen = ip->ip.ihl * 4;
        if (iphdrlen < sizeof(struct iphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: IP header size (%zu bytes) smaller than minimum (%zu bytes), ignoring packet.",
                                       iphdrlen, sizeof(struct iphdr));

        if (packet->iov_len < iphdrlen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet (%zu bytes) smaller than IP header size (%zu bytes), ignoring packet.",
                                       packet->iov_len, iphdrlen);

        size_t totlen = be16toh(ip->ip.tot_len);
        if (totlen < iphdrlen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet size (%zu bytes) by IP header is smaller than the IP header size (%zu), ignoring packet.",
                                       totlen, iphdrlen);
        if (packet->iov_len < totlen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: packet (%zu bytes) smaller than expected (%zu) by IP header, ignoring packet.",
                                       packet->iov_len, totlen);

        if (ip->ip.protocol != IPPROTO_UDP)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: not UDP, ignoring packet.");

        if (iphdr_checksum(ip) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "IPv4: invalid IP checksum, ignoring packet.");

        /* UDP */
        if (totlen < iphdrlen + sizeof(struct udphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: packet (%zu bytes) smaller than IP header + UDP header, ignoring packet.",
                                       totlen);

        const struct udphdr *udp = (const struct udphdr*) ((const uint8_t*) packet->iov_base + iphdrlen);
        size_t udplen = be16toh(udp->len);
        if (udplen < sizeof(struct udphdr))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: UDP datagram (%zu bytes) smaller than UDP header (%zu bytes), ignoring packet.",
                                       udplen, sizeof(struct udphdr));

        if (totlen != iphdrlen + udplen)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: packet length by IP header (%zu bytes) does not match with the one by UDP header "
                                       "(IP header %zu bytes + UDP %zu bytes = %zu bytes), ignoring packet.",
                                       totlen, iphdrlen, udplen, iphdrlen + udplen);

        if (be16toh(udp->dest) != port)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: to port %u, which is not the expected port (%u), ignoring packet.",
                                       be16toh(udp->dest), port);

        /* Calculate the UDP payload length from the UDP header (udplen), rather than the input packet length
         * (len). The packet may contain garbage at the end. */
        struct iovec payload = IOVEC_MAKE(
                        (const uint8_t*) packet->iov_base + iphdrlen + sizeof(struct udphdr),
                        udplen - sizeof(struct udphdr));
        if (checksum && udp->check != 0 &&
            udphdr_checksum(ip->ip.saddr, ip->ip.daddr, udp,
                            &(struct iovec_wrapper) {
                                    .iovec = &payload,
                                    .count = 1,
                            }) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "UDP: invalid UDP checksum, ignoring packet.");

        if (ret_payload)
                *ret_payload = payload;
        return 0;
}
