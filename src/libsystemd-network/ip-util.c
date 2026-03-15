/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"

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
        const uint8_t *p = ASSERT_PTR(buf);

        while (len > 0) {
                uint64_t t = 0;
                size_t n = MIN(len, sizeof(uint64_t));
                memcpy(&t, p, n);
                sum = complement_sum(sum, t);
                len -= n;
                p += n;
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

static uint16_t udphdr_checksum(
                be32_t saddr,
                be32_t daddr,
                const struct udphdr *udp,
                const struct iovec_wrapper *payload) {

        assert(udp);

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

        if (payload) {
                uint8_t buf[2] = {};
                bool odd = false;
                FOREACH_ARRAY(iovec, payload->iovec, payload->count) {
                        if (!iovec_is_set(iovec))
                                continue;

                        struct iovec v;
                        if (odd) {
                                buf[1] = *(uint8_t*) iovec->iov_base;
                                sum = checksum_buffer(sum, buf, 2);
                                iovec_shift(iovec, 1, &v);
                        } else
                                v = *iovec;

                        odd = v.iov_len % 2;
                        sum = checksum_buffer(sum, v.iov_base, v.iov_len - odd);
                        if (odd)
                                buf[0] = ((uint8_t*) v.iov_base)[v.iov_len - 1];
                }
                if (odd) {
                        buf[1] = 0;
                        sum = checksum_buffer(sum, buf, 2);
                }
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

        assert(ret_iphdr);
        assert(ret_udphdr);

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
