/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "clat.h"
#include "in-addr-util.h"
#include "networkd-xlat-packet.h"
#include "unaligned.h"

#define ICMP_HEADER_SIZE 8U

assert_cc(sizeof(struct ip6_frag) == 8);

/* Add the 16-bit words of a buffer to a ones' complement sum. Words are summed in memory order, hence the
 * result of csum_finish() is in network byte order, independently of the endianness of the host. */
static uint64_t csum_add(uint64_t sum, const void *buf, size_t len) {
        const uint8_t *p = ASSERT_PTR(buf);

        for (; len > 1; p += 2, len -= 2)
                sum += unaligned_read_ne16(p);

        if (len == 1) {
                uint8_t last[2] = { *p, 0 };

                sum += unaligned_read_ne16(last);
        }

        return sum;
}

static uint16_t csum_finish(uint64_t sum) {
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return (uint16_t) ~sum;
}

/* The sum of an IPv4 or IPv6 pseudo-header, without the addresses */
static uint64_t csum_add_length_protocol(uint64_t sum, size_t len, uint8_t protocol) {
        sum += htobe16((uint16_t) (len >> 16));
        sum += htobe16((uint16_t) len);
        sum += htobe16(protocol);

        return sum;
}

static uint64_t csum_addresses6(const struct in6_addr *src, const struct in6_addr *dst) {
        assert(src);
        assert(dst);

        return csum_add(csum_add(/* sum= */ 0, src, sizeof(*src)), dst, sizeof(*dst));
}

static uint64_t csum_pseudo_header6(
                const struct in6_addr *src,
                const struct in6_addr *dst,
                size_t len,
                uint8_t protocol) {

        uint64_t sum;

        sum = csum_addresses6(src, dst);
        return csum_add_length_protocol(sum, len, protocol);
}

static uint64_t csum_addresses4(const struct in_addr *src, const struct in_addr *dst) {
        assert(src);
        assert(dst);

        return csum_add(csum_add(/* sum= */ 0, src, sizeof(*src)), dst, sizeof(*dst));
}

static uint64_t csum_pseudo_header4(
                const struct in_addr *src,
                const struct in_addr *dst,
                size_t len,
                uint8_t protocol) {

        uint64_t sum;

        sum = csum_addresses4(src, dst);
        return csum_add_length_protocol(sum, len, protocol);
}

/* Update a checksum for data whose sum changed from 'from' to 'to' (RFC 1624). A wrong checksum stays
 * wrong, so a corrupted packet is still discarded by the receiver. */
static uint16_t csum_replace(uint16_t old, uint64_t from, uint64_t to) {
        return csum_finish((uint64_t) (uint16_t) ~old + csum_finish(from) + to);
}

static bool address_is_in_pref64(const XlatPacketParams *params, const struct in6_addr *a) {
        return in6_addr_prefix_covers(&params->pref64, params->pref64_len, a) > 0;
}

/* RFC 6052 section 3.1 */
static bool ipv4_is_translatable(const XlatPacketParams *params, const struct in_addr *a) {
        static const struct in6_addr well_known = { .s6_addr = { 0x00, 0x64, 0xff, 0x9b } };

        if (params->pref64_len == 96 && in6_addr_equal(&params->pref64, &well_known))
                return clat_ipv4_is_global((const uint8_t*) a);

        return clat_ipv4_is_unicast((const uint8_t*) a);
}

static struct in6_addr ipv4_to_pref64(const XlatPacketParams *params, const struct in_addr *a) {
        struct in6_addr ret;

        clat_ipv4_embed(params->pref64.s6_addr, params->pref64_len, (const uint8_t*) a, ret.s6_addr);
        return ret;
}

static struct in_addr ipv4_from_pref64(const XlatPacketParams *params, const struct in6_addr *a) {
        struct in_addr ret;

        clat_ipv4_extract(a->s6_addr, params->pref64_len, (uint8_t*) &ret);
        return ret;
}

static struct in_addr clat_local_ipv4(void) {
        return (struct in_addr) { .s_addr = htobe32(CLAT_IPV4_ADDRESS) };
}

static void write_ipv6_header(
                uint8_t *ret,
                uint8_t tclass,
                size_t payload_len,
                uint8_t next_header,
                uint8_t hop_limit,
                const struct in6_addr *src,
                const struct in6_addr *dst) {

        assert(ret);
        assert(src);
        assert(dst);

        struct ip6_hdr h = {
                .ip6_flow = htobe32(UINT32_C(6) << 28 | (uint32_t) tclass << 20),
                .ip6_plen = htobe16((uint16_t) payload_len),
                .ip6_nxt = next_header,
                .ip6_hlim = hop_limit,
                .ip6_src = *src,
                .ip6_dst = *dst,
        };

        assert_cc(sizeof(h) == 40);
        memcpy(ret, &h, sizeof(h));
}

/* RFC 7915 section 5.1: DF is clear for packets of up to 1260 bytes, and set for larger ones. Packets
 * without DF may be fragmented later on, and need an identification (RFC 6864 section 4.3). */
static uint16_t ipv4_dont_fragment(size_t total_len) {
        return total_len <= CLAT_IPV4_MAX_SIZE_WITHOUT_DF ? 0 : IP_DF;
}

/* Translate the fields of an IPv6 fragment header to IPv4 (RFC 7915 section 5.1.1) */
static void ipv4_fragment_fields(const struct ip6_frag *h, uint16_t *ret_id, uint16_t *ret_frag_off) {
        assert(h);
        assert(ret_id);
        assert(ret_frag_off);

        uint16_t v = be16toh(h->ip6f_offlg);

        *ret_id = (uint16_t) be32toh(h->ip6f_ident);
        *ret_frag_off = (v >> 3) | (FLAGS_SET(v, 1) ? IP_MF : 0);
}

static void write_ipv4_header(
                uint8_t *ret,
                uint8_t tos,
                size_t total_len,
                uint16_t id,
                uint16_t frag_off,
                uint8_t ttl,
                uint8_t protocol,
                const struct in_addr *src,
                const struct in_addr *dst) {

        struct iphdr h = {
                .version = 4,
                .ihl = 5,
                .tos = tos,
                .tot_len = htobe16((uint16_t) total_len),
                .id = htobe16(id),
                .frag_off = htobe16(frag_off),
                .ttl = ttl,
                .protocol = protocol,
                .saddr = src->s_addr,
                .daddr = dst->s_addr,
        };

        assert_cc(sizeof(h) == 20);
        h.check = csum_finish(csum_add(/* sum= */ 0, &h, sizeof(h)));
        memcpy(ret, &h, sizeof(h));
}

/* RFC 7915 section 4.1: IPv4 options are ignored, but a packet with a source route option is discarded */
static bool ipv4_has_source_route(const uint8_t *options, size_t len) {
        for (size_t i = 0; i < len; ) {
                uint8_t type = options[i];

                if (type == IPOPT_EOL)
                        return false;
                if (type == IPOPT_NOP) {
                        i++;
                        continue;
                }
                if (IN_SET(type, IPOPT_LSRR, IPOPT_SSRR))
                        return true;
                if (i + 1 >= len || options[i + 1] < 2)
                        return false;

                i += options[i + 1];
        }

        return false;
}

/* Update the checksum of a transport header of a packet quoted in an ICMP error, which may be truncated.
 * 'from' and 'to' are the sums of the old and new addresses. */
static void update_quoted_transport_checksum(uint8_t *l4, size_t len, uint8_t protocol, uint64_t from, uint64_t to) {
        size_t offset;
        uint16_t check;

        assert(l4);

        if (protocol == IPPROTO_TCP)
                offset = offsetof(struct tcphdr, th_sum);
        else if (protocol == IPPROTO_UDP)
                offset = offsetof(struct udphdr, uh_sum);
        else
                return;

        if (len < offset + sizeof(check))
                return;

        check = unaligned_read_ne16(l4 + offset);
        if (protocol == IPPROTO_UDP && check == 0)
                return;

        check = csum_replace(check, from, to);
        if (protocol == IPPROTO_UDP && check == 0)
                check = 0xffff;

        unaligned_write_ne16(l4 + offset, check);
}

/* RFC 7915 sections 4.2 and 4.3 */
static int translate_icmp_error_4to6(
                const XlatPacketParams *params,
                const uint8_t *msg,
                size_t msg_len,
                const struct in6_addr *dst6,
                uint8_t *ret,           /* the ICMPv6 message */
                size_t ret_max,
                size_t *ret_len) {

        uint8_t header[ICMP_HEADER_SIZE];
        struct iphdr quoted;
        size_t quoted_hlen, quoted_total, data_len, len;
        struct in_addr quoted_src, quoted_dst, local4 = clat_local_ipv4();
        struct in6_addr quoted_src6;

        assert(params);
        assert(msg);
        assert(dst6);
        assert(ret);
        assert(ret_len);

        if (msg_len < ICMP_HEADER_SIZE + sizeof(quoted) + 8)
                return -EBADMSG;

        /* The checksum is computed from scratch below, as the message may have to be truncated. Hence it
         * has to be verified here. */
        if (csum_finish(csum_add(/* sum= */ 0, msg, msg_len)) != 0)
                return -EBADMSG;

        memcpy(&quoted, msg + ICMP_HEADER_SIZE, sizeof(quoted));
        quoted_hlen = (size_t) quoted.ihl * 4;
        quoted_total = be16toh(quoted.tot_len);
        if (quoted.version != 4 ||
            quoted_hlen < sizeof(quoted) ||
            quoted_total < quoted_hlen ||
            msg_len - ICMP_HEADER_SIZE < quoted_hlen + 8 ||
            (be16toh(quoted.frag_off) & IP_OFFMASK) != 0)
                return -EBADMSG;

        quoted_src.s_addr = quoted.saddr;
        quoted_dst.s_addr = quoted.daddr;

        /* The quoted packet is one that we delivered to the host */
        if (quoted_dst.s_addr != local4.s_addr || !ipv4_is_translatable(params, &quoted_src))
                return -EPERM;

        if (!IN_SET(quoted.protocol, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP))
                return -EOPNOTSUPP;

        if (clat_icmp_4to6(msg, quoted_total, params->mtu, header) != CLAT_ICMP_ERROR)
                return -EOPNOTSUPP;

        /* The result must fit into the IPv6 minimum MTU (RFC 4443 section 2.4) */
        data_len = msg_len - ICMP_HEADER_SIZE - quoted_hlen;
        data_len = MIN(data_len, CLAT_IPV6_MIN_MTU - 2 * sizeof(struct ip6_hdr) - ICMP_HEADER_SIZE);
        len = ICMP_HEADER_SIZE + sizeof(struct ip6_hdr) + data_len;
        if (len > ret_max)
                return -ENOBUFS;

        quoted_src6 = ipv4_to_pref64(params, &quoted_src);

        memcpy(ret, header, ICMP_HEADER_SIZE);
        write_ipv6_header(ret + ICMP_HEADER_SIZE, quoted.tos, quoted_total - quoted_hlen,
                          quoted.protocol == IPPROTO_ICMP ? IPPROTO_ICMPV6 : quoted.protocol,
                          quoted.ttl, &quoted_src6, &params->address);

        uint8_t *l4 = ret + ICMP_HEADER_SIZE + sizeof(struct ip6_hdr);
        memcpy(l4, msg + ICMP_HEADER_SIZE + quoted_hlen, data_len);

        if (quoted.protocol == IPPROTO_ICMP) {
                if (!IN_SET(l4[0], ICMP_ECHO, ICMP_ECHOREPLY))
                        return -EOPNOTSUPP;

                uint64_t from = csum_add(/* sum= */ 0, l4, 2);
                l4[0] = l4[0] == ICMP_ECHO ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
                uint64_t to = csum_add(csum_pseudo_header6(&quoted_src6, &params->address,
                                                           quoted_total - quoted_hlen, IPPROTO_ICMPV6),
                                       l4, 2);
                unaligned_write_ne16(l4 + 2, csum_replace(unaligned_read_ne16(l4 + 2), from, to));
        } else
                update_quoted_transport_checksum(
                                l4, data_len, quoted.protocol,
                                csum_addresses4(&quoted_src, &quoted_dst),
                                csum_addresses6(&quoted_src6, &params->address));

        unaligned_write_ne16(ret + 2, csum_finish(csum_add(
                        csum_pseudo_header6(&params->address, dst6, len, IPPROTO_ICMPV6), ret, len)));

        *ret_len = len;
        return 0;
}

int xlat_packet_4to6(
                XlatPacketParams *params,
                const uint8_t *packet,
                size_t size,
                uint8_t *ret,
                size_t ret_max,
                size_t *ret_size,
                struct in6_addr *ret_destination) {

        struct in_addr src4, dst4, local4 = clat_local_ipv4();
        size_t hlen, total, payload_len, out_len, extra;
        const uint8_t *payload;
        struct in6_addr dst6;
        struct iphdr ip4;
        uint16_t frag_off;
        bool fragment, first;
        uint8_t *out;
        int r;

        assert(params);
        assert(packet);
        assert(ret);
        assert(ret_size);
        assert(ret_destination);

        if (size < sizeof(ip4))
                return -EBADMSG;

        memcpy(&ip4, packet, sizeof(ip4));
        if (ip4.version != 4)
                return -EOPNOTSUPP;

        hlen = (size_t) ip4.ihl * 4;
        total = be16toh(ip4.tot_len);
        if (hlen < sizeof(ip4) || total < hlen || total > size)
                return -EBADMSG;

        frag_off = be16toh(ip4.frag_off);
        fragment = frag_off & (IP_MF | IP_OFFMASK);
        first = (frag_off & IP_OFFMASK) == 0;
        extra = fragment ? sizeof(struct ip6_frag) : 0;

        /* Fragmented ICMP messages cannot be translated (RFC 7915 section 1.2) */
        if (fragment && !IN_SET(ip4.protocol, IPPROTO_TCP, IPPROTO_UDP))
                return -EOPNOTSUPP;

        src4.s_addr = ip4.saddr;
        dst4.s_addr = ip4.daddr;
        if (src4.s_addr != local4.s_addr || !ipv4_is_translatable(params, &dst4))
                return -EPERM;

        if (ipv4_has_source_route(packet + sizeof(ip4), hlen - sizeof(ip4)))
                return -EPERM;

        payload = packet + hlen;
        payload_len = total - hlen;
        out_len = payload_len;

        if (ret_max < sizeof(struct ip6_hdr) + extra || ret_max - sizeof(struct ip6_hdr) - extra < payload_len)
                return -ENOBUFS;
        out = ret + sizeof(struct ip6_hdr) + extra;

        dst6 = ipv4_to_pref64(params, &dst4);

        /* The sums of the addresses, i.e. what differs between the two pseudo-headers */
        uint64_t from = csum_addresses4(&src4, &dst4),
                 to = csum_addresses6(&params->address, &dst6);

        switch (first ? ip4.protocol : -1) {
        case -1: /* no transport header, hence nothing to update */
                memcpy(out, payload, payload_len);
                break;

        case IPPROTO_TCP: {
                if (payload_len < sizeof(struct tcphdr))
                        return -EBADMSG;

                memcpy(out, payload, payload_len);

                size_t offset = offsetof(struct tcphdr, th_sum);
                unaligned_write_ne16(out + offset, csum_replace(unaligned_read_ne16(out + offset), from, to));
                break;
        }

        case IPPROTO_UDP: {
                if (payload_len < sizeof(struct udphdr))
                        return -EBADMSG;

                memcpy(out, payload, payload_len);

                size_t offset = offsetof(struct udphdr, uh_sum);
                uint16_t check = unaligned_read_ne16(out + offset);

                if (check == 0) {
                        /* IPv6 does not allow this (RFC 8200 section 8.1), see RFC 7915 section 4.5 */
                        size_t ulen = unaligned_read_be16(out + offsetof(struct udphdr, uh_ulen));

                        /* The checksum of a fragmented datagram cannot be computed */
                        if (params->drop_udp_zero_checksum || fragment)
                                return -ENODATA;
                        if (ulen < sizeof(struct udphdr) || ulen > payload_len)
                                return -EBADMSG;

                        check = csum_finish(csum_add(
                                        csum_pseudo_header6(&params->address, &dst6, ulen, IPPROTO_UDP), out, ulen));
                } else
                        check = csum_replace(check, from, to);

                unaligned_write_ne16(out + offset, check == 0 ? 0xffff : check);
                break;
        }

        case IPPROTO_ICMP:
                if (payload_len < ICMP_HEADER_SIZE)
                        return -EBADMSG;

                if (IN_SET(payload[0], ICMP_ECHO, ICMP_ECHOREPLY)) {
                        memcpy(out, payload, payload_len);

                        uint64_t old = csum_add(/* sum= */ 0, out, 2);
                        out[0] = out[0] == ICMP_ECHO ? ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
                        uint64_t new = csum_pseudo_header6(&params->address, &dst6, payload_len, IPPROTO_ICMPV6);
                        new = csum_add(new, out, 2);
                        unaligned_write_ne16(out + 2, csum_replace(unaligned_read_ne16(out + 2), old, new));
                } else {
                        r = translate_icmp_error_4to6(params, payload, payload_len, &dst6,
                                                      out, ret_max - sizeof(struct ip6_hdr), &out_len);
                        if (r < 0)
                                return r;
                }
                break;

        default:
                return -EOPNOTSUPP;
        }

        write_ipv6_header(ret, ip4.tos, out_len + extra,
                          fragment ? IPPROTO_FRAGMENT :
                          ip4.protocol == IPPROTO_ICMP ? IPPROTO_ICMPV6 : ip4.protocol,
                          ip4.ttl, &params->address, &dst6);

        if (fragment) {
                /* RFC 7915 section 4.1 */
                struct ip6_frag h = {
                        .ip6f_nxt = ip4.protocol,
                        .ip6f_offlg = htobe16((uint16_t) ((frag_off & IP_OFFMASK) << 3 | !!(frag_off & IP_MF))),
                        .ip6f_ident = htobe32(be16toh(ip4.id)),
                };

                memcpy(ret + sizeof(struct ip6_hdr), &h, sizeof(h));
        }

        *ret_size = sizeof(struct ip6_hdr) + extra + out_len;
        *ret_destination = dst6;
        return 0;
}

/* RFC 7915 sections 5.2 and 5.3 */
static int translate_icmp_error_6to4(
                const XlatPacketParams *params,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ret,           /* the ICMPv4 message */
                size_t ret_max,
                size_t *ret_len) {

        uint8_t header[ICMP_HEADER_SIZE], protocol, next_header;
        uint16_t quoted_id = 0, quoted_frag_off = 0;
        bool quoted_fragment = false, quoted_first = true;
        struct ip6_hdr quoted;
        size_t quoted_plen, data_len, len, extra = 0;
        struct in_addr quoted_dst4, local4 = clat_local_ipv4();

        assert(params);
        assert(msg);
        assert(ret);
        assert(ret_len);

        if (msg_len < ICMP_HEADER_SIZE + sizeof(quoted) + 8)
                return -EBADMSG;

        memcpy(&quoted, msg + ICMP_HEADER_SIZE, sizeof(quoted));
        quoted_plen = be16toh(quoted.ip6_plen);
        if (quoted.ip6_vfc >> 4 != 6 || quoted_plen > UINT16_MAX - sizeof(struct iphdr))
                return -EBADMSG;

        /* The quoted packet must be one that we sent */
        if (!in6_addr_equal(&quoted.ip6_src, &params->address) || !address_is_in_pref64(params, &quoted.ip6_dst))
                return -EPERM;

        next_header = quoted.ip6_nxt;
        if (next_header == IPPROTO_FRAGMENT) {
                struct ip6_frag h;

                if (msg_len < ICMP_HEADER_SIZE + sizeof(quoted) + sizeof(h) + 8 || quoted_plen < sizeof(h))
                        return -EBADMSG;

                memcpy(&h, msg + ICMP_HEADER_SIZE + sizeof(quoted), sizeof(h));
                next_header = h.ip6f_nxt;
                if (!IN_SET(next_header, IPPROTO_TCP, IPPROTO_UDP))
                        return -EOPNOTSUPP;

                ipv4_fragment_fields(&h, &quoted_id, &quoted_frag_off);
                quoted_fragment = true;
                quoted_first = (quoted_frag_off & IP_OFFMASK) == 0;
                quoted_plen -= sizeof(h);
                extra = sizeof(h);
        }

        switch (next_header) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
                protocol = next_header;
                break;
        case IPPROTO_ICMPV6:
                protocol = IPPROTO_ICMP;
                break;
        default:
                return -EOPNOTSUPP;
        }

        if (clat_icmp_6to4(msg, params->mtu, header) != CLAT_ICMP_ERROR)
                return -EOPNOTSUPP;

        data_len = msg_len - ICMP_HEADER_SIZE - sizeof(quoted) - extra;
        len = ICMP_HEADER_SIZE + sizeof(struct iphdr) + data_len;
        if (len > ret_max)
                return -ENOBUFS;

        quoted_dst4 = ipv4_from_pref64(params, &quoted.ip6_dst);

        memcpy(ret, header, ICMP_HEADER_SIZE);
        write_ipv4_header(ret + ICMP_HEADER_SIZE,
                          (uint8_t) (be32toh(quoted.ip6_flow) >> 20),
                          sizeof(struct iphdr) + quoted_plen,
                          quoted_id,
                          quoted_fragment ? quoted_frag_off : ipv4_dont_fragment(sizeof(struct iphdr) + quoted_plen),
                          quoted.ip6_hlim, protocol, &local4, &quoted_dst4);

        uint8_t *l4 = ret + ICMP_HEADER_SIZE + sizeof(struct iphdr);
        memcpy(l4, msg + ICMP_HEADER_SIZE + sizeof(quoted) + extra, data_len);

        if (!quoted_first) {
                /* No transport header, hence no checksum to update */
        } else if (protocol == IPPROTO_ICMP) {
                if (!IN_SET(l4[0], ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY))
                        return -EOPNOTSUPP;

                struct in6_addr src = quoted.ip6_src, dst = quoted.ip6_dst;
                uint64_t from = csum_add(csum_pseudo_header6(&src, &dst, quoted_plen, IPPROTO_ICMPV6), l4, 2);
                l4[0] = l4[0] == ICMP6_ECHO_REQUEST ? ICMP_ECHO : ICMP_ECHOREPLY;
                uint64_t to = csum_add(/* sum= */ 0, l4, 2);
                unaligned_write_ne16(l4 + 2, csum_replace(unaligned_read_ne16(l4 + 2), from, to));
        } else {
                struct in6_addr src = quoted.ip6_src, dst = quoted.ip6_dst;

                update_quoted_transport_checksum(
                                l4, data_len, protocol,
                                csum_addresses6(&src, &dst),
                                csum_addresses4(&local4, &quoted_dst4));
        }

        unaligned_write_ne16(ret + 2, csum_finish(csum_add(/* sum= */ 0, ret, len)));

        *ret_len = len;
        return 0;
}

int xlat_packet_6to4(
                XlatPacketParams *params,
                const uint8_t *packet,
                size_t size,
                bool checksum_partial,
                uint8_t *ret,
                size_t ret_max,
                size_t *ret_size) {

        struct in_addr src4, local4 = clat_local_ipv4();
        size_t payload_len, out_len;
        const uint8_t *payload;
        struct ip6_hdr ip6;
        struct in6_addr src6, dst6;
        uint16_t id = 0, frag_off = 0;
        uint8_t *out, protocol, next_header;
        bool is_error, fragment = false, first = true;
        int r;

        assert(params);
        assert(packet);
        assert(ret);
        assert(ret_size);

        if (size < sizeof(ip6))
                return -EBADMSG;

        memcpy(&ip6, packet, sizeof(ip6));
        payload_len = be16toh(ip6.ip6_plen);
        if (ip6.ip6_vfc >> 4 != 6 || payload_len > size - sizeof(ip6) ||
            payload_len > UINT16_MAX - sizeof(struct iphdr))
                return -EBADMSG;

        src6 = ip6.ip6_src;
        dst6 = ip6.ip6_dst;
        if (!in6_addr_equal(&dst6, &params->address))
                return -EPERM;

        payload = packet + sizeof(ip6);
        next_header = ip6.ip6_nxt;

        if (next_header == IPPROTO_FRAGMENT) {
                struct ip6_frag h;

                if (payload_len < sizeof(h))
                        return -EBADMSG;

                memcpy(&h, payload, sizeof(h));
                next_header = h.ip6f_nxt;
                /* Fragmented ICMPv6 messages cannot be translated (RFC 7915 section 1.2) */
                if (!IN_SET(next_header, IPPROTO_TCP, IPPROTO_UDP))
                        return -EOPNOTSUPP;

                ipv4_fragment_fields(&h, &id, &frag_off);
                fragment = true;
                first = (frag_off & IP_OFFMASK) == 0;
                payload += sizeof(h);
                payload_len -= sizeof(h);

                /* Fragmented packets always carry complete checksums */
                checksum_partial = false;
        }

        switch (next_header) {
        case IPPROTO_TCP:
                if (first && payload_len < sizeof(struct tcphdr))
                        return -EBADMSG;
                protocol = IPPROTO_TCP;
                break;
        case IPPROTO_UDP:
                if (first && payload_len < sizeof(struct udphdr))
                        return -EBADMSG;
                protocol = IPPROTO_UDP;
                break;
        case IPPROTO_ICMPV6:
                if (payload_len < ICMP_HEADER_SIZE)
                        return -EBADMSG;
                protocol = IPPROTO_ICMP;
                break;
        default:
                return -EOPNOTSUPP;
        }

        out_len = payload_len;
        is_error = protocol == IPPROTO_ICMP && payload[0] < 128;

        if (protocol == IPPROTO_ICMP && !is_error && !IN_SET(payload[0], ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY))
                return -EOPNOTSUPP;

        if (address_is_in_pref64(params, &src6)) {
                src4 = ipv4_from_pref64(params, &src6);
                if (!ipv4_is_translatable(params, &src4))
                        return -EPERM;
        } else if (is_error)
                /* Errors may come from any router on the way, which has no IPv4 address (RFC 6791) */
                clat_ipv4_dummy_address((uint8_t*) &src4);
        else
                return -EPERM;

        if (ret_max < sizeof(struct iphdr) || ret_max - sizeof(struct iphdr) < payload_len)
                return -ENOBUFS;
        out = ret + sizeof(struct iphdr);

        uint64_t from = csum_addresses6(&src6, &dst6),
                 to = csum_addresses4(&src4, &local4);

        if (is_error) {
                /* ICMPv6 errors are checksummed by the sender, and the checksum of the translated message
                 * is computed from scratch, hence verify the received one. */
                if (!checksum_partial &&
                    csum_finish(csum_add(csum_pseudo_header6(&src6, &dst6, payload_len, IPPROTO_ICMPV6),
                                         payload, payload_len)) != 0)
                        return -EBADMSG;

                r = translate_icmp_error_6to4(params, payload, payload_len,
                                              out, ret_max - sizeof(struct iphdr), &out_len);
                if (r < 0)
                        return r;

        } else if (!first) {
                /* No transport header, hence nothing to update */
                memcpy(out, payload, payload_len);

        } else if (protocol == IPPROTO_ICMP) {
                memcpy(out, payload, payload_len);

                uint64_t old = csum_add(csum_pseudo_header6(&src6, &dst6, payload_len, IPPROTO_ICMPV6), out, 2);
                out[0] = out[0] == ICMP6_ECHO_REQUEST ? ICMP_ECHO : ICMP_ECHOREPLY;

                if (checksum_partial) {
                        unaligned_write_ne16(out + 2, 0);
                        unaligned_write_ne16(out + 2, csum_finish(csum_add(/* sum= */ 0, out, payload_len)));
                } else
                        unaligned_write_ne16(out + 2, csum_replace(unaligned_read_ne16(out + 2), old,
                                                                   csum_add(/* sum= */ 0, out, 2)));

        } else {
                size_t offset = protocol == IPPROTO_TCP ? offsetof(struct tcphdr, th_sum) :
                                                          offsetof(struct udphdr, uh_sum),
                       len = payload_len;
                uint16_t check;

                memcpy(out, payload, payload_len);
                check = unaligned_read_ne16(out + offset);

                if (protocol == IPPROTO_UDP) {
                        /* A zero checksum is not valid in IPv6, and would make the translated datagram be
                         * accepted unverified. */
                        if (check == 0 && !checksum_partial)
                                return -EBADMSG;

                        /* The length of a fragmented datagram is that of all fragments */
                        if (!fragment) {
                                len = unaligned_read_be16(out + offsetof(struct udphdr, uh_ulen));
                                if (len < sizeof(struct udphdr) || len > payload_len)
                                        return -EBADMSG;
                        }
                }

                if (checksum_partial) {
                        /* The field only covers the pseudo-header yet */
                        unaligned_write_ne16(out + offset, 0);
                        check = csum_finish(csum_add(csum_pseudo_header4(&src4, &local4, len, protocol), out, len));
                } else
                        check = csum_replace(check, from, to);

                if (protocol == IPPROTO_UDP && check == 0)
                        check = 0xffff;

                unaligned_write_ne16(out + offset, check);
        }

        size_t total = sizeof(struct iphdr) + out_len;
        if (!fragment) {
                frag_off = ipv4_dont_fragment(total);
                if (frag_off == 0)
                        id = params->ipv4_id++;
        }

        write_ipv4_header(ret, (uint8_t) (be32toh(ip6.ip6_flow) >> 20), total, id, frag_off,
                          ip6.ip6_hlim, protocol, &src4, &local4);

        *ret_size = total;
        return 0;
}
