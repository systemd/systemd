/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>

#include "sd-event.h"
#include "sd-netlink.h"

#if ENABLE_CLAT_BPF
#include <linux/bpf.h>
#include <sys/syscall.h>

#include "bpf/clat/clat-skel.h"
#endif

#include "conf-parser.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-network.h"
#include "networkd-route-util.h"
#include "networkd-xlat.h"
#include "set.h"
#include "string-util.h"

#define TUN_DEV "/dev/net/tun"

/* RFC 7335: IPv4 address used for CLAT local endpoint */
#define CLAT_V4_ADDR_U32 UINT32_C(0xC0000001) /* 192.0.0.1 in host byte order */

/* Route metric for the CLAT default route (high enough to not conflict with normal routes) */
#define CLAT_ROUTE_METRIC UINT32_C(2048)

/* MTU for CLAT default route. IPv6 minimum MTU (1280) minus IPv4 header (20) = 1260.
 * TCP MSS = MTU - 40 (IPv4 header + TCP header) = 1220. */
#define CLAT_ROUTE_MTU UINT32_C(1260)
#define CLAT_ROUTE_ADVMSS UINT32_C(1220)

/* Max packet buffer size */
#define CLAT_BUFSIZE 2048

bool link_xlat_enabled(Link *link) {
        assert(link);

        return link->network && link->network->clat;
}

/* RFC 6052 Section 2.2: Embed IPv4 address into IPv6 PREF64 prefix.
 * Supports all valid NAT64 prefix lengths: /32, /40, /48, /56, /64, /96. */
static void xlat_embed_ipv4_in_pref64(
                const struct in6_addr *prefix,
                uint8_t prefix_len,
                const struct in_addr *v4,
                struct in6_addr *ret) {

        const uint8_t *v4b = (const uint8_t *) &v4->s_addr;

        assert(prefix);
        assert(v4);
        assert(ret);

        *ret = *prefix;

        switch (prefix_len) {
        case 96:
                ret->s6_addr[12] = v4b[0];
                ret->s6_addr[13] = v4b[1];
                ret->s6_addr[14] = v4b[2];
                ret->s6_addr[15] = v4b[3];
                break;
        case 64:
                ret->s6_addr[9]  = v4b[0];
                ret->s6_addr[10] = v4b[1];
                ret->s6_addr[11] = v4b[2];
                ret->s6_addr[12] = v4b[3];
                ret->s6_addr[8]  = 0; /* "u" byte must be zero */
                break;
        case 56:
                ret->s6_addr[7]  = v4b[0];
                ret->s6_addr[9]  = v4b[1];
                ret->s6_addr[10] = v4b[2];
                ret->s6_addr[11] = v4b[3];
                ret->s6_addr[8]  = 0;
                break;
        case 48:
                ret->s6_addr[6]  = v4b[0];
                ret->s6_addr[7]  = v4b[1];
                ret->s6_addr[9]  = v4b[2];
                ret->s6_addr[10] = v4b[3];
                ret->s6_addr[8]  = 0;
                break;
        case 40:
                ret->s6_addr[5]  = v4b[0];
                ret->s6_addr[6]  = v4b[1];
                ret->s6_addr[7]  = v4b[2];
                ret->s6_addr[9]  = v4b[3];
                ret->s6_addr[8]  = 0;
                break;
        case 32:
                ret->s6_addr[4]  = v4b[0];
                ret->s6_addr[5]  = v4b[1];
                ret->s6_addr[6]  = v4b[2];
                ret->s6_addr[7]  = v4b[3];
                ret->s6_addr[8]  = 0;
                break;
        default:
                assert_not_reached();
        }
}

/* Reverse of xlat_embed_ipv4_in_pref64: extract IPv4 from PREF64-mapped IPv6 address */
static void xlat_extract_ipv4_from_pref64(
                const struct in6_addr *v6,
                uint8_t prefix_len,
                struct in_addr *ret) {

        uint8_t *v4b = (uint8_t *) &ret->s_addr;

        assert(v6);
        assert(ret);

        switch (prefix_len) {
        case 96:
                v4b[0] = v6->s6_addr[12];
                v4b[1] = v6->s6_addr[13];
                v4b[2] = v6->s6_addr[14];
                v4b[3] = v6->s6_addr[15];
                break;
        case 64:
                v4b[0] = v6->s6_addr[9];
                v4b[1] = v6->s6_addr[10];
                v4b[2] = v6->s6_addr[11];
                v4b[3] = v6->s6_addr[12];
                break;
        case 56:
                v4b[0] = v6->s6_addr[7];
                v4b[1] = v6->s6_addr[9];
                v4b[2] = v6->s6_addr[10];
                v4b[3] = v6->s6_addr[11];
                break;
        case 48:
                v4b[0] = v6->s6_addr[6];
                v4b[1] = v6->s6_addr[7];
                v4b[2] = v6->s6_addr[9];
                v4b[3] = v6->s6_addr[10];
                break;
        case 40:
                v4b[0] = v6->s6_addr[5];
                v4b[1] = v6->s6_addr[6];
                v4b[2] = v6->s6_addr[7];
                v4b[3] = v6->s6_addr[9];
                break;
        case 32:
                v4b[0] = v6->s6_addr[4];
                v4b[1] = v6->s6_addr[5];
                v4b[2] = v6->s6_addr[6];
                v4b[3] = v6->s6_addr[7];
                break;
        default:
                assert_not_reached();
        }
}

/* Compute one's complement checksum over a buffer */
static uint16_t xlat_checksum(const void *buf, size_t len) {
        const uint8_t *p = buf;
        uint32_t sum = 0;

        while (len > 1) {
                uint16_t v;
                memcpy(&v, p, sizeof(v));
                sum += v;
                p += 2;
                len -= 2;
        }

        if (len == 1) {
                uint16_t v = 0;
                memcpy(&v, p, 1);
                sum += v;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return (uint16_t) ~sum;
}

/* Compute IPv6 pseudo-header checksum contribution */
static uint32_t xlat_pseudo_header_checksum(
                const struct in6_addr *src,
                const struct in6_addr *dst,
                size_t payload_len,
                uint8_t next_header) {

        uint32_t sum = 0;

        for (size_t i = 0; i < 16; i += 2) {
                uint16_t v;
                memcpy(&v, &src->s6_addr[i], sizeof(v));
                sum += v;
        }

        for (size_t i = 0; i < 16; i += 2) {
                uint16_t v;
                memcpy(&v, &dst->s6_addr[i], sizeof(v));
                sum += v;
        }

        /* payload_len fits in 16 bits since IPv6 payload length field is 16-bit */
        sum += htobe16((uint16_t) payload_len);
        sum += htobe16((uint16_t) next_header);

        return sum;
}

/* Recompute checksum from pseudo-header + payload */
static uint16_t xlat_compute_full_checksum(
                uint32_t pseudo_sum,
                const uint8_t *payload,
                size_t payload_len) {

        uint32_t sum = pseudo_sum;
        const uint8_t *p = payload;

        while (payload_len > 1) {
                uint16_t v;
                memcpy(&v, p, sizeof(v));
                sum += v;
                p += 2;
                payload_len -= 2;
        }
        if (payload_len == 1) {
                uint16_t v = 0;
                memcpy(&v, p, 1);
                sum += v;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return (uint16_t) ~sum;
}

/* Adjust TCP/UDP checksum when translating IPv4->IPv6 */
static void xlat_update_transport_checksum_4to6(
                uint8_t *payload,
                size_t payload_len,
                uint8_t protocol,
                const struct in6_addr *src6,
                const struct in6_addr *dst6) {

        uint16_t *csum_field;
        uint32_t sum;
        uint16_t csum;

        if (protocol == IPPROTO_TCP && payload_len >= sizeof(struct tcphdr))
                csum_field = &((struct tcphdr *) payload)->th_sum;
        else if (protocol == IPPROTO_UDP && payload_len >= sizeof(struct udphdr))
                csum_field = &((struct udphdr *) payload)->uh_sum;
        else
                return;

        /* UDP checksum is mandatory in IPv6 - must compute if it was zero */
        sum = xlat_pseudo_header_checksum(src6, dst6, payload_len, protocol);
        *csum_field = 0;
        csum = xlat_compute_full_checksum(sum, payload, payload_len);

        /* Per RFC 768, a computed zero UDP checksum is transmitted as 0xFFFF */
        if (csum == 0 && protocol == IPPROTO_UDP)
                csum = 0xFFFF;

        *csum_field = csum;
}

/* Adjust TCP/UDP checksum when translating IPv6->IPv4 */
static void xlat_update_transport_checksum_6to4(
                uint8_t *payload,
                size_t payload_len,
                uint8_t protocol,
                const struct in_addr *src4,
                const struct in_addr *dst4) {

        uint16_t *csum_field;
        uint32_t sum = 0;
        uint16_t v, csum;

        if (protocol == IPPROTO_TCP && payload_len >= sizeof(struct tcphdr))
                csum_field = &((struct tcphdr *) payload)->th_sum;
        else if (protocol == IPPROTO_UDP && payload_len >= sizeof(struct udphdr))
                csum_field = &((struct udphdr *) payload)->uh_sum;
        else
                return;

        /* IPv4 pseudo-header */
        memcpy(&v, (const uint8_t *) &src4->s_addr, sizeof(v));
        sum += v;
        memcpy(&v, (const uint8_t *) &src4->s_addr + 2, sizeof(v));
        sum += v;
        memcpy(&v, (const uint8_t *) &dst4->s_addr, sizeof(v));
        sum += v;
        memcpy(&v, (const uint8_t *) &dst4->s_addr + 2, sizeof(v));
        sum += v;
        sum += htobe16((uint16_t) protocol);
        sum += htobe16((uint16_t) payload_len);

        *csum_field = 0;
        csum = xlat_compute_full_checksum(sum, payload, payload_len);

        if (csum == 0 && protocol == IPPROTO_UDP)
                csum = 0xFFFF;

        *csum_field = csum;
}

/* Translate ICMP Echo to ICMPv6 Echo (outbound) */
static int xlat_translate_icmp_4to6(
                uint8_t *payload,
                size_t payload_len,
                const struct in6_addr *src6,
                const struct in6_addr *dst6) {

        struct icmphdr *icmp4;
        uint32_t sum;

        if (payload_len < sizeof(struct icmphdr))
                return -EINVAL;

        icmp4 = (struct icmphdr *) payload;

        /* Only translate Echo Request/Reply for now */
        switch (icmp4->type) {
        case ICMP_ECHO:
                icmp4->type = ICMP6_ECHO_REQUEST;
                icmp4->code = 0;
                break;
        case ICMP_ECHOREPLY:
                icmp4->type = ICMP6_ECHO_REPLY;
                icmp4->code = 0;
                break;
        default:
                return -EOPNOTSUPP;
        }

        /* ICMPv6 checksum uses pseudo-header (unlike ICMP which doesn't) */
        icmp4->checksum = 0;
        sum = xlat_pseudo_header_checksum(src6, dst6, payload_len, IPPROTO_ICMPV6);
        icmp4->checksum = xlat_compute_full_checksum(sum, payload, payload_len);

        return 0;
}

/* Translate ICMPv6 Echo to ICMP Echo (inbound) */
static int xlat_translate_icmp_6to4(uint8_t *payload, size_t payload_len) {
        struct icmp6_hdr *icmp6;

        if (payload_len < sizeof(struct icmp6_hdr))
                return -EINVAL;

        icmp6 = (struct icmp6_hdr *) payload;

        switch (icmp6->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
                icmp6->icmp6_type = ICMP_ECHO;
                break;
        case ICMP6_ECHO_REPLY:
                icmp6->icmp6_type = ICMP_ECHOREPLY;
                break;
        default:
                return -EOPNOTSUPP;
        }

        /* ICMP checksum does not use pseudo-header */
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_cksum = xlat_checksum(payload, payload_len);

        return 0;
}

/* Select a global unicast IPv6 address from the link for CLAT source */
static int xlat_select_ipv6_source(Link *link, struct in6_addr *ret) {
        Address *a;

        assert(link);
        assert(ret);

        /* First pass: prefer ready addresses */
        SET_FOREACH(a, link->addresses) {
                if (a->family != AF_INET6)
                        continue;

                if (in6_addr_is_link_local(&a->in_addr.in6))
                        continue;

                if (!address_is_ready(a))
                        continue;

                *ret = a->in_addr.in6;
                return 0;
        }

        /* Second pass: accept any non-link-local IPv6 address */
        SET_FOREACH(a, link->addresses) {
                if (a->family != AF_INET6)
                        continue;

                if (in6_addr_is_link_local(&a->in_addr.in6))
                        continue;

                *ret = a->in_addr.in6;
                return 0;
        }

        return -ENOENT;
}

/* IPv4->IPv6 translation and send */
static int xlat_translate_and_send_4to6(Link *link, const uint8_t *pkt4, size_t len4) {
        uint8_t pkt6[CLAT_BUFSIZE];
        const struct iphdr *ip4;
        struct ip6_hdr *ip6;
        size_t ip4_hlen, payload_len;
        struct in6_addr dst6;
        struct in_addr dst4;
        uint8_t protocol;
        int r;

        assert(link);
        assert(pkt4);

        if (len4 < sizeof(struct iphdr))
                return -EINVAL;

        ip4 = (const struct iphdr *) pkt4;

        if (ip4->version != 4)
                return -EINVAL;

        ip4_hlen = (size_t) ip4->ihl * 4;
        if (ip4_hlen < sizeof(struct iphdr) || ip4_hlen > len4)
                return -EINVAL;

        if (be16toh(ip4->tot_len) < ip4_hlen)
                return -EINVAL;

        payload_len = be16toh(ip4->tot_len) - ip4_hlen;
        if (ip4_hlen + payload_len > len4)
                return -EINVAL;

        if (sizeof(struct ip6_hdr) + payload_len > sizeof(pkt6))
                return -EMSGSIZE;

        /* Reject fragmented IPv4 packets - we cannot correctly translate non-first fragments
         * as they lack transport headers needed for checksum recalculation (RFC 7915 Section 4.1) */
        if (be16toh(ip4->frag_off) & (IP_MF | IP_OFFMASK))
                return -EOPNOTSUPP;

        protocol = ip4->protocol;
        dst4.s_addr = ip4->daddr;

        /* Destination: embed IPv4 dst into PREF64 prefix (RFC 6052) */
        xlat_embed_ipv4_in_pref64(&link->clat_pref64_prefix, link->clat_pref64_prefix_len,
                                  &dst4, &dst6);

        /* Build IPv6 header */
        ip6 = (struct ip6_hdr *) pkt6;
        memset(ip6, 0, sizeof(*ip6));
        ip6->ip6_flow = htobe32(UINT32_C(6) << 28 | ((uint32_t) ip4->tos << 20));
        ip6->ip6_plen = htobe16((uint16_t) payload_len);
        ip6->ip6_hlim = ip4->ttl;
        /* Source: cached global IPv6 address (per RFC 6877 Section 4.4) */
        ip6->ip6_src = link->clat_ipv6_src;
        ip6->ip6_dst = dst6;

        /* Copy payload after IPv6 header */
        memcpy(pkt6 + sizeof(struct ip6_hdr), pkt4 + ip4_hlen, payload_len);
        uint8_t *payload = pkt6 + sizeof(struct ip6_hdr);

        /* Protocol-specific translation */
        if (protocol == IPPROTO_ICMP) {
                r = xlat_translate_icmp_4to6(payload, payload_len, &link->clat_ipv6_src, &dst6);
                if (r < 0)
                        return r;
                ip6->ip6_nxt = IPPROTO_ICMPV6;
        } else if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                ip6->ip6_nxt = protocol;
                xlat_update_transport_checksum_4to6(payload, payload_len, protocol, &link->clat_ipv6_src, &dst6);
        } else {
                return -EOPNOTSUPP;
        }

        /* Send via raw IPv6 socket */
        struct sockaddr_in6 sa = {
                .sin6_family = AF_INET6,
                .sin6_addr = dst6,
        };

        if (sendto(link->clat_send_fd, pkt6, sizeof(struct ip6_hdr) + payload_len, 0,
                   (struct sockaddr *) &sa, sizeof(sa)) < 0)
                return -errno;

        return 0;
}

/* IPv6->IPv4 translation and write to TUN */
static int xlat_translate_and_send_6to4(Link *link, const uint8_t *pkt6, size_t len6) {
        uint8_t pkt4[CLAT_BUFSIZE];
        const struct ip6_hdr *ip6;
        struct iphdr *ip4;
        size_t payload_len;
        struct in_addr src4, dst4;
        uint8_t protocol;
        int r;

        assert(link);
        assert(pkt6);

        if (len6 < sizeof(struct ip6_hdr))
                return -EINVAL;

        ip6 = (const struct ip6_hdr *) pkt6;

        if ((be32toh(ip6->ip6_flow) >> 28) != 6)
                return -EINVAL;

        payload_len = be16toh(ip6->ip6_plen);
        if (sizeof(struct ip6_hdr) + payload_len > len6)
                return -EINVAL;

        if (sizeof(struct iphdr) + payload_len > sizeof(pkt4))
                return -EMSGSIZE;

        protocol = ip6->ip6_nxt;

        /* Source: extract IPv4 from PREF64-mapped source address */
        xlat_extract_ipv4_from_pref64(&ip6->ip6_src, link->clat_pref64_prefix_len, &src4);

        /* Destination: 192.0.0.1 (our CLAT address) */
        dst4.s_addr = htobe32(CLAT_V4_ADDR_U32);

        /* Build IPv4 header */
        ip4 = (struct iphdr *) pkt4;
        memset(ip4, 0, sizeof(*ip4));
        ip4->version = 4;
        ip4->ihl = 5;
        ip4->tos = (be32toh(ip6->ip6_flow) >> 20) & 0xFF;
        ip4->tot_len = htobe16((uint16_t) (sizeof(struct iphdr) + payload_len));
        ip4->id = 0;
        ip4->frag_off = htobe16(IP_DF); /* Don't Fragment, per RFC 7915 */
        ip4->ttl = ip6->ip6_hlim;
        ip4->saddr = src4.s_addr;
        ip4->daddr = dst4.s_addr;

        /* Copy payload after IPv4 header */
        memcpy(pkt4 + sizeof(struct iphdr), pkt6 + sizeof(struct ip6_hdr), payload_len);
        uint8_t *payload = pkt4 + sizeof(struct iphdr);

        /* Protocol-specific translation */
        if (protocol == IPPROTO_ICMPV6) {
                r = xlat_translate_icmp_6to4(payload, payload_len);
                if (r < 0)
                        return r;
                ip4->protocol = IPPROTO_ICMP;
        } else if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                ip4->protocol = protocol;
                xlat_update_transport_checksum_6to4(payload, payload_len, protocol, &src4, &dst4);
        } else {
                return -EOPNOTSUPP;
        }

        /* Compute IPv4 header checksum */
        ip4->check = 0;
        ip4->check = xlat_checksum(ip4, sizeof(struct iphdr));

        /* Write to TUN */
        if (write(link->clat_tun_fd, pkt4, sizeof(struct iphdr) + payload_len) < 0)
                return -errno;

        return 0;
}

static int xlat_tun_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        uint8_t buf[CLAT_BUFSIZE];
        ssize_t n;

        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                log_link_warning_errno(link, errno, "CLAT: failed to read from TUN: %m");
                return 0;
        }
        if (n == 0)
                return 0;

        (void) xlat_translate_and_send_4to6(link, buf, (size_t) n);
        return 0;
}

static int xlat_recv_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        uint8_t buf[CLAT_BUFSIZE];
        ssize_t n;

        /* The BPF socket filter already ensures we only receive IPv6 packets with:
         *   - next header = TCP, UDP, or ICMPv6
         *   - source address matching our PREF64 prefix
         *   - destination address = our cached IPv6 source address
         * So no further filtering is needed here. */

        n = recv(fd, buf, sizeof(buf), MSG_TRUNC);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                log_link_warning_errno(link, errno, "CLAT: failed to read from packet socket: %m");
                return 0;
        }
        if ((size_t) n > sizeof(buf))
                return 0; /* Packet was truncated, skip */
        if (n < (ssize_t) sizeof(struct ip6_hdr))
                return 0;

        (void) xlat_translate_and_send_6to4(link, buf, (size_t) n);
        return 0;
}

static int xlat_create_tun(Link *link) {
        _cleanup_close_ int fd = -EBADF;
        struct ifreq ifr = {};
        const char *tun_name;
        int r;

        assert(link);
        assert(link->ifname);

        tun_name = strjoina("cl-", link->ifname);
        if (strlen(tun_name) >= IFNAMSIZ)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(ENAMETOOLONG),
                                            "CLAT TUN name '%s' is too long.", tun_name);

        fd = open(TUN_DEV, O_RDWR|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_link_error_errno(link, errno, "Failed to open " TUN_DEV ": %m");

        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, tun_name, IFNAMSIZ - 1);

        if (ioctl(fd, TUNSETIFF, &ifr) < 0)
                return log_link_error_errno(link, errno,
                                            "Failed to create CLAT TUN device '%s': %m", tun_name);

        /* Do NOT set TUNSETPERSIST - TUN is automatically removed when fd is closed */

        link->clat_ifindex = (int) if_nametoindex(ifr.ifr_name);
        if (link->clat_ifindex <= 0)
                return log_link_error_errno(link, SYNTHETIC_ERRNO(ENODEV),
                                            "Failed to get ifindex for CLAT TUN '%s'", ifr.ifr_name);

        r = sd_event_add_io(link->manager->event, &link->clat_tun_event_source,
                                fd, EPOLLIN, xlat_tun_handler, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to add CLAT TUN event source: %m");

        (void) sd_event_source_set_description(link->clat_tun_event_source, "network-clat-tun");

        link->clat_tun_fd = TAKE_FD(fd);

        log_link_info(link, "CLAT: TUN device '%s' created (ifindex=%d).",
                      ifr.ifr_name, link->clat_ifindex);
        return 0;
}

static int xlat_create_send_socket(Link *link) {
        _cleanup_close_ int fd = -EBADF;
        int r, one = 1;

        assert(link);

        fd = socket(AF_INET6, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_RAW);
        if (fd < 0)
                return log_link_error_errno(link, errno,
                                            "CLAT: failed to create raw IPv6 send socket: %m");

        r = setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one));
        if (r < 0)
                return log_link_error_errno(link, errno, "CLAT: failed to set IPV6_HDRINCL: %m");

        /* Bind to the outgoing physical interface */
        r = setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &link->ifindex, sizeof(link->ifindex));
        if (r < 0)
                return log_link_error_errno(link, errno,
                                            "CLAT: failed to bind send socket to interface: %m");

        link->clat_send_fd = TAKE_FD(fd);

        log_link_debug(link, "CLAT: raw IPv6 send socket created.");
        return 0;
}

/* Build and attach a classic BPF socket filter to the receive socket.
 *
 * With SOCK_DGRAM on AF_PACKET, we receive IPv6 packets with L2 headers stripped,
 * so the data starts at the IPv6 header. The filter matches:
 *   - IPv6 next header = TCP (6), UDP (17), or ICMPv6 (58)
 *   - Source address starts with the PREF64 prefix
 *   - Destination address = our cached CLAT IPv6 source address
 *
 * IPv6 header layout (offsets from start of packet data):
 *   Byte 6:     Next Header
 *   Bytes 8-23: Source Address (16 bytes)
 *   Bytes 24-39: Destination Address (16 bytes)
 */
static int xlat_attach_bpf_filter(Link *link, int fd) {
        size_t prefix_words = link->clat_pref64_prefix_len / 32;
        size_t prefix_remainder = (link->clat_pref64_prefix_len % 32) / 8;
        const uint8_t *prefix = link->clat_pref64_prefix.s6_addr;
        const uint8_t *dst = link->clat_ipv6_src.s6_addr;

        /* Max filter size: next_header(4) + prefix(3*3 worst case /32) + dst(4*2) + accept/reject(2) = 21
         * Worst case is /32 prefix: 4 + 1*2 + 0 + 4*2 + 2 = 16. /96: 4 + 3*2 + 0 + 4*2 + 2 = 20 */
        struct sock_filter insns[32];
        assert_cc(20 <= ELEMENTSOF(insns));
        size_t i = 0;

        /* Load next header field (byte 6) */
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6);

        /* Accept if next header is TCP, UDP, or ICMPv6 */
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 2, 0);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 1, 0);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, /* reject */ 0);
        /* The reject jump offset in insns[3] will be patched at the end */

        /* Check source address against PREF64 prefix (starts at offset 8).
         * Compare 32-bit words for the full-word portion of the prefix. */
        for (size_t w = 0; w < prefix_words; w++) {
                uint32_t word;
                memcpy(&word, prefix + w * 4, sizeof(word));

                insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8 + w * 4);
                insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, be32toh(word), 0, /* reject */ 0);
        }

        /* Handle remaining bytes of the prefix (if prefix_len is not a multiple of 32) */
        if (prefix_remainder > 0) {
                uint32_t word = 0, mask = 0;

                memcpy(&word, prefix + prefix_words * 4, prefix_remainder);
                memset(&mask, 0xFF, prefix_remainder);

                insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8 + prefix_words * 4);
                insns[i++] = (struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, be32toh(mask));
                insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, be32toh(word), 0, /* reject */ 0);
        }

        /* Check destination address = our IPv6 source (16 bytes at offset 24), 4 words */
        for (size_t w = 0; w < 4; w++) {
                uint32_t word;
                memcpy(&word, dst + w * 4, sizeof(word));

                insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 24 + w * 4);
                insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, be32toh(word), 0, /* reject */ 0);
        }

        /* Accept: return full packet length */
        size_t accept_idx = i;
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, UINT32_MAX);

        /* Reject: return 0 (drop packet) */
        size_t reject_idx = i;
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, 0);

        assert(i <= ELEMENTSOF(insns));

        /* Patch all reject jump offsets. BPF jump targets are relative to the NEXT instruction.
         * Instructions with jf=0 that are JEQ comparisons (not the first three next-header checks)
         * need their false branch pointed to the reject instruction. */
        for (size_t j = 4; j < accept_idx; j++) {
                if (BPF_CLASS(insns[j].code) == BPF_JMP &&
                    BPF_OP(insns[j].code) == BPF_JEQ &&
                    insns[j].jf == 0)
                        insns[j].jf = (uint8_t) (reject_idx - j - 1);
        }

        /* Patch the ICMPv6 check (insns[3]): on mismatch, jump to reject */
        insns[3].jf = (uint8_t) (reject_idx - 3 - 1);

        struct sock_fprog prog = {
                .len = (unsigned short) i,
                .filter = insns,
        };

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
                return log_link_error_errno(link, errno,
                                            "CLAT: failed to attach BPF filter to receive socket: %m");

        log_link_debug(link, "CLAT: attached BPF filter (%zu instructions) to receive socket.", i);
        return 0;
}

static int xlat_create_recv_socket(Link *link) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(link);

        /* AF_PACKET SOCK_DGRAM receives IPv6 packets with L2 headers stripped.
         * A BPF socket filter ensures only relevant CLAT reply packets are delivered
         * to userspace, avoiding unnecessary context switches and copies. */
        fd = socket(AF_PACKET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, htobe16(ETH_P_IPV6));
        if (fd < 0)
                return log_link_error_errno(link, errno,
                                            "CLAT: failed to create packet receive socket: %m");

        /* Bind to the physical interface */
        struct sockaddr_ll sll = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IPV6),
                .sll_ifindex = link->ifindex,
        };

        r = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
        if (r < 0)
                return log_link_error_errno(link, errno,
                                            "CLAT: failed to bind packet socket to interface: %m");

        /* Attach BPF filter to reduce userspace packet processing */
        r = xlat_attach_bpf_filter(link, fd);
        if (r < 0)
                return r;

        r = sd_event_add_io(link->manager->event, &link->clat_recv_event_source,
                            fd, EPOLLIN, xlat_recv_handler, link);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to add receive event source: %m");

        (void) sd_event_source_set_description(link->clat_recv_event_source, "network-clat-recv");

        link->clat_recv_fd = TAKE_FD(fd);

        log_link_debug(link, "CLAT: packet receive socket created.");
        return 0;
}

static int xlat_set_tun_up(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->clat_ifindex > 0);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &m, RTM_SETLINK, link->clat_ifindex);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create RTM_SETLINK message: %m");

        r = sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set IFF_UP flag: %m");

        /* IPv6 header is 40 bytes vs IPv4's 20 bytes = 20 bytes overhead.
         * Cap TUN MTU so packets always fit in the translation buffer. */
        {
                /* Cap TUN MTU so translated IPv6 packets fit within the physical link MTU.
                 * Default to 1280 (IPv6 minimum) when link MTU is unknown. */
                uint32_t base_mtu = link->mtu > 20 ? link->mtu : 1280;
                uint32_t tun_mtu = MIN(base_mtu - 20, CLAT_BUFSIZE - sizeof(struct ip6_hdr));
                r = sd_netlink_message_append_u32(m, IFLA_MTU, tun_mtu);
                if (r < 0)
                        return log_link_error_errno(link, r, "CLAT: failed to set MTU: %m");
        }

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to bring TUN up: %m");

        return 0;
}

static int xlat_configure_address(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct in_addr addr = { .s_addr = htobe32(CLAT_V4_ADDR_U32) };
        int r;

        assert(link);
        assert(link->clat_ifindex > 0);

        r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &m, link->clat_ifindex, AF_INET);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(m, 32);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set prefix length: %m");

        r = sd_rtnl_message_addr_set_scope(m, RT_SCOPE_UNIVERSE);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set address scope: %m");

        r = sd_netlink_message_append_in_addr(m, IFA_LOCAL, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to append IFA_LOCAL: %m");

        r = sd_netlink_message_append_in_addr(m, IFA_ADDRESS, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to append IFA_ADDRESS: %m");

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to configure address 192.0.0.1/32: %m");

        log_link_debug(link, "CLAT: assigned 192.0.0.1/32 to TUN device.");
        return 0;
}

static int xlat_configure_route(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->clat_ifindex > 0);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &m, RTM_NEWROUTE, AF_INET, RTPROT_STATIC);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create RTM_NEWROUTE message: %m");

        r = sd_rtnl_message_route_set_type(m, RTN_UNICAST);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route type: %m");

        r = sd_rtnl_message_route_set_scope(m, RT_SCOPE_UNIVERSE);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route scope: %m");

        /* Default route: 0.0.0.0/0 */
        r = sd_rtnl_message_route_set_dst_prefixlen(m, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set dst prefixlen: %m");

        r = sd_netlink_message_append_u32(m, RTA_OIF, (uint32_t) link->clat_ifindex);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to set output interface: %m");

        r = sd_netlink_message_append_u32(m, RTA_PRIORITY, CLAT_ROUTE_METRIC);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route metric: %m");

        /* Set route MTU and TCP MSS to avoid fragmentation issues.
         * IPv6 minimum MTU is 1280; translated packets gain 20 bytes of IPv6 header overhead,
         * so the effective IPv4 path MTU is 1260. TCP MSS = 1260 - 40 = 1220. */
        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to open RTA_METRICS: %m");

        r = sd_netlink_message_append_u32(m, RTAX_MTU, CLAT_ROUTE_MTU);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route MTU: %m");

        r = sd_netlink_message_append_u32(m, RTAX_ADVMSS, CLAT_ROUTE_ADVMSS);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route advmss: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to close RTA_METRICS: %m");

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to add default route via TUN: %m");

        log_link_debug(link, "CLAT: added default IPv4 route via TUN (metric %" PRIu32 ", mtu %" PRIu32 ").",
                       CLAT_ROUTE_METRIC, CLAT_ROUTE_MTU);
        return 0;
}

/* Add an IPv6 route for the PREF64 prefix via the TUN device.
 * This prevents the kernel's TCP/IPv6 stack from processing translated return
 * traffic (which would generate spurious RSTs), because reverse path filtering
 * drops packets arriving on the physical interface whose source address is
 * routable only through the TUN device. */
static int xlat_configure_pref64_route(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);
        assert(link->clat_ifindex > 0);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &m, RTM_NEWROUTE, AF_INET6, RTPROT_STATIC);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create PREF64 route message: %m");

        r = sd_rtnl_message_route_set_type(m, RTN_UNICAST);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route type: %m");

        r = sd_rtnl_message_route_set_dst_prefixlen(m, link->clat_pref64_prefix_len);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set dst prefixlen: %m");

        r = sd_netlink_message_append_in6_addr(m, RTA_DST, &link->clat_pref64_prefix);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route destination: %m");

        r = sd_netlink_message_append_u32(m, RTA_OIF, (uint32_t) link->clat_ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set output interface: %m");

        r = sd_netlink_message_append_u32(m, RTA_PRIORITY, CLAT_ROUTE_METRIC);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route metric: %m");

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "CLAT: failed to add PREF64 route via TUN: %m");

        log_link_debug(link, "CLAT: added %s/%u route via TUN for reverse path filtering.",
                       IN6_ADDR_TO_STRING(&link->clat_pref64_prefix),
                       link->clat_pref64_prefix_len);
        return 0;
}

#if ENABLE_CLAT_BPF

static struct clat_bpf* clat_bpf_free(struct clat_bpf *obj) {
        clat_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct clat_bpf *, clat_bpf_free);

/* Attach a BPF program to a TC hook using the raw BPF syscall.
 * This avoids requiring bpf_program__attach_tcx from libbpf >= 1.3. */
static int xlat_bpf_attach_tcx(int prog_fd, int ifindex, enum bpf_attach_type attach_type) {
        union bpf_attr attr = {
                .link_create = {
                        .prog_fd        = (__u32) prog_fd,
                        .target_ifindex = (__u32) ifindex,
                        .attach_type    = attach_type,
                },
        };

        int fd = (int) syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
        if (fd < 0)
                return -errno;

        return fd;
}

static int xlat_configure_address_on_link(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct in_addr addr = { .s_addr = htobe32(CLAT_V4_ADDR_U32) };
        int r;

        assert(link);

        r = sd_rtnl_message_new_addr_update(link->manager->rtnl, &m, link->ifindex, AF_INET);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create RTM_NEWADDR message: %m");

        r = sd_rtnl_message_addr_set_prefixlen(m, 32);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set prefix length: %m");

        r = sd_rtnl_message_addr_set_scope(m, RT_SCOPE_UNIVERSE);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set address scope: %m");

        r = sd_netlink_message_append_in_addr(m, IFA_LOCAL, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to append IFA_LOCAL: %m");

        r = sd_netlink_message_append_in_addr(m, IFA_ADDRESS, &addr);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to append IFA_ADDRESS: %m");

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to configure address 192.0.0.1/32 on link: %m");

        log_link_debug(link, "CLAT: assigned 192.0.0.1/32 to physical interface.");
        return 0;
}

static int xlat_configure_route_on_link(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        uint32_t mtu;
        int r;

        assert(link);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &m, RTM_NEWROUTE, AF_INET, RTPROT_STATIC);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to create RTM_NEWROUTE message: %m");

        r = sd_rtnl_message_route_set_type(m, RTN_UNICAST);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route type: %m");

        r = sd_rtnl_message_route_set_scope(m, RT_SCOPE_UNIVERSE);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route scope: %m");

        r = sd_rtnl_message_route_set_dst_prefixlen(m, 0);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set dst prefixlen: %m");

        r = sd_netlink_message_append_u32(m, RTA_OIF, (uint32_t) link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to set output interface: %m");

        r = sd_netlink_message_append_u32(m, RTA_PRIORITY, CLAT_ROUTE_METRIC);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route metric: %m");

        /* Dynamic MTU: link MTU minus 20 bytes for IPv4→IPv6 header size difference
         * (IPv6 header is 40 bytes vs IPv4's 20 bytes). Consistent with TUN path. */
        mtu = link->mtu > 0 ? link->mtu : 1500;
        if (mtu < 1280)
                mtu = 1280;
        mtu -= 20;

        r = sd_netlink_message_open_container(m, RTA_METRICS);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to open RTA_METRICS: %m");

        r = sd_netlink_message_append_u32(m, RTAX_MTU, mtu);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route MTU: %m");

        uint32_t advmss = mtu > 40 ? mtu - 40 : 0;
        r = sd_netlink_message_append_u32(m, RTAX_ADVMSS, advmss);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to set route advmss: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_link_error_errno(link, r, "CLAT: failed to close RTA_METRICS: %m");

        r = sd_netlink_call(link->manager->rtnl, m, 0, NULL);
        if (r < 0)
                return log_link_error_errno(link, r,
                                            "CLAT: failed to add default route via physical interface: %m");

        log_link_debug(link, "CLAT: added default IPv4 route (metric %" PRIu32 ", mtu %" PRIu32 ").",
                       CLAT_ROUTE_METRIC, mtu);
        return 0;
}

static int xlat_remove_address_from_link(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct in_addr addr = { .s_addr = htobe32(CLAT_V4_ADDR_U32) };
        int r;

        assert(link);

        r = sd_rtnl_message_new_addr(link->manager->rtnl, &m, RTM_DELADDR, link->ifindex, AF_INET);
        if (r < 0)
                return r;

        r = sd_rtnl_message_addr_set_prefixlen(m, 32);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_in_addr(m, IFA_LOCAL, &addr);
        if (r < 0)
                return r;

        return sd_netlink_call(link->manager->rtnl, m, 0, NULL);
}

static int xlat_remove_route_from_link(Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(link);

        r = sd_rtnl_message_new_route(link->manager->rtnl, &m, RTM_DELROUTE, AF_INET, RTPROT_STATIC);
        if (r < 0)
                return r;

        r = sd_rtnl_message_route_set_dst_prefixlen(m, 0);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, RTA_OIF, (uint32_t) link->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, RTA_PRIORITY, CLAT_ROUTE_METRIC);
        if (r < 0)
                return r;

        return sd_netlink_call(link->manager->rtnl, m, 0, NULL);
}

static void xlat_close_bpf(Link *link) {
        assert(link);

        /* Remove address and route from the physical interface.
         * Ignore errors — the interface may already be gone. */
        (void) xlat_remove_route_from_link(link);
        (void) xlat_remove_address_from_link(link);

        link->clat_bpf_ingress_fd = safe_close(link->clat_bpf_ingress_fd);
        link->clat_bpf_egress_fd = safe_close(link->clat_bpf_egress_fd);

        if (link->clat_bpf_obj) {
                clat_bpf__destroy(link->clat_bpf_obj);
                link->clat_bpf_obj = NULL;
        }

        link->clat_bpf_active = false;
}

static int xlat_start_bpf(Link *link) {
        _cleanup_(clat_bpf_freep) struct clat_bpf *obj = NULL;
        int r, egress_fd = -EBADF, ingress_fd = -EBADF;

        assert(link);

        r = dlopen_bpf();
        if (r < 0)
                return log_link_debug_errno(link, r,
                                            "CLAT: BPF support not available, will try TUN fallback.");

        obj = clat_bpf__open();
        if (!obj)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "CLAT: failed to open BPF program, will try TUN fallback.");

        /* Configure BPF program via BSS section before loading */
        struct in_addr v4 = { .s_addr = htobe32(CLAT_V4_ADDR_U32) };
        memcpy(obj->bss->clat_cfg.local_v6, &link->clat_ipv6_src, 16);
        memcpy(obj->bss->clat_cfg.pref64, &link->clat_pref64_prefix, 16);
        memcpy(obj->bss->clat_cfg.local_v4, &v4, 4);
        obj->bss->clat_cfg.pref64_len = link->clat_pref64_prefix_len;

        r = clat_bpf__load(obj);
        if (r < 0)
                return log_link_debug_errno(link, r,
                                            "CLAT: failed to load BPF program, will try TUN fallback.");

        /* Attach egress program (IPv4→IPv6) */
        egress_fd = xlat_bpf_attach_tcx(
                        sym_bpf_program__fd(obj->progs.clat_egress),
                        link->ifindex,
                        BPF_TCX_EGRESS);
        if (egress_fd < 0)
                return log_link_debug_errno(link, egress_fd,
                                            "CLAT: failed to attach BPF egress program, will try TUN fallback.");

        /* Attach ingress program (IPv6→IPv4) */
        ingress_fd = xlat_bpf_attach_tcx(
                        sym_bpf_program__fd(obj->progs.clat_ingress),
                        link->ifindex,
                        BPF_TCX_INGRESS);
        if (ingress_fd < 0) {
                safe_close(egress_fd);
                return log_link_debug_errno(link, ingress_fd,
                                            "CLAT: failed to attach BPF ingress program, will try TUN fallback.");
        }

        /* Commit BPF state to link before configuring address/route,
         * so xlat_close_bpf() can clean up everything on failure. */
        link->clat_bpf_obj = TAKE_PTR(obj);
        link->clat_bpf_egress_fd = egress_fd;
        link->clat_bpf_ingress_fd = ingress_fd;
        link->clat_bpf_active = true;

        /* Configure IPv4 address on physical interface */
        r = xlat_configure_address_on_link(link);
        if (r < 0) {
                xlat_close_bpf(link);
                return r;
        }

        /* Configure default IPv4 route */
        r = xlat_configure_route_on_link(link);
        if (r < 0) {
                xlat_close_bpf(link);
                return r;
        }

        log_link_info(link, "CLAT: started using BPF TC translation.");
        return 0;
}

#endif /* ENABLE_CLAT_BPF */

/* Clean up all CLAT resources unconditionally (does not check clat_running) */
static void xlat_close(Link *link) {
        assert(link);

#if ENABLE_CLAT_BPF
        if (link->clat_bpf_active)
                xlat_close_bpf(link);
        else
#endif
        {
                /* TUN fallback cleanup */
                link->clat_tun_event_source = sd_event_source_disable_unref(link->clat_tun_event_source);
                link->clat_recv_event_source = sd_event_source_disable_unref(link->clat_recv_event_source);

                link->clat_tun_fd = safe_close(link->clat_tun_fd);
                link->clat_send_fd = safe_close(link->clat_send_fd);
                link->clat_recv_fd = safe_close(link->clat_recv_fd);

                link->clat_ifindex = 0;
        }

        link->clat_running = false;
}

int xlat_start(Link *link) {
        NDiscPREF64 *p64;
        int r;

        assert(link);

        if (!link_xlat_enabled(link))
                return 0;

        if (link->clat_running)
                return 0;

        /* Skip CLAT if the link already has native IPv4 connectivity */
        if (link_has_default_gateway(link, AF_INET)) {
                log_link_debug(link, "CLAT: link already has IPv4 default gateway, skipping.");
                return 0;
        }

        /* Use manually configured PREF64 prefix if available, otherwise use NDisc-discovered one */
        if (link->network->clat_pref64_prefix_len > 0) {
                link->clat_pref64_prefix = link->network->clat_pref64_prefix;
                link->clat_pref64_prefix_len = link->network->clat_pref64_prefix_len;
        } else {
                if (set_isempty(link->ndisc_pref64))
                        return 0;

                /* Pick an arbitrary PREF64 entry. When multiple entries exist (e.g., from
                 * different routers), the choice is non-deterministic. Use Pref64Prefix= for
                 * deterministic prefix selection. */
                p64 = set_first(link->ndisc_pref64);
                if (!p64)
                        return 0;

                link->clat_pref64_prefix = p64->prefix;
                link->clat_pref64_prefix_len = p64->prefix_len;
        }

        /* Select and cache the global IPv6 source address for translation */
        r = xlat_select_ipv6_source(link, &link->clat_ipv6_src);
        if (r < 0)
                return log_link_debug_errno(link, r,
                                            "CLAT: no global IPv6 address available, deferring.");

        log_link_info(link, "CLAT: starting with PREF64 %s/%u, source %s.",
                      IN6_ADDR_TO_STRING(&link->clat_pref64_prefix),
                      link->clat_pref64_prefix_len,
                      IN6_ADDR_TO_STRING(&link->clat_ipv6_src));

#if ENABLE_CLAT_BPF
        /* Try BPF TC translation first (in-kernel, zero context switches per packet) */
        r = xlat_start_bpf(link);
        if (r >= 0) {
                link->clat_running = true;
                return 0;
        }

        /* BPF failed, fall through to TUN */
        log_link_info(link, "CLAT: falling back to TUN device translation.");
#endif

        /* TUN fallback: userspace packet translation */
        r = xlat_create_tun(link);
        if (r < 0)
                goto fail;

        r = xlat_set_tun_up(link);
        if (r < 0)
                goto fail;

        r = xlat_configure_address(link);
        if (r < 0)
                goto fail;

        r = xlat_configure_route(link);
        if (r < 0)
                goto fail;

        r = xlat_create_send_socket(link);
        if (r < 0)
                goto fail;

        r = xlat_create_recv_socket(link);
        if (r < 0)
                goto fail;

        /* Add PREF64 route via TUN to prevent kernel TCP stack from processing
         * CLAT return traffic and generating spurious RSTs (non-fatal if it fails) */
        (void) xlat_configure_pref64_route(link);

        log_link_info(link, "CLAT: started using TUN device translation.");
        link->clat_running = true;
        return 0;

fail:
        xlat_close(link);
        return r;
}

int xlat_stop(Link *link) {
        assert(link);

        if (!link->clat_running)
                return 0;

        xlat_close(link);

        log_link_info(link, "CLAT stopped.");
        return 0;
}

int xlat_check_address(Link *link) {
        struct in6_addr current_src;

        assert(link);

        if (!link->clat_running)
                return 0;

        /* Check if the cached IPv6 source address is still valid */
        if (xlat_select_ipv6_source(link, &current_src) < 0 ||
            !in6_addr_equal(&current_src, &link->clat_ipv6_src)) {
                int r;

                log_link_info(link, "CLAT: IPv6 source address changed or removed, restarting.");
                xlat_stop(link);
                r = xlat_start(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "CLAT: failed to restart after source address change.");
                return r;
        }

        return 0;
}

int xlat_check_route(Link *link) {
        assert(link);

        if (!link->clat_running)
                return 0;

        /* Stop CLAT if a native IPv4 default gateway has appeared */
        if (link_has_default_gateway(link, AF_INET)) {
                log_link_info(link, "CLAT: native IPv4 default gateway appeared, stopping.");
                return xlat_stop(link);
        }

        return 0;
}

void xlat_done(Link *link) {
        if (!link)
                return;

        xlat_stop(link);
}

int config_parse_clat_pref64_prefix(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        union in_addr_union a;
        uint8_t prefixlen;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->clat_pref64_prefix = (struct in6_addr) {};
                network->clat_pref64_prefix_len = 0;
                return 0;
        }

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &prefixlen);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "CLAT PREF64 prefix is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        if (!IN_SET(prefixlen, 96, 64, 56, 48, 40, 32)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "CLAT PREF64 prefix length must be 32, 40, 48, 56, 64, or 96, "
                           "ignoring assignment: %s", rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, prefixlen);
        network->clat_pref64_prefix = a.in6;
        network->clat_pref64_prefix_len = prefixlen;

        return 0;
}
