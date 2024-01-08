/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "resolved-dns-packet.h"
#include "resolved-manager.h"
#include "socket-netlink.h"
#include "socket-util.h"

/* Taken from resolved-dns-stub.c */
#define ADVERTISE_DATAGRAM_SIZE_MAX (65536U-14U-20U-8U)

/* This is more or less verbatim manager_recv() from resolved-manager.c, sans the manager stuff */
static int server_recv(int fd, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        CMSG_BUFFER_TYPE(CMSG_SPACE(MAXSIZE(struct in_pktinfo, struct in6_pktinfo))
                         + CMSG_SPACE(int) /* ttl/hoplimit */
                         + EXTRA_CMSG_SPACE /* kernel appears to require extra buffer space */) control;
        union sockaddr_union sa;
        struct iovec iov;
        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t ms, l;
        int r;

        assert(fd >= 0);
        assert(ret);

        ms = next_datagram_size_fd(fd);
        if (ms < 0)
                return ms;

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, ms, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        iov = IOVEC_MAKE(DNS_PACKET_DATA(p), p->allocated);

        l = recvmsg_safe(fd, &mh, 0);
        if (ERRNO_IS_NEG_TRANSIENT(l))
                return 0;
        if (l <= 0)
                return l;

        assert(!(mh.msg_flags & MSG_TRUNC));

        p->size = (size_t) l;

        p->family = sa.sa.sa_family;
        p->ipproto = IPPROTO_UDP;
        if (p->family == AF_INET) {
                p->sender.in = sa.in.sin_addr;
                p->sender_port = be16toh(sa.in.sin_port);
        } else if (p->family == AF_INET6) {
                p->sender.in6 = sa.in6.sin6_addr;
                p->sender_port = be16toh(sa.in6.sin6_port);
                p->ifindex = sa.in6.sin6_scope_id;
        } else
                return -EAFNOSUPPORT;

        p->timestamp = now(CLOCK_BOOTTIME);

        CMSG_FOREACH(cmsg, &mh) {

                if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        assert(p->family == AF_INET6);

                        switch (cmsg->cmsg_type) {

                        case IPV6_PKTINFO: {
                                struct in6_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi6_ifindex;

                                p->destination.in6 = i->ipi6_addr;
                                break;
                        }

                        case IPV6_HOPLIMIT:
                                p->ttl = *CMSG_TYPED_DATA(cmsg, int);
                                break;

                        case IPV6_RECVFRAGSIZE:
                                p->fragsize = *CMSG_TYPED_DATA(cmsg, int);
                                break;
                        }
                } else if (cmsg->cmsg_level == IPPROTO_IP) {
                        assert(p->family == AF_INET);

                        switch (cmsg->cmsg_type) {

                        case IP_PKTINFO: {
                                struct in_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in_pktinfo);

                                if (p->ifindex <= 0)
                                        p->ifindex = i->ipi_ifindex;

                                p->destination.in = i->ipi_addr;
                                break;
                        }

                        case IP_TTL:
                                p->ttl = *CMSG_TYPED_DATA(cmsg, int);
                                break;

                        case IP_RECVFRAGSIZE:
                                p->fragsize = *CMSG_TYPED_DATA(cmsg, int);
                                break;
                        }
                }
        }

        /* The Linux kernel sets the interface index to the loopback
         * device if the packet came from the local host since it
         * avoids the routing table in such a case. Let's unset the
         * interface index in such a case. */
        if (p->ifindex == LOOPBACK_IFINDEX)
                p->ifindex = 0;

        log_debug("Received DNS UDP packet of size %zu, ifindex=%i, ttl=%u, fragsize=%zu, sender=%s, destination=%s",
                  p->size, p->ifindex, p->ttl, p->fragsize,
                  IN_ADDR_TO_STRING(p->family, &p->sender),
                  IN_ADDR_TO_STRING(p->family, &p->destination));

        *ret = TAKE_PTR(p);
        return 1;
}

/* Same as above, see manager_ipv4_send() in resolved-manager.c */
static int server_ipv4_send(
                int fd,
                const struct in_addr *destination,
                uint16_t port,
                const struct in_addr *source,
                DnsPacket *packet) {

        union sockaddr_union sa;
        struct iovec iov;
        struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa.in),
        };

        assert(fd >= 0);
        assert(destination);
        assert(port > 0);
        assert(packet);

        iov = IOVEC_MAKE(DNS_PACKET_DATA(packet), packet->size);

        sa = (union sockaddr_union) {
                .in.sin_family = AF_INET,
                .in.sin_addr = *destination,
                .in.sin_port = htobe16(port),
        };

        return sendmsg_loop(fd, &mh, 0);
}

static int make_reply_packet(DnsPacket *packet, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        assert(packet);
        assert(ret);

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, DNS_PACKET_PAYLOAD_SIZE_MAX(packet));
        if (r < 0)
                return r;

        r = dns_packet_append_question(p, packet->question);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(p)->id = DNS_PACKET_ID(packet);
        DNS_PACKET_HEADER(p)->qdcount = htobe16(dns_question_size(packet->question));

        *ret = TAKE_PTR(p);
        return 0;
}

static int reply_append_edns(DnsPacket *packet, DnsPacket *reply, const char *extra_text, size_t rcode, uint16_t ede_code) {
        size_t saved_size;
        int r;

        assert(packet);
        assert(reply);

        /* Append EDNS0 stuff (inspired by dns_packet_append_opt() from resolved-dns-packet.c).
         *
         * Relevant headers from RFC 6891:
         *
         * +------------+--------------+------------------------------+
         * | Field Name | Field Type   | Description                  |
         * +------------+--------------+------------------------------+
         * | NAME       | domain name  | MUST be 0 (root domain)      |
         * | TYPE       | u_int16_t    | OPT (41)                     |
         * | CLASS      | u_int16_t    | requestor's UDP payload size |
         * | TTL        | u_int32_t    | extended RCODE and flags     |
         * | RDLEN      | u_int16_t    | length of all RDATA          |
         * | RDATA      | octet stream | {attribute,value} pairs      |
         * +------------+--------------+------------------------------+
         *
         *               +0 (MSB)                            +1 (LSB)
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 0: |                          OPTION-CODE                          |
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 2: |                         OPTION-LENGTH                         |
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 4: |                                                               |
         *    /                          OPTION-DATA                          /
         *    /                                                               /
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         *
         * And from RFC 8914:
         *
         *                                              1   1   1   1   1   1
         *      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 0: |                            OPTION-CODE                        |
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 2: |                           OPTION-LENGTH                       |
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 4: | INFO-CODE                                                     |
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         * 6: / EXTRA-TEXT ...                                                /
         *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         */

        saved_size = reply->size;

        /* empty name */
        r = dns_packet_append_uint8(reply, 0, NULL);
        if (r < 0)
                return r;

        /* type */
        r = dns_packet_append_uint16(reply, DNS_TYPE_OPT, NULL);
        if (r < 0)
                return r;

        /* class: maximum udp packet that can be received */
        r = dns_packet_append_uint16(reply, ADVERTISE_DATAGRAM_SIZE_MAX, NULL);
        if (r < 0)
                return r;

        /* extended RCODE and VERSION */
        r = dns_packet_append_uint16(reply, ((uint16_t) rcode & 0x0FF0) << 4, NULL);
        if (r < 0)
                return r;

        /* flags: DNSSEC OK (DO), see RFC3225 */
        r = dns_packet_append_uint16(reply, 0, NULL);
        if (r < 0)
                return r;

        /* RDATA */

        size_t extra_text_len = isempty(extra_text) ? 0 : strlen(extra_text);
        /* RDLENGTH (OPTION CODE + OPTION LENGTH + INFO-CODE + EXTRA-TEXT) */
        r = dns_packet_append_uint16(reply, 2 + 2 + 2 + extra_text_len, NULL);
        if (r < 0)
                return 0;

        /* OPTION-CODE: 15 for EDE */
        r = dns_packet_append_uint16(reply, 15, NULL);
        if (r < 0)
                return r;

        /* OPTION-LENGTH: INFO-CODE + EXTRA-TEXT */
        r = dns_packet_append_uint16(reply, 2 + extra_text_len, NULL);
        if (r < 0)
                return r;

        /* INFO-CODE: EDE code */
        r = dns_packet_append_uint16(reply, ede_code, NULL);
        if (r < 0)
                return r;

        /* EXTRA-TEXT */
        if (extra_text_len > 0) {
                /* From RFC 8914:
                 *  EDE text may be null terminated but MUST NOT be assumed to be; the length MUST be derived
                 *  from the OPTION-LENGTH field
                 *
                 *  Let's exercise our code on the receiving side and not NUL-terminate the EXTRA-TEXT field
                 */
                r = dns_packet_append_blob(reply, extra_text, extra_text_len, NULL);
                if (r < 0)
                        return r;
        }

        DNS_PACKET_HEADER(reply)->arcount = htobe16(DNS_PACKET_ARCOUNT(reply) + 1);
        reply->opt_start = saved_size;
        reply->opt_size = reply->size - saved_size;

        /* Order: qr, opcode, aa, tc, rd, ra, ad, cd, rcode */
        DNS_PACKET_HEADER(reply)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                1, 0, 0, 0, DNS_PACKET_RD(packet), 1, 0, 1, rcode));
        return 0;
}

static void server_fail(DnsPacket *packet, DnsPacket *reply, int rcode) {
        assert(reply);

        /* Order: qr, opcode, aa, tc, rd, ra, ad, cd, rcode */
        DNS_PACKET_HEADER(reply)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                1, 0, 0, 0, DNS_PACKET_RD(packet), 1, 0, 1, rcode));
}

static int server_handle_edns_bogus_dnssec(DnsPacket *packet, DnsPacket *reply) {
        assert(packet);
        assert(reply);

        return reply_append_edns(packet, reply, NULL, DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_DNSSEC_BOGUS);
}

static int server_handle_edns_extra_text(DnsPacket *packet, DnsPacket *reply) {
        assert(packet);
        assert(reply);

        return reply_append_edns(packet, reply, "Nothing to see here!", DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_CENSORED);
}

static int server_handle_edns_invalid_code(DnsPacket *packet, DnsPacket *reply, const char *extra_text) {
        assert(packet);
        assert(reply);
        assert_cc(_DNS_EDE_RCODE_MAX_DEFINED < UINT16_MAX);

        return reply_append_edns(packet, reply, extra_text, DNS_RCODE_SERVFAIL, _DNS_EDE_RCODE_MAX_DEFINED + 1);
}

static int server_handle_edns_code_zero(DnsPacket *packet, DnsPacket *reply) {
        assert(packet);
        assert(reply);
        assert_cc(DNS_EDE_RCODE_OTHER == 0);

        return reply_append_edns(packet, reply, "\xF0\x9F\x90\xB1", DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_OTHER);
}

int main(int argc, char *argv[]) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        log_parse_environment();
        log_open();

        if (argc != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes one argument in format ip_address:port");

        fd = make_socket_fd(LOG_DEBUG, argv[1], SOCK_DGRAM, SOCK_CLOEXEC);
        if (fd < 0)
                return log_error_errno(fd, "Failed to listen on address '%s': %m", argv[1]);

        (void) sd_notify(/* unset_environment=false */ false, "READY=1");

        for (;;) {
                _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
                _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
                const char *name;

                r = server_recv(fd, &packet);
                if (r < 0) {
                        log_debug_errno(r, "Failed to receive packet, ignoring: %m");
                        continue;
                }

                r = dns_packet_validate_query(packet);
                if (r < 0) {
                        log_debug_errno(r, "Invalid DNS UDP packet, ignoring.");
                        continue;
                }

                r = dns_packet_extract(packet);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract DNS packet, ignoring: %m");
                        continue;
                }

                name = dns_question_first_name(packet->question);
                log_info("Processing question for name '%s'", name);

                (void) dns_question_dump(packet->question, stdout);

                r = make_reply_packet(packet, &reply);
                if (r < 0) {
                        log_debug_errno(r, "Failed to make reply packet: %m");
                        break;
                }

                if (streq_ptr(name, "edns-bogus-dnssec.forwarded.test"))
                        r = server_handle_edns_bogus_dnssec(packet, reply);
                else if (streq_ptr(name, "edns-extra-text.forwarded.test"))
                        r = server_handle_edns_extra_text(packet, reply);
                else if (streq_ptr(name, "edns-invalid-code.forwarded.test"))
                        r = server_handle_edns_invalid_code(packet, reply, NULL);
                else if (streq_ptr(name, "edns-invalid-code-with-extra-text.forwarded.test"))
                        r = server_handle_edns_invalid_code(packet, reply, "Hello [#]$%~ World");
                else if (streq_ptr(name, "edns-code-zero.forwarded.test"))
                        r = server_handle_edns_code_zero(packet, reply);
                else
                        r = log_debug_errno(SYNTHETIC_ERRNO(EFAULT), "Unhandled name '%s', ignoring.", name);

                if (r < 0)
                        server_fail(packet, reply, DNS_RCODE_NXDOMAIN);

                r = server_ipv4_send(fd, &packet->sender.in, packet->sender_port, &packet->destination.in, reply);
                if (r < 0)
                        log_debug_errno(r, "Failed to send reply: %m");

        }

        return 0;
}
