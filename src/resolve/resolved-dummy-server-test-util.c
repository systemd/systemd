/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "resolved-dummy-server-test-util.h"
#include "resolved-manager.h"
#include "set.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

/* The names this server knows about:
 *
 *   edns-bogus-dnssec.forwarded.test                  → SERVFAIL + EDE "DNSSEC Bogus"
 *   edns-extra-text.forwarded.test                    → SERVFAIL + EDE "Censored" + extra text
 *   edns-invalid-code.forwarded.test                  → SERVFAIL + an undefined EDE code
 *   edns-invalid-code-with-extra-text.forwarded.test  → SERVFAIL + an undefined EDE code + extra text
 *   edns-code-zero.forwarded.test                     → SERVFAIL + EDE "Other" + extra text
 *
 *   The *.stream.test names below reply with a truncated packet over UDP, to force the client to use a
 *   stream (TCP, or DNS-over-TLS terminated by a proxy in front of us). Over the stream:
 *
 *   servfail-with-opt.stream.test    → SERVFAIL as long as the query carries an OPT RR, i.e. emulates a
 *                                      server choking on EDNS0, and an A record otherwise.
 *   not-ready-then-ok.stream.test    → SERVFAIL + EDE "Not Ready" and an A record, alternatingly.
 *
 *   Everything else → NXDOMAIN
 */

struct DummyServer {
        sd_event_source *udp_event_source;
        sd_event_source *stream_event_source;
        Set *connections;

        unsigned n_not_ready_queries;
};

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

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, dns_packet_payload_size_max(packet));
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

static void server_truncate(DnsPacket *packet, DnsPacket *reply) {
        assert(packet);
        assert(reply);

        /* Order: qr, opcode, aa, tc, rd, ra, ad, cd, rcode */
        DNS_PACKET_HEADER(reply)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                1, 0, 0, 1, DNS_PACKET_RD(packet), 1, 0, 0, DNS_RCODE_SUCCESS));
}

static int server_answer_stream_test_address(DnsPacket *packet, DnsPacket *reply) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        union in_addr_union address;
        int r;

        assert(packet);
        assert(reply);

        assert_se(in_addr_from_string(AF_INET, DUMMY_SERVER_STREAM_TEST_ADDRESS, &address) >= 0);

        r = dns_resource_record_new_address(&rr, AF_INET, &address, dns_question_first_name(packet->question));
        if (r < 0)
                return r;

        r = dns_packet_append_rr(reply, rr, 0, NULL, NULL);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(reply)->ancount = htobe16(1);

        /* Like any EDNS0-capable server, reply with an OPT RR if the query carried one. Otherwise resolved
         * concludes that we don't support EDNS0, and restarts the lookup at a lower feature level. */
        if (packet->opt) {
                r = dns_packet_append_opt(reply, ADVERTISE_DATAGRAM_SIZE_MAX, /* edns0_do= */ false,
                                          /* include_rfc6975= */ false, /* nsid= */ NULL, DNS_RCODE_SUCCESS,
                                          /* ret_start= */ NULL);
                if (r < 0)
                        return r;
        }

        /* Order: qr, opcode, aa, tc, rd, ra, ad, cd, rcode */
        DNS_PACKET_HEADER(reply)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                                1, 0, 1, 0, DNS_PACKET_RD(packet), 1, 0, 0, DNS_RCODE_SUCCESS));
        return 0;
}

static int server_handle_servfail_with_opt(DnsPacket *packet, DnsPacket *reply) {
        assert(packet);
        assert(reply);

        if (packet->ipproto == IPPROTO_UDP) {
                server_truncate(packet, reply);
                return 0;
        }

        if (packet->opt) {
                log_info("Query carries an OPT RR, replying with SERVFAIL.");
                server_fail(packet, reply, DNS_RCODE_SERVFAIL);
                return 0;
        }

        return server_answer_stream_test_address(packet, reply);
}

static int server_handle_not_ready_then_ok(DummyServer *s, DnsPacket *packet, DnsPacket *reply) {
        assert(s);
        assert(packet);
        assert(reply);

        if (packet->ipproto == IPPROTO_UDP) {
                server_truncate(packet, reply);
                return 0;
        }

        if (s->n_not_ready_queries++ % 2 == 0) {
                log_info("Replying with SERVFAIL (Not Ready).");
                return reply_append_edns(packet, reply, NULL, DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_NOT_READY);
        }

        return server_answer_stream_test_address(packet, reply);
}

static int server_process_query(DummyServer *s, DnsPacket *packet, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        const char *name;
        int r;

        assert(s);
        assert(packet);
        assert(ret);

        r = dns_packet_validate_query(packet);
        if (r < 0)
                return log_debug_errno(r, "Invalid DNS packet, ignoring.");

        r = dns_packet_extract(packet);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract DNS packet, ignoring: %m");

        name = dns_question_first_name(packet->question);
        log_info("Processing question for name '%s' (%s, %s OPT RR)",
                 name,
                 packet->ipproto == IPPROTO_TCP ? "TCP" : "UDP",
                 packet->opt ? "with" : "without");

        dns_question_dump(packet->question, stdout);

        r = make_reply_packet(packet, &reply);
        if (r < 0)
                return log_debug_errno(r, "Failed to make reply packet, ignoring: %m");

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
        else if (streq_ptr(name, "servfail-with-opt.stream.test"))
                r = server_handle_servfail_with_opt(packet, reply);
        else if (streq_ptr(name, "not-ready-then-ok.stream.test"))
                r = server_handle_not_ready_then_ok(s, packet, reply);
        else
                r = log_debug_errno(SYNTHETIC_ERRNO(EFAULT), "Unhandled name '%s', ignoring.", name);
        if (r < 0)
                server_fail(packet, reply, DNS_RCODE_NXDOMAIN);

        *ret = TAKE_PTR(reply);
        return 0;
}

static int on_dns_packet(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DummyServer *s = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        r = server_recv(fd, &packet);
        if (r < 0) {
                log_debug_errno(r, "Failed to receive packet, ignoring: %m");
                return 0;
        }
        if (r == 0)
                return 0;

        if (server_process_query(s, packet, &reply) < 0)
                return 0;

        r = server_ipv4_send(fd, &packet->sender.in, packet->sender_port, &packet->destination.in, reply);
        if (r < 0)
                log_debug_errno(r, "Failed to send reply, ignoring: %m");

        return 0;
}

static int on_dns_stream_packet(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        DummyServer *s = ASSERT_PTR(userdata);
        be16_t size;
        ssize_t n;
        int r;

        assert(source);
        assert(fd >= 0);

        /* Each message on a DNS stream is prefixed by its size as 16-bit big-endian integer (RFC 1035,
         * Section 4.2.2). For simplicity we do blocking I/O here, a test server doesn't need to be fancy. */

        n = loop_read(fd, &size, sizeof(size), /* do_poll= */ true);
        if (n < 0)
                log_debug_errno(n, "Failed to read message size from stream: %m");
        if (n != sizeof(size))
                goto close;

        r = dns_packet_new(&packet, DNS_PROTOCOL_DNS, be16toh(size), DNS_PACKET_SIZE_MAX);
        if (r < 0) {
                log_debug_errno(r, "Failed to allocate packet: %m");
                goto close;
        }

        r = loop_read_exact(fd, DNS_PACKET_DATA(packet), be16toh(size), /* do_poll= */ true);
        if (r < 0) {
                log_debug_errno(r, "Failed to read message from stream: %m");
                goto close;
        }

        packet->size = be16toh(size);
        packet->ipproto = IPPROTO_TCP;
        packet->timestamp = now(CLOCK_BOOTTIME);

        if (server_process_query(s, packet, &reply) < 0)
                goto close;

        size = htobe16(reply->size);
        r = loop_write(fd, &size, sizeof(size));
        if (r >= 0)
                r = loop_write(fd, DNS_PACKET_DATA(reply), reply->size);
        if (r < 0) {
                log_debug_errno(r, "Failed to write reply to stream: %m");
                goto close;
        }

        return 0;

close:
        /* This also closes the fd, as the event source owns it. */
        sd_event_source_disable_unref(set_remove(s->connections, source));
        return 0;
}

static int on_dns_stream_connection(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *connection = NULL;
        _cleanup_close_ int cfd = -EBADF;
        DummyServer *s = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
                log_debug_errno(errno, "Failed to accept stream connection, ignoring: %m");
                return 0;
        }

        r = sd_event_add_io(sd_event_source_get_event(source), &connection, cfd, EPOLLIN, on_dns_stream_packet, s);
        if (r < 0) {
                log_debug_errno(r, "Failed to add IO event source for stream connection, ignoring: %m");
                return 0;
        }

        r = sd_event_source_set_io_fd_own(connection, true);
        if (r < 0) {
                log_debug_errno(r, "Failed to pass ownership of stream fd to event source, ignoring: %m");
                return 0;
        }
        TAKE_FD(cfd);

        r = set_ensure_consume(&s->connections, &event_source_hash_ops, TAKE_PTR(connection));
        if (r < 0)
                log_debug_errno(r, "Failed to track stream connection, ignoring: %m");

        return 0;
}

static int add_listener(
                sd_event *event,
                const char *address,
                int type,
                sd_event_io_handler_t callback,
                DummyServer *s,
                sd_event_source **ret) {

        _cleanup_(sd_event_source_disable_unrefp) sd_event_source *source = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(event);
        assert(address);
        assert(s);
        assert(ret);

        fd = make_socket_fd(LOG_DEBUG, address, type, SOCK_CLOEXEC);
        if (fd < 0)
                return log_error_errno(fd, "Failed to listen on %s address '%s': %m",
                                       type == SOCK_STREAM ? "stream" : "datagram", address);

        r = sd_event_add_io(event, &source, fd, EPOLLIN, callback, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add IO event source: %m");

        r = sd_event_source_set_io_fd_own(source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to pass ownership of fd to event source: %m");
        TAKE_FD(fd);

        *ret = TAKE_PTR(source);
        return 0;
}

int dummy_server_new(sd_event *event, const char *address, DummyServer **ret) {
        _cleanup_(dummy_server_freep) DummyServer *s = NULL;
        int r;

        assert(event);
        assert(address);
        assert(ret);

        s = new0(DummyServer, 1);
        if (!s)
                return log_oom();

        r = add_listener(event, address, SOCK_DGRAM, on_dns_packet, s, &s->udp_event_source);
        if (r < 0)
                return r;

        r = add_listener(event, address, SOCK_STREAM, on_dns_stream_connection, s, &s->stream_event_source);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

DummyServer* dummy_server_free(DummyServer *s) {
        if (!s)
                return NULL;

        sd_event_source_disable_unref(s->udp_event_source);
        sd_event_source_disable_unref(s->stream_event_source);
        set_free(s->connections);

        return mfree(s);
}
