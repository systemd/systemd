/* SPDX-License-Identifier: LGPL-2.1+ */

#include <netinet/in.h>
#include <resolv.h>

#include "errno-util.h"
#include "fd-util.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"

void manager_llmnr_stop(Manager *m) {
        assert(m);

        m->llmnr_ipv4_udp_event_source = sd_event_source_unref(m->llmnr_ipv4_udp_event_source);
        m->llmnr_ipv4_udp_fd = safe_close(m->llmnr_ipv4_udp_fd);

        m->llmnr_ipv6_udp_event_source = sd_event_source_unref(m->llmnr_ipv6_udp_event_source);
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);

        m->llmnr_ipv4_tcp_event_source = sd_event_source_unref(m->llmnr_ipv4_tcp_event_source);
        m->llmnr_ipv4_tcp_fd = safe_close(m->llmnr_ipv4_tcp_fd);

        m->llmnr_ipv6_tcp_event_source = sd_event_source_unref(m->llmnr_ipv6_tcp_event_source);
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
}

int manager_llmnr_start(Manager *m) {
        int r;

        assert(m);

        if (m->llmnr_support == RESOLVE_SUPPORT_NO)
                return 0;

        r = manager_llmnr_ipv4_udp_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        r = manager_llmnr_ipv4_tcp_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        if (socket_ipv6_is_supported()) {
                r = manager_llmnr_ipv6_udp_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;

                r = manager_llmnr_ipv6_tcp_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;
        }

        return 0;

eaddrinuse:
        log_warning("Another LLMNR responder prohibits binding the socket to the same port. Turning off LLMNR support.");
        m->llmnr_support = RESOLVE_SUPPORT_NO;
        manager_llmnr_stop(m);

        return 0;
}

static int on_llmnr_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = NULL;
        Manager *m = userdata;
        DnsScope *scope;
        int r;

        assert(s);
        assert(fd >= 0);
        assert(m);

        r = manager_recv(m, fd, DNS_PROTOCOL_LLMNR, &p);
        if (r <= 0)
                return r;

        if (manager_our_packet(m, p))
                return 0;

        scope = manager_find_scope(m, p);
        if (!scope) {
                log_debug("Got LLMNR UDP packet on unknown scope. Ignoring.");
                return 0;
        }

        if (dns_packet_validate_reply(p) > 0) {
                log_debug("Got LLMNR UDP reply packet for id %u", DNS_PACKET_ID(p));

                dns_scope_check_conflicts(scope, p);

                t = hashmap_get(m->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (t)
                        dns_transaction_process_reply(t, p);

        } else if (dns_packet_validate_query(p) > 0)  {
                log_debug("Got LLMNR UDP query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, NULL, p);
        } else
                log_debug("Invalid LLMNR UDP packet, ignoring.");

        return 0;
}

int manager_llmnr_ipv4_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(m);

        if (m->llmnr_ipv4_udp_fd >= 0)
                return m->llmnr_ipv4_udp_fd;

        s = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to create socket: %m");

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt_int(s, IPPROTO_IP, IP_TTL, 255);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_TTL, 255);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_LOOP, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_PKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_RECVTTL, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_RECVTTL: %m");

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt_int(s, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_MTU_DISCOVER: %m");

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(s, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to bind socket: %m");

                log_warning("LLMNR-IPv4(UDP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in));
                if (r < 0)
                        return log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set SO_REUSEADDR: %m");
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_udp_event_source, s, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to create event source: %m");

        (void) sd_event_source_set_description(m->llmnr_ipv4_udp_event_source, "llmnr-ipv4-udp");

        return m->llmnr_ipv4_udp_fd = TAKE_FD(s);
}

int manager_llmnr_ipv6_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(m);

        if (m->llmnr_ipv6_udp_fd >= 0)
                return m->llmnr_ipv6_udp_fd;

        s = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to create socket: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_UNICAST_HOPS: %m");

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_MULTICAST_HOPS: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_MULTICAST_LOOP: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_V6ONLY: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_RECVPKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set IPV6_RECVHOPLIMIT: %m");

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(s, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to bind socket: %m");

                log_warning("LLMNR-IPv6(UDP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in6));
                if (r < 0)
                        return log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set SO_REUSEADDR: %m");
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_udp_event_source, s, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to create event source: %m");

        (void) sd_event_source_set_description(m->llmnr_ipv6_udp_event_source, "llmnr-ipv6-udp");

        return m->llmnr_ipv6_udp_fd = TAKE_FD(s);
}

static int on_llmnr_stream_packet(DnsStream *s) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsScope *scope;

        assert(s);

        p = dns_stream_take_read_packet(s);
        assert(p);

        scope = manager_find_scope(s->manager, p);
        if (!scope)
                log_debug("Got LLMNR TCP packet on unknown scope. Ignoring.");
        else if (dns_packet_validate_query(p) > 0) {
                log_debug("Got LLMNR TCP query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, s, p);
        } else
                log_debug("Invalid LLMNR TCP packet, ignoring.");

        dns_stream_unref(s);
        return 0;
}

static int on_llmnr_stream(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        DnsStream *stream;
        Manager *m = userdata;
        int cfd, r;

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return -errno;
        }

        r = dns_stream_new(m, &stream, DNS_STREAM_LLMNR_RECV, DNS_PROTOCOL_LLMNR, cfd, NULL);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        stream->on_packet = on_llmnr_stream_packet;
        /* We don't configure a "complete" handler here, we rely on the default handler than simply drops the
         * reference to the stream, thus freeing it */
        return 0;
}

int manager_llmnr_ipv4_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(m);

        if (m->llmnr_ipv4_tcp_fd >= 0)
                return m->llmnr_ipv4_tcp_fd;

        s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to create socket: %m");

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt_int(s, IPPROTO_IP, IP_TTL, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set IP_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set IP_PKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_RECVTTL, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set IP_RECVTTL: %m");

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt_int(s, IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set IP_MTU_DISCOVER: %m");

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(s, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to bind socket: %m");

                log_warning("LLMNR-IPv4(TCP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in));
                if (r < 0)
                        return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set SO_REUSEADDR: %m");
        }

        r = listen(s, SOMAXCONN);
        if (r < 0)
                return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to listen the stream: %m");

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_tcp_event_source, s, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to create event source: %m");

        (void) sd_event_source_set_description(m->llmnr_ipv4_tcp_event_source, "llmnr-ipv4-tcp");

        return m->llmnr_ipv4_tcp_fd = TAKE_FD(s);
}

int manager_llmnr_ipv6_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(m);

        if (m->llmnr_ipv6_tcp_fd >= 0)
                return m->llmnr_ipv6_tcp_fd;

        s = socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to create socket: %m");

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set IPV6_UNICAST_HOPS: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set IPV6_V6ONLY: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set IPV6_RECVPKTINFO: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set IPV6_RECVHOPLIMIT: %m");

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(s, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                if (errno != EADDRINUSE)
                        return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to bind socket: %m");

                log_warning("LLMNR-IPv6(TCP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set SO_REUSEADDR: %m");

                r = bind(s, &sa.sa, sizeof(sa.in6));
                if (r < 0)
                        return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to bind socket: %m");
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
                if (r < 0)
                        return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set SO_REUSEADDR: %m");
        }

        r = listen(s, SOMAXCONN);
        if (r < 0)
                return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to listen the stream: %m");

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_tcp_event_source, s, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to create event source: %m");

        (void) sd_event_source_set_description(m->llmnr_ipv6_tcp_event_source, "llmnr-ipv6-tcp");

        return m->llmnr_ipv6_tcp_fd = TAKE_FD(s);
}
