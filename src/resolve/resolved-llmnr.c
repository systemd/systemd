/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <resolv.h>

#include "errno-util.h"
#include "fd-util.h"
#include "resolved-llmnr.h"
#include "resolved-manager.h"

void manager_llmnr_stop(Manager *m) {
        assert(m);

        m->llmnr_ipv4_udp_event_source = sd_event_source_disable_unref(m->llmnr_ipv4_udp_event_source);
        m->llmnr_ipv4_udp_fd = safe_close(m->llmnr_ipv4_udp_fd);

        m->llmnr_ipv6_udp_event_source = sd_event_source_disable_unref(m->llmnr_ipv6_udp_event_source);
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);

        m->llmnr_ipv4_tcp_event_source = sd_event_source_disable_unref(m->llmnr_ipv4_tcp_event_source);
        m->llmnr_ipv4_tcp_fd = safe_close(m->llmnr_ipv4_tcp_fd);

        m->llmnr_ipv6_tcp_event_source = sd_event_source_disable_unref(m->llmnr_ipv6_tcp_event_source);
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
}

void manager_llmnr_maybe_stop(Manager *m) {
        assert(m);

        /* This stops LLMNR only when no interface enables LLMNR. */

        Link *l;
        HASHMAP_FOREACH(l, m->links)
                if (link_get_llmnr_support(l) != RESOLVE_SUPPORT_NO)
                        return;

        manager_llmnr_stop(m);
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

        if (socket_ipv6_is_enabled()) {
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
        Manager *m = ASSERT_PTR(userdata);
        DnsScope *scope;
        int r;

        assert(s);
        assert(fd >= 0);

        r = manager_recv(m, fd, DNS_PROTOCOL_LLMNR, &p);
        if (r <= 0)
                return r;

        if (manager_packet_from_local_address(m, p))
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
                        dns_transaction_process_reply(t, p, false);

        } else if (dns_packet_validate_query(p) > 0)  {
                log_debug("Got LLMNR UDP query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, NULL, p);
        } else
                log_debug("Invalid LLMNR UDP packet, ignoring.");

        return 0;
}

static int set_llmnr_common_socket_options(int fd, int family) {
        int r;

        r = socket_set_recvpktinfo(fd, family, true);
        if (r < 0)
                return r;

        r = socket_set_recvttl(fd, family, true);
        if (r < 0)
                return r;

        return 0;
}

static int set_llmnr_common_udp_socket_options(int fd, int family) {
        int r;

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = socket_set_ttl(fd, family, 255);
        if (r < 0)
                return r;

        return 0;
}

int manager_llmnr_ipv4_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->llmnr_ipv4_udp_fd >= 0)
                return m->llmnr_ipv4_udp_fd;

        s = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to create socket: %m");

        r = set_llmnr_common_socket_options(s, AF_INET);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set common socket options: %m");

        r = set_llmnr_common_udp_socket_options(s, AF_INET);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set common UDP socket options: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_TTL, 255);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_TTL: %m");

        r = setsockopt_int(s, IPPROTO_IP, IP_MULTICAST_LOOP, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_LOOP: %m");

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
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->llmnr_ipv6_udp_fd >= 0)
                return m->llmnr_ipv6_udp_fd;

        s = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to create socket: %m");

        r = set_llmnr_common_socket_options(s, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set common socket options: %m");

        r = set_llmnr_common_udp_socket_options(s, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(UDP): Failed to set common UDP socket options: %m");

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

static int on_llmnr_stream_packet(DnsStream *s, DnsPacket *p) {
        DnsScope *scope;

        assert(s);
        assert(s->manager);
        assert(p);

        scope = manager_find_scope(s->manager, p);
        if (!scope)
                log_debug("Got LLMNR TCP packet on unknown scope. Ignoring.");
        else if (dns_packet_validate_query(p) > 0) {
                log_debug("Got LLMNR TCP query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, s, p);
        } else
                log_debug("Invalid LLMNR TCP packet, ignoring.");

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

        /* We don't configure a "complete" handler here, we rely on the default handler, thus freeing it */
        r = dns_stream_new(m, &stream, DNS_STREAM_LLMNR_RECV, DNS_PROTOCOL_LLMNR, cfd, NULL,
                           on_llmnr_stream_packet, NULL, DNS_STREAM_DEFAULT_TIMEOUT_USEC);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        return 0;
}

static int set_llmnr_common_tcp_socket_options(int fd, int family) {
        int r;

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = socket_set_ttl(fd, family, 1);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, IPPROTO_TCP, TCP_FASTOPEN, 5); /* Everybody appears to pick qlen=5, let's do the same here. */
        if (r < 0)
                log_debug_errno(r, "Failed to enable TCP_FASTOPEN on TCP listening socket, ignoring: %m");

        r = setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable TCP_NODELAY mode, ignoring: %m");

        return 0;
}

int manager_llmnr_ipv4_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(LLMNR_PORT),
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->llmnr_ipv4_tcp_fd >= 0)
                return m->llmnr_ipv4_tcp_fd;

        s = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to create socket: %m");

        r = set_llmnr_common_socket_options(s, AF_INET);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set common socket options: %m");

        r = set_llmnr_common_tcp_socket_options(s, AF_INET);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv4(TCP): Failed to set common TCP socket options: %m");

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

        r = listen(s, SOMAXCONN_DELUXE);
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
        _cleanup_close_ int s = -EBADF;
        int r;

        assert(m);

        if (m->llmnr_ipv6_tcp_fd >= 0)
                return m->llmnr_ipv6_tcp_fd;

        s = socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (s < 0)
                return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to create socket: %m");

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set IPV6_V6ONLY: %m");

        r = set_llmnr_common_socket_options(s, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set common socket options: %m");

        r = set_llmnr_common_tcp_socket_options(s, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to set common TCP socket options: %m");

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

        r = listen(s, SOMAXCONN_DELUXE);
        if (r < 0)
                return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to listen the stream: %m");

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_tcp_event_source, s, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                return log_error_errno(r, "LLMNR-IPv6(TCP): Failed to create event source: %m");

        (void) sd_event_source_set_description(m->llmnr_ipv6_tcp_event_source, "llmnr-ipv6-tcp");

        return m->llmnr_ipv6_tcp_fd = TAKE_FD(s);
}
