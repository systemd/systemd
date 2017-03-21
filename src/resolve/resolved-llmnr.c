/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
 ***/

#include <netinet/in.h>
#include <resolv.h>

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

        scope = manager_find_scope(m, p);
        if (!scope)
                log_warning("Got LLMNR UDP packet on unknown scope. Ignoring.");
        else if (dns_packet_validate_reply(p) > 0) {
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
        static const int one = 1, pmtu = IP_PMTUDISC_DONT, ttl = 255;
        int r;

        assert(m);

        if (m->llmnr_ipv4_udp_fd >= 0)
                return m->llmnr_ipv4_udp_fd;

        m->llmnr_ipv4_udp_fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv4_udp_fd < 0)
                return log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to create socket: %m");

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_TTL: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_TTL: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_MULTICAST_LOOP: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_PKTINFO: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_RECVTTL: %m");
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set IP_MTU_DISCOVER: %m");
                goto fail;
        }

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(m->llmnr_ipv4_udp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                if (errno != EADDRINUSE) {
                        r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to bind socket: %m");
                        goto fail;
                }

                log_warning("LLMNR-IPv4(UDP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt(m->llmnr_ipv4_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }

                r = bind(m->llmnr_ipv4_udp_fd, &sa.sa, sizeof(sa.in));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to bind socket: %m");
                        goto fail;
                }
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt(m->llmnr_ipv4_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(UDP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_udp_event_source, m->llmnr_ipv4_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(m->llmnr_ipv4_udp_event_source, "llmnr-ipv4-udp");

        return m->llmnr_ipv4_udp_fd;

fail:
        m->llmnr_ipv4_udp_fd = safe_close(m->llmnr_ipv4_udp_fd);
        return r;
}

int manager_llmnr_ipv6_udp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(LLMNR_PORT),
        };
        static const int one = 1, ttl = 255;
        int r;

        assert(m);

        if (m->llmnr_ipv6_udp_fd >= 0)
                return m->llmnr_ipv6_udp_fd;

        m->llmnr_ipv6_udp_fd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv6_udp_fd < 0)
                return log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to create socket: %m");

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_UNICAST_HOPS: %m");
                goto fail;
        }

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_MULTICAST_HOPS: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_MULTICAST_LOOP: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_V6ONLY: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_RECVPKTINFO: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set IPV6_RECVHOPLIMIT: %m");
                goto fail;
        }

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(m->llmnr_ipv6_udp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                if (errno != EADDRINUSE) {
                        r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to bind socket: %m");
                        goto fail;
                }

                log_warning("LLMNR-IPv6(UDP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt(m->llmnr_ipv6_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }

                r = bind(m->llmnr_ipv6_udp_fd, &sa.sa, sizeof(sa.in6));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to bind socket: %m");
                        goto fail;
                }
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt(m->llmnr_ipv6_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(UDP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_udp_event_source, m->llmnr_ipv6_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(m->llmnr_ipv6_udp_event_source, "llmnr-ipv6-udp");

        return m->llmnr_ipv6_udp_fd;

fail:
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);
        return r;
}

static int on_llmnr_stream_packet(DnsStream *s) {
        DnsScope *scope;

        assert(s);
        assert(s->read_packet);

        scope = manager_find_scope(s->manager, s->read_packet);
        if (!scope)
                log_warning("Got LLMNR TCP packet on unknown scope. Ignoring.");
        else if (dns_packet_validate_query(s->read_packet) > 0) {
                log_debug("Got LLMNR TCP query packet for id %u", DNS_PACKET_ID(s->read_packet));

                dns_scope_process_query(scope, s, s->read_packet);
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
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        r = dns_stream_new(m, &stream, DNS_PROTOCOL_LLMNR, cfd);
        if (r < 0) {
                safe_close(cfd);
                return r;
        }

        stream->on_packet = on_llmnr_stream_packet;
        return 0;
}

int manager_llmnr_ipv4_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(LLMNR_PORT),
        };
        static const int one = 1, pmtu = IP_PMTUDISC_DONT;
        int r;

        assert(m);

        if (m->llmnr_ipv4_tcp_fd >= 0)
                return m->llmnr_ipv4_tcp_fd;

        m->llmnr_ipv4_tcp_fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv4_tcp_fd < 0)
                return log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to create socket: %m");

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_TTL, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set IP_TTL: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set IP_PKTINFO: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set IP_RECVTTL: %m");
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set IP_MTU_DISCOVER: %m");
                goto fail;
        }

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(m->llmnr_ipv4_tcp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                if (errno != EADDRINUSE) {
                        r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to bind socket: %m");
                        goto fail;
                }

                log_warning("LLMNR-IPv4(TCP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt(m->llmnr_ipv4_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }

                r = bind(m->llmnr_ipv4_tcp_fd, &sa.sa, sizeof(sa.in));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to bind socket: %m");
                        goto fail;
                }
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt(m->llmnr_ipv4_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }
        }

        r = listen(m->llmnr_ipv4_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv4(TCP): Failed to listen the stream: %m");
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_tcp_event_source, m->llmnr_ipv4_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(m->llmnr_ipv4_tcp_event_source, "llmnr-ipv4-tcp");

        return m->llmnr_ipv4_tcp_fd;

fail:
        m->llmnr_ipv4_tcp_fd = safe_close(m->llmnr_ipv4_tcp_fd);
        return r;
}

int manager_llmnr_ipv6_tcp_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(LLMNR_PORT),
        };
        static const int one = 1;
        int r;

        assert(m);

        if (m->llmnr_ipv6_tcp_fd >= 0)
                return m->llmnr_ipv6_tcp_fd;

        m->llmnr_ipv6_tcp_fd = socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->llmnr_ipv6_tcp_fd < 0)
                return log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to create socket: %m");

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set IPV6_UNICAST_HOPS: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set IPV6_V6ONLY: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set IPV6_RECVPKTINFO: %m");
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set IPV6_RECVHOPLIMIT: %m");
                goto fail;
        }

        /* first try to bind without SO_REUSEADDR to detect another LLMNR responder */
        r = bind(m->llmnr_ipv6_tcp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                if (errno != EADDRINUSE) {
                        r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to bind socket: %m");
                        goto fail;
                }

                log_warning("LLMNR-IPv6(TCP): There appears to be another LLMNR responder running, or previously systemd-resolved crashed with some outstanding transfers.");

                /* try again with SO_REUSEADDR */
                r = setsockopt(m->llmnr_ipv6_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }

                r = bind(m->llmnr_ipv6_tcp_fd, &sa.sa, sizeof(sa.in6));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to bind socket: %m");
                        goto fail;
                }
        } else {
                /* enable SO_REUSEADDR for the case that the user really wants multiple LLMNR responders */
                r = setsockopt(m->llmnr_ipv6_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
                if (r < 0) {
                        r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to set SO_REUSEADDR: %m");
                        goto fail;
                }
        }

        r = listen(m->llmnr_ipv6_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = log_error_errno(errno, "LLMNR-IPv6(TCP): Failed to listen the stream: %m");
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_tcp_event_source, m->llmnr_ipv6_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(m->llmnr_ipv6_tcp_event_source, "llmnr-ipv6-tcp");

        return m->llmnr_ipv6_tcp_fd;

fail:
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
        return r;
}
