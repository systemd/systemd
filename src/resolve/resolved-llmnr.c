/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <resolv.h>
#include <netinet/in.h>

#include "resolved-manager.h"
#include "resolved-llmnr.h"

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

        if (m->llmnr_support == SUPPORT_NO)
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
        log_warning("There appears to be another LLMNR responder running. Turning off LLMNR support.");
        m->llmnr_support = SUPPORT_NO;
        manager_llmnr_stop(m);

        return 0;
}

static int on_llmnr_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        DnsTransaction *t = NULL;
        Manager *m = userdata;
        DnsScope *scope;
        int r;

        r = manager_recv(m, fd, DNS_PROTOCOL_LLMNR, &p);
        if (r <= 0)
                return r;

        scope = manager_find_scope(m, p);
        if (!scope) {
                log_warning("Got LLMNR UDP packet on unknown scope. Ignoring.");
                return 0;
        }

        if (dns_packet_validate_reply(p) > 0) {
                log_debug("Got LLMNR reply packet for id %u", DNS_PACKET_ID(p));

                dns_scope_check_conflicts(scope, p);

                t = hashmap_get(m->dns_transactions, UINT_TO_PTR(DNS_PACKET_ID(p)));
                if (t)
                        dns_transaction_process_reply(t, p);

        } else if (dns_packet_validate_query(p) > 0)  {
                log_debug("Got LLMNR query packet for id %u", DNS_PACKET_ID(p));

                dns_scope_process_query(scope, NULL, p);
        } else
                log_debug("Invalid LLMNR UDP packet.");

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
                return -errno;

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_udp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv4_udp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_udp_event_source, m->llmnr_ipv4_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)
                goto fail;

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
                return -errno;

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_udp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv6_udp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_udp_event_source, m->llmnr_ipv6_udp_fd, EPOLLIN, on_llmnr_packet, m);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        return m->llmnr_ipv6_udp_fd;

fail:
        m->llmnr_ipv6_udp_fd = safe_close(m->llmnr_ipv6_udp_fd);
        return r;
}

static int on_llmnr_stream_packet(DnsStream *s) {
        DnsScope *scope;

        assert(s);

        scope = manager_find_scope(s->manager, s->read_packet);
        if (!scope) {
                log_warning("Got LLMNR TCP packet on unknown scope. Ignroing.");
                return 0;
        }

        if (dns_packet_validate_query(s->read_packet) > 0) {
                log_debug("Got query packet for id %u", DNS_PACKET_ID(s->read_packet));

                dns_scope_process_query(scope, s, s->read_packet);

                /* If no reply packet was set, we free the stream */
                if (s->write_packet)
                        return 0;
        } else
                log_debug("Invalid LLMNR TCP packet.");

        dns_stream_free(s);
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
                return -errno;

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_TTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->llmnr_ipv4_tcp_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv4_tcp_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = listen(m->llmnr_ipv4_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv4_tcp_event_source, m->llmnr_ipv4_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)
                goto fail;

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
                return -errno;

        /* RFC 4795, section 2.5. requires setting the TTL of TCP streams to 1 */
        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->llmnr_ipv6_tcp_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->llmnr_ipv6_tcp_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = listen(m->llmnr_ipv6_tcp_fd, SOMAXCONN);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->llmnr_ipv6_tcp_event_source, m->llmnr_ipv6_tcp_fd, EPOLLIN, on_llmnr_stream, m);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        return m->llmnr_ipv6_tcp_fd;

fail:
        m->llmnr_ipv6_tcp_fd = safe_close(m->llmnr_ipv6_tcp_fd);
        return r;
}
