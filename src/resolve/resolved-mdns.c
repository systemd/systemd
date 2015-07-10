/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Daniel Mack

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
#include <arpa/inet.h>

#include "fd-util.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"

void manager_mdns_stop(Manager *m) {
        assert(m);

        m->mdns_ipv4_event_source = sd_event_source_unref(m->mdns_ipv4_event_source);
        m->mdns_ipv4_fd = safe_close(m->mdns_ipv4_fd);

        m->mdns_ipv6_event_source = sd_event_source_unref(m->mdns_ipv6_event_source);
        m->mdns_ipv6_fd = safe_close(m->mdns_ipv6_fd);
}

int manager_mdns_start(Manager *m) {
        int r;

        assert(m);

        if (m->mdns_support == SUPPORT_NO)
                return 0;

        r = manager_mdns_ipv4_fd(m);
        if (r == -EADDRINUSE)
                goto eaddrinuse;
        if (r < 0)
                return r;

        if (socket_ipv6_is_supported()) {
                r = manager_mdns_ipv6_fd(m);
                if (r == -EADDRINUSE)
                        goto eaddrinuse;
                if (r < 0)
                        return r;
        }

        return 0;

eaddrinuse:
        log_warning("There appears to be another mDNS responder running. Turning off mDNS support.");
        m->mdns_support = SUPPORT_NO;
        manager_mdns_stop(m);

        return 0;
}

static int on_mdns_packet(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        /* TODO */
        return 0;
}

int manager_mdns_ipv4_fd(Manager *m) {
        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(MDNS_PORT),
        };
        static const int one = 1, pmtu = IP_PMTUDISC_DONT, ttl = 255;
        int r;

        assert(m);

        if (m->mdns_ipv4_fd >= 0)
                return m->mdns_ipv4_fd;

        m->mdns_ipv4_fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->mdns_ipv4_fd < 0)
                return -errno;

        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv4_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_RECVTTL, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* Disable Don't-Fragment bit in the IP header */
        r = setsockopt(m->mdns_ipv4_fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->mdns_ipv4_fd, &sa.sa, sizeof(sa.in));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->mdns_ipv4_event_source, m->mdns_ipv4_fd, EPOLLIN, on_mdns_packet, m);
        if (r < 0)
                goto fail;

        return m->mdns_ipv4_fd;

fail:
        m->mdns_ipv4_fd = safe_close(m->mdns_ipv4_fd);
        return r;
}

int manager_mdns_ipv6_fd(Manager *m) {
        union sockaddr_union sa = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(MDNS_PORT),
        };
        static const int one = 1, ttl = 255;
        int r;

        assert(m);

        if (m->mdns_ipv6_fd >= 0)
                return m->mdns_ipv6_fd;

        m->mdns_ipv6_fd = socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (m->mdns_ipv6_fd < 0)
                return -errno;

        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        /* RFC 4795, section 2.5 recommends setting the TTL of UDP packets to 255. */
        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv6_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = setsockopt(m->mdns_ipv6_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = bind(m->mdns_ipv6_fd, &sa.sa, sizeof(sa.in6));
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        r = sd_event_add_io(m->event, &m->mdns_ipv6_event_source, m->mdns_ipv6_fd, EPOLLIN, on_mdns_packet, m);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        return m->mdns_ipv6_fd;

fail:
        m->mdns_ipv6_fd = safe_close(m->mdns_ipv6_fd);
        return r;
}
