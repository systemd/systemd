/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <netinet/tcp.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "missing.h"
#include "resolved-dns-stream.h"

#define DNS_STREAM_TIMEOUT_USEC (10 * USEC_PER_SEC)
#define DNS_STREAMS_MAX 128

static void dns_stream_stop(DnsStream *s) {
        assert(s);

        s->io_event_source = sd_event_source_unref(s->io_event_source);
        s->timeout_event_source = sd_event_source_unref(s->timeout_event_source);
        s->fd = safe_close(s->fd);
}

static int dns_stream_update_io(DnsStream *s) {
        int f = 0;

        assert(s);

        if (s->write_packet && s->n_written < sizeof(s->write_size) + s->write_packet->size)
                f |= EPOLLOUT;
        if (!s->read_packet || s->n_read < sizeof(s->read_size) + s->read_packet->size)
                f |= EPOLLIN;

        return sd_event_source_set_io_events(s->io_event_source, f);
}

static int dns_stream_complete(DnsStream *s, int error) {
        assert(s);

        dns_stream_stop(s);

        if (s->complete)
                s->complete(s, error);
        else
                dns_stream_free(s);

        return 0;
}

static int dns_stream_identify(DnsStream *s) {
        union {
                struct cmsghdr header; /* For alignment */
                uint8_t buffer[CMSG_SPACE(MAXSIZE(struct in_pktinfo, struct in6_pktinfo))
                               + EXTRA_CMSG_SPACE /* kernel appears to require extra space */];
        } control;
        struct msghdr mh = {};
        struct cmsghdr *cmsg;
        socklen_t sl;
        int r;

        assert(s);

        if (s->identified)
                return 0;

        /* Query the local side */
        s->local_salen = sizeof(s->local);
        r = getsockname(s->fd, &s->local.sa, &s->local_salen);
        if (r < 0)
                return -errno;
        if (s->local.sa.sa_family == AF_INET6 && s->ifindex <= 0)
                s->ifindex = s->local.in6.sin6_scope_id;

        /* Query the remote side */
        s->peer_salen = sizeof(s->peer);
        r = getpeername(s->fd, &s->peer.sa, &s->peer_salen);
        if (r < 0)
                return -errno;
        if (s->peer.sa.sa_family == AF_INET6 && s->ifindex <= 0)
                s->ifindex = s->peer.in6.sin6_scope_id;

        /* Check consistency */
        assert(s->peer.sa.sa_family == s->local.sa.sa_family);
        assert(IN_SET(s->peer.sa.sa_family, AF_INET, AF_INET6));

        /* Query connection meta information */
        sl = sizeof(control);
        if (s->peer.sa.sa_family == AF_INET) {
                r = getsockopt(s->fd, IPPROTO_IP, IP_PKTOPTIONS, &control, &sl);
                if (r < 0)
                        return -errno;
        } else if (s->peer.sa.sa_family == AF_INET6) {

                r = getsockopt(s->fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, &control, &sl);
                if (r < 0)
                        return -errno;
        } else
                return -EAFNOSUPPORT;

        mh.msg_control = &control;
        mh.msg_controllen = sl;

        CMSG_FOREACH(cmsg, &mh) {

                if (cmsg->cmsg_level == IPPROTO_IPV6) {
                        assert(s->peer.sa.sa_family == AF_INET6);

                        switch (cmsg->cmsg_type) {

                        case IPV6_PKTINFO: {
                                struct in6_pktinfo *i = (struct in6_pktinfo*) CMSG_DATA(cmsg);

                                if (s->ifindex <= 0)
                                        s->ifindex = i->ipi6_ifindex;
                                break;
                        }

                        case IPV6_HOPLIMIT:
                                s->ttl = *(int *) CMSG_DATA(cmsg);
                                break;
                        }

                } else if (cmsg->cmsg_level == IPPROTO_IP) {
                        assert(s->peer.sa.sa_family == AF_INET);

                        switch (cmsg->cmsg_type) {

                        case IP_PKTINFO: {
                                struct in_pktinfo *i = (struct in_pktinfo*) CMSG_DATA(cmsg);

                                if (s->ifindex <= 0)
                                        s->ifindex = i->ipi_ifindex;
                                break;
                        }

                        case IP_TTL:
                                s->ttl = *(int *) CMSG_DATA(cmsg);
                                break;
                        }
                }
        }

        /* The Linux kernel sets the interface index to the loopback
         * device if the connection came from the local host since it
         * avoids the routing table in such a case. Let's unset the
         * interface index in such a case. */
        if (s->ifindex == LOOPBACK_IFINDEX)
                s->ifindex = 0;

        /* If we don't know the interface index still, we look for the
         * first local interface with a matching address. Yuck! */
        if (s->ifindex <= 0)
                s->ifindex = manager_find_ifindex(s->manager, s->local.sa.sa_family, s->local.sa.sa_family == AF_INET ? (union in_addr_union*) &s->local.in.sin_addr : (union in_addr_union*)  &s->local.in6.sin6_addr);

        if (s->protocol == DNS_PROTOCOL_LLMNR && s->ifindex > 0) {
                uint32_t ifindex = htobe32(s->ifindex);

                /* Make sure all packets for this connection are sent on the same interface */
                if (s->local.sa.sa_family == AF_INET) {
                        r = setsockopt(s->fd, IPPROTO_IP, IP_UNICAST_IF, &ifindex, sizeof(ifindex));
                        if (r < 0)
                                log_debug_errno(errno, "Failed to invoke IP_UNICAST_IF: %m");
                } else if (s->local.sa.sa_family == AF_INET6) {
                        r = setsockopt(s->fd, IPPROTO_IPV6, IPV6_UNICAST_IF, &ifindex, sizeof(ifindex));
                        if (r < 0)
                                log_debug_errno(errno, "Failed to invoke IPV6_UNICAST_IF: %m");
                }
        }

        s->identified = true;

        return 0;
}

static int on_stream_timeout(sd_event_source *es, usec_t usec, void *userdata) {
        DnsStream *s = userdata;

        assert(s);

        return dns_stream_complete(s, ETIMEDOUT);
}

static int on_stream_io(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        DnsStream *s = userdata;
        int r;

        assert(s);

        r = dns_stream_identify(s);
        if (r < 0)
                return dns_stream_complete(s, -r);

        if ((revents & EPOLLOUT) &&
            s->write_packet &&
            s->n_written < sizeof(s->write_size) + s->write_packet->size) {

                struct iovec iov[2];
                ssize_t ss;

                iov[0].iov_base = &s->write_size;
                iov[0].iov_len = sizeof(s->write_size);
                iov[1].iov_base = DNS_PACKET_DATA(s->write_packet);
                iov[1].iov_len = s->write_packet->size;

                IOVEC_INCREMENT(iov, 2, s->n_written);

                ss = writev(fd, iov, 2);
                if (ss < 0) {
                        if (errno != EINTR && errno != EAGAIN)
                                return dns_stream_complete(s, errno);
                } else
                        s->n_written += ss;

                /* Are we done? If so, disable the event source for EPOLLOUT */
                if (s->n_written >= sizeof(s->write_size) + s->write_packet->size) {
                        r = dns_stream_update_io(s);
                        if (r < 0)
                                return dns_stream_complete(s, -r);
                }
        }

        if ((revents & (EPOLLIN|EPOLLHUP|EPOLLRDHUP)) &&
            (!s->read_packet ||
             s->n_read < sizeof(s->read_size) + s->read_packet->size)) {

                if (s->n_read < sizeof(s->read_size)) {
                        ssize_t ss;

                        ss = read(fd, (uint8_t*) &s->read_size + s->n_read, sizeof(s->read_size) - s->n_read);
                        if (ss < 0) {
                                if (errno != EINTR && errno != EAGAIN)
                                        return dns_stream_complete(s, errno);
                        } else if (ss == 0)
                                return dns_stream_complete(s, ECONNRESET);
                        else
                                s->n_read += ss;
                }

                if (s->n_read >= sizeof(s->read_size)) {

                        if (be16toh(s->read_size) < DNS_PACKET_HEADER_SIZE)
                                return dns_stream_complete(s, EBADMSG);

                        if (s->n_read < sizeof(s->read_size) + be16toh(s->read_size)) {
                                ssize_t ss;

                                if (!s->read_packet) {
                                        r = dns_packet_new(&s->read_packet, s->protocol, be16toh(s->read_size));
                                        if (r < 0)
                                                return dns_stream_complete(s, -r);

                                        s->read_packet->size = be16toh(s->read_size);
                                        s->read_packet->ipproto = IPPROTO_TCP;
                                        s->read_packet->family = s->peer.sa.sa_family;
                                        s->read_packet->ttl = s->ttl;
                                        s->read_packet->ifindex = s->ifindex;

                                        if (s->read_packet->family == AF_INET) {
                                                s->read_packet->sender.in = s->peer.in.sin_addr;
                                                s->read_packet->sender_port = be16toh(s->peer.in.sin_port);
                                                s->read_packet->destination.in = s->local.in.sin_addr;
                                                s->read_packet->destination_port = be16toh(s->local.in.sin_port);
                                        } else {
                                                assert(s->read_packet->family == AF_INET6);
                                                s->read_packet->sender.in6 = s->peer.in6.sin6_addr;
                                                s->read_packet->sender_port = be16toh(s->peer.in6.sin6_port);
                                                s->read_packet->destination.in6 = s->local.in6.sin6_addr;
                                                s->read_packet->destination_port = be16toh(s->local.in6.sin6_port);

                                                if (s->read_packet->ifindex == 0)
                                                        s->read_packet->ifindex = s->peer.in6.sin6_scope_id;
                                                if (s->read_packet->ifindex == 0)
                                                        s->read_packet->ifindex = s->local.in6.sin6_scope_id;
                                        }
                                }

                                ss = read(fd,
                                          (uint8_t*) DNS_PACKET_DATA(s->read_packet) + s->n_read - sizeof(s->read_size),
                                          sizeof(s->read_size) + be16toh(s->read_size) - s->n_read);
                                if (ss < 0) {
                                        if (errno != EINTR && errno != EAGAIN)
                                                return dns_stream_complete(s, errno);
                                } else if (ss == 0)
                                        return dns_stream_complete(s, ECONNRESET);
                                else
                                        s->n_read += ss;
                        }

                        /* Are we done? If so, disable the event source for EPOLLIN */
                        if (s->n_read >= sizeof(s->read_size) + be16toh(s->read_size)) {
                                r = dns_stream_update_io(s);
                                if (r < 0)
                                        return dns_stream_complete(s, -r);

                                /* If there's a packet handler
                                 * installed, call that. Note that
                                 * this is optional... */
                                if (s->on_packet)
                                        return s->on_packet(s);
                        }
                }
        }

        if ((s->write_packet && s->n_written >= sizeof(s->write_size) + s->write_packet->size) &&
            (s->read_packet && s->n_read >= sizeof(s->read_size) + s->read_packet->size))
                return dns_stream_complete(s, 0);

        return 0;
}

DnsStream *dns_stream_free(DnsStream *s) {
        if (!s)
                return NULL;

        dns_stream_stop(s);

        if (s->manager) {
                LIST_REMOVE(streams, s->manager->dns_streams, s);
                s->manager->n_dns_streams--;
        }

        dns_packet_unref(s->write_packet);
        dns_packet_unref(s->read_packet);

        free(s);

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsStream*, dns_stream_free);

int dns_stream_new(Manager *m, DnsStream **ret, DnsProtocol protocol, int fd) {
        static const int one = 1;
        _cleanup_(dns_stream_freep) DnsStream *s = NULL;
        int r;

        assert(m);
        assert(fd >= 0);

        if (m->n_dns_streams > DNS_STREAMS_MAX)
                return -EBUSY;

        s = new0(DnsStream, 1);
        if (!s)
                return -ENOMEM;

        s->fd = -1;
        s->protocol = protocol;

        r = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (r < 0)
                return -errno;

        r = sd_event_add_io(m->event, &s->io_event_source, fd, EPOLLIN, on_stream_io, s);
        if (r < 0)
                return r;

        r = sd_event_add_time(
                        m->event,
                        &s->timeout_event_source,
                        clock_boottime_or_monotonic(),
                        now(clock_boottime_or_monotonic()) + DNS_STREAM_TIMEOUT_USEC, 0,
                        on_stream_timeout, s);
        if (r < 0)
                return r;

        LIST_PREPEND(streams, m->dns_streams, s);
        s->manager = m;
        s->fd = fd;
        m->n_dns_streams++;

        *ret = s;
        s = NULL;

        return 0;
}

int dns_stream_write_packet(DnsStream *s, DnsPacket *p) {
        assert(s);

        if (s->write_packet)
                return -EBUSY;

        s->write_packet = dns_packet_ref(p);
        s->write_size = htobe16(p->size);
        s->n_written = 0;

        return dns_stream_update_io(s);
}
