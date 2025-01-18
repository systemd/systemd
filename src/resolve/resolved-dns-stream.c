/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "macro.h"
#include "missing_network.h"
#include "resolved-dns-stream.h"
#include "resolved-manager.h"

#define DNS_STREAMS_MAX 128

#define DNS_QUERIES_PER_STREAM 32

static void dns_stream_stop(DnsStream *s) {
        assert(s);

        s->io_event_source = sd_event_source_disable_unref(s->io_event_source);
        s->timeout_event_source = sd_event_source_disable_unref(s->timeout_event_source);
        s->fd = safe_close(s->fd);

        /* Disconnect us from the server object if we are now not usable anymore */
        dns_stream_detach(s);
}

static int dns_stream_update_io(DnsStream *s) {
        uint32_t f = 0;

        assert(s);

        if (s->write_packet && s->n_written < sizeof(s->write_size) + s->write_packet->size)
                f |= EPOLLOUT;
        else if (!ordered_set_isempty(s->write_queue)) {
                dns_packet_unref(s->write_packet);
                s->write_packet = ordered_set_steal_first(s->write_queue);
                s->write_size = htobe16(s->write_packet->size);
                s->n_written = 0;
                f |= EPOLLOUT;
        }

        /* Let's read a packet if we haven't queued any yet. Except if we already hit a limit of parallel
         * queries for this connection. */
        if ((!s->read_packet || s->n_read < sizeof(s->read_size) + s->read_packet->size) &&
                set_size(s->queries) < DNS_QUERIES_PER_STREAM)
                f |= EPOLLIN;

        s->requested_events = f;

#if ENABLE_DNS_OVER_TLS
        /* For handshake and clean closing purposes, TLS can override requested events */
        if (s->dnstls_events != 0)
                f = s->dnstls_events;
#endif

        return sd_event_source_set_io_events(s->io_event_source, f);
}

static int dns_stream_complete(DnsStream *s, int error) {
        _cleanup_(dns_stream_unrefp) _unused_ DnsStream *ref = dns_stream_ref(s); /* Protect stream while we process it */

        assert(s);
        assert(error >= 0);

        /* Error is > 0 when the connection failed for some reason in the network stack. It's == 0 if we sent
         * and received exactly one packet each (in the LLMNR client case). */

#if ENABLE_DNS_OVER_TLS
        if (s->encrypted) {
                int r;

                r = dnstls_stream_shutdown(s, error);
                if (r != -EAGAIN)
                        dns_stream_stop(s);
        } else
#endif
                dns_stream_stop(s);

        dns_stream_detach(s);

        if (s->complete)
                s->complete(s, error);
        else /* the default action if no completion function is set is to close the stream */
                dns_stream_unref(s);

        return 0;
}

static int dns_stream_identify(DnsStream *s) {
        CMSG_BUFFER_TYPE(CMSG_SPACE(MAXSIZE(struct in_pktinfo, struct in6_pktinfo))
                         + CMSG_SPACE(int) + /* for the TTL */
                         + EXTRA_CMSG_SPACE /* kernel appears to require extra space */) control;
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
                                struct in6_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in6_pktinfo);

                                if (s->ifindex <= 0)
                                        s->ifindex = i->ipi6_ifindex;
                                break;
                        }

                        case IPV6_HOPLIMIT:
                                s->ttl = *CMSG_TYPED_DATA(cmsg, int);
                                break;
                        }

                } else if (cmsg->cmsg_level == IPPROTO_IP) {
                        assert(s->peer.sa.sa_family == AF_INET);

                        switch (cmsg->cmsg_type) {

                        case IP_PKTINFO: {
                                struct in_pktinfo *i = CMSG_TYPED_DATA(cmsg, struct in_pktinfo);

                                if (s->ifindex <= 0)
                                        s->ifindex = i->ipi_ifindex;
                                break;
                        }

                        case IP_TTL:
                                s->ttl = *CMSG_TYPED_DATA(cmsg, int);
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
                s->ifindex = manager_find_ifindex(s->manager, s->local.sa.sa_family, sockaddr_in_addr(&s->local.sa));

        if (s->protocol == DNS_PROTOCOL_LLMNR && s->ifindex > 0) {
                /* Make sure all packets for this connection are sent on the same interface */
                r = socket_set_unicast_if(s->fd, s->local.sa.sa_family, s->ifindex);
                if (r < 0)
                        log_debug_errno(r, "Failed to invoke IP_UNICAST_IF/IPV6_UNICAST_IF: %m");
        }

        s->identified = true;

        return 0;
}

ssize_t dns_stream_writev(DnsStream *s, const struct iovec *iov, size_t iovcnt, int flags) {
        ssize_t m;
        int r;

        assert(s);
        assert(iov);

#if ENABLE_DNS_OVER_TLS
        if (s->encrypted && !(flags & DNS_STREAM_WRITE_TLS_DATA))
                return dnstls_stream_writev(s, iov, iovcnt);
#endif

        if (s->tfo_salen > 0) {
                struct msghdr hdr = {
                        .msg_iov = (struct iovec*) iov,
                        .msg_iovlen = iovcnt,
                        .msg_name = &s->tfo_address.sa,
                        .msg_namelen = s->tfo_salen
                };

                m = sendmsg(s->fd, &hdr, MSG_FASTOPEN);
                if (m < 0) {
                        if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                                /* MSG_FASTOPEN not supported? Then try to connect() traditionally */
                                r = RET_NERRNO(connect(s->fd, &s->tfo_address.sa, s->tfo_salen));
                                s->tfo_salen = 0; /* connection is made */
                                if (r < 0 && r != -EINPROGRESS)
                                        return r;

                                return -EAGAIN; /* In case of EINPROGRESS, EAGAIN or success: return EAGAIN, so that caller calls us again */
                        }
                        if (errno == EINPROGRESS)
                                return -EAGAIN;

                        return -errno;
                } else
                        s->tfo_salen = 0; /* connection is made */
        } else {
                m = writev(s->fd, iov, iovcnt);
                if (m < 0)
                        return -errno;
        }

        return m;
}

static ssize_t dns_stream_read(DnsStream *s, void *buf, size_t count) {
        ssize_t ss;

#if ENABLE_DNS_OVER_TLS
        if (s->encrypted)
                ss = dnstls_stream_read(s, buf, count);
        else
#endif
        {
                ss = read(s->fd, buf, count);
                if (ss < 0)
                        return -errno;
        }

        return ss;
}

static int on_stream_timeout(sd_event_source *es, usec_t usec, void *userdata) {
        DnsStream *s = ASSERT_PTR(userdata);

        return dns_stream_complete(s, ETIMEDOUT);
}

static DnsPacket *dns_stream_take_read_packet(DnsStream *s) {
        assert(s);

        /* Note, dns_stream_update() should be called after this is called. When this is called, the
         * stream may be already full and the EPOLLIN flag is dropped from the stream IO event source.
         * Even this makes a room to read in the stream, this does not call dns_stream_update(), hence
         * EPOLLIN flag is not set automatically. So, to read further packets from the stream,
         * dns_stream_update() must be called explicitly. Currently, this is only called from
         * on_stream_io(), and there dns_stream_update() is called. */

        if (!s->read_packet)
                return NULL;

        if (s->n_read < sizeof(s->read_size))
                return NULL;

        if (s->n_read < sizeof(s->read_size) + be16toh(s->read_size))
                return NULL;

        s->n_read = 0;
        return TAKE_PTR(s->read_packet);
}

static int on_stream_io(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        _cleanup_(dns_stream_unrefp) DnsStream *s = dns_stream_ref(userdata); /* Protect stream while we process it */
        bool progressed = false;
        int r;

        assert(s);

#if ENABLE_DNS_OVER_TLS
        if (s->encrypted) {
                r = dnstls_stream_on_io(s, revents);
                if (r == DNSTLS_STREAM_CLOSED)
                        return 0;
                if (r == -EAGAIN)
                        return dns_stream_update_io(s);
                if (r < 0)
                        return dns_stream_complete(s, -r);

                r = dns_stream_update_io(s);
                if (r < 0)
                        return r;
        }
#endif

        /* only identify after connecting */
        if (s->tfo_salen == 0) {
                r = dns_stream_identify(s);
                if (r < 0)
                        return dns_stream_complete(s, -r);
        }

        if (revents & EPOLLERR) {
                socklen_t errlen = sizeof(r);
                if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &r, &errlen) == 0)
                        return dns_stream_complete(s, r);
        }

        if ((revents & EPOLLOUT) &&
            s->write_packet &&
            s->n_written < sizeof(s->write_size) + s->write_packet->size) {

                struct iovec iov[] = {
                        IOVEC_MAKE(&s->write_size, sizeof(s->write_size)),
                        IOVEC_MAKE(DNS_PACKET_DATA(s->write_packet), s->write_packet->size),
                };

                iovec_increment(iov, ELEMENTSOF(iov), s->n_written);

                ssize_t ss = dns_stream_writev(s, iov, ELEMENTSOF(iov), 0);
                if (ss < 0) {
                        if (!ERRNO_IS_TRANSIENT(ss))
                                return dns_stream_complete(s, -ss);
                } else {
                        progressed = true;
                        s->n_written += ss;
                }

                /* Are we done? If so, disable the event source for EPOLLOUT */
                if (s->n_written >= sizeof(s->write_size) + s->write_packet->size) {
                        r = dns_stream_update_io(s);
                        if (r < 0)
                                return dns_stream_complete(s, -r);
                }
        }

        while ((revents & (EPOLLIN|EPOLLHUP|EPOLLRDHUP)) &&
               (!s->read_packet ||
                s->n_read < sizeof(s->read_size) + s->read_packet->size)) {

                if (s->n_read < sizeof(s->read_size)) {
                        ssize_t ss;

                        ss = dns_stream_read(s, (uint8_t*) &s->read_size + s->n_read, sizeof(s->read_size) - s->n_read);
                        if (ss < 0) {
                                if (!ERRNO_IS_TRANSIENT(ss))
                                        return dns_stream_complete(s, -ss);
                                break;
                        } else if (ss == 0)
                                return dns_stream_complete(s, ECONNRESET);
                        else {
                                progressed = true;
                                s->n_read += ss;
                        }
                }

                if (s->n_read >= sizeof(s->read_size)) {

                        if (be16toh(s->read_size) < DNS_PACKET_HEADER_SIZE)
                                return dns_stream_complete(s, EBADMSG);

                        if (s->n_read < sizeof(s->read_size) + be16toh(s->read_size)) {
                                ssize_t ss;

                                if (!s->read_packet) {
                                        r = dns_packet_new(&s->read_packet, s->protocol, be16toh(s->read_size), DNS_PACKET_SIZE_MAX);
                                        if (r < 0)
                                                return dns_stream_complete(s, -r);

                                        s->read_packet->size = be16toh(s->read_size);
                                        s->read_packet->ipproto = IPPROTO_TCP;
                                        s->read_packet->family = s->peer.sa.sa_family;
                                        s->read_packet->ttl = s->ttl;
                                        s->read_packet->ifindex = s->ifindex;
                                        s->read_packet->timestamp = now(CLOCK_BOOTTIME);

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

                                ss = dns_stream_read(s,
                                          (uint8_t*) DNS_PACKET_DATA(s->read_packet) + s->n_read - sizeof(s->read_size),
                                          sizeof(s->read_size) + be16toh(s->read_size) - s->n_read);
                                if (ss < 0) {
                                        if (!ERRNO_IS_TRANSIENT(ss))
                                                return dns_stream_complete(s, -ss);
                                        break;
                                } else if (ss == 0)
                                        return dns_stream_complete(s, ECONNRESET);
                                else
                                        s->n_read += ss;
                        }

                        /* Are we done? If so, call the packet handler and re-enable EPOLLIN for the
                         * event source if necessary. */
                        _cleanup_(dns_packet_unrefp) DnsPacket *p = dns_stream_take_read_packet(s);
                        if (p) {
                                assert(s->on_packet);
                                r = s->on_packet(s, p);
                                if (r < 0)
                                        return r;

                                r = dns_stream_update_io(s);
                                if (r < 0)
                                        return dns_stream_complete(s, -r);

                                s->packet_received = true;

                                /* If we just disabled the read event, stop reading */
                                if (!FLAGS_SET(s->requested_events, EPOLLIN))
                                        break;
                        }
                }
        }

        /* Complete the stream if finished reading and writing one packet, and there's nothing
         * else left to write. */
        if (s->type == DNS_STREAM_LLMNR_SEND && s->packet_received &&
            !FLAGS_SET(s->requested_events, EPOLLOUT))
                return dns_stream_complete(s, 0);

        /* If we did something, let's restart the timeout event source */
        if (progressed && s->timeout_event_source) {
                r = sd_event_source_set_time_relative(s->timeout_event_source, DNS_STREAM_ESTABLISHED_TIMEOUT_USEC);
                if (r < 0)
                        log_warning_errno(r, "Couldn't restart TCP connection timeout, ignoring: %m");
        }

        return 0;
}

static DnsStream *dns_stream_free(DnsStream *s) {
        DnsPacket *p;

        assert(s);

        dns_stream_stop(s);

        if (s->manager) {
                LIST_REMOVE(streams, s->manager->dns_streams, s);
                s->manager->n_dns_streams[s->type]--;
        }

#if ENABLE_DNS_OVER_TLS
        if (s->encrypted)
                dnstls_stream_free(s);
#endif

        ORDERED_SET_FOREACH(p, s->write_queue)
                dns_packet_unref(ordered_set_remove(s->write_queue, p));

        dns_packet_unref(s->write_packet);
        dns_packet_unref(s->read_packet);
        dns_server_unref(s->server);

        ordered_set_free(s->write_queue);

        return mfree(s);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsStream, dns_stream, dns_stream_free);

int dns_stream_new(
                Manager *m,
                DnsStream **ret,
                DnsStreamType type,
                DnsProtocol protocol,
                int fd,
                const union sockaddr_union *tfo_address,
                int (on_packet)(DnsStream*, DnsPacket*),
                int (complete)(DnsStream*, int), /* optional */
                usec_t connect_timeout_usec) {

        _cleanup_(dns_stream_unrefp) DnsStream *s = NULL;
        int r;

        assert(m);
        assert(ret);
        assert(type >= 0);
        assert(type < _DNS_STREAM_TYPE_MAX);
        assert(protocol >= 0);
        assert(protocol < _DNS_PROTOCOL_MAX);
        assert(fd >= 0);
        assert(on_packet);

        if (m->n_dns_streams[type] > DNS_STREAMS_MAX)
                return -EBUSY;

        s = new(DnsStream, 1);
        if (!s)
                return -ENOMEM;

        *s = (DnsStream) {
                .n_ref = 1,
                .fd = -EBADF,
                .protocol = protocol,
                .type = type,
        };

        r = ordered_set_ensure_allocated(&s->write_queue, &dns_packet_hash_ops);
        if (r < 0)
                return r;

        r = sd_event_add_io(m->event, &s->io_event_source, fd, EPOLLIN, on_stream_io, s);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->io_event_source, "dns-stream-io");

        r = sd_event_add_time_relative(
                        m->event,
                        &s->timeout_event_source,
                        CLOCK_BOOTTIME,
                        connect_timeout_usec, 0,
                        on_stream_timeout, s);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s->timeout_event_source, "dns-stream-timeout");

        LIST_PREPEND(streams, m->dns_streams, s);
        m->n_dns_streams[type]++;
        s->manager = m;

        s->fd = fd;
        s->on_packet = on_packet;
        s->complete = complete;

        if (tfo_address) {
                s->tfo_address = *tfo_address;
                s->tfo_salen = SOCKADDR_LEN(*tfo_address);
        }

        *ret = TAKE_PTR(s);

        return 0;
}

int dns_stream_write_packet(DnsStream *s, DnsPacket *p) {
        int r;

        assert(s);
        assert(p);

        r = ordered_set_put(s->write_queue, p);
        if (r < 0)
                return r;

        dns_packet_ref(p);

        return dns_stream_update_io(s);
}

void dns_stream_detach(DnsStream *s) {
        assert(s);

        if (!s->server)
                return;

        if (s->server->stream != s)
                return;

        dns_server_unref_stream(s->server);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                dns_stream_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                dns_stream_unref);

int dns_stream_disconnect_all(Manager *m) {
        _cleanup_set_free_ Set *closed = NULL;
        int r;

        assert(m);

        /* Terminates all TCP connections (called after system suspend for example, to speed up recovery) */

        log_info("Closing all remaining TCP connections.");

        bool restart;
        do {
                restart = false;

                LIST_FOREACH(streams, s, m->dns_streams) {
                        r = set_ensure_put(&closed, &dns_stream_hash_ops, s);
                        if (r < 0)
                                return log_oom();
                        if (r > 0) {
                                /* Haven't seen this one before. Close it. */
                                dns_stream_ref(s);
                                (void) dns_stream_complete(s, ECONNRESET);

                                /* This might have a ripple effect, let's hence no look at the list further,
                                 * but scan from the beginning again */
                                restart = true;
                                break;
                        }
                }
        } while (restart);

        return 0;
}
