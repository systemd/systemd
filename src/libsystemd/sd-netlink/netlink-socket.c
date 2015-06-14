/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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
#include <stdbool.h>
#include <unistd.h>

#include "util.h"
#include "socket-util.h"
#include "formats-util.h"
#include "refcnt.h"
#include "missing.h"

#include "sd-netlink.h"
#include "netlink-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"

int socket_open(int family) {
        int fd;

        fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, family);
        if (fd < 0)
                return -errno;

        return fd;
}

int socket_bind(sd_netlink *nl) {
        socklen_t addrlen;
        int r, one = 1;

        r = setsockopt(nl->fd, SOL_NETLINK, NETLINK_PKTINFO, &one, sizeof(one));
        if (r < 0)
                return -errno;

        addrlen = sizeof(nl->sockaddr);

        r = bind(nl->fd, &nl->sockaddr.sa, addrlen);
        /* ignore EINVAL to allow opening an already bound socket */
        if (r < 0 && errno != EINVAL)
                return -errno;

        r = getsockname(nl->fd, &nl->sockaddr.sa, &addrlen);
        if (r < 0)
                return -errno;

        return 0;
}


int socket_join_broadcast_group(sd_netlink *nl, unsigned group) {
        int r;

        assert(nl);
        assert(nl->fd >= 0);
        assert(group > 0);

        r = setsockopt(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));
        if (r < 0)
                return -errno;

        return 0;
}

/* returns the number of bytes sent, or a negative error code */
int socket_write_message(sd_netlink *nl, sd_netlink_message *m) {
        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } addr = {
                .nl.nl_family = AF_NETLINK,
        };
        ssize_t k;

        assert(nl);
        assert(m);
        assert(m->hdr);

        k = sendto(nl->fd, m->hdr, m->hdr->nlmsg_len,
                        0, &addr.sa, sizeof(addr));
        if (k < 0)
                return -errno;

        return k;
}

static int socket_recv_message(int fd, struct iovec *iov, uint32_t *_group, bool peek) {
        union sockaddr_union sender;
        uint8_t cmsg_buffer[CMSG_SPACE(sizeof(struct nl_pktinfo))];
        struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = 1,
                .msg_name = &sender,
                .msg_namelen = sizeof(sender),
                .msg_control = cmsg_buffer,
                .msg_controllen = sizeof(cmsg_buffer),
        };
        struct cmsghdr *cmsg;
        uint32_t group = 0;
        int r;

        assert(fd >= 0);
        assert(iov);

        r = recvmsg(fd, &msg, MSG_TRUNC | (peek ? MSG_PEEK : 0));
        if (r < 0) {
                /* no data */
                if (errno == ENOBUFS)
                        log_debug("rtnl: kernel receive buffer overrun");
                else if (errno == EAGAIN)
                        log_debug("rtnl: no data in socket");

                return (errno == EAGAIN || errno == EINTR) ? 0 : -errno;
        }

        if (sender.nl.nl_pid != 0) {
                /* not from the kernel, ignore */
                log_debug("rtnl: ignoring message from portid %"PRIu32, sender.nl.nl_pid);

                if (peek) {
                        /* drop the message */
                        r = recvmsg(fd, &msg, 0);
                        if (r < 0)
                                return (errno == EAGAIN || errno == EINTR) ? 0 : -errno;
                }

                return 0;
        }

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == SOL_NETLINK &&
                    cmsg->cmsg_type == NETLINK_PKTINFO &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct nl_pktinfo))) {
                        struct nl_pktinfo *pktinfo = (void *)CMSG_DATA(cmsg);

                        /* multi-cast group */
                        group = pktinfo->group;
                }
        }

        if (_group)
                *_group = group;

        return r;
}

/* On success, the number of bytes received is returned and *ret points to the received message
 * which has a valid header and the correct size.
 * If nothing useful was received 0 is returned.
 * On failure, a negative error code is returned.
 */
int socket_read_message(sd_netlink *rtnl) {
        _cleanup_netlink_message_unref_ sd_netlink_message *first = NULL;
        struct iovec iov = {};
        uint32_t group = 0;
        bool multi_part = false, done = false;
        struct nlmsghdr *new_msg;
        size_t len;
        int r;
        unsigned i = 0;

        assert(rtnl);
        assert(rtnl->rbuffer);
        assert(rtnl->rbuffer_allocated >= sizeof(struct nlmsghdr));

        /* read nothing, just get the pending message size */
        r = socket_recv_message(rtnl->fd, &iov, NULL, true);
        if (r <= 0)
                return r;
        else
                len = (size_t)r;

        /* make room for the pending message */
        if (!greedy_realloc((void **)&rtnl->rbuffer,
                            &rtnl->rbuffer_allocated,
                            len, sizeof(uint8_t)))
                return -ENOMEM;

        iov.iov_base = rtnl->rbuffer;
        iov.iov_len = rtnl->rbuffer_allocated;

        /* read the pending message */
        r = socket_recv_message(rtnl->fd, &iov, &group, false);
        if (r <= 0)
                return r;
        else
                len = (size_t)r;

        if (len > rtnl->rbuffer_allocated)
                /* message did not fit in read buffer */
                return -EIO;

        if (NLMSG_OK(rtnl->rbuffer, len) && rtnl->rbuffer->nlmsg_flags & NLM_F_MULTI) {
                multi_part = true;

                for (i = 0; i < rtnl->rqueue_partial_size; i++) {
                        if (rtnl_message_get_serial(rtnl->rqueue_partial[i]) ==
                            rtnl->rbuffer->nlmsg_seq) {
                                first = rtnl->rqueue_partial[i];
                                break;
                        }
                }
        }

        for (new_msg = rtnl->rbuffer; NLMSG_OK(new_msg, len) && !done; new_msg = NLMSG_NEXT(new_msg, len)) {
                _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
                const NLType *nl_type;

                if (!group && new_msg->nlmsg_pid != rtnl->sockaddr.nl.nl_pid)
                        /* not broadcast and not for us */
                        continue;

                if (new_msg->nlmsg_type == NLMSG_NOOP)
                        /* silently drop noop messages */
                        continue;

                if (new_msg->nlmsg_type == NLMSG_DONE) {
                        /* finished reading multi-part message */
                        done = true;

                        /* if first is not defined, put NLMSG_DONE into the receive queue. */
                        if (first)
                                continue;
                }

                /* check that we support this message type */
                r = type_system_get_type(NULL, &nl_type, new_msg->nlmsg_type);
                if (r < 0) {
                        if (r == -EOPNOTSUPP)
                                log_debug("sd-netlink: ignored message with unknown type: %i",
                                          new_msg->nlmsg_type);

                        continue;
                }

                /* check that the size matches the message type */
                if (new_msg->nlmsg_len < NLMSG_LENGTH(nl_type->size)) {
                        log_debug("sd-netlink: message larger than expected, dropping");
                        continue;
                }

                r = message_new_empty(rtnl, &m);
                if (r < 0)
                        return r;

                m->broadcast = !!group;

                m->hdr = memdup(new_msg, new_msg->nlmsg_len);
                if (!m->hdr)
                        return -ENOMEM;

                /* seal and parse the top-level message */
                r = sd_netlink_message_rewind(m);
                if (r < 0)
                        return r;

                /* push the message onto the multi-part message stack */
                if (first)
                        m->next = first;
                first = m;
                m = NULL;
        }

        if (len)
                log_debug("sd-netlink: discarding %zu bytes of incoming message", len);

        if (!first)
                return 0;

        if (!multi_part || done) {
                /* we got a complete message, push it on the read queue */
                r = rtnl_rqueue_make_room(rtnl);
                if (r < 0)
                        return r;

                rtnl->rqueue[rtnl->rqueue_size ++] = first;
                first = NULL;

                if (multi_part && (i < rtnl->rqueue_partial_size)) {
                        /* remove the message form the partial read queue */
                        memmove(rtnl->rqueue_partial + i,rtnl->rqueue_partial + i + 1,
                                sizeof(sd_netlink_message*) * (rtnl->rqueue_partial_size - i - 1));
                        rtnl->rqueue_partial_size --;
                }

                return 1;
        } else {
                /* we only got a partial multi-part message, push it on the
                   partial read queue */
                if (i < rtnl->rqueue_partial_size) {
                        rtnl->rqueue_partial[i] = first;
                } else {
                        r = rtnl_rqueue_partial_make_room(rtnl);
                        if (r < 0)
                                return r;

                        rtnl->rqueue_partial[rtnl->rqueue_partial_size ++] = first;
                }
                first = NULL;

                return 0;
        }
}
