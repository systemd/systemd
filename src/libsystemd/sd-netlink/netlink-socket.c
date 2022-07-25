/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <unistd.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "netlink-internal.h"
#include "netlink-types.h"
#include "socket-util.h"
#include "util.h"

static int broadcast_groups_get(sd_netlink *nl) {
        _cleanup_free_ uint32_t *groups = NULL;
        socklen_t len = 0, old_len;
        int r;

        assert(nl);
        assert(nl->fd >= 0);

        if (getsockopt(nl->fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, NULL, &len) < 0) {
                if (errno != ENOPROTOOPT)
                        return -errno;

                nl->broadcast_group_dont_leave = true;
                return 0;
        }

        if (len == 0)
                return 0;

        groups = new0(uint32_t, len);
        if (!groups)
                return -ENOMEM;

        old_len = len;

        if (getsockopt(nl->fd, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, groups, &len) < 0)
                return -errno;

        if (old_len != len)
                return -EIO;

        for (unsigned i = 0; i < len; i++)
                for (unsigned j = 0; j < sizeof(uint32_t) * 8; j++)
                        if (groups[i] & (1U << j)) {
                                unsigned group = i * sizeof(uint32_t) * 8 + j + 1;

                                r = hashmap_ensure_put(&nl->broadcast_group_refs, NULL, UINT_TO_PTR(group), UINT_TO_PTR(1));
                                if (r < 0)
                                        return r;
                        }

        return 0;
}

int socket_bind(sd_netlink *nl) {
        socklen_t addrlen;
        int r;

        r = setsockopt_int(nl->fd, SOL_NETLINK, NETLINK_PKTINFO, true);
        if (r < 0)
                return r;

        addrlen = sizeof(nl->sockaddr);

        /* ignore EINVAL to allow binding an already bound socket */
        if (bind(nl->fd, &nl->sockaddr.sa, addrlen) < 0 && errno != EINVAL)
                return -errno;

        if (getsockname(nl->fd, &nl->sockaddr.sa, &addrlen) < 0)
                return -errno;

        return broadcast_groups_get(nl);
}

static unsigned broadcast_group_get_ref(sd_netlink *nl, unsigned group) {
        assert(nl);

        return PTR_TO_UINT(hashmap_get(nl->broadcast_group_refs, UINT_TO_PTR(group)));
}

static int broadcast_group_set_ref(sd_netlink *nl, unsigned group, unsigned n_ref) {
        int r;

        assert(nl);

        r = hashmap_ensure_allocated(&nl->broadcast_group_refs, NULL);
        if (r < 0)
                return r;

        return hashmap_replace(nl->broadcast_group_refs, UINT_TO_PTR(group), UINT_TO_PTR(n_ref));
}

static int broadcast_group_join(sd_netlink *nl, unsigned group) {
        assert(nl);
        assert(nl->fd >= 0);
        assert(group > 0);

        /* group is "unsigned", but netlink(7) says the argument for NETLINK_ADD_MEMBERSHIP is "int" */
        return setsockopt_int(nl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group);
}

int socket_broadcast_group_ref(sd_netlink *nl, unsigned group) {
        unsigned n_ref;
        int r;

        assert(nl);

        n_ref = broadcast_group_get_ref(nl, group);

        n_ref++;

        r = broadcast_group_set_ref(nl, group, n_ref);
        if (r < 0)
                return r;

        if (n_ref > 1)
                /* already in the group */
                return 0;

        return broadcast_group_join(nl, group);
}

static int broadcast_group_leave(sd_netlink *nl, unsigned group) {
        assert(nl);
        assert(nl->fd >= 0);
        assert(group > 0);

        if (nl->broadcast_group_dont_leave)
                return 0;

        /* group is "unsigned", but netlink(7) says the argument for NETLINK_DROP_MEMBERSHIP is "int" */
        return setsockopt_int(nl->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, group);
}

int socket_broadcast_group_unref(sd_netlink *nl, unsigned group) {
        unsigned n_ref;
        int r;

        assert(nl);

        n_ref = broadcast_group_get_ref(nl, group);
        if (n_ref == 0)
                return 0;

        n_ref--;

        r = broadcast_group_set_ref(nl, group, n_ref);
        if (r < 0)
                return r;

        if (n_ref > 0)
                /* still refs left */
                return 0;

        return broadcast_group_leave(nl, group);
}

/* returns the number of bytes sent, or a negative error code */
int socket_write_message(sd_netlink *nl, sd_netlink_message *m) {
        union sockaddr_union addr = {
                .nl.nl_family = AF_NETLINK,
        };
        ssize_t k;

        assert(nl);
        assert(m);
        assert(m->hdr);

        k = sendto(nl->fd, m->hdr, m->hdr->nlmsg_len, 0, &addr.sa, sizeof(addr));
        if (k < 0)
                return -errno;

        return k;
}

static int socket_recv_message(int fd, struct iovec *iov, uint32_t *ret_mcast_group, bool peek) {
        union sockaddr_union sender;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct nl_pktinfo))) control;
        struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = 1,
                .msg_name = &sender,
                .msg_namelen = sizeof(sender),
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t n;

        assert(fd >= 0);
        assert(iov);

        n = recvmsg_safe(fd, &msg, MSG_TRUNC | (peek ? MSG_PEEK : 0));
        if (n < 0) {
                if (n == -ENOBUFS)
                        return log_debug_errno(n, "sd-netlink: kernel receive buffer overrun");
                if (ERRNO_IS_TRANSIENT(n))
                        return 0;
                return (int) n;
        }

        if (sender.nl.nl_pid != 0) {
                /* not from the kernel, ignore */
                log_debug("sd-netlink: ignoring message from PID %"PRIu32, sender.nl.nl_pid);

                if (peek) {
                        /* drop the message */
                        n = recvmsg_safe(fd, &msg, 0);
                        if (n < 0)
                                return (int) n;
                }

                return 0;
        }

        if (ret_mcast_group) {
                struct nl_pktinfo *pi;

                pi = CMSG_FIND_DATA(&msg, SOL_NETLINK, NETLINK_PKTINFO, struct nl_pktinfo);
                if (pi)
                        *ret_mcast_group = pi->group;
                else
                        *ret_mcast_group = 0;
        }

        return (int) n;
}

/* On success, the number of bytes received is returned and *ret points to the received message
 * which has a valid header and the correct size.
 * If nothing useful was received 0 is returned.
 * On failure, a negative error code is returned.
 */
int socket_read_message(sd_netlink *nl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *first = NULL;
        bool multi_part = false, done = false;
        size_t len, allocated;
        struct iovec iov = {};
        uint32_t group = 0;
        unsigned i = 0;
        int r;

        assert(nl);
        assert(nl->rbuffer);

        /* read nothing, just get the pending message size */
        r = socket_recv_message(nl->fd, &iov, NULL, true);
        if (r <= 0)
                return r;
        else
                len = (size_t) r;

        /* make room for the pending message */
        if (!greedy_realloc((void**) &nl->rbuffer, len, sizeof(uint8_t)))
                return -ENOMEM;

        allocated = MALLOC_SIZEOF_SAFE(nl->rbuffer);
        iov = IOVEC_MAKE(nl->rbuffer, allocated);

        /* read the pending message */
        r = socket_recv_message(nl->fd, &iov, &group, false);
        if (r <= 0)
                return r;
        else
                len = (size_t) r;

        if (len > allocated)
                /* message did not fit in read buffer */
                return -EIO;

        if (NLMSG_OK(nl->rbuffer, len) && nl->rbuffer->nlmsg_flags & NLM_F_MULTI) {
                multi_part = true;

                for (i = 0; i < nl->rqueue_partial_size; i++)
                        if (message_get_serial(nl->rqueue_partial[i]) ==
                            nl->rbuffer->nlmsg_seq) {
                                first = nl->rqueue_partial[i];
                                break;
                        }
        }

        for (struct nlmsghdr *new_msg = nl->rbuffer; NLMSG_OK(new_msg, len) && !done; new_msg = NLMSG_NEXT(new_msg, len)) {
                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
                size_t size;

                if (group == 0 && new_msg->nlmsg_pid != nl->sockaddr.nl.nl_pid)
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
                r = netlink_get_policy_set_and_header_size(nl, new_msg->nlmsg_type, NULL, &size);
                if (r < 0) {
                        if (r == -EOPNOTSUPP)
                                log_debug("sd-netlink: ignored message with unknown type: %i",
                                          new_msg->nlmsg_type);

                        continue;
                }

                /* check that the size matches the message type */
                if (new_msg->nlmsg_len < NLMSG_LENGTH(size)) {
                        log_debug("sd-netlink: message is shorter than expected, dropping");
                        continue;
                }

                r = message_new_empty(nl, &m);
                if (r < 0)
                        return r;

                m->multicast_group = group;
                m->hdr = memdup(new_msg, new_msg->nlmsg_len);
                if (!m->hdr)
                        return -ENOMEM;

                /* seal and parse the top-level message */
                r = sd_netlink_message_rewind(m, nl);
                if (r < 0)
                        return r;

                /* push the message onto the multi-part message stack */
                if (first)
                        m->next = first;
                first = TAKE_PTR(m);
        }

        if (len > 0)
                log_debug("sd-netlink: discarding %zu bytes of incoming message", len);

        if (!first)
                return 0;

        if (!multi_part || done) {
                /* we got a complete message, push it on the read queue */
                r = netlink_rqueue_make_room(nl);
                if (r < 0)
                        return r;

                nl->rqueue[nl->rqueue_size++] = TAKE_PTR(first);

                if (multi_part && (i < nl->rqueue_partial_size)) {
                        /* remove the message form the partial read queue */
                        memmove(nl->rqueue_partial + i, nl->rqueue_partial + i + 1,
                                sizeof(sd_netlink_message*) * (nl->rqueue_partial_size - i - 1));
                        nl->rqueue_partial_size--;
                }

                return 1;
        } else {
                /* we only got a partial multi-part message, push it on the
                   partial read queue */
                if (i < nl->rqueue_partial_size)
                        nl->rqueue_partial[i] = TAKE_PTR(first);
                else {
                        r = netlink_rqueue_partial_make_room(nl);
                        if (r < 0)
                                return r;

                        nl->rqueue_partial[nl->rqueue_partial_size++] = TAKE_PTR(first);
                }

                return 0;
        }
}
