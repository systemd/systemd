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

static int socket_recv_message(int fd, void *buf, size_t buf_size, uint32_t *ret_mcast_group, bool peek) {
        struct iovec iov = IOVEC_MAKE(buf, buf_size);
        union sockaddr_union sender;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct nl_pktinfo))) control;
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_name = &sender,
                .msg_namelen = sizeof(sender),
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t n;

        assert(fd >= 0);
        assert(peek || (buf && buf_size > 0));

        n = recvmsg_safe(fd, &msg, MSG_TRUNC | (peek ? MSG_PEEK : 0));
        if (n < 0) {
                if (n == -ENOBUFS)
                        return log_debug_errno(n, "sd-netlink: kernel receive buffer overrun");
                if (ERRNO_IS_TRANSIENT(n)) {
                        if (ret_mcast_group)
                                *ret_mcast_group = 0;
                        return 0;
                }
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

                if (ret_mcast_group)
                        *ret_mcast_group = 0;
                return 0;
        }

        if (!peek && (size_t) n > buf_size) /* message did not fit in read buffer */
                return -EIO;

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

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        netlink_message_hash_ops,
        void, trivial_hash_func, trivial_compare_func,
        sd_netlink_message, sd_netlink_message_unref);

static int netlink_queue_received_message(sd_netlink *nl, sd_netlink_message *m) {
        int r;

        assert(nl);
        assert(m);

        if (ordered_set_size(nl->rqueue) >= NETLINK_RQUEUE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "sd-netlink: exhausted the read queue size (%d)", NETLINK_RQUEUE_MAX);

        r = ordered_set_ensure_put(&nl->rqueue, &netlink_message_hash_ops, m);
        if (r < 0)
                return r;

        sd_netlink_message_ref(m);
        return 0;
}

static int netlink_queue_partially_received_message(sd_netlink *nl, sd_netlink_message *m) {
        uint32_t serial;
        int r;

        assert(nl);
        assert(m);
        assert(m->hdr->nlmsg_flags & NLM_F_MULTI);

        if (hashmap_size(nl->rqueue_partial_by_serial) >= NETLINK_RQUEUE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "sd-netlink: exhausted the partial read queue size (%d)", NETLINK_RQUEUE_MAX);

        serial = message_get_serial(m);
        r = hashmap_ensure_put(&nl->rqueue_partial_by_serial, &netlink_message_hash_ops, UINT32_TO_PTR(serial), m);
        if (r < 0)
                return r;

        sd_netlink_message_ref(m);
        return 0;
}

/* On success, the number of bytes received is returned and *ret points to the received message
 * which has a valid header and the correct size.
 * If nothing useful was received 0 is returned.
 * On failure, a negative error code is returned.
 */
int socket_read_message(sd_netlink *nl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *first = NULL;
        bool multi_part = false, done = false;
        size_t len;
        uint32_t group;
        int r;

        assert(nl);

        /* read nothing, just get the pending message size */
        r = socket_recv_message(nl->fd, NULL, 0, NULL, true);
        if (r <= 0)
                return r;
        len = (size_t) r;

        /* make room for the pending message */
        if (!greedy_realloc((void**) &nl->rbuffer, len, sizeof(uint8_t)))
                return -ENOMEM;

        /* read the pending message */
        r = socket_recv_message(nl->fd, nl->rbuffer, MALLOC_SIZEOF_SAFE(nl->rbuffer), &group, false);
        if (r <= 0)
                return r;
        len = (size_t) r;

        if (!NLMSG_OK(nl->rbuffer, len)) {
                log_debug("sd-netlink: received invalid message, discarding %zu bytes of incoming message", len);
                return 0;
        }

        if (nl->rbuffer->nlmsg_flags & NLM_F_MULTI) {
                multi_part = true;
                first = hashmap_remove(nl->rqueue_partial_by_serial, UINT32_TO_PTR(nl->rbuffer->nlmsg_seq));
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
                log_debug("sd-netlink: discarding trailing %zu bytes of incoming message", len);

        if (!first)
                return 0;

        done = done || !multi_part;
        if (done)
                /* we got a complete message, push it on the read queue */
                r = netlink_queue_received_message(nl, first);
        else
                /* we only got a partial multi-part message, push it on the partial read queue. */
                r = netlink_queue_partially_received_message(nl, first);
        if (r < 0)
                return r;

        return done;
}
