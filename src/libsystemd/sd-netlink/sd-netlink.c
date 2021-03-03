/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "macro.h"
#include "netlink-internal.h"
#include "netlink-slot.h"
#include "netlink-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

/* Some really high limit, to catch programming errors */
#define REPLY_CALLBACKS_MAX UINT16_MAX

static int sd_netlink_new(sd_netlink **ret) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;

        assert_return(ret, -EINVAL);

        rtnl = new(sd_netlink, 1);
        if (!rtnl)
                return -ENOMEM;

        *rtnl = (sd_netlink) {
                .n_ref = 1,
                .fd = -1,
                .sockaddr.nl.nl_family = AF_NETLINK,
                .original_pid = getpid_cached(),
                .protocol = -1,

                /* Kernel change notification messages have sequence number 0. We want to avoid that with our
                 * own serials, in order not to get confused when matching up kernel replies to our earlier
                 * requests.
                 *
                 * Moreover, when using netlink socket activation (i.e. where PID 1 binds an AF_NETLINK
                 * socket for us and passes it to us across execve()) and we get restarted multiple times
                 * while the socket sticks around we might get confused by replies from earlier runs coming
                 * in late — which is pretty likely if we'd start our sequence numbers always from 1. Hence,
                 * let's start with a value based on the system clock. This should make collisions much less
                 * likely (though still theoretically possible). We use a 32 bit µs counter starting at boot
                 * for this (and explicitly exclude the zero, see above). This counter will wrap around after
                 * a bit more than 1h, but that's hopefully OK as the kernel shouldn't take that long to
                 * reply to our requests.
                 *
                 * We only pick the initial start value this way. For each message we simply increase the
                 * sequence number by 1. This means we could enqueue 1 netlink message per µs without risking
                 * collisions, which should be OK.
                 *
                 * Note this means the serials will be in the range 1…UINT32_MAX here.
                 *
                 * (In an ideal world we'd attach the current serial counter to the netlink socket itself
                 * somehow, to avoid all this, but I couldn't come up with a nice way to do this) */
                .serial = (uint32_t) (now(CLOCK_MONOTONIC) % UINT32_MAX) + 1,
        };

        /* We guarantee that the read buffer has at least space for
         * a message header */
        if (!greedy_realloc((void**)&rtnl->rbuffer, &rtnl->rbuffer_allocated,
                            sizeof(struct nlmsghdr), sizeof(uint8_t)))
                return -ENOMEM;

        *ret = TAKE_PTR(rtnl);

        return 0;
}

int sd_netlink_new_from_netlink(sd_netlink **ret, int fd) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        socklen_t addrlen;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_netlink_new(&rtnl);
        if (r < 0)
                return r;

        addrlen = sizeof(rtnl->sockaddr);

        r = getsockname(fd, &rtnl->sockaddr.sa, &addrlen);
        if (r < 0)
                return -errno;

        if (rtnl->sockaddr.nl.nl_family != AF_NETLINK)
                return -EINVAL;

        rtnl->fd = fd;

        *ret = TAKE_PTR(rtnl);

        return 0;
}

static bool rtnl_pid_changed(const sd_netlink *rtnl) {
        assert(rtnl);

        /* We don't support people creating an rtnl connection and
         * keeping it around over a fork(). Let's complain. */

        return rtnl->original_pid != getpid_cached();
}

int sd_netlink_open_fd(sd_netlink **ret, int fd) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r, protocol;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = sd_netlink_new(&rtnl);
        if (r < 0)
                return r;

        r = getsockopt_int(fd, SOL_SOCKET, SO_PROTOCOL, &protocol);
        if (r < 0)
                return r;

        rtnl->fd = fd;
        rtnl->protocol = protocol;

        r = setsockopt_int(fd, SOL_NETLINK, NETLINK_EXT_ACK, 1);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: Failed to enable NETLINK_EXT_ACK option, ignoring: %m");

        r = socket_bind(rtnl);
        if (r < 0) {
                rtnl->fd = -1; /* on failure, the caller remains owner of the fd, hence don't close it here */
                rtnl->protocol = -1;
                return r;
        }

        *ret = TAKE_PTR(rtnl);

        return 0;
}

int netlink_open_family(sd_netlink **ret, int family) {
        _cleanup_close_ int fd = -1;
        int r;

        fd = socket_open(family);
        if (fd < 0)
                return fd;

        r = sd_netlink_open_fd(ret, fd);
        if (r < 0)
                return r;
        TAKE_FD(fd);

        return 0;
}

int sd_netlink_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_ROUTE);
}

int sd_netlink_inc_rcvbuf(sd_netlink *rtnl, size_t size) {
        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        return fd_inc_rcvbuf(rtnl->fd, size);
}

static sd_netlink *netlink_free(sd_netlink *rtnl) {
        sd_netlink_slot *s;
        unsigned i;

        assert(rtnl);

        for (i = 0; i < rtnl->rqueue_size; i++)
                sd_netlink_message_unref(rtnl->rqueue[i]);
        free(rtnl->rqueue);

        for (i = 0; i < rtnl->rqueue_partial_size; i++)
                sd_netlink_message_unref(rtnl->rqueue_partial[i]);
        free(rtnl->rqueue_partial);

        free(rtnl->rbuffer);

        while ((s = rtnl->slots)) {
                assert(s->floating);
                netlink_slot_disconnect(s, true);
        }
        hashmap_free(rtnl->reply_callbacks);
        prioq_free(rtnl->reply_callbacks_prioq);

        sd_event_source_unref(rtnl->io_event_source);
        sd_event_source_unref(rtnl->time_event_source);
        sd_event_unref(rtnl->event);

        hashmap_free(rtnl->broadcast_group_refs);

        hashmap_free(rtnl->genl_family_to_nlmsg_type);
        hashmap_free(rtnl->nlmsg_type_to_genl_family);

        safe_close(rtnl->fd);
        return mfree(rtnl);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_netlink, sd_netlink, netlink_free);

static void rtnl_seal_message(sd_netlink *rtnl, sd_netlink_message *m) {
        uint32_t picked;

        assert(rtnl);
        assert(!rtnl_pid_changed(rtnl));
        assert(m);
        assert(m->hdr);

        /* Avoid collisions with outstanding requests */
        do {
                picked = rtnl->serial;

                /* Don't use seq == 0, as that is used for broadcasts, so we would get confused by replies to
                   such messages */
                rtnl->serial = rtnl->serial == UINT32_MAX ? 1 : rtnl->serial + 1;

        } while (hashmap_contains(rtnl->reply_callbacks, UINT32_TO_PTR(picked)));

        m->hdr->nlmsg_seq = picked;
        rtnl_message_seal(m);
}

int sd_netlink_send(sd_netlink *nl,
                    sd_netlink_message *message,
                    uint32_t *serial) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);
        assert_return(!message->sealed, -EPERM);

        rtnl_seal_message(nl, message);

        r = socket_write_message(nl, message);
        if (r < 0)
                return r;

        if (serial)
                *serial = rtnl_message_get_serial(message);

        return 1;
}

int sd_netlink_sendv(sd_netlink *nl,
                     sd_netlink_message **messages,
                     size_t msgcount,
                     uint32_t **ret_serial) {
        _cleanup_free_ uint32_t *serials = NULL;
        unsigned i;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);
        assert_return(messages, -EINVAL);
        assert_return(msgcount > 0, -EINVAL);

        if (ret_serial) {
                serials = new0(uint32_t, msgcount);
                if (!serials)
                        return -ENOMEM;
        }

        for (i = 0; i < msgcount; i++) {
                assert_return(!messages[i]->sealed, -EPERM);
                rtnl_seal_message(nl, messages[i]);
                if (serials)
                        serials[i] = rtnl_message_get_serial(messages[i]);
        }

        r = socket_writev_message(nl, messages, msgcount);
        if (r < 0)
                return r;

        if (ret_serial)
                *ret_serial = TAKE_PTR(serials);

        return r;
}

int rtnl_rqueue_make_room(sd_netlink *rtnl) {
        assert(rtnl);

        if (rtnl->rqueue_size >= RTNL_RQUEUE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "rtnl: exhausted the read queue size (%d)",
                                       RTNL_RQUEUE_MAX);

        if (!GREEDY_REALLOC(rtnl->rqueue, rtnl->rqueue_allocated, rtnl->rqueue_size + 1))
                return -ENOMEM;

        return 0;
}

int rtnl_rqueue_partial_make_room(sd_netlink *rtnl) {
        assert(rtnl);

        if (rtnl->rqueue_partial_size >= RTNL_RQUEUE_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOBUFS),
                                       "rtnl: exhausted the partial read queue size (%d)",
                                       RTNL_RQUEUE_MAX);

        if (!GREEDY_REALLOC(rtnl->rqueue_partial, rtnl->rqueue_partial_allocated,
                            rtnl->rqueue_partial_size + 1))
                return -ENOMEM;

        return 0;
}

static int dispatch_rqueue(sd_netlink *rtnl, sd_netlink_message **message) {
        int r;

        assert(rtnl);
        assert(message);

        if (rtnl->rqueue_size <= 0) {
                /* Try to read a new message */
                r = socket_read_message(rtnl);
                if (r == -ENOBUFS) { /* FIXME: ignore buffer overruns for now */
                        log_debug_errno(r, "Got ENOBUFS from netlink socket, ignoring.");
                        return 1;
                }
                if (r <= 0)
                        return r;
        }

        /* Dispatch a queued message */
        *message = rtnl->rqueue[0];
        rtnl->rqueue_size--;
        memmove(rtnl->rqueue, rtnl->rqueue + 1, sizeof(sd_netlink_message*) * rtnl->rqueue_size);

        return 1;
}

static int process_timeout(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        struct reply_callback *c;
        sd_netlink_slot *slot;
        usec_t n;
        int r;

        assert(rtnl);

        c = prioq_peek(rtnl->reply_callbacks_prioq);
        if (!c)
                return 0;

        n = now(CLOCK_MONOTONIC);
        if (c->timeout > n)
                return 0;

        r = rtnl_message_new_synthetic_error(rtnl, -ETIMEDOUT, c->serial, &m);
        if (r < 0)
                return r;

        assert_se(prioq_pop(rtnl->reply_callbacks_prioq) == c);
        c->timeout = 0;
        hashmap_remove(rtnl->reply_callbacks, UINT32_TO_PTR(c->serial));

        slot = container_of(c, sd_netlink_slot, reply_callback);

        r = c->callback(rtnl, m, slot->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: timedout callback %s%s%sfailed: %m",
                                slot->description ? "'" : "",
                                strempty(slot->description),
                                slot->description ? "' " : "");

        if (slot->floating)
                netlink_slot_disconnect(slot, true);

        return 1;
}

static int process_reply(sd_netlink *rtnl, sd_netlink_message *m) {
        struct reply_callback *c;
        sd_netlink_slot *slot;
        uint32_t serial;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(m);

        serial = rtnl_message_get_serial(m);
        c = hashmap_remove(rtnl->reply_callbacks, UINT32_TO_PTR(serial));
        if (!c)
                return 0;

        if (c->timeout != 0) {
                prioq_remove(rtnl->reply_callbacks_prioq, c, &c->prioq_idx);
                c->timeout = 0;
        }

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        if (type == NLMSG_DONE)
                m = NULL;

        slot = container_of(c, sd_netlink_slot, reply_callback);

        r = c->callback(rtnl, m, slot->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: reply callback %s%s%sfailed: %m",
                                slot->description ? "'" : "",
                                strempty(slot->description),
                                slot->description ? "' " : "");

        if (slot->floating)
                netlink_slot_disconnect(slot, true);

        return 1;
}

static int process_match(sd_netlink *rtnl, sd_netlink_message *m) {
        struct match_callback *c;
        sd_netlink_slot *slot;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(m);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        LIST_FOREACH(match_callbacks, c, rtnl->match_callbacks) {
                if (type != c->type)
                        continue;

                slot = container_of(c, sd_netlink_slot, match_callback);

                r = c->callback(rtnl, m, slot->userdata);
                if (r < 0)
                        log_debug_errno(r, "sd-netlink: match callback %s%s%sfailed: %m",
                                        slot->description ? "'" : "",
                                        strempty(slot->description),
                                        slot->description ? "' " : "");
                if (r != 0)
                        break;
        }

        return 1;
}

static int process_running(sd_netlink *rtnl, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(rtnl);

        r = process_timeout(rtnl);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(rtnl, &m);
        if (r < 0)
                return r;
        if (!m)
                goto null_message;

        if (sd_netlink_message_is_broadcast(m)) {
                r = process_match(rtnl, m);
                if (r != 0)
                        goto null_message;
        } else {
                r = process_reply(rtnl, m);
                if (r != 0)
                        goto null_message;
        }

        if (ret) {
                *ret = TAKE_PTR(m);

                return 1;
        }

        return 1;

null_message:
        if (r >= 0 && ret)
                *ret = NULL;

        return r;
}

int sd_netlink_process(sd_netlink *rtnl, sd_netlink_message **ret) {
        NETLINK_DONT_DESTROY(rtnl);
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);
        assert_return(!rtnl->processing, -EBUSY);

        rtnl->processing = true;
        r = process_running(rtnl, ret);
        rtnl->processing = false;

        return r;
}

static usec_t calc_elapse(uint64_t usec) {
        if (usec == UINT64_MAX)
                return 0;

        if (usec == 0)
                usec = RTNL_DEFAULT_TIMEOUT;

        return usec_add(now(CLOCK_MONOTONIC), usec);
}

static int rtnl_poll(sd_netlink *rtnl, bool need_more, uint64_t timeout_usec) {
        usec_t m = USEC_INFINITY;
        int r, e;

        assert(rtnl);

        e = sd_netlink_get_events(rtnl);
        if (e < 0)
                return e;

        if (need_more)
                /* Caller wants more data, and doesn't care about
                 * what's been read or any other timeouts. */
                e |= POLLIN;
        else {
                usec_t until;
                /* Caller wants to process if there is something to
                 * process, but doesn't care otherwise */

                r = sd_netlink_get_timeout(rtnl, &until);
                if (r < 0)
                        return r;
                if (r > 0) {
                        usec_t nw;
                        nw = now(CLOCK_MONOTONIC);
                        m = until > nw ? until - nw : 0;
                }
        }

        if (timeout_usec != UINT64_MAX && (m == USEC_INFINITY || timeout_usec < m))
                m = timeout_usec;

        r = fd_wait_for_event(rtnl->fd, e, m);
        if (r <= 0)
                return r;

        return 1;
}

int sd_netlink_wait(sd_netlink *nl, uint64_t timeout_usec) {
        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);

        if (nl->rqueue_size > 0)
                return 0;

        return rtnl_poll(nl, false, timeout_usec);
}

static int timeout_compare(const void *a, const void *b) {
        const struct reply_callback *x = a, *y = b;

        if (x->timeout != 0 && y->timeout == 0)
                return -1;

        if (x->timeout == 0 && y->timeout != 0)
                return 1;

        return CMP(x->timeout, y->timeout);
}

int sd_netlink_call_async(
                sd_netlink *nl,
                sd_netlink_slot **ret_slot,
                sd_netlink_message *m,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                uint64_t usec,
                const char *description) {
        _cleanup_free_ sd_netlink_slot *slot = NULL;
        int r, k;

        assert_return(nl, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);

        if (hashmap_size(nl->reply_callbacks) >= REPLY_CALLBACKS_MAX)
                return -ERANGE;

        r = hashmap_ensure_allocated(&nl->reply_callbacks, &trivial_hash_ops);
        if (r < 0)
                return r;

        if (usec != UINT64_MAX) {
                r = prioq_ensure_allocated(&nl->reply_callbacks_prioq, timeout_compare);
                if (r < 0)
                        return r;
        }

        r = netlink_slot_allocate(nl, !ret_slot, NETLINK_REPLY_CALLBACK, sizeof(struct reply_callback), userdata, description, &slot);
        if (r < 0)
                return r;

        slot->reply_callback.callback = callback;
        slot->reply_callback.timeout = calc_elapse(usec);

        k = sd_netlink_send(nl, m, &slot->reply_callback.serial);
        if (k < 0)
                return k;

        r = hashmap_put(nl->reply_callbacks, UINT32_TO_PTR(slot->reply_callback.serial), &slot->reply_callback);
        if (r < 0)
                return r;

        if (slot->reply_callback.timeout != 0) {
                r = prioq_put(nl->reply_callbacks_prioq, &slot->reply_callback, &slot->reply_callback.prioq_idx);
                if (r < 0) {
                        (void) hashmap_remove(nl->reply_callbacks, UINT32_TO_PTR(slot->reply_callback.serial));
                        return r;
                }
        }

        /* Set this at last. Otherwise, some failures in above call the destroy callback but some do not. */
        slot->destroy_callback = destroy_callback;

        if (ret_slot)
                *ret_slot = slot;

        TAKE_PTR(slot);

        return k;
}

int sd_netlink_read(sd_netlink *rtnl,
                    uint32_t serial,
                    uint64_t usec,
                    sd_netlink_message **ret) {
        usec_t timeout;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;
                unsigned i;

                for (i = 0; i < rtnl->rqueue_size; i++) {
                        uint32_t received_serial;

                        received_serial = rtnl_message_get_serial(rtnl->rqueue[i]);

                        if (received_serial == serial) {
                                _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *incoming = NULL;
                                uint16_t type;

                                incoming = rtnl->rqueue[i];

                                /* found a match, remove from rqueue and return it */
                                memmove(rtnl->rqueue + i,rtnl->rqueue + i + 1,
                                        sizeof(sd_netlink_message*) * (rtnl->rqueue_size - i - 1));
                                rtnl->rqueue_size--;

                                r = sd_netlink_message_get_errno(incoming);
                                if (r < 0)
                                        return r;

                                r = sd_netlink_message_get_type(incoming, &type);
                                if (r < 0)
                                        return r;

                                if (type == NLMSG_DONE) {
                                        *ret = NULL;
                                        return 0;
                                }

                                if (ret)
                                        *ret = TAKE_PTR(incoming);

                                return 1;
                        }
                }

                r = socket_read_message(rtnl);
                if (r < 0)
                        return r;
                if (r > 0)
                        /* received message, so try to process straight away */
                        continue;

                if (timeout > 0) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        left = timeout - n;
                } else
                        left = UINT64_MAX;

                r = rtnl_poll(rtnl, true, left);
                if (r < 0)
                        return r;
                else if (r == 0)
                        return -ETIMEDOUT;
        }
}

int sd_netlink_call(sd_netlink *rtnl,
                sd_netlink_message *message,
                uint64_t usec,
                sd_netlink_message **ret) {
        uint32_t serial;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);
        assert_return(message, -EINVAL);

        r = sd_netlink_send(rtnl, message, &serial);
        if (r < 0)
                return r;

        return sd_netlink_read(rtnl, serial, usec, ret);
}

int sd_netlink_get_events(const sd_netlink *rtnl) {
        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        if (rtnl->rqueue_size == 0)
                return POLLIN;
        else
                return 0;
}

int sd_netlink_get_timeout(const sd_netlink *rtnl, uint64_t *timeout_usec) {
        struct reply_callback *c;

        assert_return(rtnl, -EINVAL);
        assert_return(timeout_usec, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        if (rtnl->rqueue_size > 0) {
                *timeout_usec = 0;
                return 1;
        }

        c = prioq_peek(rtnl->reply_callbacks_prioq);
        if (!c) {
                *timeout_usec = UINT64_MAX;
                return 0;
        }

        *timeout_usec = c->timeout;

        return 1;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_netlink *rtnl = userdata;
        int r;

        assert(rtnl);

        r = sd_netlink_process(rtnl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_netlink *rtnl = userdata;
        int r;

        assert(rtnl);

        r = sd_netlink_process(rtnl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_netlink *rtnl = userdata;
        int r, e;
        usec_t until;

        assert(s);
        assert(rtnl);

        e = sd_netlink_get_events(rtnl);
        if (e < 0)
                return e;

        r = sd_event_source_set_io_events(rtnl->io_event_source, e);
        if (r < 0)
                return r;

        r = sd_netlink_get_timeout(rtnl, &until);
        if (r < 0)
                return r;
        if (r > 0) {
                int j;

                j = sd_event_source_set_time(rtnl->time_event_source, until);
                if (j < 0)
                        return j;
        }

        r = sd_event_source_set_enabled(rtnl->time_event_source, r > 0);
        if (r < 0)
                return r;

        return 1;
}

int sd_netlink_attach_event(sd_netlink *rtnl, sd_event *event, int64_t priority) {
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl->event, -EBUSY);

        assert(!rtnl->io_event_source);
        assert(!rtnl->time_event_source);

        if (event)
                rtnl->event = sd_event_ref(event);
        else {
                r = sd_event_default(&rtnl->event);
                if (r < 0)
                        return r;
        }

        r = sd_event_add_io(rtnl->event, &rtnl->io_event_source, rtnl->fd, 0, io_callback, rtnl);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(rtnl->io_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(rtnl->io_event_source, "rtnl-receive-message");
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(rtnl->io_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_add_time(rtnl->event, &rtnl->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, rtnl);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(rtnl->time_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(rtnl->time_event_source, "rtnl-timer");
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_netlink_detach_event(rtnl);
        return r;
}

int sd_netlink_detach_event(sd_netlink *rtnl) {
        assert_return(rtnl, -EINVAL);
        assert_return(rtnl->event, -ENXIO);

        rtnl->io_event_source = sd_event_source_unref(rtnl->io_event_source);

        rtnl->time_event_source = sd_event_source_unref(rtnl->time_event_source);

        rtnl->event = sd_event_unref(rtnl->event);

        return 0;
}

int sd_netlink_add_match(
                sd_netlink *rtnl,
                sd_netlink_slot **ret_slot,
                uint16_t type,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                const char *description) {
        _cleanup_free_ sd_netlink_slot *slot = NULL;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        r = netlink_slot_allocate(rtnl, !ret_slot, NETLINK_MATCH_CALLBACK, sizeof(struct match_callback), userdata, description, &slot);
        if (r < 0)
                return r;

        slot->match_callback.callback = callback;
        slot->match_callback.type = type;

        switch (type) {
                case RTM_NEWLINK:
                case RTM_DELLINK:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_LINK);
                        if (r < 0)
                                return r;

                        break;
                case RTM_NEWADDR:
                case RTM_DELADDR:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV4_IFADDR);
                        if (r < 0)
                                return r;

                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV6_IFADDR);
                        if (r < 0)
                                return r;

                        break;
                case RTM_NEWNEIGH:
                case RTM_DELNEIGH:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_NEIGH);
                        if (r < 0)
                                return r;

                        break;
                case RTM_NEWROUTE:
                case RTM_DELROUTE:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV4_ROUTE);
                        if (r < 0)
                                return r;

                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV6_ROUTE);
                        if (r < 0)
                                return r;
                        break;
                case RTM_NEWRULE:
                case RTM_DELRULE:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV4_RULE);
                        if (r < 0)
                                return r;

                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_IPV6_RULE);
                        if (r < 0)
                                return r;
                        break;
                case RTM_NEWNEXTHOP:
                case RTM_DELNEXTHOP:
                        r = socket_broadcast_group_ref(rtnl, RTNLGRP_NEXTHOP);
                        if (r < 0)
                                return r;
                break;

                default:
                        return -EOPNOTSUPP;
        }

        LIST_PREPEND(match_callbacks, rtnl->match_callbacks, &slot->match_callback);

        /* Set this at last. Otherwise, some failures in above call the destroy callback but some do not. */
        slot->destroy_callback = destroy_callback;

        if (ret_slot)
                *ret_slot = slot;

        TAKE_PTR(slot);

        return 0;
}
