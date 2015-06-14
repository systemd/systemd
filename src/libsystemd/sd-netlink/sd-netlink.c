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

#include <sys/socket.h>
#include <poll.h>

#include "missing.h"
#include "macro.h"
#include "util.h"
#include "hashmap.h"

#include "sd-netlink.h"
#include "netlink-internal.h"
#include "netlink-util.h"

static int sd_netlink_new(sd_netlink **ret) {
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;

        assert_return(ret, -EINVAL);

        rtnl = new0(sd_netlink, 1);
        if (!rtnl)
                return -ENOMEM;

        rtnl->n_ref = REFCNT_INIT;

        rtnl->fd = -1;

        rtnl->sockaddr.nl.nl_family = AF_NETLINK;

        rtnl->original_pid = getpid();

        LIST_HEAD_INIT(rtnl->match_callbacks);

        /* We guarantee that the read buffer has at least space for
         * a message header */
        if (!greedy_realloc((void**)&rtnl->rbuffer, &rtnl->rbuffer_allocated,
                            sizeof(struct nlmsghdr), sizeof(uint8_t)))
                return -ENOMEM;

        /* Change notification responses have sequence 0, so we must
         * start our request sequence numbers at 1, or we may confuse our
         * responses with notifications from the kernel */
        rtnl->serial = 1;

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

int sd_netlink_new_from_netlink(sd_netlink **ret, int fd) {
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
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

        rtnl->fd = fd;

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

static bool rtnl_pid_changed(sd_netlink *rtnl) {
        assert(rtnl);

        /* We don't support people creating an rtnl connection and
         * keeping it around over a fork(). Let's complain. */

        return rtnl->original_pid != getpid();
}

int sd_netlink_open_fd(sd_netlink **ret, int fd) {
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EINVAL);

        r = sd_netlink_new(&rtnl);
        if (r < 0)
                return r;

        rtnl->fd = fd;

        r = socket_bind(rtnl);
        if (r < 0)
                return r;

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

int sd_netlink_open(sd_netlink **ret) {
        _cleanup_close_ int fd = -1;
        int r;

        fd = socket_open(NETLINK_ROUTE);
        if (fd < 0)
                return fd;

        r = sd_netlink_open_fd(ret, fd);
        if (r < 0)
                return r;

        fd = -1;

        return 0;
}

int sd_netlink_inc_rcvbuf(const sd_netlink *const rtnl, const int size) {
        return fd_inc_rcvbuf(rtnl->fd, size);
}

sd_netlink *sd_netlink_ref(sd_netlink *rtnl) {
        assert_return(rtnl, NULL);
        assert_return(!rtnl_pid_changed(rtnl), NULL);

        if (rtnl)
                assert_se(REFCNT_INC(rtnl->n_ref) >= 2);

        return rtnl;
}

sd_netlink *sd_netlink_unref(sd_netlink *rtnl) {
        if (!rtnl)
                return NULL;

        assert_return(!rtnl_pid_changed(rtnl), NULL);

        if (REFCNT_DEC(rtnl->n_ref) == 0) {
                struct match_callback *f;
                unsigned i;

                for (i = 0; i < rtnl->rqueue_size; i++)
                        sd_netlink_message_unref(rtnl->rqueue[i]);
                free(rtnl->rqueue);

                for (i = 0; i < rtnl->rqueue_partial_size; i++)
                        sd_netlink_message_unref(rtnl->rqueue_partial[i]);
                free(rtnl->rqueue_partial);

                free(rtnl->rbuffer);

                hashmap_free_free(rtnl->reply_callbacks);
                prioq_free(rtnl->reply_callbacks_prioq);

                sd_event_source_unref(rtnl->io_event_source);
                sd_event_source_unref(rtnl->time_event_source);
                sd_event_unref(rtnl->event);

                while ((f = rtnl->match_callbacks)) {
                        LIST_REMOVE(match_callbacks, rtnl->match_callbacks, f);
                        free(f);
                }

                safe_close(rtnl->fd);
                free(rtnl);
        }

        return NULL;
}

static void rtnl_seal_message(sd_netlink *rtnl, sd_netlink_message *m) {
        assert(rtnl);
        assert(!rtnl_pid_changed(rtnl));
        assert(m);
        assert(m->hdr);

        /* don't use seq == 0, as that is used for broadcasts, so we
           would get confused by replies to such messages */
        m->hdr->nlmsg_seq = rtnl->serial++ ? : rtnl->serial++;

        rtnl_message_seal(m);

        return;
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

int rtnl_rqueue_make_room(sd_netlink *rtnl) {
        assert(rtnl);

        if (rtnl->rqueue_size >= RTNL_RQUEUE_MAX) {
                log_debug("rtnl: exhausted the read queue size (%d)", RTNL_RQUEUE_MAX);
                return -ENOBUFS;
        }

        if (!GREEDY_REALLOC(rtnl->rqueue, rtnl->rqueue_allocated, rtnl->rqueue_size + 1))
                return -ENOMEM;

        return 0;
}

int rtnl_rqueue_partial_make_room(sd_netlink *rtnl) {
        assert(rtnl);

        if (rtnl->rqueue_partial_size >= RTNL_RQUEUE_MAX) {
                log_debug("rtnl: exhausted the partial read queue size (%d)", RTNL_RQUEUE_MAX);
                return -ENOBUFS;
        }

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
                if (r <= 0)
                        return r;
        }

        /* Dispatch a queued message */
        *message = rtnl->rqueue[0];
        rtnl->rqueue_size --;
        memmove(rtnl->rqueue, rtnl->rqueue + 1, sizeof(sd_netlink_message*) * rtnl->rqueue_size);

        return 1;
}

static int process_timeout(sd_netlink *rtnl) {
        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
        struct reply_callback *c;
        usec_t n;
        int r;

        assert(rtnl);

        c = prioq_peek(rtnl->reply_callbacks_prioq);
        if (!c)
                return 0;

        n = now(CLOCK_MONOTONIC);
        if (c->timeout > n)
                return 0;

        r = rtnl_message_new_synthetic_error(-ETIMEDOUT, c->serial, &m);
        if (r < 0)
                return r;

        assert_se(prioq_pop(rtnl->reply_callbacks_prioq) == c);
        hashmap_remove(rtnl->reply_callbacks, &c->serial);

        r = c->callback(rtnl, m, c->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: timedout callback failed: %m");

        free(c);

        return 1;
}

static int process_reply(sd_netlink *rtnl, sd_netlink_message *m) {
        _cleanup_free_ struct reply_callback *c = NULL;
        uint64_t serial;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(m);

        serial = rtnl_message_get_serial(m);
        c = hashmap_remove(rtnl->reply_callbacks, &serial);
        if (!c)
                return 0;

        if (c->timeout != 0)
                prioq_remove(rtnl->reply_callbacks_prioq, c, &c->prioq_idx);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return 0;

        if (type == NLMSG_DONE)
                m = NULL;

        r = c->callback(rtnl, m, c->userdata);
        if (r < 0)
                log_debug_errno(r, "sd-netlink: callback failed: %m");

        return 1;
}

static int process_match(sd_netlink *rtnl, sd_netlink_message *m) {
        struct match_callback *c;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(m);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        LIST_FOREACH(match_callbacks, c, rtnl->match_callbacks) {
                if (type == c->type) {
                        r = c->callback(rtnl, m, c->userdata);
                        if (r != 0) {
                                if (r < 0)
                                        log_debug_errno(r, "sd-netlink: match callback failed: %m");

                                break;
                        }
                }
        }

        return 1;
}

static int process_running(sd_netlink *rtnl, sd_netlink_message **ret) {
        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL;
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
                *ret = m;
                m = NULL;

                return 1;
        }

        return 1;

null_message:
        if (r >= 0 && ret)
                *ret = NULL;

        return r;
}

int sd_netlink_process(sd_netlink *rtnl, sd_netlink_message **ret) {
        RTNL_DONT_DESTROY(rtnl);
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
        if (usec == (uint64_t) -1)
                return 0;

        if (usec == 0)
                usec = RTNL_DEFAULT_TIMEOUT;

        return now(CLOCK_MONOTONIC) + usec;
}

static int rtnl_poll(sd_netlink *rtnl, bool need_more, uint64_t timeout_usec) {
        struct pollfd p[1] = {};
        struct timespec ts;
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

        if (timeout_usec != (uint64_t) -1 && (m == (uint64_t) -1 || timeout_usec < m))
                m = timeout_usec;

        p[0].fd = rtnl->fd;
        p[0].events = e;

        r = ppoll(p, 1, m == (uint64_t) -1 ? NULL : timespec_store(&ts, m), NULL);
        if (r < 0)
                return -errno;

        return r > 0 ? 1 : 0;
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

        if (x->timeout < y->timeout)
                return -1;

        if (x->timeout > y->timeout)
                return 1;

        return 0;
}

int sd_netlink_call_async(sd_netlink *nl,
                       sd_netlink_message *m,
                       sd_netlink_message_handler_t callback,
                       void *userdata,
                       uint64_t usec,
                       uint32_t *serial) {
        struct reply_callback *c;
        uint32_t s;
        int r, k;

        assert_return(nl, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);

        r = hashmap_ensure_allocated(&nl->reply_callbacks, &uint64_hash_ops);
        if (r < 0)
                return r;

        if (usec != (uint64_t) -1) {
                r = prioq_ensure_allocated(&nl->reply_callbacks_prioq, timeout_compare);
                if (r < 0)
                        return r;
        }

        c = new0(struct reply_callback, 1);
        if (!c)
                return -ENOMEM;

        c->callback = callback;
        c->userdata = userdata;
        c->timeout = calc_elapse(usec);

        k = sd_netlink_send(nl, m, &s);
        if (k < 0) {
                free(c);
                return k;
        }

        c->serial = s;

        r = hashmap_put(nl->reply_callbacks, &c->serial, c);
        if (r < 0) {
                free(c);
                return r;
        }

        if (c->timeout != 0) {
                r = prioq_put(nl->reply_callbacks_prioq, c, &c->prioq_idx);
                if (r > 0) {
                        c->timeout = 0;
                        sd_netlink_call_async_cancel(nl, c->serial);
                        return r;
                }
        }

        if (serial)
                *serial = s;

        return k;
}

int sd_netlink_call_async_cancel(sd_netlink *nl, uint32_t serial) {
        struct reply_callback *c;
        uint64_t s = serial;

        assert_return(nl, -EINVAL);
        assert_return(serial != 0, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);

        c = hashmap_remove(nl->reply_callbacks, &s);
        if (!c)
                return 0;

        if (c->timeout != 0)
                prioq_remove(nl->reply_callbacks_prioq, c, &c->prioq_idx);

        free(c);
        return 1;
}

int sd_netlink_call(sd_netlink *rtnl,
                sd_netlink_message *message,
                uint64_t usec,
                sd_netlink_message **ret) {
        usec_t timeout;
        uint32_t serial;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);
        assert_return(message, -EINVAL);

        r = sd_netlink_send(rtnl, message, &serial);
        if (r < 0)
                return r;

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;
                unsigned i;

                for (i = 0; i < rtnl->rqueue_size; i++) {
                        uint32_t received_serial;

                        received_serial = rtnl_message_get_serial(rtnl->rqueue[i]);

                        if (received_serial == serial) {
                                _cleanup_netlink_message_unref_ sd_netlink_message *incoming = NULL;
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

                                if (ret) {
                                        *ret = incoming;
                                        incoming = NULL;
                                }

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
                        left = (uint64_t) -1;

                r = rtnl_poll(rtnl, true, left);
                if (r < 0)
                        return r;
                else if (r == 0)
                        return -ETIMEDOUT;
        }
}

int sd_netlink_get_events(sd_netlink *rtnl) {
        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        if (rtnl->rqueue_size == 0)
                return POLLIN;
        else
                return 0;
}

int sd_netlink_get_timeout(sd_netlink *rtnl, uint64_t *timeout_usec) {
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
                *timeout_usec = (uint64_t) -1;
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

int sd_netlink_attach_event(sd_netlink *rtnl, sd_event *event, int priority) {
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

int sd_netlink_add_match(sd_netlink *rtnl,
                      uint16_t type,
                      sd_netlink_message_handler_t callback,
                      void *userdata) {
        _cleanup_free_ struct match_callback *c = NULL;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        c = new0(struct match_callback, 1);
        if (!c)
                return -ENOMEM;

        c->callback = callback;
        c->type = type;
        c->userdata = userdata;

        switch (type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        r = socket_join_broadcast_group(rtnl, RTNLGRP_LINK);
                        if (r < 0)
                                return r;

                        break;
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        r = socket_join_broadcast_group(rtnl, RTNLGRP_IPV4_IFADDR);
                        if (r < 0)
                                return r;

                        r = socket_join_broadcast_group(rtnl, RTNLGRP_IPV6_IFADDR);
                        if (r < 0)
                                return r;

                        break;
                default:
                        return -EOPNOTSUPP;
        }

        LIST_PREPEND(match_callbacks, rtnl->match_callbacks, c);

        c = NULL;

        return 0;
}

int sd_netlink_remove_match(sd_netlink *rtnl,
                         uint16_t type,
                         sd_netlink_message_handler_t callback,
                         void *userdata) {
        struct match_callback *c;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        /* we should unsubscribe from the broadcast groups at this point, but it is not so
           trivial for a few reasons: the refcounting is a bit of a mess and not obvious
           how it will look like after we add genetlink support, and it is also not possible
           to query what broadcast groups were subscribed to when we inherit the socket to get
           the initial refcount. The latter could indeed be done for the first 32 broadcast
           groups (which incidentally is all we currently support in .socket units anyway),
           but we better not rely on only ever using 32 groups. */
        LIST_FOREACH(match_callbacks, c, rtnl->match_callbacks)
                if (c->callback == callback && c->type == type && c->userdata == userdata) {
                        LIST_REMOVE(match_callbacks, rtnl->match_callbacks, c);
                        free(c);

                        return 1;
                }

        return 0;
}
