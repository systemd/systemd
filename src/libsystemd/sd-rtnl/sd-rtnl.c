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

#include "sd-rtnl.h"
#include "rtnl-internal.h"
#include "rtnl-util.h"

static int sd_rtnl_new(sd_rtnl **ret) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;

        assert_return(ret, -EINVAL);

        rtnl = new0(sd_rtnl, 1);
        if (!rtnl)
                return -ENOMEM;

        rtnl->n_ref = REFCNT_INIT;

        rtnl->fd = -1;

        rtnl->sockaddr.nl.nl_family = AF_NETLINK;

        rtnl->original_pid = getpid();

        LIST_HEAD_INIT(rtnl->match_callbacks);

        /* We guarantee that wqueue always has space for at least
         * one entry */
        if (!GREEDY_REALLOC(rtnl->wqueue, rtnl->wqueue_allocated, 1))
                return -ENOMEM;

        /* We guarantee that the read buffer has at least space for
         * a message header */
        if (!greedy_realloc((void**)&rtnl->rbuffer, &rtnl->rbuffer_allocated,
                            sizeof(struct nlmsghdr), sizeof(uint8_t)))
                return -ENOMEM;

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

static bool rtnl_pid_changed(sd_rtnl *rtnl) {
        assert(rtnl);

        /* We don't support people creating an rtnl connection and
         * keeping it around over a fork(). Let's complain. */

        return rtnl->original_pid != getpid();
}

static int rtnl_compute_groups_ap(uint32_t *_groups, unsigned n_groups, va_list ap) {
        uint32_t groups = 0;
        unsigned i;

        for (i = 0; i < n_groups; i++) {
                unsigned group;

                group = va_arg(ap, unsigned);
                assert_return(group < 32, -EINVAL);

                groups |= group ? (1 << (group - 1)) : 0;
        }

        *_groups = groups;

        return 0;
}

int sd_rtnl_open(sd_rtnl **ret, unsigned n_groups, ...) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        va_list ap;
        socklen_t addrlen;
        int r, one = 1;

        assert_return(ret, -EINVAL);

        r = sd_rtnl_new(&rtnl);
        if (r < 0)
                return r;

        rtnl->fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_ROUTE);
        if (rtnl->fd < 0)
                return -errno;

        r = setsockopt(rtnl->fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return -errno;

        r = setsockopt(rtnl->fd, SOL_NETLINK, NETLINK_PKTINFO, &one, sizeof(one));
        if (r < 0)
                return -errno;

        va_start(ap, n_groups);
        r = rtnl_compute_groups_ap(&rtnl->sockaddr.nl.nl_groups, n_groups, ap);
        va_end(ap);
        if (r < 0)
                return r;

        addrlen = sizeof(rtnl->sockaddr);

        r = bind(rtnl->fd, &rtnl->sockaddr.sa, addrlen);
        if (r < 0)
                return -errno;

        r = getsockname(rtnl->fd, &rtnl->sockaddr.sa, &addrlen);
        if (r < 0)
                return r;

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

sd_rtnl *sd_rtnl_ref(sd_rtnl *rtnl) {
        assert_return(rtnl, NULL);
        assert_return(!rtnl_pid_changed(rtnl), NULL);

        if (rtnl)
                assert_se(REFCNT_INC(rtnl->n_ref) >= 2);

        return rtnl;
}

sd_rtnl *sd_rtnl_unref(sd_rtnl *rtnl) {
        if (!rtnl)
                return NULL;

        assert_return(!rtnl_pid_changed(rtnl), NULL);

        if (REFCNT_DEC(rtnl->n_ref) <= 0) {
                struct match_callback *f;
                unsigned i;

                for (i = 0; i < rtnl->rqueue_size; i++)
                        sd_rtnl_message_unref(rtnl->rqueue[i]);
                free(rtnl->rqueue);

                for (i = 0; i < rtnl->rqueue_partial_size; i++)
                        sd_rtnl_message_unref(rtnl->rqueue_partial[i]);
                free(rtnl->rqueue_partial);

                for (i = 0; i < rtnl->wqueue_size; i++)
                        sd_rtnl_message_unref(rtnl->wqueue[i]);
                free(rtnl->wqueue);

                free(rtnl->rbuffer);

                hashmap_free_free(rtnl->reply_callbacks);
                prioq_free(rtnl->reply_callbacks_prioq);

                sd_event_source_unref(rtnl->io_event_source);
                sd_event_source_unref(rtnl->time_event_source);
                sd_event_source_unref(rtnl->exit_event_source);
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

static void rtnl_seal_message(sd_rtnl *rtnl, sd_rtnl_message *m) {
        assert(rtnl);
        assert(!rtnl_pid_changed(rtnl));
        assert(m);
        assert(m->hdr);

        m->hdr->nlmsg_seq = rtnl->serial++;

        rtnl_message_seal(m);

        return;
}

int sd_rtnl_send(sd_rtnl *nl,
                 sd_rtnl_message *message,
                 uint32_t *serial) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);
        assert_return(!message->sealed, -EPERM);

        rtnl_seal_message(nl, message);

        if (nl->wqueue_size <= 0) {
                /* send directly */
                r = socket_write_message(nl, message);
                if (r < 0)
                        return r;
                else if (r == 0) {
                        /* nothing was sent, so let's put it on
                         * the queue */
                        nl->wqueue[0] = sd_rtnl_message_ref(message);
                        nl->wqueue_size = 1;
                }
        } else {
                /* append to queue */
                if (nl->wqueue_size >= RTNL_WQUEUE_MAX) {
                        log_debug("rtnl: exhausted the write queue size (%d)", RTNL_WQUEUE_MAX);
                        return -ENOBUFS;
                }

                if (!GREEDY_REALLOC(nl->wqueue, nl->wqueue_allocated, nl->wqueue_size + 1))
                        return -ENOMEM;

                nl->wqueue[nl->wqueue_size ++] = sd_rtnl_message_ref(message);
        }

        if (serial)
                *serial = rtnl_message_get_serial(message);

        return 1;
}

int rtnl_rqueue_make_room(sd_rtnl *rtnl) {
        assert(rtnl);

        if (rtnl->rqueue_size >= RTNL_RQUEUE_MAX) {
                log_debug("rtnl: exhausted the read queue size (%d)", RTNL_RQUEUE_MAX);
                return -ENOBUFS;
        }

        if (!GREEDY_REALLOC(rtnl->rqueue, rtnl->rqueue_allocated, rtnl->rqueue_size + 1))
                return -ENOMEM;

        return 0;
}

int rtnl_rqueue_partial_make_room(sd_rtnl *rtnl) {
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

static int dispatch_rqueue(sd_rtnl *rtnl, sd_rtnl_message **message) {
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
        memmove(rtnl->rqueue, rtnl->rqueue + 1, sizeof(sd_rtnl_message*) * rtnl->rqueue_size);

        return 1;
}

static int dispatch_wqueue(sd_rtnl *rtnl) {
        int r, ret = 0;

        assert(rtnl);

        while (rtnl->wqueue_size > 0) {
                r = socket_write_message(rtnl, rtnl->wqueue[0]);
                if (r < 0)
                        return r;
                else if (r == 0)
                        /* Didn't do anything this time */
                        return ret;
                else {
                        /* see equivalent in sd-bus.c */
                        sd_rtnl_message_unref(rtnl->wqueue[0]);
                        rtnl->wqueue_size --;
                        memmove(rtnl->wqueue, rtnl->wqueue + 1, sizeof(sd_rtnl_message*) * rtnl->wqueue_size);

                        ret = 1;
                }
        }

        return ret;
}

static int process_timeout(sd_rtnl *rtnl) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
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
        free(c);

        return r < 0 ? r : 1;
}

static int process_reply(sd_rtnl *rtnl, sd_rtnl_message *m) {
        struct reply_callback *c;
        uint64_t serial;
        int r;

        assert(rtnl);
        assert(m);

        if (sd_rtnl_message_is_broadcast(m))
                return 0;

        serial = rtnl_message_get_serial(m);
        c = hashmap_remove(rtnl->reply_callbacks, &serial);
        if (!c)
                return 0;

        if (c->timeout != 0)
                prioq_remove(rtnl->reply_callbacks_prioq, c, &c->prioq_idx);

        r = c->callback(rtnl, m, c->userdata);
        free(c);

        return r;
}

static int process_match(sd_rtnl *rtnl, sd_rtnl_message *m) {
        struct match_callback *c;
        uint16_t type;
        int r;

        assert(rtnl);
        assert(m);

        r = sd_rtnl_message_get_type(m, &type);
        if (r < 0)
                return r;

        LIST_FOREACH(match_callbacks, c, rtnl->match_callbacks) {
                if (type == c->type) {
                        r = c->callback(rtnl, m, c->userdata);
                        if (r != 0)
                                return r;
                }
        }

        return 0;
}

static int process_running(sd_rtnl *rtnl, sd_rtnl_message **ret) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        int r;

        assert(rtnl);

        r = process_timeout(rtnl);
        if (r != 0)
                goto null_message;

        r = dispatch_wqueue(rtnl);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(rtnl, &m);
        if (r < 0)
                return r;
        if (!m)
                goto null_message;

        r = process_reply(rtnl, m);
        if (r != 0)
                goto null_message;

        r = process_match(rtnl, m);
        if (r != 0)
                goto null_message;

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

int sd_rtnl_process(sd_rtnl *rtnl, sd_rtnl_message **ret) {
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

static int rtnl_poll(sd_rtnl *rtnl, bool need_more, uint64_t timeout_usec) {
        struct pollfd p[1] = {};
        struct timespec ts;
        usec_t m = (usec_t) -1;
        int r, e;

        assert(rtnl);

        e = sd_rtnl_get_events(rtnl);
        if (e < 0)
                return e;

        if (need_more)
                /* Caller wants more data, and doesn't care about
                 * what's been read or any other timeouts. */
                return e |= POLLIN;
        else {
                usec_t until;
                /* Caller wants to process if there is something to
                 * process, but doesn't care otherwise */

                r = sd_rtnl_get_timeout(rtnl, &until);
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

int sd_rtnl_wait(sd_rtnl *nl, uint64_t timeout_usec) {
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

int sd_rtnl_call_async(sd_rtnl *nl,
                       sd_rtnl_message *m,
                       sd_rtnl_message_handler_t callback,
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

        r = hashmap_ensure_allocated(&nl->reply_callbacks, uint64_hash_func, uint64_compare_func);
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

        k = sd_rtnl_send(nl, m, &s);
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
                        sd_rtnl_call_async_cancel(nl, c->serial);
                        return r;
                }
        }

        if (serial)
                *serial = s;

        return k;
}

int sd_rtnl_call_async_cancel(sd_rtnl *nl, uint32_t serial) {
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

int sd_rtnl_call(sd_rtnl *rtnl,
                sd_rtnl_message *message,
                uint64_t usec,
                sd_rtnl_message **ret) {
        usec_t timeout;
        uint32_t serial;
        unsigned i = 0;
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);
        assert_return(message, -EINVAL);

        r = sd_rtnl_send(rtnl, message, &serial);
        if (r < 0)
                return r;

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;

                while (i < rtnl->rqueue_size) {
                        sd_rtnl_message *incoming;
                        uint32_t received_serial;

                        incoming = rtnl->rqueue[i];
                        received_serial = rtnl_message_get_serial(incoming);

                        if (received_serial == serial) {
                                /* found a match, remove from rqueue and return it */
                                memmove(rtnl->rqueue + i,rtnl->rqueue + i + 1,
                                        sizeof(sd_rtnl_message*) * (rtnl->rqueue_size - i - 1));
                                rtnl->rqueue_size--;

                                r = sd_rtnl_message_get_errno(incoming);
                                if (r < 0) {
                                        sd_rtnl_message_unref(incoming);
                                        return r;
                                }

                                if (ret) {
                                        *ret = incoming;
                                } else
                                        sd_rtnl_message_unref(incoming);

                                return 1;
                        }

                        /* Try to read more, right away */
                        i ++;
                }

                r = socket_read_message(rtnl);
                if (r < 0)
                        return r;
                if (r > 0)
                        /* receieved message, so try to process straight away */
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

                r = dispatch_wqueue(rtnl);
                if (r < 0)
                        return r;
        }
}

int sd_rtnl_flush(sd_rtnl *rtnl) {
        int r;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        if (rtnl->wqueue_size <= 0)
                return 0;

        for (;;) {
                r = dispatch_wqueue(rtnl);
                if (r < 0)
                        return r;

                if (rtnl->wqueue_size <= 0)
                        return 0;

                r = rtnl_poll(rtnl, false, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

int sd_rtnl_get_events(sd_rtnl *rtnl) {
        int flags = 0;

        assert_return(rtnl, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        if (rtnl->rqueue_size <= 0)
                flags |= POLLIN;
        if (rtnl->wqueue_size > 0)
                flags |= POLLOUT;

        return flags;
}

int sd_rtnl_get_timeout(sd_rtnl *rtnl, uint64_t *timeout_usec) {
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
        sd_rtnl *rtnl = userdata;
        int r;

        assert(rtnl);

        r = sd_rtnl_process(rtnl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_rtnl *rtnl = userdata;
        int r;

        assert(rtnl);

        r = sd_rtnl_process(rtnl, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_rtnl *rtnl = userdata;
        int r, e;
        usec_t until;

        assert(s);
        assert(rtnl);

        e = sd_rtnl_get_events(rtnl);
        if (e < 0)
                return e;

        r = sd_event_source_set_io_events(rtnl->io_event_source, e);
        if (r < 0)
                return r;

        r = sd_rtnl_get_timeout(rtnl, &until);
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

static int exit_callback(sd_event_source *event, void *userdata) {
        sd_rtnl *rtnl = userdata;

        assert(event);

        sd_rtnl_flush(rtnl);

        return 1;
}

int sd_rtnl_attach_event(sd_rtnl *rtnl, sd_event *event, int priority) {
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

        r = sd_event_source_set_prepare(rtnl->io_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_add_time(rtnl->event, &rtnl->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, rtnl);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(rtnl->time_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_add_exit(rtnl->event, &rtnl->exit_event_source, exit_callback, rtnl);
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_rtnl_detach_event(rtnl);
        return r;
}

int sd_rtnl_detach_event(sd_rtnl *rtnl) {
        assert_return(rtnl, -EINVAL);
        assert_return(rtnl->event, -ENXIO);

        if (rtnl->io_event_source)
                rtnl->io_event_source = sd_event_source_unref(rtnl->io_event_source);

        if (rtnl->time_event_source)
                rtnl->time_event_source = sd_event_source_unref(rtnl->time_event_source);

        if (rtnl->exit_event_source)
                rtnl->exit_event_source = sd_event_source_unref(rtnl->exit_event_source);

        if (rtnl->event)
                rtnl->event = sd_event_unref(rtnl->event);

        return 0;
}

int sd_rtnl_add_match(sd_rtnl *rtnl,
                      uint16_t type,
                      sd_rtnl_message_handler_t callback,
                      void *userdata) {
        struct match_callback *c;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);
        assert_return(rtnl_message_type_is_link(type) ||
                      rtnl_message_type_is_addr(type) ||
                      rtnl_message_type_is_route(type), -ENOTSUP);

        c = new0(struct match_callback, 1);
        if (!c)
                return -ENOMEM;

        c->callback = callback;
        c->type = type;
        c->userdata = userdata;

        LIST_PREPEND(match_callbacks, rtnl->match_callbacks, c);

        return 0;
}

int sd_rtnl_remove_match(sd_rtnl *rtnl,
                         uint16_t type,
                         sd_rtnl_message_handler_t callback,
                         void *userdata) {
        struct match_callback *c;

        assert_return(rtnl, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(!rtnl_pid_changed(rtnl), -ECHILD);

        LIST_FOREACH(match_callbacks, c, rtnl->match_callbacks)
                if (c->callback == callback && c->type == type && c->userdata == userdata) {
                        LIST_REMOVE(match_callbacks, rtnl->match_callbacks, c);
                        free(c);

                        return 1;
                }

        return 0;
}
