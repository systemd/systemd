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

#include "macro.h"
#include "util.h"

#include "sd-rtnl.h"
#include "rtnl-internal.h"
#include "rtnl-util.h"

static int sd_rtnl_new(sd_rtnl **ret) {
        sd_rtnl *rtnl;

        assert_return(ret, -EINVAL);

        rtnl = new0(sd_rtnl, 1);
        if (!rtnl)
                return -ENOMEM;

        rtnl->n_ref = REFCNT_INIT;

        rtnl->fd = -1;

        rtnl->sockaddr.nl.nl_family = AF_NETLINK;

        rtnl->original_pid = getpid();

        /* We guarantee that wqueue always has space for at least
         * one entry */
        rtnl->wqueue = new(sd_rtnl_message*, 1);
        if (!rtnl->wqueue) {
                free(rtnl);
                return -ENOMEM;
        }

        *ret = rtnl;
        return 0;
}

static bool rtnl_pid_changed(sd_rtnl *rtnl) {
        assert(rtnl);

        /* We don't support people creating an rtnl connection and
         * keeping it around over a fork(). Let's complain. */

        return rtnl->original_pid != getpid();
}

int sd_rtnl_open(uint32_t groups, sd_rtnl **ret) {
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;
        socklen_t addrlen;
        int r;

        r = sd_rtnl_new(&rtnl);
        if (r < 0)
                return r;

        rtnl->fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_ROUTE);
        if (rtnl->fd < 0)
                return -errno;

        rtnl->sockaddr.nl.nl_groups = groups;

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
        if (rtnl)
                assert_se(REFCNT_INC(rtnl->n_ref) >= 2);

        return rtnl;
}

sd_rtnl *sd_rtnl_unref(sd_rtnl *rtnl) {

        if (rtnl && REFCNT_DEC(rtnl->n_ref) <= 0) {
                unsigned i;

                for (i = 0; i < rtnl->rqueue_size; i++)
                        sd_rtnl_message_unref(rtnl->rqueue[i]);
                free(rtnl->rqueue);

                for (i = 0; i < rtnl->wqueue_size; i++)
                        sd_rtnl_message_unref(rtnl->wqueue[i]);
                free(rtnl->wqueue);

                if (rtnl->fd >= 0)
                        close_nointr_nofail(rtnl->fd);

                free(rtnl);
        }

        return NULL;
}

int sd_rtnl_send(sd_rtnl *nl,
                 sd_rtnl_message *message,
                 uint32_t *serial) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);

        r = message_seal(nl, message);
        if (r < 0)
                return r;

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
                sd_rtnl_message **q;

                /* append to queue */
                if (nl->wqueue_size >= RTNL_WQUEUE_MAX)
                        return -ENOBUFS;

                q = realloc(nl->wqueue, sizeof(sd_rtnl_message*) * (nl->wqueue_size + 1));
                if (!q)
                        return -ENOMEM;

                nl->wqueue = q;
                q[nl->wqueue_size ++] = sd_rtnl_message_ref(message);
        }

        if (serial)
                *serial = message_get_serial(message);

        return 1;
}

static int dispatch_rqueue(sd_rtnl *rtnl, sd_rtnl_message **message) {
        sd_rtnl_message *z = NULL;
        int r;

        assert(rtnl);
        assert(message);

        if (rtnl->rqueue_size > 0) {
                /* Dispatch a queued message */

                *message = rtnl->rqueue[0];
                rtnl->rqueue_size --;
                memmove(rtnl->rqueue, rtnl->rqueue + 1, sizeof(sd_rtnl_message*) * rtnl->rqueue_size);

                return 1;
        }

        /* Try to read a new message */
        r = socket_read_message(rtnl, &z);
        if (r < 0)
                return r;
        if (r == 0)
                return 0;

        *message = z;

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

static int process_running(sd_rtnl *rtnl, sd_rtnl_message **ret) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        int r;

        r = dispatch_wqueue(rtnl);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(rtnl, &m);
        if (r < 0)
                return r;
        if (!m)
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

static int rtnl_poll(sd_rtnl *nl, uint64_t timeout_usec) {
        struct pollfd p[1] = {};
        struct timespec ts;
        int r;

        assert(nl);

        p[0].fd = nl->fd;
        p[0].events = POLLIN;

        r = ppoll(p, 1, timeout_usec == (uint64_t) -1 ? NULL :
                        timespec_store(&ts, timeout_usec), NULL);
        if (r < 0)
                return -errno;

        return r > 0 ? 1 : 0;
}

int sd_rtnl_wait(sd_rtnl *nl, uint64_t timeout_usec) {
        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);

        if (nl->rqueue_size > 0)
                return 0;

        return rtnl_poll(nl, timeout_usec);
}

int sd_rtnl_call(sd_rtnl *nl,
                sd_rtnl_message *message,
                uint64_t usec,
                sd_rtnl_message **ret) {
        usec_t timeout;
        uint32_t serial;
        bool room = false;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(!rtnl_pid_changed(nl), -ECHILD);
        assert_return(message, -EINVAL);

        r = sd_rtnl_send(nl, message, &serial);
        if (r < 0)
                return r;

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;
                _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *incoming = NULL;

                if (!room) {
                        sd_rtnl_message **q;

                        if (nl->rqueue_size >= RTNL_RQUEUE_MAX)
                                return -ENOBUFS;

                        /* Make sure there's room for queueing this
                         * locally, before we read the message */

                        q = realloc(nl->rqueue, (nl->rqueue_size + 1) * sizeof(sd_rtnl_message*));
                        if (!q)
                                return -ENOMEM;

                        nl->rqueue = q;
                        room = true;
                }

                r = socket_read_message(nl, &incoming);
                if (r < 0)
                        return r;
                if (incoming) {
                        uint32_t received_serial = message_get_serial(incoming);

                        if (received_serial == serial) {
                                r = message_get_errno(incoming);
                                if (r < 0)
                                        return r;

                                if (ret) {
                                        *ret = incoming;
                                        incoming = NULL;
                                }

                                return 1;
                        }

                        /* Room was allocated on the queue above */
                        nl->rqueue[nl->rqueue_size ++] = incoming;
                        incoming = NULL;
                        room = false;

                        /* Try to read more, right away */
                        continue;
                }
                if (r != 0)
                        continue;

                if (timeout > 0) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        left = timeout - n;
                } else
                        left = (uint64_t) -1;

                r = rtnl_poll(nl, left);
                if (r < 0)
                        return r;

                r = dispatch_wqueue(nl);
                if (r < 0)
                        return r;
        }
}
