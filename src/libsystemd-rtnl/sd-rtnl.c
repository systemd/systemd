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

static int sd_rtnl_new(sd_rtnl **ret) {
        sd_rtnl *rtnl;

        assert_return(ret, -EINVAL);

        rtnl = new0(sd_rtnl, 1);
        if (!rtnl)
                return -ENOMEM;

        rtnl->n_ref = REFCNT_INIT;

        rtnl->fd = -1;

        rtnl->sockaddr.nl.nl_family = AF_NETLINK;

        *ret = rtnl;
        return 0;
}

int sd_rtnl_open(uint32_t groups, sd_rtnl **ret) {
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;
        int r;

        r = sd_rtnl_new(&rtnl);
        if (r < 0)
                return r;

        rtnl->fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_ROUTE);
        if (rtnl->fd < 0)
                return -errno;

        rtnl->sockaddr.nl.nl_groups = groups;

        r = bind(rtnl->fd, &rtnl->sockaddr.sa, sizeof(rtnl->sockaddr));
        if (r < 0)
                return -errno;

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
                if (rtnl->fd >= 0)
                        close_nointr_nofail(rtnl->fd);
                free(rtnl);
        }

        return NULL;
}

int sd_rtnl_send_with_reply_and_block(sd_rtnl *nl,
                sd_rtnl_message *message,
                uint64_t usec,
                sd_rtnl_message **ret) {
        struct pollfd p[1] = {};
        struct timespec left;
        usec_t timeout;
        int r, serial;

        assert_return(nl, -EINVAL);
        assert_return(message, -EINVAL);

        r = message_seal(nl, message);
        if (r < 0)
                return r;

        serial = message_get_serial(message);

        p[0].fd = nl->fd;
        p[0].events = POLLOUT;

        if (usec == (uint64_t) -1)
                timeout = 0;
        else if (usec == 0)
                timeout = now(CLOCK_MONOTONIC) + RTNL_DEFAULT_TIMEOUT;
        else
                timeout = now(CLOCK_MONOTONIC) + usec;

        for (;;) {
                if (timeout) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        timespec_store(&left, timeout - n);
                }

                r = ppoll(p, 1, timeout ? &left : NULL, NULL);
                if (r < 0)
                        return 0;

                r = socket_write_message(nl, message);
                if (r < 0)
                        return r;

                if (r > 0) {
                        break;
                }
        }

        p[0].events = POLLIN;

        for (;;) {
                _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *reply = NULL;

                if (timeout) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        timespec_store(&left, timeout - n);
                }

                r = ppoll(p, 1, timeout ? &left : NULL, NULL);
                if (r < 0)
                        return r;

                r = socket_read_message(nl, &reply);
                if (r < 0)
                        return r;

                if (r > 0) {
                        int received_serial = message_get_serial(reply);

                        if (received_serial == serial) {
                                r = message_get_errno(reply);
                                if (r < 0)
                                        return r;

                                if (ret) {
                                        *ret = reply;
                                        reply = NULL;
                                }

                                break;;
                        }
                }
        }

        return 0;
}
