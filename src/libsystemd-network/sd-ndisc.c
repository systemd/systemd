/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "ndisc-internal.h"
#include "ndisc-router.h"
#include "socket-util.h"
#include "string-util.h"
#include "util.h"

#define NDISC_ROUTER_SOLICITATION_INTERVAL (4U * USEC_PER_SEC)
#define NDISC_MAX_ROUTER_SOLICITATIONS 3U

static void ndisc_callback(sd_ndisc *ndisc, sd_ndisc_event event, sd_ndisc_router *rt) {
        assert(ndisc);

        log_ndisc("Invoking callback for '%c'.", event);

        if (!ndisc->callback)
                return;

        ndisc->callback(ndisc, event, rt, ndisc->userdata);
}

_public_ int sd_ndisc_set_callback(
                sd_ndisc *nd,
                sd_ndisc_callback_t callback,
                void *userdata) {

        assert_return(nd, -EINVAL);

        nd->callback = callback;
        nd->userdata = userdata;

        return 0;
}

_public_ int sd_ndisc_set_ifindex(sd_ndisc *nd, int ifindex) {
        assert_return(nd, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(nd->fd < 0, -EBUSY);

        nd->ifindex = ifindex;
        return 0;
}

_public_ int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr) {
        assert_return(nd, -EINVAL);

        if (mac_addr)
                nd->mac_addr = *mac_addr;
        else
                zero(nd->mac_addr);

        return 0;
}

_public_ int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int64_t priority) {
        int r;

        assert_return(nd, -EINVAL);
        assert_return(nd->fd < 0, -EBUSY);
        assert_return(!nd->event, -EBUSY);

        if (event)
                nd->event = sd_event_ref(event);
        else {
                r = sd_event_default(&nd->event);
                if (r < 0)
                        return 0;
        }

        nd->event_priority = priority;

        return 0;
}

_public_ int sd_ndisc_detach_event(sd_ndisc *nd) {

        assert_return(nd, -EINVAL);
        assert_return(nd->fd < 0, -EBUSY);

        nd->event = sd_event_unref(nd->event);
        return 0;
}

_public_ sd_event *sd_ndisc_get_event(sd_ndisc *nd) {
        assert_return(nd, NULL);

        return nd->event;
}

_public_ sd_ndisc *sd_ndisc_ref(sd_ndisc *nd) {

        if (!nd)
                return NULL;

        assert(nd->n_ref > 0);
        nd->n_ref++;

        return nd;
}

static int ndisc_reset(sd_ndisc *nd) {
        assert(nd);

        nd->timeout_event_source = sd_event_source_unref(nd->timeout_event_source);
        nd->recv_event_source = sd_event_source_unref(nd->recv_event_source);
        nd->fd = safe_close(nd->fd);

        return 0;
}

_public_ sd_ndisc *sd_ndisc_unref(sd_ndisc *nd) {

        if (!nd)
                return NULL;

        assert(nd->n_ref > 0);
        nd->n_ref--;

        if (nd->n_ref > 0)
                return NULL;

        ndisc_reset(nd);
        sd_ndisc_detach_event(nd);
        free(nd);

        return NULL;
}

_public_ int sd_ndisc_new(sd_ndisc **ret) {
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_return(ret, -EINVAL);

        nd = new0(sd_ndisc, 1);
        if (!nd)
                return -ENOMEM;

        nd->n_ref = 1;
        nd->fd = -1;

        *ret = nd;
        nd = NULL;

        return 0;
}

_public_ int sd_ndisc_get_mtu(sd_ndisc *nd, uint32_t *mtu) {
        assert_return(nd, -EINVAL);
        assert_return(mtu, -EINVAL);

        if (nd->mtu == 0)
                return -ENODATA;

        *mtu = nd->mtu;
        return 0;
}

_public_ int sd_ndisc_get_hop_limit(sd_ndisc *nd, uint8_t *ret) {
        assert_return(nd, -EINVAL);
        assert_return(ret, -EINVAL);

        if (nd->hop_limit == 0)
                return -ENODATA;

        *ret = nd->hop_limit;
        return 0;
}

static int ndisc_handle_datagram(sd_ndisc *nd, sd_ndisc_router *rt) {
        int r;

        assert(nd);
        assert(rt);

        r = ndisc_router_parse(rt);
        if (r == -EBADMSG) /* Bad packet */
                return 0;
        if (r < 0)
                return 0;

        /* Update global variables we keep */
        if (rt->mtu > 0)
                nd->mtu = rt->mtu;
        if (rt->hop_limit > 0)
                nd->hop_limit = rt->hop_limit;

        log_ndisc("Received Router Advertisement: flags %s preference %s lifetime %" PRIu16 " sec",
                  rt->flags & ND_RA_FLAG_MANAGED ? "MANAGED" : rt->flags & ND_RA_FLAG_OTHER ? "OTHER" : "none",
                  rt->preference == SD_NDISC_PREFERENCE_HIGH ? "high" : rt->preference == SD_NDISC_PREFERENCE_LOW ? "low" : "medium",
                  rt->lifetime);

        ndisc_callback(nd, SD_NDISC_EVENT_ROUTER, rt);
        return 0;
}

static int ndisc_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_ndisc_router_unrefp) sd_ndisc_router *rt = NULL;
        sd_ndisc *nd = userdata;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int)) + /* ttl */
                            CMSG_SPACE(sizeof(struct timeval))];
        } control = {};
        struct iovec iov = {};
        union sockaddr_union sa = {};
        struct msghdr msg = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t len, buflen;

        assert(s);
        assert(nd);
        assert(nd->event);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return log_ndisc_errno(buflen, "Failed to determine datagram size to read: %m");

        rt = ndisc_router_new(buflen);
        if (!rt)
                return -ENOMEM;

        iov.iov_base = NDISC_ROUTER_RAW(rt);
        iov.iov_len = rt->raw_size;

        len = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return log_ndisc_errno(errno, "Could not receive message from ICMPv6 socket: %m");
        }

        if ((size_t) len != rt->raw_size) {
                log_ndisc("Packet size mismatch.");
                return -EINVAL;
        }

        if (msg.msg_namelen == sizeof(struct sockaddr_in6) &&
            sa.in6.sin6_family == AF_INET6)  {

                if (in_addr_is_link_local(AF_INET6, (union in_addr_union*) &sa.in6.sin6_addr) <= 0) {
                        _cleanup_free_ char *addr = NULL;

                        (void) in_addr_to_string(AF_INET6, (union in_addr_union*) &sa.in6.sin6_addr, &addr);
                        log_ndisc("Received RA from non-link-local address %s. Ignoring.", strna(addr));
                        return 0;
                }

                rt->address = sa.in6.sin6_addr;

        } else if (msg.msg_namelen > 0) {
                log_ndisc("Received invalid source address size from ICMPv6 socket: %zu bytes", (size_t) msg.msg_namelen);
                return -EINVAL;
        }

        /* namelen == 0 only happens when running the test-suite over a socketpair */

        assert(!(msg.msg_flags & MSG_CTRUNC));
        assert(!(msg.msg_flags & MSG_TRUNC));

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == SOL_IPV6 &&
                    cmsg->cmsg_type == IPV6_HOPLIMIT &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
                        int hops = *(int*) CMSG_DATA(cmsg);

                        if (hops != 255) {
                                log_ndisc("Received RA with invalid hop limit %d. Ignoring.", hops);
                                return 0;
                        }
                }

                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SO_TIMESTAMP &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval)))
                        triple_timestamp_from_realtime(&rt->timestamp, timeval_load((struct timeval*) CMSG_DATA(cmsg)));
        }

        if (!triple_timestamp_is_set(&rt->timestamp))
                triple_timestamp_get(&rt->timestamp);

        nd->timeout_event_source = sd_event_source_unref(nd->timeout_event_source);

        return ndisc_handle_datagram(nd, rt);
}

static int ndisc_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ndisc *nd = userdata;
        usec_t time_now, next_timeout;
        int r;

        assert(s);
        assert(nd);
        assert(nd->event);

        if (nd->nd_sent >= NDISC_MAX_ROUTER_SOLICITATIONS) {
                nd->timeout_event_source = sd_event_source_unref(nd->timeout_event_source);
                ndisc_callback(nd, SD_NDISC_EVENT_TIMEOUT, NULL);
                return 0;
        }

        r = icmp6_send_router_solicitation(nd->fd, &nd->mac_addr);
        if (r < 0) {
                log_ndisc_errno(r, "Error sending Router Solicitation: %m");
                goto fail;
        }

        log_ndisc("Sent Router Solicitation");
        nd->nd_sent++;

        assert_se(sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now) >= 0);
        next_timeout = time_now + NDISC_ROUTER_SOLICITATION_INTERVAL;

        r = sd_event_source_set_time(nd->timeout_event_source, next_timeout);
        if (r < 0) {
                log_ndisc_errno(r, "Error updating timer: %m");
                goto fail;
        }

        r = sd_event_source_set_enabled(nd->timeout_event_source, SD_EVENT_ONESHOT);
        if (r < 0) {
                log_ndisc_errno(r, "Error reenabling timer: %m");
                goto fail;
        }

        return 0;

fail:
        sd_ndisc_stop(nd);
        return 0;
}

_public_ int sd_ndisc_stop(sd_ndisc *nd) {
        assert_return(nd, -EINVAL);

        if (nd->fd < 0)
                return 0;

        log_ndisc("Stopping IPv6 Router Solicitation client");

        ndisc_reset(nd);
        return 1;
}

_public_ int sd_ndisc_start(sd_ndisc *nd) {
        int r;

        assert_return(nd, -EINVAL);
        assert_return(nd->event, -EINVAL);
        assert_return(nd->ifindex > 0, -EINVAL);

        if (nd->fd >= 0)
                return 0;

        assert(!nd->recv_event_source);
        assert(!nd->timeout_event_source);

        nd->fd = icmp6_bind_router_solicitation(nd->ifindex);
        if (nd->fd < 0)
                return nd->fd;

        r = sd_event_add_io(nd->event, &nd->recv_event_source, nd->fd, EPOLLIN, ndisc_recv, nd);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(nd->recv_event_source, nd->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(nd->recv_event_source, "ndisc-receive-message");

        r = sd_event_add_time(nd->event, &nd->timeout_event_source, clock_boottime_or_monotonic(), 0, 0, ndisc_timeout, nd);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(nd->timeout_event_source, nd->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(nd->timeout_event_source, "ndisc-timeout");

        log_ndisc("Started IPv6 Router Solicitation client");
        return 1;

fail:
        ndisc_reset(nd);
        return r;
}
