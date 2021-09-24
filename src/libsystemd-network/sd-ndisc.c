/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "ndisc-internal.h"
#include "ndisc-router.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"

#define NDISC_TIMEOUT_NO_RA_USEC (NDISC_ROUTER_SOLICITATION_INTERVAL * NDISC_MAX_ROUTER_SOLICITATIONS)

static const char * const ndisc_event_table[_SD_NDISC_EVENT_MAX] = {
        [SD_NDISC_EVENT_TIMEOUT] = "timeout",
        [SD_NDISC_EVENT_ROUTER] = "router",
};

DEFINE_STRING_TABLE_LOOKUP(ndisc_event, sd_ndisc_event_t);

static void ndisc_callback(sd_ndisc *ndisc, sd_ndisc_event_t event, sd_ndisc_router *rt) {
        assert(ndisc);
        assert(event >= 0 && event < _SD_NDISC_EVENT_MAX);

        if (!ndisc->callback)
                return (void) log_ndisc(ndisc, "Received '%s' event.", ndisc_event_to_string(event));

        log_ndisc(ndisc, "Invoking callback for '%s' event.", ndisc_event_to_string(event));
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

int sd_ndisc_set_ifname(sd_ndisc *nd, const char *ifname) {
        assert_return(nd, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&nd->ifname, ifname);
}

const char *sd_ndisc_get_ifname(sd_ndisc *nd) {
        if (!nd)
                return NULL;

        return get_ifname(nd->ifindex, &nd->ifname);
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

static void ndisc_reset(sd_ndisc *nd) {
        assert(nd);

        (void) event_source_disable(nd->timeout_event_source);
        (void) event_source_disable(nd->timeout_no_ra);
        nd->retransmit_time = 0;
        nd->recv_event_source = sd_event_source_disable_unref(nd->recv_event_source);
        nd->fd = safe_close(nd->fd);
}

static sd_ndisc *ndisc_free(sd_ndisc *nd) {
        assert(nd);

        ndisc_reset(nd);

        sd_event_source_unref(nd->timeout_event_source);
        sd_event_source_unref(nd->timeout_no_ra);
        sd_ndisc_detach_event(nd);

        free(nd->ifname);
        return mfree(nd);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_ndisc, sd_ndisc, ndisc_free);

_public_ int sd_ndisc_new(sd_ndisc **ret) {
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_return(ret, -EINVAL);

        nd = new(sd_ndisc, 1);
        if (!nd)
                return -ENOMEM;

        *nd = (sd_ndisc) {
                .n_ref = 1,
                .fd = -1,
        };

        *ret = TAKE_PTR(nd);

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

        r = ndisc_router_parse(nd, rt);
        if (r == -EBADMSG) /* Bad packet */
                return 0;
        if (r < 0)
                return 0;

        /* Update global variables we keep */
        if (rt->mtu > 0)
                nd->mtu = rt->mtu;
        if (rt->hop_limit > 0)
                nd->hop_limit = rt->hop_limit;

        log_ndisc(nd, "Received Router Advertisement: flags %s preference %s lifetime %" PRIu16 " sec",
                  rt->flags & ND_RA_FLAG_MANAGED ? "MANAGED" : rt->flags & ND_RA_FLAG_OTHER ? "OTHER" : "none",
                  rt->preference == SD_NDISC_PREFERENCE_HIGH ? "high" : rt->preference == SD_NDISC_PREFERENCE_LOW ? "low" : "medium",
                  rt->lifetime);

        ndisc_callback(nd, SD_NDISC_EVENT_ROUTER, rt);
        return 0;
}

static int ndisc_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(sd_ndisc_router_unrefp) sd_ndisc_router *rt = NULL;
        sd_ndisc *nd = userdata;
        ssize_t buflen;
        int r;
        _cleanup_free_ char *addr = NULL;

        assert(s);
        assert(nd);
        assert(nd->event);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0) {
                log_ndisc_errno(nd, buflen, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        rt = ndisc_router_new(buflen);
        if (!rt)
                return -ENOMEM;

        r = icmp6_receive(fd, NDISC_ROUTER_RAW(rt), rt->raw_size, &rt->address, &rt->timestamp);
        if (r < 0) {
                switch (r) {
                case -EADDRNOTAVAIL:
                        (void) in_addr_to_string(AF_INET6, (const union in_addr_union*) &rt->address, &addr);
                        log_ndisc(nd, "Received RA from non-link-local address %s. Ignoring", addr);
                        break;

                case -EMULTIHOP:
                        log_ndisc(nd, "Received RA with invalid hop limit. Ignoring.");
                        break;

                case -EPFNOSUPPORT:
                        log_ndisc(nd, "Received invalid source address from ICMPv6 socket. Ignoring.");
                        break;

                case -EAGAIN: /* ignore spurious wakeups */
                        break;

                default:
                        log_ndisc_errno(nd, r, "Unexpected error while reading from ICMPv6, ignoring: %m");
                        break;
                }

                return 0;
        }

        (void) event_source_disable(nd->timeout_event_source);

        return ndisc_handle_datagram(nd, rt);
}

static usec_t ndisc_timeout_compute_random(usec_t val) {
        /* compute a time that is random within ±10% of the given value */
        return val - val / 10 +
                (random_u64() % (2 * USEC_PER_SEC)) * val / 10 / USEC_PER_SEC;
}

static int ndisc_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        char time_string[FORMAT_TIMESPAN_MAX];
        sd_ndisc *nd = userdata;
        usec_t time_now;
        int r;

        assert(s);
        assert(nd);
        assert(nd->event);

        assert_se(sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        if (!nd->retransmit_time)
                nd->retransmit_time = ndisc_timeout_compute_random(NDISC_ROUTER_SOLICITATION_INTERVAL);
        else {
                if (nd->retransmit_time > NDISC_MAX_ROUTER_SOLICITATION_INTERVAL / 2)
                        nd->retransmit_time = ndisc_timeout_compute_random(NDISC_MAX_ROUTER_SOLICITATION_INTERVAL);
                else
                        nd->retransmit_time += ndisc_timeout_compute_random(nd->retransmit_time);
        }

        r = event_reset_time(nd->event, &nd->timeout_event_source,
                             clock_boottime_or_monotonic(),
                             time_now + nd->retransmit_time, 10 * USEC_PER_MSEC,
                             ndisc_timeout, nd,
                             nd->event_priority, "ndisc-timeout-no-ra", true);
        if (r < 0)
                goto fail;

        r = icmp6_send_router_solicitation(nd->fd, &nd->mac_addr);
        if (r < 0) {
                log_ndisc_errno(nd, r, "Error sending Router Solicitation: %m");
                goto fail;
        }

        log_ndisc(nd, "Sent Router Solicitation, next solicitation in %s",
                  format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                                  nd->retransmit_time, USEC_PER_SEC));

        return 0;

fail:
        (void) sd_ndisc_stop(nd);
        return 0;
}

static int ndisc_timeout_no_ra(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ndisc *nd = userdata;

        assert(s);
        assert(nd);

        log_ndisc(nd, "No RA received before link confirmation timeout");

        (void) event_source_disable(nd->timeout_no_ra);
        ndisc_callback(nd, SD_NDISC_EVENT_TIMEOUT, NULL);

        return 0;
}

_public_ int sd_ndisc_stop(sd_ndisc *nd) {
        if (!nd)
                return 0;

        if (nd->fd < 0)
                return 0;

        log_ndisc(nd, "Stopping IPv6 Router Solicitation client");

        ndisc_reset(nd);
        return 1;
}

_public_ int sd_ndisc_start(sd_ndisc *nd) {
        int r;
        usec_t time_now;

        assert_return(nd, -EINVAL);
        assert_return(nd->event, -EINVAL);
        assert_return(nd->ifindex > 0, -EINVAL);

        if (nd->fd >= 0)
                return 0;

        assert(!nd->recv_event_source);

        r = sd_event_now(nd->event, clock_boottime_or_monotonic(), &time_now);
        if (r < 0)
                goto fail;

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

        r = event_reset_time(nd->event, &nd->timeout_event_source,
                             clock_boottime_or_monotonic(),
                             time_now + USEC_PER_SEC / 2, 1 * USEC_PER_SEC, /* See RFC 8415 sec. 18.2.1 */
                             ndisc_timeout, nd,
                             nd->event_priority, "ndisc-timeout", true);
        if (r < 0)
                goto fail;

        r = event_reset_time(nd->event, &nd->timeout_no_ra,
                             clock_boottime_or_monotonic(),
                             time_now + NDISC_TIMEOUT_NO_RA_USEC, 10 * USEC_PER_MSEC,
                             ndisc_timeout_no_ra, nd,
                             nd->event_priority, "ndisc-timeout-no-ra", true);
        if (r < 0)
                goto fail;

        log_ndisc(nd, "Started IPv6 Router Solicitation client");
        return 1;

fail:
        ndisc_reset(nd);
        return r;
}
