/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "sd-ndisc.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "icmp6-util.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "ndisc-internal.h"
#include "ndisc-neighbor-internal.h"
#include "ndisc-redirect-internal.h"
#include "ndisc-router-internal.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"

#define NDISC_TIMEOUT_NO_RA_USEC (NDISC_ROUTER_SOLICITATION_INTERVAL * NDISC_MAX_ROUTER_SOLICITATIONS)

static const char * const ndisc_event_table[_SD_NDISC_EVENT_MAX] = {
        [SD_NDISC_EVENT_TIMEOUT]  = "timeout",
        [SD_NDISC_EVENT_ROUTER]   = "router",
        [SD_NDISC_EVENT_NEIGHBOR] = "neighbor",
        [SD_NDISC_EVENT_REDIRECT] = "redirect",
};

DEFINE_STRING_TABLE_LOOKUP(ndisc_event, sd_ndisc_event_t);

static void ndisc_callback(sd_ndisc *ndisc, sd_ndisc_event_t event, void *message) {
        assert(ndisc);
        assert(event >= 0 && event < _SD_NDISC_EVENT_MAX);

        if (!ndisc->callback)
                return (void) log_ndisc(ndisc, "Received '%s' event.", ndisc_event_to_string(event));

        log_ndisc(ndisc, "Invoking callback for '%s' event.", ndisc_event_to_string(event));
        ndisc->callback(ndisc, event, message, ndisc->userdata);
}

int sd_ndisc_is_running(sd_ndisc *nd) {
        if (!nd)
                return false;

        return sd_event_source_get_enabled(nd->recv_event_source, NULL) > 0;
}

int sd_ndisc_set_callback(
                sd_ndisc *nd,
                sd_ndisc_callback_t callback,
                void *userdata) {

        assert_return(nd, -EINVAL);

        nd->callback = callback;
        nd->userdata = userdata;

        return 0;
}

int sd_ndisc_set_ifindex(sd_ndisc *nd, int ifindex) {
        assert_return(nd, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(!sd_ndisc_is_running(nd), -EBUSY);

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

int sd_ndisc_get_ifname(sd_ndisc *nd, const char **ret) {
        int r;

        assert_return(nd, -EINVAL);

        r = get_ifname(nd->ifindex, &nd->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = nd->ifname;

        return 0;
}

int sd_ndisc_set_link_local_address(sd_ndisc *nd, const struct in6_addr *addr) {
        assert_return(nd, -EINVAL);
        assert_return(!addr || in6_addr_is_link_local(addr), -EINVAL);

        if (addr)
                nd->link_local_addr = *addr;
        else
                zero(nd->link_local_addr);

        return 0;
}

int sd_ndisc_set_mac(sd_ndisc *nd, const struct ether_addr *mac_addr) {
        assert_return(nd, -EINVAL);

        if (mac_addr)
                nd->mac_addr = *mac_addr;
        else
                zero(nd->mac_addr);

        return 0;
}

int sd_ndisc_attach_event(sd_ndisc *nd, sd_event *event, int64_t priority) {
        int r;

        assert_return(nd, -EINVAL);
        assert_return(!sd_ndisc_is_running(nd), -EBUSY);
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

int sd_ndisc_detach_event(sd_ndisc *nd) {

        assert_return(nd, -EINVAL);
        assert_return(!sd_ndisc_is_running(nd), -EBUSY);

        nd->event = sd_event_unref(nd->event);
        return 0;
}

sd_event *sd_ndisc_get_event(sd_ndisc *nd) {
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

int sd_ndisc_new(sd_ndisc **ret) {
        _cleanup_(sd_ndisc_unrefp) sd_ndisc *nd = NULL;

        assert_return(ret, -EINVAL);

        nd = new(sd_ndisc, 1);
        if (!nd)
                return -ENOMEM;

        *nd = (sd_ndisc) {
                .n_ref = 1,
                .fd = -EBADF,
        };

        *ret = TAKE_PTR(nd);

        return 0;
}

static int ndisc_handle_router(sd_ndisc *nd, ICMP6Packet *packet) {
        _cleanup_(sd_ndisc_router_unrefp) sd_ndisc_router *rt = NULL;
        int r;

        assert(nd);
        assert(packet);

        rt = ndisc_router_new(packet);
        if (!rt)
                return -ENOMEM;

        r = ndisc_router_parse(nd, rt);
        if (r < 0)
                return r;

        (void) event_source_disable(nd->timeout_event_source);
        (void) event_source_disable(nd->timeout_no_ra);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *s = NULL;
                struct in6_addr a;
                uint64_t flags;
                uint8_t pref;
                usec_t lifetime;

                r = sd_ndisc_router_get_sender_address(rt, &a);
                if (r < 0)
                        return r;

                r = sd_ndisc_router_get_flags(rt, &flags);
                if (r < 0)
                        return r;

                r = ndisc_router_flags_to_string(flags, &s);
                if (r < 0)
                        return r;

                r = sd_ndisc_router_get_preference(rt, &pref);
                if (r < 0)
                        return r;

                r = sd_ndisc_router_get_lifetime(rt, &lifetime);
                if (r < 0)
                        return r;

                log_ndisc(nd, "Received Router Advertisement from %s: flags=0x%0*"PRIx64"(%s), preference=%s, lifetime=%s",
                          IN6_ADDR_TO_STRING(&a),
                          flags & UINT64_C(0x00ffffffffffff00) ? 14 : 2, flags, /* suppress too many zeros if no extension */
                          s ?: "none",
                          ndisc_router_preference_to_string(pref),
                          FORMAT_TIMESPAN(lifetime, USEC_PER_SEC));
        }

        ndisc_callback(nd, SD_NDISC_EVENT_ROUTER, rt);
        return 0;
}

static int ndisc_handle_neighbor(sd_ndisc *nd, ICMP6Packet *packet) {
        _cleanup_(sd_ndisc_neighbor_unrefp) sd_ndisc_neighbor *na = NULL;
        int r;

        assert(nd);
        assert(packet);

        na = ndisc_neighbor_new(packet);
        if (!na)
                return -ENOMEM;

        r = ndisc_neighbor_parse(nd, na);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                struct in6_addr a;

                r = sd_ndisc_neighbor_get_sender_address(na, &a);
                if (r < 0)
                        return r;

                log_ndisc(nd, "Received Neighbor Advertisement from %s: Router=%s, Solicited=%s, Override=%s",
                          IN6_ADDR_TO_STRING(&a),
                          yes_no(sd_ndisc_neighbor_is_router(na) > 0),
                          yes_no(sd_ndisc_neighbor_is_solicited(na) > 0),
                          yes_no(sd_ndisc_neighbor_is_override(na) > 0));
        }

        ndisc_callback(nd, SD_NDISC_EVENT_NEIGHBOR, na);
        return 0;
}

static int ndisc_handle_redirect(sd_ndisc *nd, ICMP6Packet *packet) {
        _cleanup_(sd_ndisc_redirect_unrefp) sd_ndisc_redirect *rd = NULL;
        int r;

        assert(nd);
        assert(packet);

        rd = ndisc_redirect_new(packet);
        if (!rd)
                return -ENOMEM;

        r = ndisc_redirect_parse(nd, rd);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                struct in6_addr sender, target, dest;

                r = sd_ndisc_redirect_get_sender_address(rd, &sender);
                if (r < 0)
                        return r;

                r = sd_ndisc_redirect_get_target_address(rd, &target);
                if (r < 0)
                        return r;

                r = sd_ndisc_redirect_get_destination_address(rd, &dest);
                if (r < 0)
                        return r;

                log_ndisc(nd, "Received Redirect message from %s: Target=%s, Destination=%s",
                          IN6_ADDR_TO_STRING(&sender),
                          IN6_ADDR_TO_STRING(&target),
                          IN6_ADDR_TO_STRING(&dest));
        }

        ndisc_callback(nd, SD_NDISC_EVENT_REDIRECT, rd);
        return 0;
}

static int ndisc_recv(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        _cleanup_(icmp6_packet_unrefp) ICMP6Packet *packet = NULL;
        sd_ndisc *nd = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(nd->event);

        r = icmp6_packet_receive(fd, &packet);
        if (r < 0) {
                log_ndisc_errno(nd, r, "Failed to receive ICMPv6 packet, ignoring: %m");
                return 0;
        }

        /* The function icmp6_receive() accepts the null source address, but RFC 4861 Section 6.1.2 states
         * that hosts MUST discard messages with the null source address. */
        if (in6_addr_is_null(&packet->sender_address)) {
                log_ndisc(nd, "Received an ICMPv6 packet from null address, ignoring.");
                return 0;
        }

        if (in6_addr_equal(&packet->sender_address, &nd->link_local_addr)) {
                log_ndisc(nd, "Received an ICMPv6 packet sent by the same interface, ignoring.");
                return 0;
        }

        r = icmp6_packet_get_type(packet);
        if (r < 0) {
                log_ndisc_errno(nd, r, "Received an invalid ICMPv6 packet, ignoring: %m");
                return 0;
        }

        switch (r) {
        case ND_ROUTER_ADVERT:
                (void) ndisc_handle_router(nd, packet);
                break;

        case ND_NEIGHBOR_ADVERT:
                (void) ndisc_handle_neighbor(nd, packet);
                break;

        case ND_REDIRECT:
                (void) ndisc_handle_redirect(nd, packet);
                break;

        default:
                log_ndisc(nd, "Received an ICMPv6 packet with unexpected type %i, ignoring.", r);
        }

        return 0;
}

static int ndisc_send_router_solicitation(sd_ndisc *nd) {
        static const struct nd_router_solicit header = {
                .nd_rs_type = ND_ROUTER_SOLICIT,
        };

        _cleanup_set_free_ Set *options = NULL;
        int r;

        assert(nd);

        if (!ether_addr_is_null(&nd->mac_addr)) {
                r = ndisc_option_set_link_layer_address(&options, SD_NDISC_OPTION_SOURCE_LL_ADDRESS, &nd->mac_addr);
                if (r < 0)
                        return r;
        }

        return ndisc_send(nd->fd, &IN6_ADDR_ALL_ROUTERS_MULTICAST, &header.nd_rs_hdr, options, USEC_INFINITY);
}

static usec_t ndisc_timeout_compute_random(usec_t val) {
        /* compute a time that is random within ±10% of the given value */
        return val - val / 10 +
                (random_u64() % (2 * USEC_PER_SEC)) * val / 10 / USEC_PER_SEC;
}

static int ndisc_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ndisc *nd = ASSERT_PTR(userdata);
        usec_t time_now;
        int r;

        assert(s);
        assert(nd->event);

        assert_se(sd_event_now(nd->event, CLOCK_BOOTTIME, &time_now) >= 0);

        if (!nd->retransmit_time)
                nd->retransmit_time = ndisc_timeout_compute_random(NDISC_ROUTER_SOLICITATION_INTERVAL);
        else {
                if (nd->retransmit_time > NDISC_MAX_ROUTER_SOLICITATION_INTERVAL / 2)
                        nd->retransmit_time = ndisc_timeout_compute_random(NDISC_MAX_ROUTER_SOLICITATION_INTERVAL);
                else
                        nd->retransmit_time += ndisc_timeout_compute_random(nd->retransmit_time);
        }

        r = event_reset_time(nd->event, &nd->timeout_event_source,
                             CLOCK_BOOTTIME,
                             time_now + nd->retransmit_time, 10 * USEC_PER_MSEC,
                             ndisc_timeout, nd,
                             nd->event_priority, "ndisc-timeout-no-ra", true);
        if (r < 0)
                goto fail;

        r = ndisc_send_router_solicitation(nd);
        if (r < 0)
                log_ndisc_errno(nd, r, "Failed to send Router Solicitation, next solicitation in %s, ignoring: %m",
                                FORMAT_TIMESPAN(nd->retransmit_time, USEC_PER_SEC));
        else
                log_ndisc(nd, "Sent Router Solicitation, next solicitation in %s",
                          FORMAT_TIMESPAN(nd->retransmit_time, USEC_PER_SEC));

        return 0;

fail:
        (void) sd_ndisc_stop(nd);
        return 0;
}

static int ndisc_timeout_no_ra(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ndisc *nd = ASSERT_PTR(userdata);

        assert(s);

        log_ndisc(nd, "No RA received before link confirmation timeout");

        (void) event_source_disable(nd->timeout_no_ra);
        ndisc_callback(nd, SD_NDISC_EVENT_TIMEOUT, NULL);

        return 0;
}

int sd_ndisc_stop(sd_ndisc *nd) {
        if (!nd)
                return 0;

        if (!sd_ndisc_is_running(nd))
                return 0;

        log_ndisc(nd, "Stopping IPv6 Router Solicitation client");

        ndisc_reset(nd);
        return 1;
}

static int ndisc_setup_recv_event(sd_ndisc *nd) {
        int r;

        assert(nd);
        assert(nd->event);
        assert(nd->ifindex > 0);

        _cleanup_close_ int fd = -EBADF;
        fd = icmp6_bind(nd->ifindex, /* is_router = */ false);
        if (fd < 0)
                return fd;

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(nd->event, &s, fd, EPOLLIN, ndisc_recv, nd);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, nd->event_priority);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, "ndisc-receive-router-message");

        nd->fd = TAKE_FD(fd);
        nd->recv_event_source = TAKE_PTR(s);
        return 1;
}

static int ndisc_setup_timer(sd_ndisc *nd) {
        int r;

        assert(nd);
        assert(nd->event);

        r = event_reset_time_relative(nd->event, &nd->timeout_event_source,
                                      CLOCK_BOOTTIME,
                                      USEC_PER_SEC / 2, 1 * USEC_PER_SEC, /* See RFC 8415 sec. 18.2.1 */
                                      ndisc_timeout, nd,
                                      nd->event_priority, "ndisc-timeout", true);
        if (r < 0)
                return r;

        r = event_reset_time_relative(nd->event, &nd->timeout_no_ra,
                                      CLOCK_BOOTTIME,
                                      NDISC_TIMEOUT_NO_RA_USEC, 10 * USEC_PER_MSEC,
                                      ndisc_timeout_no_ra, nd,
                                      nd->event_priority, "ndisc-timeout-no-ra", true);
        if (r < 0)
                return r;

        return 0;
}

int sd_ndisc_start(sd_ndisc *nd) {
        int r;

        assert_return(nd, -EINVAL);
        assert_return(nd->event, -EINVAL);
        assert_return(nd->ifindex > 0, -EINVAL);

        if (sd_ndisc_is_running(nd))
                return 0;

        r = ndisc_setup_recv_event(nd);
        if (r < 0)
                goto fail;

        r = ndisc_setup_timer(nd);
        if (r < 0)
                goto fail;

        log_ndisc(nd, "Started IPv6 Router Solicitation client");
        return 1;

fail:
        ndisc_reset(nd);
        return r;
}
