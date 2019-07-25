/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd-ipv4acd.h"

#include "alloc-util.h"
#include "arp-util.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "random-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "time-util.h"

/* Constants from the RFC */
#define PROBE_WAIT_USEC (1U * USEC_PER_SEC)
#define PROBE_NUM 3U
#define PROBE_MIN_USEC (1U * USEC_PER_SEC)
#define PROBE_MAX_USEC (2U * USEC_PER_SEC)
#define ANNOUNCE_WAIT_USEC (2U * USEC_PER_SEC)
#define ANNOUNCE_NUM 2U
#define ANNOUNCE_INTERVAL_USEC (2U * USEC_PER_SEC)
#define MAX_CONFLICTS 10U
#define RATE_LIMIT_INTERVAL_USEC (60U * USEC_PER_SEC)
#define DEFEND_INTERVAL_USEC (10U * USEC_PER_SEC)

typedef enum IPv4ACDState {
        IPV4ACD_STATE_INIT,
        IPV4ACD_STATE_STARTED,
        IPV4ACD_STATE_WAITING_PROBE,
        IPV4ACD_STATE_PROBING,
        IPV4ACD_STATE_WAITING_ANNOUNCE,
        IPV4ACD_STATE_ANNOUNCING,
        IPV4ACD_STATE_RUNNING,
        _IPV4ACD_STATE_MAX,
        _IPV4ACD_STATE_INVALID = -1
} IPv4ACDState;

struct sd_ipv4acd {
        unsigned n_ref;

        IPv4ACDState state;
        int ifindex;
        int fd;

        unsigned n_iteration;
        unsigned n_conflict;

        sd_event_source *receive_message_event_source;
        sd_event_source *timer_event_source;

        usec_t defend_window;
        be32_t address;

        /* External */
        struct ether_addr mac_addr;

        sd_event *event;
        int event_priority;
        sd_ipv4acd_callback_t callback;
        void* userdata;
};

#define log_ipv4acd_errno(acd, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "IPV4ACD: " fmt, ##__VA_ARGS__)
#define log_ipv4acd(acd, fmt, ...) log_ipv4acd_errno(acd, 0, fmt, ##__VA_ARGS__)

static void ipv4acd_set_state(sd_ipv4acd *acd, IPv4ACDState st, bool reset_counter) {
        assert(acd);
        assert(st < _IPV4ACD_STATE_MAX);

        if (st == acd->state && !reset_counter)
                acd->n_iteration++;
        else {
                acd->state = st;
                acd->n_iteration = 0;
        }
}

static void ipv4acd_reset(sd_ipv4acd *acd) {
        assert(acd);

        (void) event_source_disable(acd->timer_event_source);
        acd->receive_message_event_source = sd_event_source_unref(acd->receive_message_event_source);

        acd->fd = safe_close(acd->fd);

        ipv4acd_set_state(acd, IPV4ACD_STATE_INIT, true);
}

static sd_ipv4acd *ipv4acd_free(sd_ipv4acd *acd) {
        assert(acd);

        acd->timer_event_source = sd_event_source_unref(acd->timer_event_source);

        ipv4acd_reset(acd);
        sd_ipv4acd_detach_event(acd);

        return mfree(acd);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ipv4acd, sd_ipv4acd, ipv4acd_free);

int sd_ipv4acd_new(sd_ipv4acd **ret) {
        _cleanup_(sd_ipv4acd_unrefp) sd_ipv4acd *acd = NULL;

        assert_return(ret, -EINVAL);

        acd = new(sd_ipv4acd, 1);
        if (!acd)
                return -ENOMEM;

        *acd = (sd_ipv4acd) {
                .n_ref = 1,
                .state = IPV4ACD_STATE_INIT,
                .ifindex = -1,
                .fd = -1,
        };

        *ret = TAKE_PTR(acd);

        return 0;
}

static void ipv4acd_client_notify(sd_ipv4acd *acd, int event) {
        assert(acd);

        if (!acd->callback)
                return;

        acd->callback(acd, event, acd->userdata);
}

int sd_ipv4acd_stop(sd_ipv4acd *acd) {
        assert_return(acd, -EINVAL);

        ipv4acd_reset(acd);

        log_ipv4acd(acd, "STOPPED");

        ipv4acd_client_notify(acd, SD_IPV4ACD_EVENT_STOP);

        return 0;
}

static int ipv4acd_on_timeout(sd_event_source *s, uint64_t usec, void *userdata);

static int ipv4acd_set_next_wakeup(sd_ipv4acd *acd, usec_t usec, usec_t random_usec) {
        usec_t next_timeout, time_now;

        assert(acd);

        next_timeout = usec;

        if (random_usec > 0)
                next_timeout += (usec_t) random_u64() % random_usec;

        assert_se(sd_event_now(acd->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        return event_reset_time(acd->event, &acd->timer_event_source,
                                clock_boottime_or_monotonic(),
                                time_now + next_timeout, 0,
                                ipv4acd_on_timeout, acd,
                                acd->event_priority, "ipv4acd-timer", true);
}

static bool ipv4acd_arp_conflict(sd_ipv4acd *acd, struct ether_arp *arp) {
        assert(acd);
        assert(arp);

        /* see the BPF */
        if (memcmp(arp->arp_spa, &acd->address, sizeof(acd->address)) == 0)
                return true;

        /* the TPA matched instead of the SPA, this is not a conflict */
        return false;
}

static int ipv4acd_on_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ipv4acd *acd = userdata;
        int r = 0;

        assert(acd);

        switch (acd->state) {

        case IPV4ACD_STATE_STARTED:
                ipv4acd_set_state(acd, IPV4ACD_STATE_WAITING_PROBE, true);

                if (acd->n_conflict >= MAX_CONFLICTS) {
                        char ts[FORMAT_TIMESPAN_MAX];
                        log_ipv4acd(acd, "Max conflicts reached, delaying by %s", format_timespan(ts, sizeof(ts), RATE_LIMIT_INTERVAL_USEC, 0));

                        r = ipv4acd_set_next_wakeup(acd, RATE_LIMIT_INTERVAL_USEC, PROBE_WAIT_USEC);
                        if (r < 0)
                                goto fail;
                } else {
                        r = ipv4acd_set_next_wakeup(acd, 0, PROBE_WAIT_USEC);
                        if (r < 0)
                                goto fail;
                }

                break;

        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
                /* Send a probe */
                r = arp_send_probe(acd->fd, acd->ifindex, acd->address, &acd->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(acd, r, "Failed to send ARP probe: %m");
                        goto fail;
                } else {
                        _cleanup_free_ char *address = NULL;
                        union in_addr_union addr = { .in.s_addr = acd->address };

                        (void) in_addr_to_string(AF_INET, &addr, &address);
                        log_ipv4acd(acd, "Probing %s", strna(address));
                }

                if (acd->n_iteration < PROBE_NUM - 2) {
                        ipv4acd_set_state(acd, IPV4ACD_STATE_PROBING, false);

                        r = ipv4acd_set_next_wakeup(acd, PROBE_MIN_USEC, (PROBE_MAX_USEC-PROBE_MIN_USEC));
                        if (r < 0)
                                goto fail;
                } else {
                        ipv4acd_set_state(acd, IPV4ACD_STATE_WAITING_ANNOUNCE, true);

                        r = ipv4acd_set_next_wakeup(acd, ANNOUNCE_WAIT_USEC, 0);
                        if (r < 0)
                                goto fail;
                }

                break;

        case IPV4ACD_STATE_ANNOUNCING:
                if (acd->n_iteration >= ANNOUNCE_NUM - 1) {
                        ipv4acd_set_state(acd, IPV4ACD_STATE_RUNNING, false);
                        break;
                }

                _fallthrough_;
        case IPV4ACD_STATE_WAITING_ANNOUNCE:
                /* Send announcement packet */
                r = arp_send_announcement(acd->fd, acd->ifindex, acd->address, &acd->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(acd, r, "Failed to send ARP announcement: %m");
                        goto fail;
                } else
                        log_ipv4acd(acd, "ANNOUNCE");

                ipv4acd_set_state(acd, IPV4ACD_STATE_ANNOUNCING, false);

                r = ipv4acd_set_next_wakeup(acd, ANNOUNCE_INTERVAL_USEC, 0);
                if (r < 0)
                        goto fail;

                if (acd->n_iteration == 0) {
                        acd->n_conflict = 0;
                        ipv4acd_client_notify(acd, SD_IPV4ACD_EVENT_BIND);
                }

                break;

        default:
                assert_not_reached("Invalid state.");
        }

        return 0;

fail:
        sd_ipv4acd_stop(acd);
        return 0;
}

static void ipv4acd_on_conflict(sd_ipv4acd *acd) {
        _cleanup_free_ char *address = NULL;
        union in_addr_union addr = { .in.s_addr = acd->address };

        assert(acd);

        acd->n_conflict++;

        (void) in_addr_to_string(AF_INET, &addr, &address);
        log_ipv4acd(acd, "Conflict on %s (%u)", strna(address), acd->n_conflict);

        ipv4acd_reset(acd);
        ipv4acd_client_notify(acd, SD_IPV4ACD_EVENT_CONFLICT);
}

static int ipv4acd_on_packet(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata) {

        sd_ipv4acd *acd = userdata;
        struct ether_arp packet;
        ssize_t n;
        int r;

        assert(s);
        assert(acd);
        assert(fd >= 0);

        n = recv(fd, &packet, sizeof(struct ether_arp), 0);
        if (n < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                log_ipv4acd_errno(acd, errno, "Failed to read ARP packet: %m");
                goto fail;
        }
        if ((size_t) n != sizeof(struct ether_arp)) {
                log_ipv4acd(acd, "Ignoring too short ARP packet.");
                return 0;
        }

        switch (acd->state) {

        case IPV4ACD_STATE_ANNOUNCING:
        case IPV4ACD_STATE_RUNNING:

                if (ipv4acd_arp_conflict(acd, &packet)) {
                        usec_t ts;

                        assert_se(sd_event_now(acd->event, clock_boottime_or_monotonic(), &ts) >= 0);

                        /* Defend address */
                        if (ts > acd->defend_window) {
                                acd->defend_window = ts + DEFEND_INTERVAL_USEC;
                                r = arp_send_announcement(acd->fd, acd->ifindex, acd->address, &acd->mac_addr);
                                if (r < 0) {
                                        log_ipv4acd_errno(acd, r, "Failed to send ARP announcement: %m");
                                        goto fail;
                                } else
                                        log_ipv4acd(acd, "DEFEND");

                        } else
                                ipv4acd_on_conflict(acd);
                }
                break;

        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
        case IPV4ACD_STATE_WAITING_ANNOUNCE:
                /* BPF ensures this packet indicates a conflict */
                ipv4acd_on_conflict(acd);
                break;

        default:
                assert_not_reached("Invalid state.");
        }

        return 0;

fail:
        sd_ipv4acd_stop(acd);
        return 0;
}

int sd_ipv4acd_set_ifindex(sd_ipv4acd *acd, int ifindex) {
        assert_return(acd, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(acd->state == IPV4ACD_STATE_INIT, -EBUSY);

        acd->ifindex = ifindex;

        return 0;
}

int sd_ipv4acd_set_mac(sd_ipv4acd *acd, const struct ether_addr *addr) {
        assert_return(acd, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(acd->state == IPV4ACD_STATE_INIT, -EBUSY);

        acd->mac_addr = *addr;

        return 0;
}

int sd_ipv4acd_detach_event(sd_ipv4acd *acd) {
        assert_return(acd, -EINVAL);

        acd->event = sd_event_unref(acd->event);

        return 0;
}

int sd_ipv4acd_attach_event(sd_ipv4acd *acd, sd_event *event, int64_t priority) {
        int r;

        assert_return(acd, -EINVAL);
        assert_return(!acd->event, -EBUSY);

        if (event)
                acd->event = sd_event_ref(event);
        else {
                r = sd_event_default(&acd->event);
                if (r < 0)
                        return r;
        }

        acd->event_priority = priority;

        return 0;
}

int sd_ipv4acd_set_callback(sd_ipv4acd *acd, sd_ipv4acd_callback_t cb, void *userdata) {
        assert_return(acd, -EINVAL);

        acd->callback = cb;
        acd->userdata = userdata;

        return 0;
}

int sd_ipv4acd_set_address(sd_ipv4acd *acd, const struct in_addr *address) {
        assert_return(acd, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(acd->state == IPV4ACD_STATE_INIT, -EBUSY);

        acd->address = address->s_addr;

        return 0;
}

int sd_ipv4acd_is_running(sd_ipv4acd *acd) {
        assert_return(acd, false);

        return acd->state != IPV4ACD_STATE_INIT;
}

int sd_ipv4acd_start(sd_ipv4acd *acd) {
        int r;

        assert_return(acd, -EINVAL);
        assert_return(acd->event, -EINVAL);
        assert_return(acd->ifindex > 0, -EINVAL);
        assert_return(acd->address != 0, -EINVAL);
        assert_return(!ether_addr_is_null(&acd->mac_addr), -EINVAL);
        assert_return(acd->state == IPV4ACD_STATE_INIT, -EBUSY);

        r = arp_network_bind_raw_socket(acd->ifindex, acd->address, &acd->mac_addr);
        if (r < 0)
                return r;

        safe_close(acd->fd);
        acd->fd = r;
        acd->defend_window = 0;
        acd->n_conflict = 0;

        r = sd_event_add_io(acd->event, &acd->receive_message_event_source, acd->fd, EPOLLIN, ipv4acd_on_packet, acd);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(acd->receive_message_event_source, acd->event_priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(acd->receive_message_event_source, "ipv4acd-receive-message");

        r = ipv4acd_set_next_wakeup(acd, 0, 0);
        if (r < 0)
                goto fail;

        ipv4acd_set_state(acd, IPV4ACD_STATE_STARTED, true);
        return 0;

fail:
        ipv4acd_reset(acd);
        return r;
}
