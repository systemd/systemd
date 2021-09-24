/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-ipv4acd.h"

#include "alloc-util.h"
#include "arp-util.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "log-link.h"
#include "memory-util.h"
#include "network-common.h"
#include "random-util.h"
#include "siphash24.h"
#include "string-table.h"
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
        _IPV4ACD_STATE_INVALID = -EINVAL,
} IPv4ACDState;

struct sd_ipv4acd {
        unsigned n_ref;

        IPv4ACDState state;
        int ifindex;
        int fd;

        char *ifname;
        unsigned n_iteration;
        unsigned n_conflict;

        sd_event_source *receive_message_event_source;
        sd_event_source *timer_event_source;

        usec_t defend_window;
        struct in_addr address;

        /* External */
        struct ether_addr mac_addr;

        sd_event *event;
        int event_priority;
        sd_ipv4acd_callback_t callback;
        void *userdata;
        sd_ipv4acd_check_mac_callback_t check_mac_callback;
        void *check_mac_userdata;
};

#define log_ipv4acd_errno(acd, error, fmt, ...)         \
        log_interface_prefix_full_errno(                \
                "IPv4ACD: ",                            \
                sd_ipv4acd_get_ifname(acd),             \
                error, fmt, ##__VA_ARGS__)
#define log_ipv4acd(acd, fmt, ...)                      \
        log_interface_prefix_full_errno_zerook(         \
                "IPv4ACD: ",                            \
                sd_ipv4acd_get_ifname(acd),             \
                0, fmt, ##__VA_ARGS__)

static const char * const ipv4acd_state_table[_IPV4ACD_STATE_MAX] = {
        [IPV4ACD_STATE_INIT]             = "init",
        [IPV4ACD_STATE_STARTED]          = "started",
        [IPV4ACD_STATE_WAITING_PROBE]    = "waiting-probe",
        [IPV4ACD_STATE_PROBING]          = "probing",
        [IPV4ACD_STATE_WAITING_ANNOUNCE] = "waiting-announce",
        [IPV4ACD_STATE_ANNOUNCING]       = "announcing",
        [IPV4ACD_STATE_RUNNING]          = "running",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(ipv4acd_state, IPv4ACDState);

static void ipv4acd_set_state(sd_ipv4acd *acd, IPv4ACDState st, bool reset_counter) {
        assert(acd);
        assert(st < _IPV4ACD_STATE_MAX);

        if (st != acd->state)
                log_ipv4acd(acd, "%s -> %s", ipv4acd_state_to_string(acd->state), ipv4acd_state_to_string(st));

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
        acd->receive_message_event_source = sd_event_source_disable_unref(acd->receive_message_event_source);

        acd->fd = safe_close(acd->fd);

        ipv4acd_set_state(acd, IPV4ACD_STATE_INIT, true);
}

static sd_ipv4acd *ipv4acd_free(sd_ipv4acd *acd) {
        assert(acd);

        ipv4acd_reset(acd);
        sd_event_source_unref(acd->timer_event_source);
        sd_ipv4acd_detach_event(acd);
        free(acd->ifname);
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
        IPv4ACDState old_state;

        if (!acd)
                return 0;

        old_state = acd->state;

        ipv4acd_reset(acd);

        if (old_state == IPV4ACD_STATE_INIT)
                return 0;

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

static int ipv4acd_on_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ipv4acd *acd = userdata;
        int r = 0;

        assert(acd);

        switch (acd->state) {

        case IPV4ACD_STATE_STARTED:
                acd->defend_window = 0;

                ipv4acd_set_state(acd, IPV4ACD_STATE_WAITING_PROBE, true);

                if (acd->n_conflict >= MAX_CONFLICTS) {
                        char ts[FORMAT_TIMESPAN_MAX];

                        log_ipv4acd(acd, "Max conflicts reached, delaying by %s",
                                    format_timespan(ts, sizeof(ts), RATE_LIMIT_INTERVAL_USEC, 0));
                        r = ipv4acd_set_next_wakeup(acd, RATE_LIMIT_INTERVAL_USEC, PROBE_WAIT_USEC);
                } else
                        r = ipv4acd_set_next_wakeup(acd, 0, PROBE_WAIT_USEC);
                if (r < 0)
                        goto fail;

                break;

        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
                /* Send a probe */
                r = arp_send_probe(acd->fd, acd->ifindex, &acd->address, &acd->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(acd, r, "Failed to send ARP probe: %m");
                        goto fail;
                }

                log_ipv4acd(acd, "Probing "IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(acd->address));

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
                r = arp_send_announcement(acd->fd, acd->ifindex, &acd->address, &acd->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(acd, r, "Failed to send ARP announcement: %m");
                        goto fail;
                }

                log_ipv4acd(acd, "Announcing "IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(acd->address));

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

static bool ipv4acd_arp_conflict(sd_ipv4acd *acd, const struct ether_arp *arp, bool announced) {
        assert(acd);
        assert(arp);

        /* RFC 5227 section 2.1.1.
         * "the host receives any ARP packet (Request *or* Reply) on the interface where the probe is
         * being performed, where the packet's 'sender IP address' is the address being probed for,
         * then the host MUST treat this address as being in use by some other host" */
        if (memcmp(arp->arp_spa, &acd->address, sizeof(struct in_addr)) == 0)
                return true;

        if (announced)
                /* the TPA matched instead of SPA, this is not a conflict */
                return false;

        /* "any ARP Probe where the packet's 'target IP address' is the address being probed for, and
         * the packet's 'sender hardware address' is not the hardware address of any of the host's
         * interfaces, then the host SHOULD similarly treat this as an address conflict" */
        if (arp->ea_hdr.ar_op != htobe16(ARPOP_REQUEST))
                return false; /* not ARP Request, ignoring. */
        if (memeqzero(arp->arp_spa, sizeof(struct in_addr)) == 0)
                return false; /* not ARP Probe, ignoring. */
        if (memcmp(arp->arp_tpa, &acd->address, sizeof(struct in_addr)) != 0)
                return false; /* target IP address does not match, BPF code is broken? */

        if (acd->check_mac_callback &&
            acd->check_mac_callback(acd, (const struct ether_addr*) arp->arp_sha, acd->check_mac_userdata) > 0)
                /* sender hardware is one of the host's interfaces, ignoring. */
                return true;

        return true; /* conflict! */
}

static void ipv4acd_on_conflict(sd_ipv4acd *acd) {
        assert(acd);

        acd->n_conflict++;

        log_ipv4acd(acd, "Conflict on "IPV4_ADDRESS_FMT_STR" (%u)", IPV4_ADDRESS_FMT_VAL(acd->address), acd->n_conflict);

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

                if (ipv4acd_arp_conflict(acd, &packet, true)) {
                        usec_t ts;

                        assert_se(sd_event_now(acd->event, clock_boottime_or_monotonic(), &ts) >= 0);

                        /* Defend address */
                        if (ts > acd->defend_window) {
                                acd->defend_window = ts + DEFEND_INTERVAL_USEC;
                                r = arp_send_announcement(acd->fd, acd->ifindex, &acd->address, &acd->mac_addr);
                                if (r < 0) {
                                        log_ipv4acd_errno(acd, r, "Failed to send ARP announcement: %m");
                                        goto fail;
                                }

                                log_ipv4acd(acd, "Defending "IPV4_ADDRESS_FMT_STR, IPV4_ADDRESS_FMT_VAL(acd->address));

                        } else
                                ipv4acd_on_conflict(acd);
                }
                break;

        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
        case IPV4ACD_STATE_WAITING_ANNOUNCE:
                if (ipv4acd_arp_conflict(acd, &packet, false))
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

int sd_ipv4acd_get_ifindex(sd_ipv4acd *acd) {
        if (!acd)
                return -EINVAL;

        return acd->ifindex;
}

int sd_ipv4acd_set_ifname(sd_ipv4acd *acd, const char *ifname) {
        assert_return(acd, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&acd->ifname, ifname);
}

const char *sd_ipv4acd_get_ifname(sd_ipv4acd *acd) {
        if (!acd)
                return NULL;

        return get_ifname(acd->ifindex, &acd->ifname);
}

int sd_ipv4acd_set_mac(sd_ipv4acd *acd, const struct ether_addr *addr) {
        int r;

        assert_return(acd, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(!ether_addr_is_null(addr), -EINVAL);

        acd->mac_addr = *addr;

        if (!sd_ipv4acd_is_running(acd))
                return 0;

        assert(acd->fd >= 0);
        r = arp_update_filter(acd->fd, &acd->address, &acd->mac_addr);
        if (r < 0) {
                ipv4acd_reset(acd);
                return r;
        }

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

int sd_ipv4acd_set_check_mac_callback(sd_ipv4acd *acd, sd_ipv4acd_check_mac_callback_t cb, void *userdata) {
        assert_return(acd, -EINVAL);

        acd->check_mac_callback = cb;
        acd->check_mac_userdata = userdata;
        return 0;
}

int sd_ipv4acd_set_address(sd_ipv4acd *acd, const struct in_addr *address) {
        int r;

        assert_return(acd, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(in4_addr_is_set(address), -EINVAL);

        if (in4_addr_equal(&acd->address, address))
                return 0;

        acd->address = *address;

        if (!sd_ipv4acd_is_running(acd))
                return 0;

        assert(acd->fd >= 0);
        r = arp_update_filter(acd->fd, &acd->address, &acd->mac_addr);
        if (r < 0)
                goto fail;

        r = ipv4acd_set_next_wakeup(acd, 0, 0);
        if (r < 0)
                goto fail;

        ipv4acd_set_state(acd, IPV4ACD_STATE_STARTED, true);
        return 0;

fail:
        ipv4acd_reset(acd);
        return r;
}

int sd_ipv4acd_get_address(sd_ipv4acd *acd, struct in_addr *address) {
        assert_return(acd, -EINVAL);
        assert_return(address, -EINVAL);

        *address = acd->address;

        return 0;
}

int sd_ipv4acd_is_running(sd_ipv4acd *acd) {
        assert_return(acd, false);

        return acd->state != IPV4ACD_STATE_INIT;
}

int sd_ipv4acd_start(sd_ipv4acd *acd, bool reset_conflicts) {
        int r;

        assert_return(acd, -EINVAL);
        assert_return(acd->event, -EINVAL);
        assert_return(acd->ifindex > 0, -EINVAL);
        assert_return(in4_addr_is_set(&acd->address), -EINVAL);
        assert_return(!ether_addr_is_null(&acd->mac_addr), -EINVAL);
        assert_return(acd->state == IPV4ACD_STATE_INIT, -EBUSY);

        r = arp_network_bind_raw_socket(acd->ifindex, &acd->address, &acd->mac_addr);
        if (r < 0)
                return r;

        CLOSE_AND_REPLACE(acd->fd, r);

        if (reset_conflicts)
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
