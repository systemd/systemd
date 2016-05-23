/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.
  Copyright (C) 2015 Tom Gundersen

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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd-ipv4acd.h"

#include "alloc-util.h"
#include "arp-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "random-util.h"
#include "siphash24.h"
#include "util.h"

/* Constants from the RFC */
#define PROBE_WAIT 1
#define PROBE_NUM 3
#define PROBE_MIN 1
#define PROBE_MAX 2
#define ANNOUNCE_WAIT 2
#define ANNOUNCE_NUM 2
#define ANNOUNCE_INTERVAL 2
#define MAX_CONFLICTS 10
#define RATE_LIMIT_INTERVAL 60
#define DEFEND_INTERVAL 10

#define IPV4ACD_NETWORK 0xA9FE0000UL
#define IPV4ACD_NETMASK 0xFFFF0000UL

#define log_ipv4acd_errno(ll, error, fmt, ...) log_internal(LOG_DEBUG, error, __FILE__, __LINE__, __func__, "ACD: " fmt, ##__VA_ARGS__)
#define log_ipv4acd(ll, fmt, ...) log_ipv4acd_errno(ll, 0, fmt, ##__VA_ARGS__)

typedef enum IPv4ACDState {
        IPV4ACD_STATE_INIT,
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

        sd_event_source *receive_message;
        sd_event_source *timer;

        usec_t defend_window;
        be32_t address;

        /* External */
        struct ether_addr mac_addr;

        sd_event *event;
        int event_priority;
        sd_ipv4acd_callback_t callback;
        void* userdata;
};

sd_ipv4acd *sd_ipv4acd_ref(sd_ipv4acd *ll) {
        if (!ll)
                return NULL;

        assert_se(ll->n_ref >= 1);
        ll->n_ref++;

        return ll;
}

sd_ipv4acd *sd_ipv4acd_unref(sd_ipv4acd *ll) {
        if (!ll)
                return NULL;

        assert_se(ll->n_ref >= 1);
        ll->n_ref--;

        if (ll->n_ref > 0)
                return NULL;

        ll->receive_message = sd_event_source_unref(ll->receive_message);
        ll->fd = safe_close(ll->fd);

        ll->timer = sd_event_source_unref(ll->timer);

        sd_ipv4acd_detach_event(ll);

        free(ll);

        return NULL;
}

int sd_ipv4acd_new(sd_ipv4acd **ret) {
        _cleanup_(sd_ipv4acd_unrefp) sd_ipv4acd *ll = NULL;

        assert_return(ret, -EINVAL);

        ll = new0(sd_ipv4acd, 1);
        if (!ll)
                return -ENOMEM;

        ll->n_ref = 1;
        ll->state = IPV4ACD_STATE_INIT;
        ll->ifindex = -1;
        ll->fd = -1;

        *ret = ll;
        ll = NULL;

        return 0;
}

static void ipv4acd_set_state(sd_ipv4acd *ll, IPv4ACDState st, bool reset_counter) {

        assert(ll);
        assert(st < _IPV4ACD_STATE_MAX);

        if (st == ll->state && !reset_counter)
                ll->n_iteration++;
        else {
                ll->state = st;
                ll->n_iteration = 0;
        }
}

static void ipv4acd_client_notify(sd_ipv4acd *ll, int event) {
        assert(ll);

        if (!ll->callback)
                return;

        ll->callback(ll, event, ll->userdata);
}

static void ipv4acd_stop(sd_ipv4acd *ll) {
        assert(ll);

        ll->receive_message = sd_event_source_unref(ll->receive_message);
        ll->fd = safe_close(ll->fd);

        ll->timer = sd_event_source_unref(ll->timer);

        log_ipv4acd(ll, "STOPPED");

        ipv4acd_set_state (ll, IPV4ACD_STATE_INIT, true);
}

int sd_ipv4acd_stop(sd_ipv4acd *ll) {
        assert_return(ll, -EINVAL);

        ipv4acd_stop(ll);

        ipv4acd_client_notify(ll, SD_IPV4ACD_EVENT_STOP);

        return 0;
}

static int ipv4acd_on_timeout(sd_event_source *s, uint64_t usec, void *userdata);

static int ipv4acd_set_next_wakeup(sd_ipv4acd *ll, int sec, int random_sec) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *timer = NULL;
        usec_t next_timeout;
        usec_t time_now;
        int r;

        assert(sec >= 0);
        assert(random_sec >= 0);
        assert(ll);

        next_timeout = sec * USEC_PER_SEC;

        if (random_sec)
                next_timeout += random_u32() % (random_sec * USEC_PER_SEC);

        assert_se(sd_event_now(ll->event, clock_boottime_or_monotonic(), &time_now) >= 0);

        r = sd_event_add_time(ll->event, &timer, clock_boottime_or_monotonic(),
                              time_now + next_timeout, 0, ipv4acd_on_timeout, ll);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(timer, ll->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(timer, "ipv4acd-timer");
        if (r < 0)
                return r;

        ll->timer = sd_event_source_unref(ll->timer);
        ll->timer = timer;
        timer = NULL;

        return 0;
}

static bool ipv4acd_arp_conflict(sd_ipv4acd *ll, struct ether_arp *arp) {
        assert(ll);
        assert(arp);

        /* see the BPF */
        if (memcmp(arp->arp_spa, &ll->address, sizeof(ll->address)) == 0)
                return true;

        /* the TPA matched instead of the SPA, this is not a conflict */
        return false;
}

static int ipv4acd_on_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ipv4acd *ll = userdata;
        int r = 0;

        assert(ll);

        switch (ll->state) {
        case IPV4ACD_STATE_INIT:

                ipv4acd_set_state(ll, IPV4ACD_STATE_WAITING_PROBE, true);

                if (ll->n_conflict >= MAX_CONFLICTS) {
                        log_ipv4acd(ll, "Max conflicts reached, delaying by %us", RATE_LIMIT_INTERVAL);

                        r = ipv4acd_set_next_wakeup(ll, RATE_LIMIT_INTERVAL, PROBE_WAIT);
                        if (r < 0)
                                goto out;

                        ll->n_conflict = 0;
                } else {
                        r = ipv4acd_set_next_wakeup(ll, 0, PROBE_WAIT);
                        if (r < 0)
                                goto out;
                }

                break;
        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
                /* Send a probe */
                r = arp_send_probe(ll->fd, ll->ifindex, ll->address, &ll->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(ll, r, "Failed to send ARP probe: %m");
                        goto out;
                } else {
                        _cleanup_free_ char *address = NULL;
                        union in_addr_union addr = { .in.s_addr = ll->address };

                        r = in_addr_to_string(AF_INET, &addr, &address);
                        if (r >= 0)
                                log_ipv4acd(ll, "Probing %s", address);
                }

                if (ll->n_iteration < PROBE_NUM - 2) {
                        ipv4acd_set_state(ll, IPV4ACD_STATE_PROBING, false);

                        r = ipv4acd_set_next_wakeup(ll, PROBE_MIN, (PROBE_MAX-PROBE_MIN));
                        if (r < 0)
                                goto out;
                } else {
                        ipv4acd_set_state(ll, IPV4ACD_STATE_WAITING_ANNOUNCE, true);

                        r = ipv4acd_set_next_wakeup(ll, ANNOUNCE_WAIT, 0);
                        if (r < 0)
                                goto out;
                }

                break;

        case IPV4ACD_STATE_ANNOUNCING:
                if (ll->n_iteration >= ANNOUNCE_NUM - 1) {
                        ipv4acd_set_state(ll, IPV4ACD_STATE_RUNNING, false);

                        break;
                }
        case IPV4ACD_STATE_WAITING_ANNOUNCE:
                /* Send announcement packet */
                r = arp_send_announcement(ll->fd, ll->ifindex, ll->address, &ll->mac_addr);
                if (r < 0) {
                        log_ipv4acd_errno(ll, r, "Failed to send ARP announcement: %m");
                        goto out;
                } else
                        log_ipv4acd(ll, "ANNOUNCE");

                ipv4acd_set_state(ll, IPV4ACD_STATE_ANNOUNCING, false);

                r = ipv4acd_set_next_wakeup(ll, ANNOUNCE_INTERVAL, 0);
                if (r < 0)
                        goto out;

                if (ll->n_iteration == 0) {
                        ll->n_conflict = 0;
                        ipv4acd_client_notify(ll, SD_IPV4ACD_EVENT_BIND);
                }

                break;
        default:
                assert_not_reached("Invalid state.");
        }

out:
        if (r < 0)
                sd_ipv4acd_stop(ll);

        return 1;
}

static void ipv4acd_on_conflict(sd_ipv4acd *ll) {
        _cleanup_free_ char *address = NULL;
        union in_addr_union addr = { .in.s_addr = ll->address };
        int r;

        assert(ll);

        ll->n_conflict++;

        r = in_addr_to_string(AF_INET, &addr, &address);
        if (r >= 0)
                log_ipv4acd(ll, "Conflict on %s (%u)", address, ll->n_conflict);

        ipv4acd_stop(ll);

        ipv4acd_client_notify(ll, SD_IPV4ACD_EVENT_CONFLICT);
}

static int ipv4acd_on_packet(
                sd_event_source *s,
                int fd,
                uint32_t revents,
                void *userdata) {

        sd_ipv4acd *ll = userdata;
        struct ether_arp packet;
        ssize_t n;
        int r;

        assert(s);
        assert(ll);
        assert(fd >= 0);

        n = recv(fd, &packet, sizeof(struct ether_arp), 0);
        if (n < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                r = log_ipv4acd_errno(ll, errno, "Failed to read ARP packet: %m");
                goto out;
        }
        if ((size_t) n != sizeof(struct ether_arp)) {
                log_ipv4acd(ll, "Ignoring too short ARP packet.");
                return 0;
        }

        switch (ll->state) {

        case IPV4ACD_STATE_ANNOUNCING:
        case IPV4ACD_STATE_RUNNING:

                if (ipv4acd_arp_conflict(ll, &packet)) {
                        usec_t ts;

                        assert_se(sd_event_now(ll->event, clock_boottime_or_monotonic(), &ts) >= 0);

                        /* Defend address */
                        if (ts > ll->defend_window) {
                                ll->defend_window = ts + DEFEND_INTERVAL * USEC_PER_SEC;
                                r = arp_send_announcement(ll->fd, ll->ifindex, ll->address, &ll->mac_addr);
                                if (r < 0) {
                                        log_ipv4acd_errno(ll, r, "Failed to send ARP announcement: %m");
                                        goto out;
                                } else
                                        log_ipv4acd(ll, "DEFEND");

                        } else
                                ipv4acd_on_conflict(ll);
                }
                break;

        case IPV4ACD_STATE_WAITING_PROBE:
        case IPV4ACD_STATE_PROBING:
        case IPV4ACD_STATE_WAITING_ANNOUNCE:
                /* BPF ensures this packet indicates a conflict */
                ipv4acd_on_conflict(ll);
                break;

        default:
                assert_not_reached("Invalid state.");
        }

out:
        if (r < 0)
                sd_ipv4acd_stop(ll);

        return 1;
}

int sd_ipv4acd_set_ifindex(sd_ipv4acd *ll, int ifindex) {
        assert_return(ll, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(ll->state == IPV4ACD_STATE_INIT, -EBUSY);

        ll->ifindex = ifindex;

        return 0;
}

int sd_ipv4acd_set_mac(sd_ipv4acd *ll, const struct ether_addr *addr) {
        assert_return(ll, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(ll->state == IPV4ACD_STATE_INIT, -EBUSY);

        memcpy(&ll->mac_addr, addr, ETH_ALEN);

        return 0;
}

int sd_ipv4acd_detach_event(sd_ipv4acd *ll) {
        assert_return(ll, -EINVAL);

        ll->event = sd_event_unref(ll->event);

        return 0;
}

int sd_ipv4acd_attach_event(sd_ipv4acd *ll, sd_event *event, int64_t priority) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(!ll->event, -EBUSY);

        if (event)
                ll->event = sd_event_ref(event);
        else {
                r = sd_event_default(&ll->event);
                if (r < 0)
                        return r;
        }

        ll->event_priority = priority;

        return 0;
}

int sd_ipv4acd_set_callback(sd_ipv4acd *ll, sd_ipv4acd_callback_t cb, void *userdata) {
        assert_return(ll, -EINVAL);

        ll->callback = cb;
        ll->userdata = userdata;

        return 0;
}

int sd_ipv4acd_set_address(sd_ipv4acd *ll, const struct in_addr *address) {
        assert_return(ll, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(ll->state == IPV4ACD_STATE_INIT, -EBUSY);

        ll->address = address->s_addr;

        return 0;
}

int sd_ipv4acd_is_running(sd_ipv4acd *ll) {
        assert_return(ll, false);

        return ll->state != IPV4ACD_STATE_INIT;
}

int sd_ipv4acd_start(sd_ipv4acd *ll) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(ll->event, -EINVAL);
        assert_return(ll->ifindex > 0, -EINVAL);
        assert_return(ll->address != 0, -EINVAL);
        assert_return(!ether_addr_is_null(&ll->mac_addr), -EINVAL);
        assert_return(ll->state == IPV4ACD_STATE_INIT, -EBUSY);

        ll->defend_window = 0;

        r = arp_network_bind_raw_socket(ll->ifindex, ll->address, &ll->mac_addr);
        if (r < 0)
                goto out;

        ll->fd = safe_close(ll->fd);
        ll->fd = r;

        r = sd_event_add_io(ll->event, &ll->receive_message, ll->fd,
                            EPOLLIN, ipv4acd_on_packet, ll);
        if (r < 0)
                goto out;

        r = sd_event_source_set_priority(ll->receive_message, ll->event_priority);
        if (r < 0)
                goto out;

        r = sd_event_source_set_description(ll->receive_message, "ipv4acd-receive-message");
        if (r < 0)
                goto out;

        r = ipv4acd_set_next_wakeup(ll, 0, 0);
        if (r < 0)
                goto out;
out:
        if (r < 0) {
                ipv4acd_stop(ll);
                return r;
        }

        return 0;
}
