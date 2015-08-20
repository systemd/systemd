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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "util.h"
#include "siphash24.h"
#include "list.h"
#include "random-util.h"
#include "event-util.h"

#include "arp-util.h"
#include "sd-ipv4ll.h"

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

#define IPV4LL_NETWORK 0xA9FE0000L
#define IPV4LL_NETMASK 0xFFFF0000L

#define log_ipv4ll(ll, fmt, ...) log_internal(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, "IPv4LL: " fmt, ##__VA_ARGS__)

#define IPV4LL_DONT_DESTROY(ll) \
        _cleanup_ipv4ll_unref_ _unused_ sd_ipv4ll *_dont_destroy_##ll = sd_ipv4ll_ref(ll)

typedef enum IPv4LLState {
        IPV4LL_STATE_INIT,
        IPV4LL_STATE_WAITING_PROBE,
        IPV4LL_STATE_PROBING,
        IPV4LL_STATE_WAITING_ANNOUNCE,
        IPV4LL_STATE_ANNOUNCING,
        IPV4LL_STATE_RUNNING,
        _IPV4LL_STATE_MAX,
        _IPV4LL_STATE_INVALID = -1
} IPv4LLState;

struct sd_ipv4ll {
        unsigned n_ref;

        IPv4LLState state;
        int index;
        int fd;
        int iteration;
        int conflict;
        sd_event_source *receive_message;
        sd_event_source *timer;
        usec_t defend_window;
        be32_t address;
        struct random_data *random_data;
        char *random_data_state;
        /* External */
        be32_t claimed_address;
        struct ether_addr mac_addr;
        sd_event *event;
        int event_priority;
        sd_ipv4ll_cb_t cb;
        void* userdata;
};

sd_ipv4ll *sd_ipv4ll_ref(sd_ipv4ll *ll) {
        if (!ll)
                return NULL;

        assert(ll->n_ref >= 1);
        ll->n_ref++;

        return ll;
}

sd_ipv4ll *sd_ipv4ll_unref(sd_ipv4ll *ll) {
        if (!ll)
                return NULL;

        assert(ll->n_ref >= 1);
        ll->n_ref--;

        if (ll->n_ref > 0)
                return NULL;

        ll->receive_message = sd_event_source_unref(ll->receive_message);
        ll->fd = safe_close(ll->fd);

        ll->timer = sd_event_source_unref(ll->timer);

        sd_ipv4ll_detach_event(ll);

        free(ll->random_data);
        free(ll->random_data_state);
        free(ll);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_ipv4ll*, sd_ipv4ll_unref);
#define _cleanup_ipv4ll_unref_ _cleanup_(sd_ipv4ll_unrefp)

int sd_ipv4ll_new(sd_ipv4ll **ret) {
        _cleanup_ipv4ll_unref_ sd_ipv4ll *ll = NULL;

        assert_return(ret, -EINVAL);

        ll = new0(sd_ipv4ll, 1);
        if (!ll)
                return -ENOMEM;

        ll->n_ref = 1;
        ll->state = IPV4LL_STATE_INIT;
        ll->index = -1;
        ll->fd = -1;

        *ret = ll;
        ll = NULL;

        return 0;
}

static void ipv4ll_set_state(sd_ipv4ll *ll, IPv4LLState st, bool reset_counter) {

        assert(ll);
        assert(st < _IPV4LL_STATE_MAX);

        if (st == ll->state && !reset_counter) {
                ll->iteration++;
        } else {
                ll->state = st;
                ll->iteration = 0;
        }
}

static void ipv4ll_client_notify(sd_ipv4ll *ll, int event) {
        assert(ll);

        if (ll->cb)
                ll->cb(ll, event, ll->userdata);
}

int sd_ipv4ll_stop(sd_ipv4ll *ll) {
        IPV4LL_DONT_DESTROY(ll);

        assert_return(ll, -EINVAL);

        ll->receive_message = sd_event_source_unref(ll->receive_message);
        ll->fd = safe_close(ll->fd);

        ll->timer = sd_event_source_unref(ll->timer);

        log_ipv4ll(ll, "STOPPED");

        ll->claimed_address = 0;
        ipv4ll_set_state (ll, IPV4LL_STATE_INIT, true);

        return 0;
}

static void ipv4ll_stop(sd_ipv4ll *ll) {
        IPV4LL_DONT_DESTROY(ll);

        assert(ll);

        sd_ipv4ll_stop(ll);

        ipv4ll_client_notify(ll, IPV4LL_EVENT_STOP);

}

static int ipv4ll_pick_address(sd_ipv4ll *ll, be32_t *address) {
        be32_t addr;
        int r;
        int32_t random;

        assert(ll);
        assert(address);
        assert(ll->random_data);

        do {
                r = random_r(ll->random_data, &random);
                if (r < 0)
                        return r;
                addr = htonl((random & 0x0000FFFF) | IPV4LL_NETWORK);
        } while (addr == ll->address ||
                (ntohl(addr) & IPV4LL_NETMASK) != IPV4LL_NETWORK ||
                (ntohl(addr) & 0x0000FF00) == 0x0000 ||
                (ntohl(addr) & 0x0000FF00) == 0xFF00);

        *address = addr;
        return 0;
}

static int ipv4ll_on_timeout(sd_event_source *s, uint64_t usec, void *userdata);

static int ipv4ll_set_next_wakeup(sd_ipv4ll *ll, int sec, int random_sec) {
        _cleanup_event_source_unref_ sd_event_source *timer = NULL;
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
                              time_now + next_timeout, 0, ipv4ll_on_timeout, ll);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(timer, ll->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(timer, "ipv4ll-timer");
        if (r < 0)
                return r;

        ll->timer = sd_event_source_unref(ll->timer);
        ll->timer = timer;
        timer = NULL;

        return 0;
}

static bool ipv4ll_arp_conflict(sd_ipv4ll *ll, struct ether_arp *arp) {
        assert(ll);
        assert(arp);

        /* see the BPF */
        if (memcmp(arp->arp_spa, &ll->address, sizeof(ll->address)) == 0)
                return true;

        /* the TPA matched instead of the SPA, this is not a conflict */
        return false;
}

static int ipv4ll_on_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ipv4ll *ll = userdata;
        int r = 0;

        assert(ll);

        switch (ll->state) {
        case IPV4LL_STATE_INIT:

                log_ipv4ll(ll, "PROBE");

                ipv4ll_set_state(ll, IPV4LL_STATE_WAITING_PROBE, true);

                if (ll->conflict >= MAX_CONFLICTS) {
                        log_ipv4ll(ll, "MAX_CONFLICTS");
                        r = ipv4ll_set_next_wakeup(ll, RATE_LIMIT_INTERVAL, PROBE_WAIT);
                        if (r < 0)
                                return r;
                } else {
                        r = ipv4ll_set_next_wakeup(ll, 0, PROBE_WAIT);
                        if (r < 0)
                                return r;
                }

                break;
        case IPV4LL_STATE_WAITING_PROBE:
        case IPV4LL_STATE_PROBING:
                /* Send a probe */
                r = arp_send_probe(ll->fd, ll->index, ll->address, &ll->mac_addr);
                if (r < 0) {
                        log_ipv4ll(ll, "Failed to send ARP probe.");
                        goto out;
                }

                if (ll->iteration < PROBE_NUM - 2) {
                        ipv4ll_set_state(ll, IPV4LL_STATE_PROBING, false);

                        r = ipv4ll_set_next_wakeup(ll, PROBE_MIN, (PROBE_MAX-PROBE_MIN));
                        if (r < 0)
                                goto out;
                } else {
                        ipv4ll_set_state(ll, IPV4LL_STATE_WAITING_ANNOUNCE, true);

                        r = ipv4ll_set_next_wakeup(ll, ANNOUNCE_WAIT, 0);
                        if (r < 0)
                                goto out;
                }

                break;

        case IPV4LL_STATE_ANNOUNCING:
                if (ll->iteration >= ANNOUNCE_NUM - 1) {
                        ipv4ll_set_state(ll, IPV4LL_STATE_RUNNING, false);

                        break;
                }
        case IPV4LL_STATE_WAITING_ANNOUNCE:
                /* Send announcement packet */
                r = arp_send_announcement(ll->fd, ll->index, ll->address, &ll->mac_addr);
                if (r < 0) {
                        log_ipv4ll(ll, "Failed to send ARP announcement.");
                        goto out;
                }

                ipv4ll_set_state(ll, IPV4LL_STATE_ANNOUNCING, false);

                r = ipv4ll_set_next_wakeup(ll, ANNOUNCE_INTERVAL, 0);
                if (r < 0)
                        goto out;

                if (ll->iteration == 0) {
                        log_ipv4ll(ll, "ANNOUNCE");
                        ll->claimed_address = ll->address;
                        ipv4ll_client_notify(ll, IPV4LL_EVENT_BIND);
                        ll->conflict = 0;
                }

                break;
        default:
                assert_not_reached("Invalid state.");
        }

out:
        if (r < 0 && ll)
                ipv4ll_stop(ll);

        return 1;
}

static int ipv4ll_on_conflict(sd_ipv4ll *ll) {
        IPV4LL_DONT_DESTROY(ll);
        int r;

        assert(ll);

        log_ipv4ll(ll, "CONFLICT");

        ll->conflict++;

        ipv4ll_client_notify(ll, IPV4LL_EVENT_CONFLICT);

        sd_ipv4ll_stop(ll);

        /* Pick a new address */
        r = ipv4ll_pick_address(ll, &ll->address);
        if (r < 0)
                return r;

        r = sd_ipv4ll_start(ll);
        if (r < 0)
                return r;

        return 0;
}

static int ipv4ll_on_packet(sd_event_source *s, int fd,
                            uint32_t revents, void *userdata) {
        sd_ipv4ll *ll = userdata;
        struct ether_arp packet;
        int r;

        assert(ll);
        assert(fd >= 0);

        r = read(fd, &packet, sizeof(struct ether_arp));
        if (r < (int) sizeof(struct ether_arp))
                goto out;

        switch (ll->state) {
        case IPV4LL_STATE_ANNOUNCING:
        case IPV4LL_STATE_RUNNING:
                if (ipv4ll_arp_conflict(ll, &packet)) {
                        usec_t ts;

                        assert_se(sd_event_now(ll->event, clock_boottime_or_monotonic(), &ts) >= 0);

                        /* Defend address */
                        if (ts > ll->defend_window) {
                                ll->defend_window = ts + DEFEND_INTERVAL * USEC_PER_SEC;
                                r = arp_send_announcement(ll->fd, ll->index, ll->address, &ll->mac_addr);
                                if (r < 0) {
                                        log_ipv4ll(ll, "Failed to send ARP announcement.");
                                        goto out;
                                }

                        } else {
                                r = ipv4ll_on_conflict(ll);
                                if (r < 0)
                                        goto out;
                        }
                }

                break;
        case IPV4LL_STATE_WAITING_PROBE:
        case IPV4LL_STATE_PROBING:
        case IPV4LL_STATE_WAITING_ANNOUNCE:
                /* BPF ensures this packet indicates a conflict */
                r = ipv4ll_on_conflict(ll);
                if (r < 0)
                        goto out;

                break;
        default:
                assert_not_reached("Invalid state.");
        }

out:
        if (r < 0 && ll)
                ipv4ll_stop(ll);

        return 1;
}

int sd_ipv4ll_set_index(sd_ipv4ll *ll, int interface_index) {
        assert_return(ll, -EINVAL);
        assert_return(interface_index > 0, -EINVAL);
        assert_return(ll->state == IPV4LL_STATE_INIT, -EBUSY);

        ll->index = interface_index;

        return 0;
}

int sd_ipv4ll_set_mac(sd_ipv4ll *ll, const struct ether_addr *addr) {
        assert_return(ll, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(ll->state == IPV4LL_STATE_INIT, -EBUSY);

        if (memcmp(&ll->mac_addr, addr, ETH_ALEN) == 0)
                return 0;

        memcpy(&ll->mac_addr, addr, ETH_ALEN);

        return 0;
}

int sd_ipv4ll_detach_event(sd_ipv4ll *ll) {
        assert_return(ll, -EINVAL);

        ll->event = sd_event_unref(ll->event);

        return 0;
}

int sd_ipv4ll_attach_event(sd_ipv4ll *ll, sd_event *event, int priority) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(!ll->event, -EBUSY);

        if (event)
                ll->event = sd_event_ref(event);
        else {
                r = sd_event_default(&ll->event);
                if (r < 0) {
                        sd_ipv4ll_stop(ll);
                        return r;
                }
        }

        ll->event_priority = priority;

        return 0;
}

int sd_ipv4ll_set_callback(sd_ipv4ll *ll, sd_ipv4ll_cb_t cb, void *userdata) {
        assert_return(ll, -EINVAL);

        ll->cb = cb;
        ll->userdata = userdata;

        return 0;
}

int sd_ipv4ll_get_address(sd_ipv4ll *ll, struct in_addr *address){
        assert_return(ll, -EINVAL);
        assert_return(address, -EINVAL);

        if (ll->claimed_address == 0) {
                return -ENOENT;
        }

        address->s_addr = ll->claimed_address;
        return 0;
}

int sd_ipv4ll_set_address_seed(sd_ipv4ll *ll, uint8_t seed[8]) {
        unsigned int entropy;
        int r;

        assert_return(ll, -EINVAL);
        assert_return(seed, -EINVAL);

        entropy = *seed;

        free(ll->random_data);
        free(ll->random_data_state);

        ll->random_data = new0(struct random_data, 1);
        ll->random_data_state = new0(char, 128);

        if (!ll->random_data || !ll->random_data_state) {
                r = -ENOMEM;
                goto error;
        }

        r = initstate_r((unsigned int)entropy, ll->random_data_state, 128, ll->random_data);
        if (r < 0)
                goto error;

error:
        if (r < 0){
                free(ll->random_data);
                free(ll->random_data_state);
                ll->random_data = NULL;
                ll->random_data_state = NULL;
        }
        return r;
}

bool sd_ipv4ll_is_running(sd_ipv4ll *ll) {
        assert_return(ll, false);

        return ll->state != IPV4LL_STATE_INIT;
}

#define HASH_KEY SD_ID128_MAKE(df,04,22,98,3f,ad,14,52,f9,87,2e,d1,9c,70,e2,f2)

int sd_ipv4ll_start(sd_ipv4ll *ll) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(ll->event, -EINVAL);
        assert_return(ll->index > 0, -EINVAL);
        assert_return(ll->state == IPV4LL_STATE_INIT, -EBUSY);

        ll->state = IPV4LL_STATE_INIT;

        ll->conflict = 0;
        ll->defend_window = 0;
        ll->claimed_address = 0;

        if (!ll->random_data) {
                uint8_t seed[8];

                /* Fallback to mac */
                siphash24(seed, &ll->mac_addr.ether_addr_octet,
                          ETH_ALEN, HASH_KEY.bytes);

                r = sd_ipv4ll_set_address_seed(ll, seed);
                if (r < 0)
                        goto out;
        }

        if (ll->address == 0) {
                r = ipv4ll_pick_address(ll, &ll->address);
                if (r < 0)
                        goto out;
        }

        r = arp_network_bind_raw_socket(ll->index, ll->address, &ll->mac_addr);
        if (r < 0)
                goto out;

        safe_close(ll->fd);
        ll->fd = r;

        ipv4ll_set_state(ll, IPV4LL_STATE_INIT, true);

        r = sd_event_add_io(ll->event, &ll->receive_message, ll->fd,
                            EPOLLIN, ipv4ll_on_packet, ll);
        if (r < 0)
                goto out;

        r = sd_event_source_set_priority(ll->receive_message, ll->event_priority);
        if (r < 0)
                goto out;

        r = sd_event_source_set_description(ll->receive_message, "ipv4ll-receive-message");
        if (r < 0)
                goto out;

        r = ipv4ll_set_next_wakeup(ll, 0, 0);
        if (r < 0)
                goto out;
out:
        if (r < 0)
                sd_ipv4ll_stop(ll);

        return 0;
}
