/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.

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
#include "refcnt.h"

#include "ipv4ll-internal.h"
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

typedef enum IPv4LLTrigger{
        IPV4LL_TRIGGER_NULL,
        IPV4LL_TRIGGER_PACKET,
        IPV4LL_TRIGGER_TIMEOUT,
        _IPV4LL_TRIGGER_MAX,
        _IPV4LL_TRIGGER_INVALID = -1
} IPv4LLTrigger;

typedef enum IPv4LLState {
        IPV4LL_STATE_INIT,
        IPV4LL_STATE_WAITING_PROBE,
        IPV4LL_STATE_PROBING,
        IPV4LL_STATE_WAITING_ANNOUNCE,
        IPV4LL_STATE_ANNOUNCING,
        IPV4LL_STATE_RUNNING,
        IPV4LL_STATE_STOPPED,
        _IPV4LL_STATE_MAX,
        _IPV4LL_STATE_INVALID = -1
} IPv4LLState;

struct sd_ipv4ll {
        RefCount n_ref;

        IPv4LLState state;
        int index;
        int fd;
        union sockaddr_union link;
        int iteration;
        int conflict;
        sd_event_source *receive_message;
        sd_event_source *timer;
        usec_t next_wakeup;
        usec_t defend_window;
        int next_wakeup_valid;
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

static void ipv4ll_run_state_machine(sd_ipv4ll *ll, IPv4LLTrigger trigger, void *trigger_data);

static void ipv4ll_set_state(sd_ipv4ll *ll, IPv4LLState st, int reset_counter) {

        assert(ll);
        assert(st < _IPV4LL_STATE_MAX);

        if (st == ll->state && !reset_counter) {
                ll->iteration++;
        } else {
                ll->state = st;
                ll->iteration = 0;
        }
}

static sd_ipv4ll *ipv4ll_client_notify(sd_ipv4ll *ll, int event) {
        assert(ll);

        if (ll->cb) {
                ll = sd_ipv4ll_ref(ll);
                ll->cb(ll, event, ll->userdata);
                ll = sd_ipv4ll_unref(ll);
        }

        return ll;
}

static sd_ipv4ll *ipv4ll_stop(sd_ipv4ll *ll, int event) {
        assert(ll);

        ll->receive_message = sd_event_source_unref(ll->receive_message);
        ll->fd = safe_close(ll->fd);

        ll->timer = sd_event_source_unref(ll->timer);

        log_ipv4ll(ll, "STOPPED");

        ll = ipv4ll_client_notify(ll, event);

        if (ll) {
                ll->claimed_address = 0;
                ipv4ll_set_state (ll, IPV4LL_STATE_INIT, 1);
        }

        return ll;
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

static int ipv4ll_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_ipv4ll *ll = (sd_ipv4ll*)userdata;

        assert(ll);

        ll->next_wakeup_valid = 0;
        ipv4ll_run_state_machine(ll, IPV4LL_TRIGGER_TIMEOUT, NULL);

        return 0;
}

static void ipv4ll_set_next_wakeup(sd_ipv4ll *ll, int sec, int random_sec) {
        usec_t next_timeout = 0;
        usec_t time_now = 0;

        assert(sec >= 0);
        assert(random_sec >= 0);
        assert(ll);

        next_timeout = sec * USEC_PER_SEC;

        if (random_sec)
                next_timeout += random_u32() % (random_sec * USEC_PER_SEC);

        if (sd_event_now(ll->event, CLOCK_MONOTONIC, &time_now) < 0)
                time_now = now(CLOCK_MONOTONIC);

        ll->next_wakeup = time_now + next_timeout;
        ll->next_wakeup_valid = 1;
}

static bool ipv4ll_arp_conflict (sd_ipv4ll *ll, struct ether_arp *arp) {
        assert(ll);
        assert(arp);

        if (memcmp(arp->arp_spa, &ll->address, sizeof(ll->address)) == 0 &&
            memcmp(arp->arp_sha, &ll->mac_addr, ETH_ALEN) != 0)
                return true;

        return false;
}

static bool ipv4ll_arp_probe_conflict (sd_ipv4ll *ll, struct ether_arp *arp) {
        assert(ll);
        assert(arp);

        if (ipv4ll_arp_conflict(ll, arp))
                return true;

        if (memcmp(arp->arp_tpa, &ll->address, sizeof(ll->address)) == 0 &&
            memcmp(arp->arp_sha, &ll->mac_addr, ETH_ALEN))
                return true;

        return false;
}

static void ipv4ll_run_state_machine(sd_ipv4ll *ll, IPv4LLTrigger trigger, void *trigger_data) {
        struct ether_arp out_packet;
        int out_packet_ready = 0;
        int r = 0;

        assert(ll);
        assert(trigger < _IPV4LL_TRIGGER_MAX);

        if (ll->state == IPV4LL_STATE_INIT) {

                log_ipv4ll(ll, "PROBE");
                ipv4ll_set_state(ll, IPV4LL_STATE_WAITING_PROBE, 1);
                ipv4ll_set_next_wakeup(ll, 0, PROBE_WAIT);

        } else if ((ll->state == IPV4LL_STATE_WAITING_PROBE && trigger == IPV4LL_TRIGGER_TIMEOUT) ||
                (ll->state == IPV4LL_STATE_PROBING && trigger == IPV4LL_TRIGGER_TIMEOUT && ll->iteration < PROBE_NUM-2)) {

                /* Send a probe */
                arp_packet_probe(&out_packet, ll->address, &ll->mac_addr);
                out_packet_ready = 1;
                ipv4ll_set_state(ll, IPV4LL_STATE_PROBING, 0);

                ipv4ll_set_next_wakeup(ll, PROBE_MIN, (PROBE_MAX-PROBE_MIN));

        } else if (ll->state == IPV4LL_STATE_PROBING && trigger == IPV4LL_TRIGGER_TIMEOUT && ll->iteration >= PROBE_NUM-2) {

                /* Send the last probe */
                arp_packet_probe(&out_packet, ll->address, &ll->mac_addr);
                out_packet_ready = 1;
                ipv4ll_set_state(ll, IPV4LL_STATE_WAITING_ANNOUNCE, 1);

                ipv4ll_set_next_wakeup(ll, ANNOUNCE_WAIT, 0);

        } else if ((ll->state == IPV4LL_STATE_WAITING_ANNOUNCE && trigger == IPV4LL_TRIGGER_TIMEOUT) ||
                (ll->state == IPV4LL_STATE_ANNOUNCING && trigger == IPV4LL_TRIGGER_TIMEOUT && ll->iteration < ANNOUNCE_NUM-1)) {

                /* Send announcement packet */
                arp_packet_announcement(&out_packet, ll->address, &ll->mac_addr);
                out_packet_ready = 1;
                ipv4ll_set_state(ll, IPV4LL_STATE_ANNOUNCING, 0);

                ipv4ll_set_next_wakeup(ll, ANNOUNCE_INTERVAL, 0);

                if (ll->iteration == 0) {
                        log_ipv4ll(ll, "ANNOUNCE");
                        ll->claimed_address = ll->address;
                        ll = ipv4ll_client_notify(ll, IPV4LL_EVENT_BIND);
                        if (!ll || ll->state == IPV4LL_STATE_STOPPED)
                                goto out;

                        ll->conflict = 0;
                }

        } else if ((ll->state == IPV4LL_STATE_ANNOUNCING && trigger == IPV4LL_TRIGGER_TIMEOUT &&
                    ll->iteration >= ANNOUNCE_NUM-1)) {

                ipv4ll_set_state(ll, IPV4LL_STATE_RUNNING, 0);
                ll->next_wakeup_valid = 0;

        } else if (trigger == IPV4LL_TRIGGER_PACKET) {

                int conflicted = 0;
                usec_t time_now;
                struct ether_arp* in_packet = (struct ether_arp*)trigger_data;

                assert(in_packet);

                if (IN_SET(ll->state, IPV4LL_STATE_ANNOUNCING, IPV4LL_STATE_RUNNING)) {

                        if (ipv4ll_arp_conflict(ll, in_packet)) {

                                r = sd_event_now(ll->event, CLOCK_MONOTONIC, &time_now);
                                if (r < 0)
                                        goto out;

                                /* Defend address */
                                if (time_now > ll->defend_window) {
                                        ll->defend_window = time_now + DEFEND_INTERVAL * USEC_PER_SEC;
                                        arp_packet_announcement(&out_packet, ll->address, &ll->mac_addr);
                                        out_packet_ready = 1;
                                } else
                                        conflicted = 1;
                        }

                } else if (IN_SET(ll->state, IPV4LL_STATE_WAITING_PROBE,
                                             IPV4LL_STATE_PROBING,
                                             IPV4LL_STATE_WAITING_ANNOUNCE)) {

                        conflicted = ipv4ll_arp_probe_conflict(ll, in_packet);
                }

                if (conflicted) {
                        log_ipv4ll(ll, "CONFLICT");
                        ll = ipv4ll_client_notify(ll, IPV4LL_EVENT_CONFLICT);
                        if (!ll || ll->state == IPV4LL_STATE_STOPPED)
                                goto out;

                        ll->claimed_address = 0;

                        /* Pick a new address */
                        r = ipv4ll_pick_address(ll, &ll->address);
                        if (r < 0)
                                goto out;
                        ll->conflict++;
                        ll->defend_window = 0;
                        ipv4ll_set_state(ll, IPV4LL_STATE_WAITING_PROBE, 1);

                        if (ll->conflict >= MAX_CONFLICTS) {
                                log_ipv4ll(ll, "MAX_CONFLICTS");
                                ipv4ll_set_next_wakeup(ll, RATE_LIMIT_INTERVAL, PROBE_WAIT);
                        } else
                                ipv4ll_set_next_wakeup(ll, 0, PROBE_WAIT);

                }
        }

        if (out_packet_ready) {
                r = arp_network_send_raw_socket(ll->fd, &ll->link, &out_packet);
                if (r < 0) {
                        log_ipv4ll(ll, "failed to send arp packet out");
                        goto out;
                }
        }

        if (ll->next_wakeup_valid) {
                ll->timer = sd_event_source_unref(ll->timer);
                r = sd_event_add_time(ll->event, &ll->timer, CLOCK_MONOTONIC,
                                      ll->next_wakeup, 0, ipv4ll_timer, ll);
                if (r < 0)
                        goto out;

                r = sd_event_source_set_priority(ll->timer, ll->event_priority);
                if (r < 0)
                        goto out;
        }

out:
        if (r < 0 && ll)
                ipv4ll_stop(ll, r);
}

static int ipv4ll_receive_message(sd_event_source *s, int fd,
                                  uint32_t revents, void *userdata) {
        int r;
        struct ether_arp arp;
        sd_ipv4ll *ll = (sd_ipv4ll*)userdata;

        assert(ll);

        r = read(fd, &arp, sizeof(struct ether_arp));
        if (r < (int) sizeof(struct ether_arp))
                return 0;

        r = arp_packet_verify_headers(&arp);
        if (r < 0)
                return 0;

        ipv4ll_run_state_machine(ll, IPV4LL_TRIGGER_PACKET, &arp);

        return 0;
}

int sd_ipv4ll_set_index(sd_ipv4ll *ll, int interface_index) {
        assert_return(ll, -EINVAL);
        assert_return(interface_index > 0, -EINVAL);
        assert_return(IN_SET(ll->state, IPV4LL_STATE_INIT,
                             IPV4LL_STATE_STOPPED), -EBUSY);

        ll->index = interface_index;

        return 0;
}

int sd_ipv4ll_set_mac(sd_ipv4ll *ll, const struct ether_addr *addr) {
        bool need_restart = false;

        assert_return(ll, -EINVAL);
        assert_return(addr, -EINVAL);

        if (memcmp(&ll->mac_addr, addr, ETH_ALEN) == 0)
                return 0;

        if (!IN_SET(ll->state, IPV4LL_STATE_INIT, IPV4LL_STATE_STOPPED)) {
                log_ipv4ll(ll, "Changing MAC address on running IPv4LL "
                           "client, restarting");
                ll = ipv4ll_stop(ll, IPV4LL_EVENT_STOP);
                need_restart = true;
        }

        if (!ll)
                return 0;

        memcpy(&ll->mac_addr, addr, ETH_ALEN);

        if (need_restart)
                sd_ipv4ll_start(ll);

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
                        ipv4ll_stop(ll, IPV4LL_EVENT_STOP);
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

int sd_ipv4ll_set_address_seed (sd_ipv4ll *ll, uint8_t seed[8]) {
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
        assert_return(ll, -EINVAL);

        return !IN_SET(ll->state, IPV4LL_STATE_INIT, IPV4LL_STATE_STOPPED);
}

#define HASH_KEY SD_ID128_MAKE(df,04,22,98,3f,ad,14,52,f9,87,2e,d1,9c,70,e2,f2)

int sd_ipv4ll_start (sd_ipv4ll *ll) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(ll->event, -EINVAL);
        assert_return(ll->index > 0, -EINVAL);
        assert_return(IN_SET(ll->state, IPV4LL_STATE_INIT,
                             IPV4LL_STATE_STOPPED), -EBUSY);

        ll->state = IPV4LL_STATE_INIT;

        r = arp_network_bind_raw_socket(ll->index, &ll->link);

        if (r < 0)
                goto out;

        ll->fd = r;
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

        ipv4ll_set_state (ll, IPV4LL_STATE_INIT, 1);

        r = sd_event_add_io(ll->event, &ll->receive_message, ll->fd,
                            EPOLLIN, ipv4ll_receive_message, ll);
        if (r < 0)
                goto out;

        r = sd_event_source_set_priority(ll->receive_message, ll->event_priority);
        if (r < 0)
                goto out;

        r = sd_event_add_time(ll->event,
                              &ll->timer,
                              CLOCK_MONOTONIC,
                              now(CLOCK_MONOTONIC), 0,
                              ipv4ll_timer, ll);

        if (r < 0)
                goto out;

        r = sd_event_source_set_priority(ll->timer, ll->event_priority);

out:
        if (r < 0)
                ipv4ll_stop(ll, IPV4LL_EVENT_STOP);

        return 0;
}

int sd_ipv4ll_stop(sd_ipv4ll *ll) {
        ipv4ll_stop(ll, IPV4LL_EVENT_STOP);
        if (ll)
                ipv4ll_set_state(ll, IPV4LL_STATE_STOPPED, 1);

        return 0;
}

sd_ipv4ll *sd_ipv4ll_ref(sd_ipv4ll *ll) {
        if (ll)
                assert_se(REFCNT_INC(ll->n_ref) >= 2);

        return ll;
}

sd_ipv4ll *sd_ipv4ll_unref(sd_ipv4ll *ll) {
        if (ll && REFCNT_DEC(ll->n_ref) <= 0) {
                ll->receive_message =
                        sd_event_source_unref(ll->receive_message);
                ll->fd = safe_close(ll->fd);

                ll->timer = sd_event_source_unref(ll->timer);

                sd_ipv4ll_detach_event(ll);

                free(ll->random_data);
                free(ll->random_data_state);
                free(ll);

                return NULL;
        }

        return ll;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_ipv4ll*, sd_ipv4ll_unref);
#define _cleanup_ipv4ll_free_ _cleanup_(sd_ipv4ll_unrefp)

int sd_ipv4ll_new(sd_ipv4ll **ret) {
        _cleanup_ipv4ll_free_ sd_ipv4ll *ll = NULL;

        assert_return(ret, -EINVAL);

        ll = new0(sd_ipv4ll, 1);
        if (!ll)
                return -ENOMEM;

        ll->n_ref = REFCNT_INIT;
        ll->state = IPV4LL_STATE_INIT;
        ll->index = -1;
        ll->fd = -1;

        *ret = ll;
        ll = NULL;

        return 0;
}
