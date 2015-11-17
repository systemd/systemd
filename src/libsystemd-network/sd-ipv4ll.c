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
#include "sd-ipv4ll.h"

#include "alloc-util.h"
#include "event-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "random-util.h"
#include "refcnt.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "util.h"

#define IPV4LL_NETWORK 0xA9FE0000L
#define IPV4LL_NETMASK 0xFFFF0000L

#define IPV4LL_DONT_DESTROY(ll) \
        _cleanup_ipv4ll_unref_ _unused_ sd_ipv4ll *_dont_destroy_##ll = sd_ipv4ll_ref(ll)

struct sd_ipv4ll {
        unsigned n_ref;

        sd_ipv4acd *acd;
        be32_t address; /* the address pushed to ACD */
        struct random_data *random_data;
        char *random_data_state;

        /* External */
        be32_t claimed_address;
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

        sd_ipv4acd_unref(ll->acd);

        free(ll->random_data);
        free(ll->random_data_state);
        free(ll);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_ipv4ll*, sd_ipv4ll_unref);
#define _cleanup_ipv4ll_unref_ _cleanup_(sd_ipv4ll_unrefp)

static void ipv4ll_on_acd(sd_ipv4acd *ll, int event, void *userdata);

int sd_ipv4ll_new(sd_ipv4ll **ret) {
        _cleanup_ipv4ll_unref_ sd_ipv4ll *ll = NULL;
        int r;

        assert_return(ret, -EINVAL);

        ll = new0(sd_ipv4ll, 1);
        if (!ll)
                return -ENOMEM;

        ll->n_ref = 1;

        r = sd_ipv4acd_new(&ll->acd);
        if (r < 0)
                return r;

        r = sd_ipv4acd_set_callback(ll->acd, ipv4ll_on_acd, ll);
        if (r < 0)
                return r;

        *ret = ll;
        ll = NULL;

        return 0;
}

int sd_ipv4ll_stop(sd_ipv4ll *ll) {
        int r;

        assert_return(ll, -EINVAL);

        r = sd_ipv4acd_stop(ll->acd);
        if (r < 0)
                return r;

        return 0;
}

int sd_ipv4ll_set_index(sd_ipv4ll *ll, int interface_index) {
        assert_return(ll, -EINVAL);

        return sd_ipv4acd_set_index(ll->acd, interface_index);
}

#define HASH_KEY SD_ID128_MAKE(df,04,22,98,3f,ad,14,52,f9,87,2e,d1,9c,70,e2,f2)

int sd_ipv4ll_set_mac(sd_ipv4ll *ll, const struct ether_addr *addr) {
        int r;

        assert_return(ll, -EINVAL);

        if (!ll->random_data) {
                uint64_t seed;

                /* If no random data is set, generate some from the MAC */
                seed = siphash24(&addr->ether_addr_octet, ETH_ALEN, HASH_KEY.bytes);

                assert_cc(sizeof(unsigned) <= 8);

                r = sd_ipv4ll_set_address_seed(ll, (unsigned) htole64(seed));
                if (r < 0)
                        return r;
        }

        return sd_ipv4acd_set_mac(ll->acd, addr);
}

int sd_ipv4ll_detach_event(sd_ipv4ll *ll) {
        assert_return(ll, -EINVAL);

        return sd_ipv4acd_detach_event(ll->acd);
}

int sd_ipv4ll_attach_event(sd_ipv4ll *ll, sd_event *event, int priority) {
        int r;

        assert_return(ll, -EINVAL);

        r = sd_ipv4acd_attach_event(ll->acd, event, priority);
        if (r < 0)
                return r;

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

        if (ll->claimed_address == 0)
                return -ENOENT;

        address->s_addr = ll->claimed_address;

        return 0;
}

int sd_ipv4ll_set_address_seed(sd_ipv4ll *ll, unsigned seed) {
        _cleanup_free_ struct random_data *random_data = NULL;
        _cleanup_free_ char *random_data_state = NULL;
        int r;

        assert_return(ll, -EINVAL);

        random_data = new0(struct random_data, 1);
        if (!random_data)
                return -ENOMEM;

        random_data_state = new0(char, 128);
        if (!random_data_state)
                return -ENOMEM;

        r = initstate_r(seed, random_data_state, 128, random_data);
        if (r < 0)
                return r;

        free(ll->random_data);
        ll->random_data = random_data;
        random_data = NULL;

        free(ll->random_data_state);
        ll->random_data_state = random_data_state;
        random_data_state = NULL;

        return 0;
}

int sd_ipv4ll_is_running(sd_ipv4ll *ll) {
        assert_return(ll, false);

        return sd_ipv4acd_is_running(ll->acd);
}

static bool ipv4ll_address_is_valid(const struct in_addr *address) {
        uint32_t addr;

        assert(address);

        if (!in_addr_is_link_local(AF_INET, (const union in_addr_union *) address))
                return false;

        addr = be32toh(address->s_addr);

        if ((addr & 0x0000FF00) == 0x0000 ||
            (addr & 0x0000FF00) == 0xFF00)
                return false;

        return true;
}

int sd_ipv4ll_set_address(sd_ipv4ll *ll, const struct in_addr *address) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(ipv4ll_address_is_valid(address), -EINVAL);

        r = sd_ipv4acd_set_address(ll->acd, address);
        if (r < 0)
                return r;

        ll->address = address->s_addr;

        return 0;
}

static int ipv4ll_pick_address(sd_ipv4ll *ll) {
        struct in_addr in_addr;
        be32_t addr;
        int r;
        int32_t random;

        assert(ll);
        assert(ll->random_data);

        do {
                r = random_r(ll->random_data, &random);
                if (r < 0)
                        return r;
                addr = htonl((random & 0x0000FFFF) | IPV4LL_NETWORK);
        } while (addr == ll->address ||
                (ntohl(addr) & 0x0000FF00) == 0x0000 ||
                (ntohl(addr) & 0x0000FF00) == 0xFF00);

        in_addr.s_addr = addr;

        r = sd_ipv4ll_set_address(ll, &in_addr);
        if (r < 0)
                return r;

        return 0;
}

int sd_ipv4ll_start(sd_ipv4ll *ll) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(ll->random_data, -EINVAL);

        if (ll->address == 0) {
                r = ipv4ll_pick_address(ll);
                if (r < 0)
                        return r;
        }

        r = sd_ipv4acd_start(ll->acd);
        if (r < 0)
                return r;

        return 0;
}

static void ipv4ll_client_notify(sd_ipv4ll *ll, int event) {
        assert(ll);

        if (ll->cb)
                ll->cb(ll, event, ll->userdata);
}

void ipv4ll_on_acd(sd_ipv4acd *acd, int event, void *userdata) {
        sd_ipv4ll *ll = userdata;
        IPV4LL_DONT_DESTROY(ll);
        int r;

        assert(acd);
        assert(ll);

        switch (event) {
        case SD_IPV4ACD_EVENT_STOP:
                ipv4ll_client_notify(ll, SD_IPV4LL_EVENT_STOP);

                ll->claimed_address = 0;

                break;
        case SD_IPV4ACD_EVENT_BIND:
                ll->claimed_address = ll->address;
                ipv4ll_client_notify(ll, SD_IPV4LL_EVENT_BIND);

                break;
        case SD_IPV4ACD_EVENT_CONFLICT:
                /* if an address was already bound we must call up to the
                   user to handle this, otherwise we just try again */
                if (ll->claimed_address != 0) {
                        ipv4ll_client_notify(ll, SD_IPV4LL_EVENT_CONFLICT);

                        ll->claimed_address = 0;
                } else {
                        r = ipv4ll_pick_address(ll);
                        if (r < 0)
                                goto error;

                        r = sd_ipv4acd_start(ll->acd);
                        if (r < 0)
                                goto error;
                }

                break;
        default:
                assert_not_reached("Invalid IPv4ACD event.");
        }

        return;

error:
        ipv4ll_client_notify(ll, SD_IPV4LL_EVENT_STOP);
}
