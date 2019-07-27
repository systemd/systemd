/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd-id128.h"
#include "sd-ipv4acd.h"
#include "sd-ipv4ll.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "list.h"
#include "random-util.h"
#include "siphash24.h"
#include "sparse-endian.h"
#include "string-util.h"
#include "util.h"

#define IPV4LL_NETWORK UINT32_C(0xA9FE0000)
#define IPV4LL_NETMASK UINT32_C(0xFFFF0000)

#define IPV4LL_DONT_DESTROY(ll) \
        _cleanup_(sd_ipv4ll_unrefp) _unused_ sd_ipv4ll *_dont_destroy_##ll = sd_ipv4ll_ref(ll)

struct sd_ipv4ll {
        unsigned n_ref;

        sd_ipv4acd *acd;

        be32_t address; /* the address pushed to ACD */
        struct ether_addr mac;

        struct {
                le64_t value;
                le64_t generation;
        } seed;
        bool seed_set;

        /* External */
        be32_t claimed_address;

        sd_ipv4ll_callback_t callback;
        void* userdata;
};

#define log_ipv4ll_errno(ll, error, fmt, ...) log_internal(LOG_DEBUG, error, PROJECT_FILE, __LINE__, __func__, "IPV4LL: " fmt, ##__VA_ARGS__)
#define log_ipv4ll(ll, fmt, ...) log_ipv4ll_errno(ll, 0, fmt, ##__VA_ARGS__)

static void ipv4ll_on_acd(sd_ipv4acd *ll, int event, void *userdata);

static sd_ipv4ll *ipv4ll_free(sd_ipv4ll *ll) {
        assert(ll);

        sd_ipv4acd_unref(ll->acd);
        return mfree(ll);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_ipv4ll, sd_ipv4ll, ipv4ll_free);

int sd_ipv4ll_new(sd_ipv4ll **ret) {
        _cleanup_(sd_ipv4ll_unrefp) sd_ipv4ll *ll = NULL;
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

        *ret = TAKE_PTR(ll);

        return 0;
}

int sd_ipv4ll_stop(sd_ipv4ll *ll) {
        assert_return(ll, -EINVAL);

        return sd_ipv4acd_stop(ll->acd);
}

int sd_ipv4ll_set_ifindex(sd_ipv4ll *ll, int ifindex) {
        assert_return(ll, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);
        assert_return(sd_ipv4ll_is_running(ll) == 0, -EBUSY);

        return sd_ipv4acd_set_ifindex(ll->acd, ifindex);
}

int sd_ipv4ll_set_mac(sd_ipv4ll *ll, const struct ether_addr *addr) {
        int r;

        assert_return(ll, -EINVAL);
        assert_return(addr, -EINVAL);
        assert_return(sd_ipv4ll_is_running(ll) == 0, -EBUSY);

        r = sd_ipv4acd_set_mac(ll->acd, addr);
        if (r < 0)
                return r;

        ll->mac = *addr;
        return 0;
}

int sd_ipv4ll_detach_event(sd_ipv4ll *ll) {
        assert_return(ll, -EINVAL);

        return sd_ipv4acd_detach_event(ll->acd);
}

int sd_ipv4ll_attach_event(sd_ipv4ll *ll, sd_event *event, int64_t priority) {
        assert_return(ll, -EINVAL);

        return sd_ipv4acd_attach_event(ll->acd, event, priority);
}

int sd_ipv4ll_set_callback(sd_ipv4ll *ll, sd_ipv4ll_callback_t cb, void *userdata) {
        assert_return(ll, -EINVAL);

        ll->callback = cb;
        ll->userdata = userdata;

        return 0;
}

int sd_ipv4ll_get_address(sd_ipv4ll *ll, struct in_addr *address) {
        assert_return(ll, -EINVAL);
        assert_return(address, -EINVAL);

        if (ll->claimed_address == 0)
                return -ENOENT;

        address->s_addr = ll->claimed_address;

        return 0;
}

int sd_ipv4ll_set_address_seed(sd_ipv4ll *ll, uint64_t seed) {
        assert_return(ll, -EINVAL);
        assert_return(sd_ipv4ll_is_running(ll) == 0, -EBUSY);

        ll->seed.value = htole64(seed);
        ll->seed_set = true;

        return 0;
}

int sd_ipv4ll_is_running(sd_ipv4ll *ll) {
        assert_return(ll, false);

        return sd_ipv4acd_is_running(ll->acd);
}

static bool ipv4ll_address_is_valid(const struct in_addr *address) {
        assert(address);

        if (!in_addr_is_link_local(AF_INET, (const union in_addr_union *) address))
                return false;

        return !IN_SET(be32toh(address->s_addr) & 0x0000FF00U, 0x0000U, 0xFF00U);
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

#define PICK_HASH_KEY SD_ID128_MAKE(15,ac,82,a6,d6,3f,49,78,98,77,5d,0c,69,02,94,0b)

static int ipv4ll_pick_address(sd_ipv4ll *ll) {
        _cleanup_free_ char *address = NULL;
        be32_t addr;

        assert(ll);

        do {
                uint64_t h;

                h = siphash24(&ll->seed, sizeof(ll->seed), PICK_HASH_KEY.bytes);

                /* Increase the generation counter by one */
                ll->seed.generation = htole64(le64toh(ll->seed.generation) + 1);

                addr = htobe32((h & UINT32_C(0x0000FFFF)) | IPV4LL_NETWORK);
        } while (addr == ll->address ||
                 IN_SET(be32toh(addr) & 0x0000FF00U, 0x0000U, 0xFF00U));

        (void) in_addr_to_string(AF_INET, &(union in_addr_union) { .in.s_addr = addr }, &address);
        log_ipv4ll(ll, "Picked new IP address %s.", strna(address));

        return sd_ipv4ll_set_address(ll, &(struct in_addr) { addr });
}

#define MAC_HASH_KEY SD_ID128_MAKE(df,04,22,98,3f,ad,14,52,f9,87,2e,d1,9c,70,e2,f2)

static int ipv4ll_start_internal(sd_ipv4ll *ll, bool reset_generation) {
        int r;
        bool picked_address = false;

        assert_return(ll, -EINVAL);
        assert_return(!ether_addr_is_null(&ll->mac), -EINVAL);

        /* If no random seed is set, generate some from the MAC address */
        if (!ll->seed_set)
                ll->seed.value = htole64(siphash24(ll->mac.ether_addr_octet, ETH_ALEN, MAC_HASH_KEY.bytes));

        if (reset_generation)
                ll->seed.generation = 0;

        if (ll->address == 0) {
                r = ipv4ll_pick_address(ll);
                if (r < 0)
                        return r;

                picked_address = true;
        }

        r = sd_ipv4acd_start(ll->acd);
        if (r < 0) {

                /* We couldn't start? If so, let's forget the picked address again, the user might make a change and
                 * retry, and we want the new data to take effect when picking an address. */
                if (picked_address)
                        ll->address = 0;

                return r;
        }

        return 0;
}

int sd_ipv4ll_start(sd_ipv4ll *ll) {
        assert_return(ll, -EINVAL);
        assert_return(sd_ipv4ll_is_running(ll) == 0, -EBUSY);

        return ipv4ll_start_internal(ll, true);
}

int sd_ipv4ll_restart(sd_ipv4ll *ll) {
        ll->address = 0;

        return ipv4ll_start_internal(ll, false);
}

static void ipv4ll_client_notify(sd_ipv4ll *ll, int event) {
        assert(ll);

        if (ll->callback)
                ll->callback(ll, event, ll->userdata);
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
                        r = sd_ipv4ll_restart(ll);
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
