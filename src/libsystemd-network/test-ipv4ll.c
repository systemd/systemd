/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <netinet/if_ether.h>
#include <stdio.h>

#include "sd-event.h"
#include "sd-ipv4ll.h"

#include "arp-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "tests.h"

static bool verbose = false;
static bool extended = false;
static int test_fd[2];

static int basic_request_handler_bind = 0;
static int basic_request_handler_stop = 0;
static void* basic_request_handler_userdata = (void*) 0xCABCAB;

static void basic_request_handler(sd_ipv4ll *ll, int event, void *userdata) {
        ASSERT_PTR_EQ(userdata, basic_request_handler_userdata);

        switch (event) {
                case SD_IPV4LL_EVENT_STOP:
                        basic_request_handler_stop = 1;
                        break;
                case SD_IPV4LL_EVENT_BIND:
                        basic_request_handler_bind = 1;
                        break;
                default:
                        assert_not_reached();
        }
}

int arp_send_packet(
                int fd,
                int ifindex,
                const struct in_addr *pa,
                const struct ether_addr *ha,
                bool announce) {

        struct ether_arp ea = {};

        ASSERT_OK(fd);
        ASSERT_GT(ifindex, 0);
        ASSERT_NOT_NULL(pa);
        ASSERT_NOT_NULL(ha);

        if (send(fd, &ea, sizeof(struct ether_arp), 0) < 0)
                return -errno;

        return 0;
}

int arp_update_filter(int fd, const struct in_addr *a, const struct ether_addr *eth_mac) {
        return 0;
}

int arp_network_bind_raw_socket(int ifindex, const struct in_addr *a, const struct ether_addr *eth_mac) {
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

static void test_public_api_setters(sd_event *e) {
        struct in_addr address = {};
        uint64_t seed = 0;
        sd_ipv4ll *ll;
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}};

        if (verbose)
                printf("* %s\n", __func__);

        ASSERT_OK_ZERO(sd_ipv4ll_new(&ll));
        ASSERT_NOT_NULL(ll);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_attach_event(/* ll= */ NULL, /* event= */ NULL, /* priority= */ 0), EINVAL));
        ASSERT_OK_ZERO(sd_ipv4ll_attach_event(ll, e, /* priority= */ 0));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_attach_event(ll, e, /* priority= */ 0), EBUSY));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_callback(/* ll= */ NULL, /* cb= */ NULL, /* userdata= */ NULL), EINVAL));
        ASSERT_OK_ZERO(sd_ipv4ll_set_callback(ll, /* cb= */ NULL, /* userdata= */ NULL));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_address(ll, &address), EINVAL));
        address.s_addr |= htobe32(169U << 24 | 254U << 16);
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_address(ll, &address), EINVAL));
        address.s_addr |= htobe32(0x00FF);
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_address(ll, &address), EINVAL));
        address.s_addr |= htobe32(0xF000);
        ASSERT_OK_ZERO(sd_ipv4ll_set_address(ll, &address));
        address.s_addr |= htobe32(0x0F00);
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_address(ll, &address), EINVAL));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_address_seed(/* ll= */ NULL, seed), EINVAL));
        ASSERT_OK_ZERO(sd_ipv4ll_set_address_seed(ll, seed));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_mac(/* ll= */ NULL, /* addr= */ NULL), EINVAL));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_mac(ll, /* addr= */ NULL), EINVAL));
        ASSERT_OK_ZERO(sd_ipv4ll_set_mac(ll, &mac_addr));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_ifindex(/* ll= */ NULL, -1), EINVAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_ifindex(ll, -1), EINVAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_set_ifindex(ll, -99), EINVAL));
        ASSERT_OK_ZERO(sd_ipv4ll_set_ifindex(ll, 1));

        ASSERT_PTR_EQ(sd_ipv4ll_ref(ll), ll);
        ASSERT_NULL(sd_ipv4ll_unref(ll));

        /* Cleanup */
        ASSERT_NULL(sd_ipv4ll_unref(ll));
}

static void test_basic_request(sd_event *e, const struct in_addr *start_address) {

        sd_ipv4ll *ll;
        struct ether_arp arp;
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}};

        if (verbose)
                printf("* %s\n", __func__);

        ASSERT_OK_ZERO(sd_ipv4ll_new(&ll));
        if (in4_addr_is_set(start_address))
                ASSERT_OK(sd_ipv4ll_set_address(ll, start_address));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_start(ll), EINVAL));

        ASSERT_OK_ZERO(sd_ipv4ll_attach_event(ll, e, /* priority= */ 0));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_start(ll), EINVAL));

        ASSERT_OK_ZERO(sd_ipv4ll_set_mac(ll, &mac_addr));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_start(ll), EINVAL));

        ASSERT_OK_ZERO(sd_ipv4ll_set_callback(ll, basic_request_handler,
                                              basic_request_handler_userdata));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_ipv4ll_start(ll), EINVAL));

        ASSERT_OK_ZERO(sd_ipv4ll_set_ifindex(ll, 1));
        ASSERT_OK_EQ(sd_ipv4ll_start(ll), 1);

        sd_event_run(e, UINT64_MAX);
        ASSERT_OK_EQ(sd_ipv4ll_start(ll), 0);

        ASSERT_OK_POSITIVE(sd_ipv4ll_is_running(ll));

        /* PROBE */
        sd_event_run(e, UINT64_MAX);
        ASSERT_OK_EQ_ERRNO(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0),
                           (ssize_t) sizeof(struct ether_arp));

        if (extended) {
                /* PROBE */
                sd_event_run(e, UINT64_MAX);
                ASSERT_OK_EQ_ERRNO(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0),
                                   (ssize_t) sizeof(struct ether_arp));

                /* PROBE */
                sd_event_run(e, UINT64_MAX);
                ASSERT_OK_EQ_ERRNO(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0),
                                   (ssize_t) sizeof(struct ether_arp));

                sd_event_run(e, UINT64_MAX);
                ASSERT_EQ(basic_request_handler_bind, 1);

                if (in4_addr_is_set(start_address)) {
                        struct in_addr address;

                        ASSERT_OK(sd_ipv4ll_get_address(ll, &address));
                        ASSERT_EQ(start_address->s_addr, address.s_addr);
                }
        }

        sd_ipv4ll_stop(ll);
        ASSERT_EQ(basic_request_handler_stop, 1);

        /* Cleanup */
        ASSERT_NULL(sd_ipv4ll_unref(ll));
        safe_close(test_fd[1]);
}

int main(int argc, char *argv[]) {
        struct in_addr start_address = {};
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(sd_event_new(&e));

        test_public_api_setters(e);
        test_basic_request(e, &start_address);

        basic_request_handler_bind = 0;
        basic_request_handler_stop = 0;
        start_address.s_addr = htobe32(169U << 24 | 254U << 16 | 1U << 8 | 2U);
        test_basic_request(e, &start_address);

        return 0;
}
