/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <errno.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-ipv4ll.h"

#include "arp-util.h"
#include "fd-util.h"
#include "socket-util.h"
#include "tests.h"
#include "util.h"

static bool verbose = false;
static bool extended = false;
static int test_fd[2];

static int basic_request_handler_bind = 0;
static int basic_request_handler_stop = 0;
static void* basic_request_handler_userdata = (void*) 0xCABCAB;

static void basic_request_handler(sd_ipv4ll *ll, int event, void *userdata) {
        assert_se(userdata == basic_request_handler_userdata);

        switch(event) {
                case SD_IPV4LL_EVENT_STOP:
                        basic_request_handler_stop = 1;
                        break;
                case SD_IPV4LL_EVENT_BIND:
                        basic_request_handler_bind = 1;
                        break;
                default:
                        assert_se(0);
                        break;
        }
}

static int arp_network_send_raw_socket(int fd, int ifindex,
                                       const struct ether_arp *arp) {
        assert_se(arp);
        assert_se(ifindex > 0);
        assert_se(fd >= 0);

        if (send(fd, arp, sizeof(struct ether_arp), 0) < 0)
                return -errno;

        return 0;
}

int arp_send_probe(int fd, int ifindex,
                    be32_t pa, const struct ether_addr *ha) {
        struct ether_arp ea = {};

        assert_se(fd >= 0);
        assert_se(ifindex > 0);
        assert_se(pa != 0);
        assert_se(ha);

        return arp_network_send_raw_socket(fd, ifindex, &ea);
}

int arp_send_announcement(int fd, int ifindex,
                          be32_t pa, const struct ether_addr *ha) {
        struct ether_arp ea = {};

        assert_se(fd >= 0);
        assert_se(ifindex > 0);
        assert_se(pa != 0);
        assert_se(ha);

        return arp_network_send_raw_socket(fd, ifindex, &ea);
}

int arp_network_bind_raw_socket(int index, be32_t address, const struct ether_addr *eth_mac) {
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
                printf("* %s\n", __FUNCTION__);

        assert_se(sd_ipv4ll_new(&ll) == 0);
        assert_se(ll);

        assert_se(sd_ipv4ll_attach_event(NULL, NULL, 0) == -EINVAL);
        assert_se(sd_ipv4ll_attach_event(ll, e, 0) == 0);
        assert_se(sd_ipv4ll_attach_event(ll, e, 0) == -EBUSY);

        assert_se(sd_ipv4ll_set_callback(NULL, NULL, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_callback(ll, NULL, NULL) == 0);

        assert_se(sd_ipv4ll_set_address(ll, &address) == -EINVAL);
        address.s_addr |= htobe32(169U << 24 | 254U << 16);
        assert_se(sd_ipv4ll_set_address(ll, &address) == -EINVAL);
        address.s_addr |= htobe32(0x00FF);
        assert_se(sd_ipv4ll_set_address(ll, &address) == -EINVAL);
        address.s_addr |= htobe32(0xF000);
        assert_se(sd_ipv4ll_set_address(ll, &address) == 0);
        address.s_addr |= htobe32(0x0F00);
        assert_se(sd_ipv4ll_set_address(ll, &address) == -EINVAL);

        assert_se(sd_ipv4ll_set_address_seed(NULL, seed) == -EINVAL);
        assert_se(sd_ipv4ll_set_address_seed(ll, seed) == 0);

        assert_se(sd_ipv4ll_set_mac(NULL, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_mac(ll, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_mac(ll, &mac_addr) == 0);

        assert_se(sd_ipv4ll_set_ifindex(NULL, -1) == -EINVAL);
        assert_se(sd_ipv4ll_set_ifindex(ll, -1) == -EINVAL);
        assert_se(sd_ipv4ll_set_ifindex(ll, -99) == -EINVAL);
        assert_se(sd_ipv4ll_set_ifindex(ll, 1) == 0);
        assert_se(sd_ipv4ll_set_ifindex(ll, 99) == 0);

        assert_se(sd_ipv4ll_ref(ll) == ll);
        assert_se(sd_ipv4ll_unref(ll) == NULL);

        /* Cleanup */
        assert_se(sd_ipv4ll_unref(ll) == NULL);
}

static void test_basic_request(sd_event *e) {

        sd_ipv4ll *ll;
        struct ether_arp arp;
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}};

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        assert_se(sd_ipv4ll_new(&ll) == 0);
        assert_se(sd_ipv4ll_start(ll) == -EINVAL);

        assert_se(sd_ipv4ll_attach_event(ll, e, 0) == 0);
        assert_se(sd_ipv4ll_start(ll) == -EINVAL);

        assert_se(sd_ipv4ll_set_mac(ll, &mac_addr) == 0);
        assert_se(sd_ipv4ll_start(ll) == -EINVAL);

        assert_se(sd_ipv4ll_set_callback(ll, basic_request_handler,
                                         basic_request_handler_userdata) == 0);
        assert_se(sd_ipv4ll_start(ll) == -EINVAL);

        assert_se(sd_ipv4ll_set_ifindex(ll, 1) == 0);
        assert_se(sd_ipv4ll_start(ll) == 0);

        sd_event_run(e, (uint64_t) -1);
        assert_se(sd_ipv4ll_start(ll) == -EBUSY);

        assert_se(sd_ipv4ll_is_running(ll));

        /* PROBE */
        sd_event_run(e, (uint64_t) -1);
        assert_se(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0) == sizeof(struct ether_arp));

        if (extended) {
                /* PROBE */
                sd_event_run(e, (uint64_t) -1);
                assert_se(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0) == sizeof(struct ether_arp));

                /* PROBE */
                sd_event_run(e, (uint64_t) -1);
                assert_se(recv(test_fd[1], &arp, sizeof(struct ether_arp), 0) == sizeof(struct ether_arp));

                sd_event_run(e, (uint64_t) -1);
                assert_se(basic_request_handler_bind == 1);
        }

        sd_ipv4ll_stop(ll);
        assert_se(basic_request_handler_stop == 1);

        /* Cleanup */
        assert_se(sd_ipv4ll_unref(ll) == NULL);
        safe_close(test_fd[1]);
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        test_setup_logging(LOG_DEBUG);

        assert_se(sd_event_new(&e) >= 0);

        test_public_api_setters(e);
        test_basic_request(e);

        return 0;
}
