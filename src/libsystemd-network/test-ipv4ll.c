/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/
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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"
#include "socket-util.h"
#include "event-util.h"

#include "sd-ipv4ll.h"
#include "ipv4ll-internal.h"

static bool verbose = false;
static bool extended = false;
static int test_fd[2];

static int basic_request_handler_bind = 0;
static int basic_request_handler_stop = 0;
static void* basic_request_handler_user_data = (void*)0xCABCAB;
static void basic_request_handler(sd_ipv4ll *ll, int event, void *userdata) {
        assert_se(userdata == basic_request_handler_user_data);

        switch(event) {
                case IPV4LL_EVENT_STOP:
                        basic_request_handler_stop = 1;
                        break;
                case IPV4LL_EVENT_BIND:
                        basic_request_handler_bind = 1;
                        break;
                default:
                        assert_se(0);
                        break;
        }
}

int arp_network_send_raw_socket(int fd, const union sockaddr_union *link,
                                        const struct ether_arp *arp) {
        assert_se(arp);
        assert_se(link);
        assert_se(fd >= 0);

        if (send(fd, arp, sizeof(struct ether_arp), 0) < 0)
                return -errno;

        return 0;
}

int arp_network_bind_raw_socket(int index, union sockaddr_union *link) {
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

static void test_arp_header(struct ether_arp *arp) {
        assert_se(arp);
        assert_se(arp->ea_hdr.ar_hrd == htons(ARPHRD_ETHER)); /* HTYPE */
        assert_se(arp->ea_hdr.ar_pro == htons(ETHERTYPE_IP)); /* PTYPE */
        assert_se(arp->ea_hdr.ar_hln == ETH_ALEN); /* HLEN */
        assert_se(arp->ea_hdr.ar_pln == sizeof arp->arp_spa); /* PLEN */
        assert_se(arp->ea_hdr.ar_op == htons(ARPOP_REQUEST)); /* REQUEST */
}

static void test_arp_probe(void) {
        struct ether_arp arp;
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}};
        be32_t pa = 0x3030;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        arp_packet_probe(&arp, pa, &mac_addr);
        test_arp_header(&arp);
        assert_se(memcmp(arp.arp_sha, &mac_addr, ETH_ALEN) == 0);
        assert_se(memcmp(arp.arp_tpa, &pa, sizeof(pa)) == 0);
}

static void test_arp_announce(void) {
        struct ether_arp arp;
        struct ether_addr mac_addr = {
                .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}};
        be32_t pa = 0x3131;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        arp_packet_announcement(&arp, pa, &mac_addr);
        test_arp_header(&arp);
        assert_se(memcmp(arp.arp_sha, &mac_addr, ETH_ALEN) == 0);
        assert_se(memcmp(arp.arp_tpa, &pa, sizeof(pa)) == 0);
        assert_se(memcmp(arp.arp_spa, &pa, sizeof(pa)) == 0);
}

static void test_public_api_setters(sd_event *e) {
        uint8_t seed[8];
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

        assert_se(sd_ipv4ll_set_address_seed(NULL, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_address_seed(ll, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_address_seed(ll, seed) == 0);

        assert_se(sd_ipv4ll_set_mac(NULL, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_mac(ll, NULL) == -EINVAL);
        assert_se(sd_ipv4ll_set_mac(ll, &mac_addr) == 0);

        assert_se(sd_ipv4ll_set_index(NULL, -1) == -EINVAL);
        assert_se(sd_ipv4ll_set_index(ll, -1) == -EINVAL);
        assert_se(sd_ipv4ll_set_index(ll, -99) == -EINVAL);
        assert_se(sd_ipv4ll_set_index(ll, 1) == 0);
        assert_se(sd_ipv4ll_set_index(ll, 99) == 0);

        assert_se(sd_ipv4ll_ref(ll) == ll);
        assert_se(sd_ipv4ll_unref(ll) == ll);

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
                                         basic_request_handler_user_data) == 0);
        assert_se(sd_ipv4ll_start(ll) == -EINVAL);

        assert_se(sd_ipv4ll_set_index(ll, 1) == 0);
        assert_se(sd_ipv4ll_start(ll) == 0);

        sd_event_run(e, (uint64_t) -1);
        assert_se(sd_ipv4ll_start(ll) == -EBUSY);

        /* PROBE */
        sd_event_run(e, (uint64_t) -1);
        assert_se(read(test_fd[1], &arp, sizeof(struct ether_arp)) == sizeof(struct ether_arp));
        test_arp_header(&arp);

        if (extended) {
                /* PROBE */
                sd_event_run(e, (uint64_t) -1);
                assert_se(read(test_fd[1], &arp, sizeof(struct ether_arp)) == sizeof(struct ether_arp));
                test_arp_header(&arp);

                /* PROBE */
                sd_event_run(e, (uint64_t) -1);
                assert_se(read(test_fd[1], &arp, sizeof(struct ether_arp)) == sizeof(struct ether_arp));
                test_arp_header(&arp);

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
        _cleanup_event_unref_ sd_event *e = NULL;

        assert_se(sd_event_new(&e) >= 0);

        test_public_api_setters(e);
        test_arp_probe();
        test_arp_announce();
        test_basic_request(e);

        return 0;
}
