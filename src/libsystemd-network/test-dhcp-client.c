/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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
#include "sd-event.h"
#include "event-util.h"

#include "dhcp-protocol.h"
#include "dhcp-internal.h"
#include "sd-dhcp-client.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

typedef int (*test_callback_recv_t)(size_t size, DHCPMessage *dhcp);

static bool verbose = false;
static int test_fd[2];
static test_callback_recv_t callback_recv;
static be32_t xid;
static sd_event_source *test_hangcheck;

static int test_dhcp_hangcheck(sd_event_source *s, uint64_t usec,
                               void *userdata)
{
        assert_not_reached("Test case should have completed in 2 seconds");

        return 0;
}

static void test_request_basic(sd_event *e)
{
        int r;

        sd_dhcp_client *client;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        r = sd_dhcp_client_new(&client);

        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_request_option(NULL, 0) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_address(NULL, NULL) == -EINVAL);
        assert_se(sd_dhcp_client_set_index(NULL, 0) == -EINVAL);

        assert_se(sd_dhcp_client_set_index(client, 15) == 0);
        assert_se(sd_dhcp_client_set_index(client, -42) == -EINVAL);
        assert_se(sd_dhcp_client_set_index(client, -1) == -EINVAL);
        assert_se(sd_dhcp_client_set_index(client, 0) == -EINVAL);
        assert_se(sd_dhcp_client_set_index(client, 1) == 0);

        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_SUBNET_MASK) == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_ROUTER) == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_HOST_NAME) == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME) == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME_SERVER)
                        == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_NTP_SERVER) == -EEXIST);

        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PAD) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_END) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_MESSAGE_TYPE) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_OVERLOAD) == -EINVAL);
        assert_se(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PARAMETER_REQUEST_LIST)
                        == -EINVAL);

        assert_se(sd_dhcp_client_set_request_option(client, 33) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, 33) == -EEXIST);
        assert_se(sd_dhcp_client_set_request_option(client, 44) == 0);
        assert_se(sd_dhcp_client_set_request_option(client, 33) == -EEXIST);

        sd_dhcp_client_unref(client);
}

static void test_checksum(void)
{
        uint8_t buf[20] = {
                0x45, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff
        };

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        assert_se(dhcp_packet_checksum((uint8_t*)&buf, 20) == be16toh(0x78ae));
}

static int check_options(uint8_t code, uint8_t len, const uint8_t *option,
                void *user_data)
{
        switch(code) {
        case DHCP_OPTION_CLIENT_IDENTIFIER:
                assert_se(len == 7);
                assert_se(option[0] == 0x01);
                assert_se(memcmp(&option[1], &mac_addr, ETH_ALEN) == 0);
                break;

        default:
                break;
        }

        return 0;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len)
{
        size_t size;
        _cleanup_free_ DHCPPacket *discover;
        uint16_t ip_check, udp_check;

        assert_se(s >= 0);
        assert_se(packet);

        size = sizeof(DHCPPacket);
        assert_se(len > size);

        discover = memdup(packet, len);

        assert_se(discover->ip.ttl == IPDEFTTL);
        assert_se(discover->ip.protocol == IPPROTO_UDP);
        assert_se(discover->ip.saddr == INADDR_ANY);
        assert_se(discover->ip.daddr == INADDR_BROADCAST);
        assert_se(discover->udp.source == be16toh(DHCP_PORT_CLIENT));
        assert_se(discover->udp.dest == be16toh(DHCP_PORT_SERVER));

        ip_check = discover->ip.check;

        discover->ip.ttl = 0;
        discover->ip.check = discover->udp.len;

        udp_check = ~dhcp_packet_checksum((uint8_t*)&discover->ip.ttl, len - 8);
        assert_se(udp_check == 0xffff);

        discover->ip.ttl = IPDEFTTL;
        discover->ip.check = ip_check;

        ip_check = ~dhcp_packet_checksum((uint8_t*)&discover->ip, sizeof(discover->ip));
        assert_se(ip_check == 0xffff);

        assert_se(discover->dhcp.xid);
        assert_se(memcmp(discover->dhcp.chaddr,
                      &mac_addr.ether_addr_octet, 6) == 0);

        size = len - sizeof(struct iphdr) - sizeof(struct udphdr);

        assert_se(callback_recv);
        callback_recv(size, &discover->dhcp);

        return 575;
}

int dhcp_network_bind_raw_socket(int index, union sockaddr_union *link, uint32_t id)
{
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int dhcp_network_bind_udp_socket(be32_t address, uint16_t port)
{
        return 0;
}

int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port,
                                 const void *packet, size_t len)
{
        return 0;
}

static int test_discover_message_verify(size_t size, struct DHCPMessage *dhcp)
{
        int res;

        res = dhcp_option_parse(dhcp, size, check_options, NULL);
        assert_se(res == DHCP_DISCOVER);

        if (verbose)
                printf("  recv DHCP Discover 0x%08x\n", be32toh(dhcp->xid));

        return 0;
}

static void test_discover_message(sd_event *e)
{
        sd_dhcp_client *client;
        int res, r;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        r = sd_dhcp_client_new(&client);
        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_index(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, &mac_addr) >= 0);

        assert_se(sd_dhcp_client_set_request_option(client, 248) >= 0);

        callback_recv = test_discover_message_verify;

        res = sd_dhcp_client_start(client);

        assert_se(res == 0 || res == -EINPROGRESS);

        sd_event_run(e, (uint64_t) -1);

        sd_dhcp_client_stop(client);
        sd_dhcp_client_unref(client);

        test_fd[1] = safe_close(test_fd[1]);

        callback_recv = NULL;
}

static uint8_t test_addr_acq_offer[] = {
        0x45, 0x10, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x11, 0xb3, 0x84, 0xc0, 0xa8, 0x02, 0x01,
        0xc0, 0xa8, 0x02, 0xbf, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x34, 0x00, 0x00, 0x02, 0x01, 0x06, 0x00,
        0x6f, 0x95, 0x2f, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x02, 0xbf,
        0xc0, 0xa8, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x02, 0x36,
        0x04, 0xc0, 0xa8, 0x02, 0x01, 0x33, 0x04, 0x00,
        0x00, 0x02, 0x58, 0x01, 0x04, 0xff, 0xff, 0xff,
        0x00, 0x2a, 0x04, 0xc0, 0xa8, 0x02, 0x01, 0x0f,
        0x09, 0x6c, 0x61, 0x62, 0x2e, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x03, 0x04, 0xc0, 0xa8, 0x02, 0x01,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t test_addr_acq_ack[] = {
        0x45, 0x10, 0x01, 0x48, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x11, 0xb3, 0x84, 0xc0, 0xa8, 0x02, 0x01,
        0xc0, 0xa8, 0x02, 0xbf, 0x00, 0x43, 0x00, 0x44,
        0x01, 0x34, 0x00, 0x00, 0x02, 0x01, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x02, 0xbf,
        0xc0, 0xa8, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x05, 0x36,
        0x04, 0xc0, 0xa8, 0x02, 0x01, 0x33, 0x04, 0x00,
        0x00, 0x02, 0x58, 0x01, 0x04, 0xff, 0xff, 0xff,
        0x00, 0x2a, 0x04, 0xc0, 0xa8, 0x02, 0x01, 0x0f,
        0x09, 0x6c, 0x61, 0x62, 0x2e, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x03, 0x04, 0xc0, 0xa8, 0x02, 0x01,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void test_addr_acq_acquired(sd_dhcp_client *client, int event,
                                   void *userdata) {
        sd_event *e = userdata;
        sd_dhcp_lease *lease;
        struct in_addr addr;

        assert_se(client);
        assert_se(event == DHCP_EVENT_IP_ACQUIRE);

        assert_se(sd_dhcp_client_get_lease(client, &lease) >= 0);
        assert_se(lease);

        assert_se(sd_dhcp_lease_get_address(lease, &addr) >= 0);
        assert_se(memcmp(&addr.s_addr, &test_addr_acq_ack[44],
                      sizeof(addr.s_addr)) == 0);

        assert_se(sd_dhcp_lease_get_netmask(lease, &addr) >= 0);
        assert_se(memcmp(&addr.s_addr, &test_addr_acq_ack[285],
                      sizeof(addr.s_addr)) == 0);

        assert_se(sd_dhcp_lease_get_router(lease, &addr) >= 0);
        assert_se(memcmp(&addr.s_addr, &test_addr_acq_ack[308],
                      sizeof(addr.s_addr)) == 0);

        if (verbose)
                printf("  DHCP address acquired\n");

        sd_dhcp_lease_unref(lease);
        sd_event_exit(e, 0);
}

static int test_addr_acq_recv_request(size_t size, DHCPMessage *request) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)request;
        int res;

        res = dhcp_option_parse(request, size, check_options, NULL);
        assert_se(res == DHCP_REQUEST);
        assert_se(xid == request->xid);

        assert_se(msg_bytes[size - 1] == DHCP_OPTION_END);

        if (verbose)
                printf("  recv DHCP Request  0x%08x\n", be32toh(xid));

        memcpy(&test_addr_acq_ack[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_ack[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_ack[56], &mac_addr.ether_addr_octet,
               ETHER_ADDR_LEN);

        callback_recv = NULL;

        res = write(test_fd[1], test_addr_acq_ack,
                    sizeof(test_addr_acq_ack));
        assert_se(res == sizeof(test_addr_acq_ack));

        if (verbose)
                printf("  send DHCP Ack\n");

        return 0;
};

static int test_addr_acq_recv_discover(size_t size, DHCPMessage *discover) {
        uint16_t udp_check = 0;
        uint8_t *msg_bytes = (uint8_t *)discover;
        int res;

        res = dhcp_option_parse(discover, size, check_options, NULL);
        assert_se(res == DHCP_DISCOVER);

        assert_se(msg_bytes[size - 1] == DHCP_OPTION_END);

        xid = discover->xid;

        if (verbose)
                printf("  recv DHCP Discover 0x%08x\n", be32toh(xid));

        memcpy(&test_addr_acq_offer[26], &udp_check, sizeof(udp_check));
        memcpy(&test_addr_acq_offer[32], &xid, sizeof(xid));
        memcpy(&test_addr_acq_offer[56], &mac_addr.ether_addr_octet,
               ETHER_ADDR_LEN);

        callback_recv = test_addr_acq_recv_request;

        res = write(test_fd[1], test_addr_acq_offer,
                    sizeof(test_addr_acq_offer));
        assert_se(res == sizeof(test_addr_acq_offer));

        if (verbose)
                printf("  sent DHCP Offer\n");

        return 0;
}

static void test_addr_acq(sd_event *e) {
        usec_t time_now = now(CLOCK_MONOTONIC);
        sd_dhcp_client *client;
        int res, r;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        r = sd_dhcp_client_new(&client);
        assert_se(r >= 0);
        assert_se(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert_se(r >= 0);

        assert_se(sd_dhcp_client_set_index(client, 42) >= 0);
        assert_se(sd_dhcp_client_set_mac(client, &mac_addr) >= 0);

        assert_se(sd_dhcp_client_set_callback(client, test_addr_acq_acquired, e)
                >= 0);

        callback_recv = test_addr_acq_recv_discover;

        assert_se(sd_event_add_time(e, &test_hangcheck,
                                    CLOCK_MONOTONIC,
                                    time_now + 2 * USEC_PER_SEC, 0,
                                    test_dhcp_hangcheck, NULL) >= 0);

        res = sd_dhcp_client_start(client);
        assert_se(res == 0 || res == -EINPROGRESS);

        sd_event_loop(e);

        test_hangcheck = sd_event_source_unref(test_hangcheck);

        sd_dhcp_client_set_callback(client, NULL, NULL);
        sd_dhcp_client_stop(client);
        sd_dhcp_client_unref(client);

        test_fd[1] = safe_close(test_fd[1]);

        callback_recv = NULL;
        xid = 0;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *e;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        assert_se(sd_event_new(&e) >= 0);

        test_request_basic(e);
        test_checksum();

        test_discover_message(e);
        test_addr_acq(e);

        return 0;
}
