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

static void test_request_basic(sd_event *e)
{
        int r;

        sd_dhcp_client *client;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        r = sd_dhcp_client_new(&client);

        assert(r >= 0);
        assert(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert(r >= 0);

        assert(sd_dhcp_client_set_request_option(NULL, 0) == -EINVAL);
        assert(sd_dhcp_client_set_request_address(NULL, NULL) == -EINVAL);
        assert(sd_dhcp_client_set_index(NULL, 0) == -EINVAL);

        assert(sd_dhcp_client_set_index(client, 15) == 0);
        assert(sd_dhcp_client_set_index(client, -42) == -EINVAL);
        assert(sd_dhcp_client_set_index(client, -1) == 0);

        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_SUBNET_MASK) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_ROUTER) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_HOST_NAME) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_DOMAIN_NAME_SERVER)
                        == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_NTP_SERVER) == -EEXIST);

        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PAD) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_END) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_MESSAGE_TYPE) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_OVERLOAD) == -EINVAL);
        assert(sd_dhcp_client_set_request_option(client,
                                        DHCP_OPTION_PARAMETER_REQUEST_LIST)
                        == -EINVAL);

        assert(sd_dhcp_client_set_request_option(client, 33) == 0);
        assert(sd_dhcp_client_set_request_option(client, 33) == -EEXIST);
        assert(sd_dhcp_client_set_request_option(client, 44) == 0);
        assert(sd_dhcp_client_set_request_option(client, 33) == -EEXIST);
}

static uint16_t client_checksum(void *buf, int len)
{
        uint32_t sum;
        uint16_t *check;
        int i;
        uint8_t *odd;

        sum = 0;
        check = buf;

        for (i = 0; i < len / 2 ; i++)
                sum += check[i];

        if (len & 0x01) {
                odd = buf;
                sum += odd[len - 1];
        }

        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
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

        assert(client_checksum(&buf, 20) == be16toh(0x78ae));
}

static int check_options(uint8_t code, uint8_t len, const uint8_t *option,
                void *user_data)
{
        return 0;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len)
{
        size_t size;
        _cleanup_free_ DHCPPacket *discover;
        uint16_t ip_check, udp_check;

        assert(s >= 0);
        assert(packet);

        size = sizeof(DHCPPacket) + 4;
        assert(len > size);

        discover = memdup(packet, len);

        assert(discover->ip.ttl == IPDEFTTL);
        assert(discover->ip.protocol == IPPROTO_UDP);
        assert(discover->ip.saddr == INADDR_ANY);
        assert(discover->ip.daddr == INADDR_BROADCAST);
        assert(discover->udp.source == be16toh(DHCP_PORT_CLIENT));
        assert(discover->udp.dest == be16toh(DHCP_PORT_SERVER));

        ip_check = discover->ip.check;

        discover->ip.ttl = 0;
        discover->ip.check = discover->udp.len;

        udp_check = ~client_checksum(&discover->ip.ttl, len - 8);
        assert(udp_check == 0xffff);

        discover->ip.ttl = IPDEFTTL;
        discover->ip.check = ip_check;

        ip_check = ~client_checksum(&discover->ip, sizeof(discover->ip));
        assert(ip_check == 0xffff);

        assert(discover->dhcp.xid);
        assert(memcmp(discover->dhcp.chaddr,
                      &mac_addr.ether_addr_octet, 6) == 0);

        size = len - sizeof(struct iphdr) - sizeof(struct udphdr);

        assert(callback_recv);
        callback_recv(size, &discover->dhcp);

        return 575;
}

int dhcp_network_bind_raw_socket(int index, union sockaddr_union *link)
{
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, test_fd) < 0)
                return -errno;

        return test_fd[0];
}

int dhcp_network_bind_udp_socket(int index, be32_t address, uint16_t port)
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
        assert(res == DHCP_DISCOVER);

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
        assert(r >= 0);
        assert(client);

        r = sd_dhcp_client_attach_event(client, e, 0);
        assert(r >= 0);

        assert(sd_dhcp_client_set_index(client, 42) >= 0);
        assert(sd_dhcp_client_set_mac(client, &mac_addr) >= 0);

        assert(sd_dhcp_client_set_request_option(client, 248) >= 0);

        callback_recv = test_discover_message_verify;

        res = sd_dhcp_client_start(client);

        assert(res == 0 || res == -EINPROGRESS);

        sd_event_run(e, (uint64_t) -1);

        sd_dhcp_client_stop(client);
        sd_dhcp_client_free(client);

        close(test_fd[0]);
        close(test_fd[1]);

        callback_recv = NULL;
}

int main(int argc, char *argv[])
{
        sd_event *e;

        assert(sd_event_new(&e) >= 0);

        test_request_basic(e);
        test_checksum();

        test_discover_message(e);

        return 0;
}
