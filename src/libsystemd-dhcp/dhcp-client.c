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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <net/ethernet.h>

#include "util.h"
#include "list.h"

#include "dhcp-protocol.h"
#include "dhcp-internal.h"
#include "sd-dhcp-client.h"

#define DHCP_CLIENT_MIN_OPTIONS_SIZE            312

struct sd_dhcp_client {
        DHCPState state;
        int index;
        uint8_t *req_opts;
        size_t req_opts_size;
        uint32_t last_addr;
        struct ether_addr mac_addr;
        uint32_t xid;
};

static const uint8_t default_req_opts[] = {
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_HOST_NAME,
        DHCP_OPTION_DOMAIN_NAME,
        DHCP_OPTION_DOMAIN_NAME_SERVER,
        DHCP_OPTION_NTP_SERVER,
};

int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option)
{
        size_t i;

        assert_return(client, -EINVAL);
        assert_return (client->state == DHCP_STATE_INIT, -EBUSY);

        switch(option) {
        case DHCP_OPTION_PAD:
        case DHCP_OPTION_OVERLOAD:
        case DHCP_OPTION_MESSAGE_TYPE:
        case DHCP_OPTION_PARAMETER_REQUEST_LIST:
        case DHCP_OPTION_END:
                return -EINVAL;

        default:
                break;
        }

        for (i = 0; i < client->req_opts_size; i++)
                if (client->req_opts[i] == option)
                        return -EEXIST;

        if (!GREEDY_REALLOC(client->req_opts, client->req_opts_size,
                            client->req_opts_size + 1))
                return -ENOMEM;

        client->req_opts[client->req_opts_size - 1] = option;

        return 0;
}

int sd_dhcp_client_set_request_address(sd_dhcp_client *client,
                                       const struct in_addr *last_addr)
{
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);

        if (last_addr)
                client->last_addr = last_addr->s_addr;
        else
                client->last_addr = INADDR_ANY;

        return 0;
}

int sd_dhcp_client_set_index(sd_dhcp_client *client, int interface_index)
{
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);
        assert_return(interface_index >= -1, -EINVAL);

        client->index = interface_index;

        return 0;
}

int sd_dhcp_client_set_mac(sd_dhcp_client *client,
                           const struct ether_addr *addr)
{
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);

        memcpy(&client->mac_addr, addr, ETH_ALEN);

        return 0;
}

static int client_packet_init(sd_dhcp_client *client, uint8_t type,
                              DHCPMessage *message, uint8_t **opt,
                              size_t *optlen)
{
        int err;

        *opt = (uint8_t *)(message + 1);

        if (*optlen < 4)
                return -ENOBUFS;
        *optlen -= 4;

        message->op = BOOTREQUEST;
        message->htype = 1;
        message->hlen = ETHER_ADDR_LEN;
        message->xid = htobe32(client->xid);

        memcpy(&message->chaddr, &client->mac_addr, ETH_ALEN);
        (*opt)[0] = 0x63;
        (*opt)[1] = 0x82;
        (*opt)[2] = 0x53;
        (*opt)[3] = 0x63;

        *opt += 4;

        err = dhcp_option_append(opt, optlen, DHCP_OPTION_MESSAGE_TYPE, 1,
                                 &type);
        if (err < 0)
                return err;

        /* Some DHCP servers will refuse to issue an DHCP lease if the Cliient
           Identifier option is not set */
        err = dhcp_option_append(opt, optlen, DHCP_OPTION_CLIENT_IDENTIFIER,
                                 ETH_ALEN, &client->mac_addr);
        if (err < 0)
                return err;

        if (type == DHCP_DISCOVER || type == DHCP_REQUEST) {
                err = dhcp_option_append(opt, optlen,
                                         DHCP_OPTION_PARAMETER_REQUEST_LIST,
                                         client->req_opts_size,
                                         client->req_opts);
                if (err < 0)
                        return err;
        }

        return 0;
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
                sum += odd[len];
        }

        return ~((sum & 0xffff) + (sum >> 16));
}

static int client_send_discover(sd_dhcp_client *client)
{
        int err = 0;
        _cleanup_free_ DHCPPacket *discover;
        size_t optlen, len;
        uint8_t *opt;

        optlen = DHCP_CLIENT_MIN_OPTIONS_SIZE;
        len = sizeof(DHCPPacket) + optlen;

        discover = malloc0(len);

        if (!discover)
                return -ENOMEM;

        err = client_packet_init(client, DHCP_DISCOVER, &discover->dhcp,
                                 &opt, &optlen);
        if (err < 0)
                return err;

        if (client->last_addr != INADDR_ANY) {
                err = dhcp_option_append(&opt, &optlen,
                                         DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                         4, &client->last_addr);
                if (err < 0)
                        return err;
        }

        err = dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
        if (err < 0)
                return err;

        discover->ip.version = IPVERSION;
        discover->ip.ihl = sizeof(discover->ip) >> 2;
        discover->ip.tot_len = htobe16(len);

        discover->ip.protocol = IPPROTO_UDP;
        discover->ip.saddr = INADDR_ANY;
        discover->ip.daddr = INADDR_BROADCAST;

        discover->udp.source = htobe16(DHCP_PORT_CLIENT);
        discover->udp.dest = htobe16(DHCP_PORT_SERVER);
        discover->udp.len = htobe16(len - sizeof(discover->ip));

        discover->ip.check = discover->udp.len;
        discover->udp.check = client_checksum(&discover->ip.ttl,
                                              len - 8);

        discover->ip.ttl = IPDEFTTL;
        discover->ip.check = 0;
        discover->ip.check = client_checksum(&discover->ip,
                                             sizeof(discover->ip));

        err = dhcp_network_send_raw_packet(client->index, discover, len);

        return 0;
}

int sd_dhcp_client_start(sd_dhcp_client *client)
{
        assert_return(client, -EINVAL);
        assert_return(client->index >= 0, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT ||
                      client->state == DHCP_STATE_INIT_REBOOT, -EBUSY);

        client->xid = random_u();

        return client_send_discover(client);
}

sd_dhcp_client *sd_dhcp_client_new(void)
{
        sd_dhcp_client *client;

        client = new0(sd_dhcp_client, 1);
        if (!client)
                return NULL;

        client->state = DHCP_STATE_INIT;
        client->index = -1;

        client->req_opts_size = ELEMENTSOF(default_req_opts);

        client->req_opts = memdup(default_req_opts, client->req_opts_size);
        if (!client->req_opts) {
                free(client);
                return NULL;
        }

        return client;
}
