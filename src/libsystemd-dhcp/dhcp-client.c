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

struct DHCPLease {
        uint32_t lifetime;
        uint32_t address;
        uint32_t server_address;
        uint32_t subnet_mask;
        uint32_t router;
};

typedef struct DHCPLease DHCPLease;

struct sd_dhcp_client {
        DHCPState state;
        sd_event *event;
        sd_event_source *timeout_resend;
        int index;
        int fd;
        union sockaddr_union link;
        sd_event_source *receive_message;
        uint8_t *req_opts;
        size_t req_opts_size;
        uint32_t last_addr;
        struct ether_addr mac_addr;
        uint32_t xid;
        usec_t start_time;
        unsigned int attempt;
        DHCPLease *lease;
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

static int client_notify(sd_dhcp_client *client, int event)
{
        return 0;
}

static int client_stop(sd_dhcp_client *client, int error)
{
        assert_return(client, -EINVAL);
        assert_return(client->state != DHCP_STATE_INIT &&
                      client->state != DHCP_STATE_INIT_REBOOT, -EALREADY);

        client->receive_message =
                sd_event_source_unref(client->receive_message);

        if (client->fd >= 0)
                close(client->fd);
        client->fd = -1;

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        client->attempt = 1;

        switch (client->state) {

        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:

                client->start_time = 0;
                client->state = DHCP_STATE_INIT;
                break;

        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                break;
        }

        if (client->lease) {
                free(client->lease);
                client->lease = NULL;
        }

        return 0;
}

static int client_packet_init(sd_dhcp_client *client, uint8_t type,
                              DHCPMessage *message, uint16_t secs,
                              uint8_t **opt, size_t *optlen)
{
        int err;
        be16_t max_size;

        *opt = (uint8_t *)(message + 1);

        if (*optlen < 4)
                return -ENOBUFS;
        *optlen -= 4;

        message->op = BOOTREQUEST;
        message->htype = 1;
        message->hlen = ETHER_ADDR_LEN;
        message->xid = htobe32(client->xid);

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers
           refuse to issue an DHCP lease if 'secs' is set to zero */
        message->secs = htobe16(secs);

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

                /* Some DHCP servers will send bigger DHCP packets than the
                   defined default size unless the Maximum Messge Size option
                   is explicitely set */
                max_size = htobe16(DHCP_IP_UDP_SIZE + DHCP_MESSAGE_SIZE +
                                   DHCP_CLIENT_MIN_OPTIONS_SIZE);
                err = dhcp_option_append(opt, optlen,
                                         DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
                                         2, &max_size);
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

static void client_append_ip_headers(DHCPPacket *packet, uint16_t len)
{
        packet->ip.version = IPVERSION;
        packet->ip.ihl = DHCP_IP_SIZE / 4;
        packet->ip.tot_len = htobe16(len);

        packet->ip.protocol = IPPROTO_UDP;
        packet->ip.saddr = INADDR_ANY;
        packet->ip.daddr = INADDR_BROADCAST;

        packet->udp.source = htobe16(DHCP_PORT_CLIENT);
        packet->udp.dest = htobe16(DHCP_PORT_SERVER);
        packet->udp.len = htobe16(len - DHCP_IP_SIZE);

        packet->ip.check = packet->udp.len;
        packet->udp.check = client_checksum(&packet->ip.ttl, len - 8);

        packet->ip.ttl = IPDEFTTL;
        packet->ip.check = 0;
        packet->ip.check = client_checksum(&packet->ip, DHCP_IP_SIZE);
}

static int client_send_discover(sd_dhcp_client *client, uint16_t secs)
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
                                 secs, &opt, &optlen);
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

        client_append_ip_headers(discover, len);

        err = dhcp_network_send_raw_socket(client->fd, &client->link,
                                           discover, len);

        return err;
}

static int client_send_request(sd_dhcp_client *client, uint16_t secs)
{
        _cleanup_free_ DHCPPacket *request;
        size_t optlen, len;
        int err;
        uint8_t *opt;

        optlen = DHCP_CLIENT_MIN_OPTIONS_SIZE;
        len = DHCP_MESSAGE_SIZE + optlen;

        request = malloc0(len);
        if (!request)
                return -ENOMEM;

        err = client_packet_init(client, DHCP_REQUEST, &request->dhcp, secs,
                                 &opt, &optlen);
        if (err < 0)
                return err;

        if (client->state == DHCP_STATE_REQUESTING) {
                err = dhcp_option_append(&opt, &optlen,
                                         DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                         4, &client->lease->address);
                if (err < 0)
                        return err;

                err = dhcp_option_append(&opt, &optlen,
                                         DHCP_OPTION_SERVER_IDENTIFIER,
                                         4, &client->lease->server_address);
                if (err < 0)
                        return err;
        }

        err = dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
        if (err < 0)
                return err;

        client_append_ip_headers(request, len);

        err = dhcp_network_send_raw_socket(client->fd, &client->link,
                                           request, len);

        return err;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec,
                                 void *userdata)
{
        sd_dhcp_client *client = userdata;
        usec_t next_timeout;
        uint16_t secs;
        int err = 0;

        secs = (usec - client->start_time) / USEC_PER_SEC;

        if (client->attempt < 64)
                client->attempt *= 2;

        next_timeout = usec + (client->attempt - 1) * USEC_PER_SEC +
                (random_u() & 0x1fffff);

        err = sd_event_add_monotonic(client->event, next_timeout,
                                     10 * USEC_PER_MSEC,
                                     client_timeout_resend, client,
                                     &client->timeout_resend);
        if (err < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_INIT:
                err = client_send_discover(client, secs);
                if (err >= 0) {
                        client->state = DHCP_STATE_SELECTING;
                        client->attempt = 1;
                } else {
                        if (client->attempt >= 64)
                                goto error;
                }

                break;

        case DHCP_STATE_SELECTING:
                err = client_send_discover(client, secs);
                if (err < 0 && client->attempt >= 64)
                        goto error;

                break;

        case DHCP_STATE_REQUESTING:
                err = client_send_request(client, secs);
                if (err < 0 && client->attempt >= 64)
                         goto error;

                break;

        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                break;
        }

        return 0;

error:
        client_stop(client, err);

        /* Errors were dealt with when stopping the client, don't spill
           errors into the event loop handler */
        return 0;
}

static int client_parse_offer(uint8_t code, uint8_t len, const uint8_t *option,
                              void *user_data)
{
        DHCPLease *lease = user_data;
        be32_t val;

        switch(code) {

        case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                if (len == 4) {
                        memcpy(&val, option, 4);
                        lease->lifetime = be32toh(val);
                }

                break;

        case DHCP_OPTION_SERVER_IDENTIFIER:
                if (len >= 4)
                        memcpy(&lease->server_address, option, 4);

                break;

        case DHCP_OPTION_SUBNET_MASK:
                if (len >= 4)
                        memcpy(&lease->subnet_mask, option, 4);

                break;

        case DHCP_OPTION_ROUTER:
                if (len >= 4)
                        memcpy(&lease->router, option, 4);

                break;
        }

        return 0;
}

static int client_verify_headers(sd_dhcp_client *client, DHCPPacket *message,
                                 size_t len)
{
        size_t hdrlen;

        if (len < (DHCP_IP_UDP_SIZE + DHCP_MESSAGE_SIZE))
                return -EINVAL;

        hdrlen = message->ip.ihl * 4;
        if (hdrlen < 20 || hdrlen > len || client_checksum(&message->ip,
                                                           hdrlen))
                return -EINVAL;

        message->ip.check = message->udp.len;
        message->ip.ttl = 0;

        if (hdrlen + be16toh(message->udp.len) > len ||
            client_checksum(&message->ip.ttl, be16toh(message->udp.len) + 12))
                return -EINVAL;

        if (be16toh(message->udp.source) != DHCP_PORT_SERVER ||
            be16toh(message->udp.dest) != DHCP_PORT_CLIENT)
                return -EINVAL;

        if (message->dhcp.op != BOOTREPLY)
                return -EINVAL;

        if (be32toh(message->dhcp.xid) != client->xid)
                return -EINVAL;

        if (memcmp(&message->dhcp.chaddr[0], &client->mac_addr.ether_addr_octet,
                    ETHER_ADDR_LEN))
                return -EINVAL;

        return 0;
}

static int client_receive_offer(sd_dhcp_client *client, DHCPPacket *offer,
                                size_t len)
{
        int err;
        DHCPLease *lease;

        err = client_verify_headers(client, offer, len);
        if (err < 0)
                return err;

        lease = new0(DHCPLease, 1);
        if (!lease)
                return -ENOMEM;

        len = len - DHCP_IP_UDP_SIZE;
        if (dhcp_option_parse(&offer->dhcp, len, client_parse_offer,
                              lease) != DHCP_OFFER)
                goto error;

        lease->address = offer->dhcp.yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->subnet_mask == INADDR_ANY ||
            lease->lifetime == 0)
                goto error;

        client->lease = lease;

        return 0;

error:
        free(lease);

        return -ENOMSG;
}

static int client_receive_ack(sd_dhcp_client *client, DHCPPacket *offer,
                              size_t len)
{
        int r;
        DHCPLease *lease;

        r = client_verify_headers(client, offer, len);
        if (r < 0)
                return r;

        lease = new0(DHCPLease, 1);
        if (!lease)
                return -ENOBUFS;

        len = len - DHCP_IP_UDP_SIZE;
        r = dhcp_option_parse(&offer->dhcp, len, client_parse_offer, lease);

        if (r != DHCP_ACK)
                goto error;

        lease->address = offer->dhcp.yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->subnet_mask == INADDR_ANY || lease->lifetime == 0) {
                r = -ENOMSG;
                goto error;
        }

        r = DHCP_EVENT_IP_ACQUIRE;
        if (client->lease) {
                if (client->lease->address != lease->address ||
                    client->lease->subnet_mask != lease->subnet_mask ||
                    client->lease->router != lease->router) {
                        r = DHCP_EVENT_IP_CHANGE;
                }

                free(client->lease);
        }

        client->lease = lease;

        return r;

error:
        free(lease);

        return r;
}

static int client_receive_raw_message(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata)
{
        sd_dhcp_client *client = userdata;
        uint8_t buf[sizeof(DHCPPacket) + DHCP_CLIENT_MIN_OPTIONS_SIZE];
        int buflen = sizeof(buf);
        int len, r = 0;
        DHCPPacket *message;
        usec_t time_now;

        len = read(fd, &buf, buflen);
        if (len < 0)
                return 0;

        r = sd_event_get_now_monotonic(client->event, &time_now);
        if (r < 0)
                goto error;

        message = (DHCPPacket *)&buf;

        switch (client->state) {
        case DHCP_STATE_SELECTING:

                if (client_receive_offer(client, message, len) >= 0) {

                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        client->state = DHCP_STATE_REQUESTING;
                        client->attempt = 1;

                        r = sd_event_add_monotonic(client->event, time_now, 0,
                                                   client_timeout_resend,
                                                   client,
                                                   &client->timeout_resend);
                        if (r < 0)
                                goto error;
                }

                break;

        case DHCP_STATE_REQUESTING:

                r = client_receive_ack(client, message, len);
                if (r == DHCP_EVENT_NO_LEASE)
                        goto error;

                if (r >= 0) {
                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        client->state = DHCP_STATE_BOUND;
                        client->attempt = 1;

                        client->last_addr = client->lease->address;

                        client_notify(client, DHCP_EVENT_IP_ACQUIRE);

                        close(client->fd);
                        client->fd = -1;
                        client->receive_message =
                                sd_event_source_unref(client->receive_message);
                }
                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                break;
        }

error:
        if (r < 0)
                return client_stop(client, r);

        return 0;
}

int sd_dhcp_client_start(sd_dhcp_client *client)
{
        int err;

        assert_return(client, -EINVAL);
        assert_return(client->index >= 0, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT ||
                      client->state == DHCP_STATE_INIT_REBOOT, -EBUSY);

        client->xid = random_u();

        client->fd = dhcp_network_bind_raw_socket(client->index,
                                                  &client->link);

        if (client->fd < 0) {
                err = client->fd;
                goto error;
        }

        err = sd_event_add_io(client->event, client->fd, EPOLLIN,
                              client_receive_raw_message, client,
                              &client->receive_message);
        if (err < 0)
                goto error;

        client->start_time = now(CLOCK_MONOTONIC);
        err = sd_event_add_monotonic(client->event, client->start_time, 0,
                                     client_timeout_resend, client,
                                     &client->timeout_resend);
        if (err < 0)
                goto error;

        return 0;

error:
        client_stop(client, err);

        return err;
}

int sd_dhcp_client_stop(sd_dhcp_client *client)
{
        return client_stop(client, 0);
}

sd_dhcp_client *sd_dhcp_client_new(sd_event *event)
{
        sd_dhcp_client *client;

        assert_return(event, NULL);

        client = new0(sd_dhcp_client, 1);
        if (!client)
                return NULL;

        client->event = sd_event_ref(event);
        client->state = DHCP_STATE_INIT;
        client->index = -1;
        client->fd = -1;
        client->attempt = 1;

        client->req_opts_size = ELEMENTSOF(default_req_opts);

        client->req_opts = memdup(default_req_opts, client->req_opts_size);
        if (!client->req_opts) {
                free(client);
                return NULL;
        }

        return client;
}
