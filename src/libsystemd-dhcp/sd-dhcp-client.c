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
#include <sys/param.h>
#include <sys/ioctl.h>

#include "util.h"
#include "list.h"

#include "dhcp-protocol.h"
#include "dhcp-lease.h"
#include "dhcp-internal.h"
#include "sd-dhcp-client.h"

struct sd_dhcp_client {
        DHCPState state;
        sd_event *event;
        int event_priority;
        sd_event_source *timeout_resend;
        int index;
        int fd;
        union sockaddr_union link;
        sd_event_source *receive_message;
        uint8_t *req_opts;
        size_t req_opts_allocated;
        size_t req_opts_size;
        be32_t last_addr;
        struct ether_addr mac_addr;
        uint32_t xid;
        usec_t start_time;
        uint16_t secs;
        unsigned int attempt;
        usec_t request_sent;
        sd_event_source *timeout_t1;
        sd_event_source *timeout_t2;
        sd_event_source *timeout_expire;
        sd_dhcp_client_cb_t cb;
        void *userdata;
        sd_dhcp_lease *lease;
};

static const uint8_t default_req_opts[] = {
        DHCP_OPTION_SUBNET_MASK,
        DHCP_OPTION_ROUTER,
        DHCP_OPTION_HOST_NAME,
        DHCP_OPTION_DOMAIN_NAME,
        DHCP_OPTION_DOMAIN_NAME_SERVER,
        DHCP_OPTION_NTP_SERVER,
};

static int client_receive_message_raw(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata);
static int client_receive_message_udp(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata);

int sd_dhcp_client_set_callback(sd_dhcp_client *client, sd_dhcp_client_cb_t cb,
                                void *userdata) {
        assert_return(client, -EINVAL);

        client->cb = cb;
        client->userdata = userdata;

        return 0;
}

int sd_dhcp_client_set_request_option(sd_dhcp_client *client, uint8_t option) {
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

        if (!GREEDY_REALLOC(client->req_opts, client->req_opts_allocated,
                            client->req_opts_size + 1))
                return -ENOMEM;

        client->req_opts[client->req_opts_size++] = option;

        return 0;
}

int sd_dhcp_client_set_request_address(sd_dhcp_client *client,
                                       const struct in_addr *last_addr) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);

        if (last_addr)
                client->last_addr = last_addr->s_addr;
        else
                client->last_addr = INADDR_ANY;

        return 0;
}

int sd_dhcp_client_set_index(sd_dhcp_client *client, int interface_index) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);
        assert_return(interface_index >= -1, -EINVAL);

        client->index = interface_index;

        return 0;
}

int sd_dhcp_client_set_mac(sd_dhcp_client *client,
                           const struct ether_addr *addr) {
        assert_return(client, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT, -EBUSY);

        memcpy(&client->mac_addr, addr, ETH_ALEN);

        return 0;
}

int sd_dhcp_client_get_lease(sd_dhcp_client *client, sd_dhcp_lease **ret) {
        assert_return(client, -EINVAL);
        assert_return(ret, -EINVAL);

        if (client->state != DHCP_STATE_BOUND &&
            client->state != DHCP_STATE_RENEWING &&
            client->state != DHCP_STATE_REBINDING)
                return -EADDRNOTAVAIL;

        *ret = sd_dhcp_lease_ref(client->lease);

        return 0;
}

static int client_notify(sd_dhcp_client *client, int event) {
        if (client->cb)
                client->cb(client, event, client->userdata);

        return 0;
}

static int client_stop(sd_dhcp_client *client, int error) {
        assert_return(client, -EINVAL);

        client->receive_message =
                sd_event_source_unref(client->receive_message);

        if (client->fd >= 0)
                close(client->fd);
        client->fd = -1;

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);
        client->timeout_expire = sd_event_source_unref(client->timeout_expire);

        client->attempt = 1;

        client_notify(client, error);

        client->start_time = 0;
        client->secs = 0;
        client->state = DHCP_STATE_INIT;

        if (client->lease)
                client->lease = sd_dhcp_lease_unref(client->lease);

        log_dhcp_client(client, "STOPPED");

        return 0;
}

static int client_message_init(sd_dhcp_client *client, DHCPMessage *message,
                               uint8_t type, uint16_t secs, uint8_t **opt,
                               size_t *optlen) {
        int r;

        assert(secs);

        r = dhcp_message_init(message, BOOTREQUEST, client->xid, type, opt,
                              optlen);
        if (r < 0)
                return r;

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers
           refuse to issue an DHCP lease if 'secs' is set to zero */
        message->secs = htobe16(secs);

        memcpy(&message->chaddr, &client->mac_addr, ETH_ALEN);

        if (client->state == DHCP_STATE_RENEWING ||
            client->state == DHCP_STATE_REBINDING)
                message->ciaddr = client->lease->address;

        /* Some DHCP servers will refuse to issue an DHCP lease if the Client
           Identifier option is not set */
        r = dhcp_option_append(opt, optlen, DHCP_OPTION_CLIENT_IDENTIFIER,
                               ETH_ALEN, &client->mac_addr);
        if (r < 0)
                return r;

        if (type == DHCP_DISCOVER || type == DHCP_REQUEST) {
                be16_t max_size;

                r = dhcp_option_append(opt, optlen,
                                       DHCP_OPTION_PARAMETER_REQUEST_LIST,
                                       client->req_opts_size,
                                       client->req_opts);
                if (r < 0)
                        return r;

                /* Some DHCP servers will send bigger DHCP packets than the
                   defined default size unless the Maximum Messge Size option
                   is explicitely set */
                max_size = htobe16(DHCP_IP_UDP_SIZE + DHCP_MESSAGE_SIZE +
                                   DHCP_MIN_OPTIONS_SIZE);
                r = dhcp_option_append(opt, optlen,
                                       DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
                                       2, &max_size);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int client_send_discover(sd_dhcp_client *client, uint16_t secs) {
        int err = 0;
        _cleanup_free_ DHCPPacket *discover;
        size_t optlen, len;
        uint8_t *opt;

        optlen = DHCP_MIN_OPTIONS_SIZE;
        len = sizeof(DHCPPacket) + optlen;

        discover = malloc0(len);

        if (!discover)
                return -ENOMEM;

        err = client_message_init(client, &discover->dhcp, DHCP_DISCOVER,
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

        dhcp_packet_append_ip_headers(discover, len);

        err = dhcp_network_send_raw_socket(client->fd, &client->link,
                                           discover, len);

        log_dhcp_client(client, "DISCOVER");

        return err;
}

static int client_send_request(sd_dhcp_client *client, uint16_t secs) {
        _cleanup_free_ DHCPPacket *request;
        size_t optlen, len;
        int err;
        uint8_t *opt;

        optlen = DHCP_MIN_OPTIONS_SIZE;
        len = sizeof(DHCPPacket) + optlen;

        request = malloc0(len);
        if (!request)
                return -ENOMEM;

        err = client_message_init(client, &request->dhcp, DHCP_REQUEST, secs,
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

        if (client->state == DHCP_STATE_RENEWING) {
                err = dhcp_network_send_udp_socket(client->fd,
                                                   client->lease->server_address,
                                                   DHCP_PORT_SERVER,
                                                   &request->dhcp,
                                                   len - DHCP_IP_UDP_SIZE);
        } else {
                dhcp_packet_append_ip_headers(request, len);

                err = dhcp_network_send_raw_socket(client->fd, &client->link,
                                                   request, len);
        }

        log_dhcp_client(client, "REQUEST");

        return err;
}

static uint16_t client_update_secs(sd_dhcp_client *client, usec_t time_now)
{
        client->secs = ((time_now - client->start_time) / USEC_PER_SEC) ? : 1;

        return client->secs;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec,
                                 void *userdata) {
        sd_dhcp_client *client = userdata;
        usec_t next_timeout = 0;
        uint32_t time_left;
        int r = 0;

        assert(s);
        assert(client);
        assert(client->event);

        switch (client->state) {
        case DHCP_STATE_RENEWING:

                time_left = (client->lease->t2 - client->lease->t1) / 2;
                if (time_left < 60)
                        time_left = 60;

                next_timeout = usec + time_left * USEC_PER_SEC;

                break;

        case DHCP_STATE_REBINDING:

                time_left = (client->lease->lifetime - client->lease->t2) / 2;
                if (time_left < 60)
                        time_left = 60;

                next_timeout = usec + time_left * USEC_PER_SEC;
                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_BOUND:

                if (client->attempt < 64)
                        client->attempt *= 2;

                next_timeout = usec + (client->attempt - 1) * USEC_PER_SEC;

                break;
        }

        next_timeout += (random_u32() & 0x1fffff);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        r = sd_event_add_monotonic(client->event,
                                     &client->timeout_resend,
                                     next_timeout,
                                     10 * USEC_PER_MSEC,
                                     client_timeout_resend, client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->timeout_resend,
                                         client->event_priority);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_INIT:

                client_update_secs(client, usec);

                r = client_send_discover(client, client->secs);
                if (r >= 0) {
                        client->state = DHCP_STATE_SELECTING;
                        client->attempt = 1;
                } else {
                        if (client->attempt >= 64)
                                goto error;
                }

                break;

        case DHCP_STATE_SELECTING:
                client_update_secs(client, usec);

                r = client_send_discover(client, client->secs);
                if (r < 0 && client->attempt >= 64)
                        goto error;

                break;

        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                r = client_send_request(client, client->secs);
                if (r < 0 && client->attempt >= 64)
                         goto error;

                client->request_sent = usec;

                break;

        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:

                break;
        }

        return 0;

error:
        client_stop(client, r);

        /* Errors were dealt with when stopping the client, don't spill
           errors into the event loop handler */
        return 0;
}

static int client_initialize_events(sd_dhcp_client *client,
                                    sd_event_io_handler_t io_callback,
                                    usec_t usec) {
        int r;

        assert(client);
        assert(client->event);

        r = sd_event_add_io(client->event, &client->receive_message,
                            client->fd, EPOLLIN, io_callback,
                            client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->receive_message,
                                         client->event_priority);
        if (r < 0)
                goto error;

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        r = sd_event_add_monotonic(client->event,
                                   &client->timeout_resend,
                                   usec, 0,
                                   client_timeout_resend, client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->timeout_resend,
                                         client->event_priority);

error:
        if (r < 0)
                client_stop(client, r);

        return 0;

}

static int client_timeout_expire(sd_event_source *s, uint64_t usec,
                                 void *userdata) {
        sd_dhcp_client *client = userdata;

        log_dhcp_client(client, "EXPIRED");

        client_stop(client, DHCP_EVENT_EXPIRED);

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = userdata;
        int r;

        if (client->fd >= 0) {
                client->receive_message =
                        sd_event_source_unref(client->receive_message);
                close(client->fd);
                client->fd = -1;
        }

        client->state = DHCP_STATE_REBINDING;
        client->attempt = 1;

        r = dhcp_network_bind_raw_socket(client->index, &client->link);
        if (r < 0) {
                client_stop(client, r);
                return 0;
        }

        client->fd = r;

        log_dhcp_client(client, "TIMEOUT T2");

        return client_initialize_events(client, client_receive_message_raw,
                                        usec);
}

static int client_timeout_t1(sd_event_source *s, uint64_t usec,
                             void *userdata) {
        sd_dhcp_client *client = userdata;
        int r;

        client->state = DHCP_STATE_RENEWING;
        client->attempt = 1;

        r = dhcp_network_bind_udp_socket(client->index,
                                         client->lease->address,
                                         DHCP_PORT_CLIENT);
        if (r < 0) {
                client_stop(client, r);
                return 0;
        }

        client->fd = r;

        log_dhcp_client(client, "TIMEOUT T1");

        return client_initialize_events(client, client_receive_message_udp, usec);
}

static int client_handle_offer(sd_dhcp_client *client, DHCPMessage *offer,
                               size_t len) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        int r;

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        r = dhcp_option_parse(offer, len, dhcp_lease_parse_options, lease);
        if (r != DHCP_OFFER)
                return -ENOMSG;

        lease->address = offer->yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->subnet_mask == INADDR_ANY ||
            lease->lifetime == 0)
                return -ENOMSG;

        client->lease = lease;
        lease = NULL;

        log_dhcp_client(client, "OFFER");

        return 0;
}

static int client_handle_ack(sd_dhcp_client *client, DHCPMessage *ack,
                             size_t len) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        int r;

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        r = dhcp_option_parse(ack, len, dhcp_lease_parse_options, lease);
        if (r == DHCP_NAK) {
                log_dhcp_client(client, "NAK");
                return DHCP_EVENT_NO_LEASE;
        }

        if (r != DHCP_ACK)
                return -ENOMSG;

        lease->address = ack->yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->subnet_mask == INADDR_ANY || lease->lifetime == 0)
                return -ENOMSG;

        r = DHCP_EVENT_IP_ACQUIRE;
        if (client->lease) {
                if (client->lease->address != lease->address ||
                    client->lease->subnet_mask != lease->subnet_mask ||
                    client->lease->router != lease->router) {
                        r = DHCP_EVENT_IP_CHANGE;
                }

                client->lease = sd_dhcp_lease_unref(client->lease);
        }

        client->lease = lease;
        lease = NULL;

        log_dhcp_client(client, "ACK");

        return r;
}

static uint64_t client_compute_timeout(uint64_t request_sent,
                                       uint32_t lifetime) {
        return request_sent + (lifetime - 3) * USEC_PER_SEC +
                + (random_u32() & 0x1fffff);
}

static int client_set_lease_timeouts(sd_dhcp_client *client, uint64_t usec) {
        uint64_t next_timeout;
        int r;

        assert(client);
        assert(client->event);

        if (client->lease->lifetime < 10)
                return -EINVAL;

        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);
        client->timeout_expire = sd_event_source_unref(client->timeout_expire);

        if (!client->lease->t1)
                client->lease->t1 = client->lease->lifetime / 2;

        next_timeout = client_compute_timeout(client->request_sent,
                                              client->lease->t1);
        if (next_timeout < usec)
                return -EINVAL;

        r = sd_event_add_monotonic(client->event,
                                     &client->timeout_t1,
                                     next_timeout,
                                     10 * USEC_PER_MSEC,
                                     client_timeout_t1, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_t1,
                                         client->event_priority);
        if (r < 0)
                return r;

        if (!client->lease->t2)
                client->lease->t2 = client->lease->lifetime * 7 / 8;

        if (client->lease->t2 < client->lease->t1)
                return -EINVAL;

        if (client->lease->lifetime < client->lease->t2)
                return -EINVAL;

        next_timeout = client_compute_timeout(client->request_sent,
                                              client->lease->t2);
        if (next_timeout < usec)
                return -EINVAL;

        r = sd_event_add_monotonic(client->event,
                                     &client->timeout_t2,
                                     next_timeout,
                                     10 * USEC_PER_MSEC,
                                     client_timeout_t2, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_t2,
                                         client->event_priority);
        if (r < 0)
                return r;

        next_timeout = client_compute_timeout(client->request_sent,
                                              client->lease->lifetime);
        if (next_timeout < usec)
                return -EINVAL;

        r = sd_event_add_monotonic(client->event,
                                     &client->timeout_expire, next_timeout,
                                     10 * USEC_PER_MSEC,
                                     client_timeout_expire, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_expire,
                                         client->event_priority);
        if (r < 0)
                return r;

        return 0;
}

static int client_handle_message(sd_dhcp_client *client, DHCPMessage *message,
                                 int len, usec_t time_now) {
        int r = 0, notify_event = 0;

        assert(client);
        assert(client->event);
        assert(message);

        if (len < DHCP_MESSAGE_SIZE) {
                log_dhcp_client(client, "message too small (%d bytes): "
                                "ignoring", len);
                return 0;
        }

        if (message->op != BOOTREPLY) {
                log_dhcp_client(client, "not a BOOTREPLY message: ignoring");
                return 0;
        }

        if (be32toh(message->xid) != client->xid) {
                log_dhcp_client(client, "received xid (%u) does not match "
                                "expected (%u): ignoring",
                                be32toh(message->xid), client->xid);
                return 0;
        }

        if (memcmp(&message->chaddr[0], &client->mac_addr.ether_addr_octet,
                   ETHER_ADDR_LEN)) {
                log_dhcp_client(client, "received chaddr does not match "
                                "expected: ignoring");
                return 0;
        }

        switch (client->state) {
        case DHCP_STATE_SELECTING:

                r = client_handle_offer(client, message, len);
                if (r >= 0) {

                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        client->state = DHCP_STATE_REQUESTING;
                        client->attempt = 1;

                        r = sd_event_add_monotonic(client->event,
                                                   &client->timeout_resend,
                                                   time_now, 0,
                                                   client_timeout_resend,
                                                   client);
                        if (r < 0)
                                goto error;

                        r = sd_event_source_set_priority(client->timeout_resend,
                                                         client->event_priority);
                        if (r < 0)
                                goto error;
                }

                break;

        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                r = client_handle_ack(client, message, len);

                if (r == DHCP_EVENT_NO_LEASE)
                        goto error;

                if (r >= 0) {
                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        if (client->state == DHCP_STATE_REQUESTING)
                                notify_event = DHCP_EVENT_IP_ACQUIRE;
                        else if (r != DHCP_EVENT_IP_ACQUIRE)
                                notify_event = r;

                        client->state = DHCP_STATE_BOUND;
                        client->attempt = 1;

                        client->last_addr = client->lease->address;

                        r = client_set_lease_timeouts(client, time_now);
                        if (r < 0)
                                goto error;

                        if (notify_event)
                                client_notify(client, notify_event);

                        client->receive_message =
                                sd_event_source_unref(client->receive_message);
                        close(client->fd);
                        client->fd = -1;
                }

                r = 0;

                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:

                break;
        }

error:
        if (r < 0 || r == DHCP_EVENT_NO_LEASE)
                return client_stop(client, r);

        return 0;
}

static int client_receive_message_udp(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata) {
        sd_dhcp_client *client = userdata;
        _cleanup_free_ DHCPMessage *message = NULL;
        int buflen = 0, len, r;
        usec_t time_now;

        assert(s);
        assert(client);
        assert(client->event);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = sizeof(DHCPMessage) + DHCP_MIN_OPTIONS_SIZE;

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        len = read(fd, message, buflen);
        if (len < 0)
                return 0;

        r = sd_event_get_now_monotonic(client->event, &time_now);
        if (r < 0)
                return client_stop(client, r);

        return client_handle_message(client, message, len,
                                     time_now);
}

static int client_receive_message_raw(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata) {
        sd_dhcp_client *client = userdata;
        _cleanup_free_ DHCPPacket *packet = NULL;
        usec_t time_now;
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        bool checksum = true;
        int buflen = 0, len, r;

        assert(s);
        assert(client);
        assert(client->event);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = sizeof(DHCPPacket) + DHCP_MIN_OPTIONS_SIZE;

        packet = malloc0(buflen);
        if (!packet)
                return -ENOMEM;

        iov.iov_base = packet;
        iov.iov_len = buflen;

        len = recvmsg(fd, &msg, 0);
        if (len < 0) {
                log_dhcp_client(client, "could not receive message from raw "
                                "socket: %s", strerror(errno));
                return 0;
        }

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_PACKET && cmsg->cmsg_type == PACKET_AUXDATA) {
                        struct tpacket_auxdata *aux = (void *)CMSG_DATA(cmsg);

                        checksum = !(aux->tp_status & TP_STATUS_CSUMNOTREADY);
                        break;
                }
        }

        r = dhcp_packet_verify_headers(packet, len, checksum);
        if (r < 0)
                return 0;

        len -= DHCP_IP_UDP_SIZE;

        r = sd_event_get_now_monotonic(client->event, &time_now);
        if (r < 0)
                return client_stop(client, r);

        return client_handle_message(client, &packet->dhcp, len, time_now);
}

int sd_dhcp_client_start(sd_dhcp_client *client) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT ||
                      client->state == DHCP_STATE_INIT_REBOOT, -EBUSY);

        client->xid = random_u32();

        r = dhcp_network_bind_raw_socket(client->index, &client->link);

        if (r < 0) {
                client_stop(client, r);
                return r;
        }

        client->fd = r;
        client->start_time = now(CLOCK_MONOTONIC);
        client->secs = 0;

        log_dhcp_client(client, "STARTED");

        return client_initialize_events(client, client_receive_message_raw,
                                        client->start_time);
}

int sd_dhcp_client_stop(sd_dhcp_client *client) {
        return client_stop(client, DHCP_EVENT_STOP);
}

int sd_dhcp_client_attach_event(sd_dhcp_client *client, sd_event *event,
                                int priority) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(!client->event, -EBUSY);

        if (event)
                client->event = sd_event_ref(event);
        else {
                r = sd_event_default(&client->event);
                if (r < 0)
                        return 0;
        }

        client->event_priority = priority;

        return 0;
}

int sd_dhcp_client_detach_event(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);

        client->event = sd_event_unref(client->event);

        return 0;
}

sd_event *sd_dhcp_client_get_event(sd_dhcp_client *client) {
        if (!client)
                return NULL;

        return client->event;
}

void sd_dhcp_client_free(sd_dhcp_client *client) {
        if (!client)
                return;

        sd_dhcp_client_stop(client);
        sd_dhcp_client_detach_event(client);

        free(client->req_opts);
        free(client);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_dhcp_client*, sd_dhcp_client_free);
#define _cleanup_dhcp_client_free_ _cleanup_(sd_dhcp_client_freep)

int sd_dhcp_client_new(sd_dhcp_client **ret) {
        _cleanup_dhcp_client_free_ sd_dhcp_client *client = NULL;

        assert_return(ret, -EINVAL);

        client = new0(sd_dhcp_client, 1);
        if (!client)
                return -ENOMEM;

        client->state = DHCP_STATE_INIT;
        client->index = -1;
        client->fd = -1;
        client->attempt = 1;

        client->req_opts_size = ELEMENTSOF(default_req_opts);

        client->req_opts = memdup(default_req_opts, client->req_opts_size);
        if (!client->req_opts)
                return -ENOMEM;

        *ret = client;
        client = NULL;

        return 0;
}
