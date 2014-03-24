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
#include "dhcp-internal.h"
#include "dhcp-lease-internal.h"
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
        struct {
                uint8_t type;
                struct ether_addr mac_addr;
        } _packed_ client_id;
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
        bool need_restart = false;

        assert_return(client, -EINVAL);
        assert_return(addr, -EINVAL);

        if (memcmp(&client->client_id.mac_addr, addr, ETH_ALEN) == 0)
                return 0;

        if (client->state != DHCP_STATE_INIT) {
                log_dhcp_client(client, "Changing MAC address on running DHCP "
                                "client, restarting");
                sd_dhcp_client_stop(client);
                need_restart = true;
        }

        memcpy(&client->client_id.mac_addr, addr, ETH_ALEN);
        client->client_id.type = 0x01;

        if (need_restart)
                sd_dhcp_client_start(client);

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

static int client_initialize(sd_dhcp_client *client) {
        assert_return(client, -EINVAL);

        client->receive_message =
                sd_event_source_unref(client->receive_message);

        client->fd = safe_close(client->fd);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);
        client->timeout_expire = sd_event_source_unref(client->timeout_expire);

        client->attempt = 1;

        client->state = DHCP_STATE_INIT;
        client->xid = 0;

        if (client->lease)
                client->lease = sd_dhcp_lease_unref(client->lease);

        return 0;
}

static int client_stop(sd_dhcp_client *client, int error) {
        assert_return(client, -EINVAL);

        client_notify(client, error);

        client_initialize(client);

        log_dhcp_client(client, "STOPPED");

        return 0;
}

static int client_message_init(sd_dhcp_client *client, DHCPMessage *message,
                               uint8_t type, uint8_t **opt, size_t *optlen) {
        int r;

        assert(client);
        assert(client->secs);
        assert(message);
        assert(opt);
        assert(optlen);

        r = dhcp_message_init(message, BOOTREQUEST, client->xid, type, opt,
                              optlen);
        if (r < 0)
                return r;

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers
           refuse to issue an DHCP lease if 'secs' is set to zero */
        message->secs = htobe16(client->secs);

        memcpy(&message->chaddr, &client->client_id.mac_addr, ETH_ALEN);

        if (client->state == DHCP_STATE_RENEWING ||
            client->state == DHCP_STATE_REBINDING)
                message->ciaddr = client->lease->address;

        /* Some DHCP servers will refuse to issue an DHCP lease if the Client
           Identifier option is not set */
        r = dhcp_option_append(opt, optlen, DHCP_OPTION_CLIENT_IDENTIFIER,
                               sizeof(client->client_id), &client->client_id);
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

static int dhcp_client_send_raw(sd_dhcp_client *client, DHCPPacket *packet,
                                size_t len) {
        dhcp_packet_append_ip_headers(packet, INADDR_ANY, DHCP_PORT_CLIENT,
                                      INADDR_BROADCAST, DHCP_PORT_SERVER, len);

        return dhcp_network_send_raw_socket(client->fd, &client->link,
                                            packet, len);
}

static int client_send_discover(sd_dhcp_client *client) {
        _cleanup_free_ DHCPPacket *discover;
        size_t optlen, len;
        uint8_t *opt;
        usec_t time_now;
        int r;

        assert(client);

        r = sd_event_now(client->event, CLOCK_MONOTONIC, &time_now);
        if (r < 0)
                return r;
        assert(time_now >= client->start_time);

        /* seconds between sending first and last DISCOVER
         * must always be strictly positive to deal with broken servers */
        client->secs = ((time_now - client->start_time) / USEC_PER_SEC) ? : 1;

        optlen = DHCP_MIN_OPTIONS_SIZE;
        len = sizeof(DHCPPacket) + optlen;

        discover = malloc0(len);
        if (!discover)
                return -ENOMEM;

        r = client_message_init(client, &discover->dhcp, DHCP_DISCOVER,
                                &opt, &optlen);
        if (r < 0)
                return r;

        if (client->last_addr != INADDR_ANY) {
                r = dhcp_option_append(&opt, &optlen,
                                         DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                         4, &client->last_addr);
                if (r < 0)
                        return r;
        }

        r = dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        r = dhcp_client_send_raw(client, discover, len - optlen);
        if (r < 0)
                return r;

        log_dhcp_client(client, "DISCOVER");

        return 0;
}

static int client_send_request(sd_dhcp_client *client) {
        _cleanup_free_ DHCPPacket *request;
        size_t optlen, len;
        uint8_t *opt;
        int r;

        optlen = DHCP_MIN_OPTIONS_SIZE;
        len = sizeof(DHCPPacket) + optlen;

        request = malloc0(len);
        if (!request)
                return -ENOMEM;

        r = client_message_init(client, &request->dhcp, DHCP_REQUEST, &opt,
                                &optlen);
        if (r < 0)
                return r;

        switch (client->state) {

        case DHCP_STATE_INIT_REBOOT:
                r = dhcp_option_append(&opt, &optlen,
                                         DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                         4, &client->last_addr);
                if (r < 0)
                        return r;
                break;

        case DHCP_STATE_REQUESTING:
                r = dhcp_option_append(&opt, &optlen,
                                       DHCP_OPTION_REQUESTED_IP_ADDRESS,
                                       4, &client->lease->address);
                if (r < 0)
                        return r;

                r = dhcp_option_append(&opt, &optlen,
                                       DHCP_OPTION_SERVER_IDENTIFIER,
                                       4, &client->lease->server_address);
                if (r < 0)
                        return r;
                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                break;
        }

        r = dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        if (client->state == DHCP_STATE_RENEWING) {
                r = dhcp_network_send_udp_socket(client->fd,
                                                 client->lease->server_address,
                                                 DHCP_PORT_SERVER,
                                                 &request->dhcp,
                                                 len - optlen - DHCP_IP_UDP_SIZE);
        } else {
                r = dhcp_client_send_raw(client, request, len - optlen);
        }
        if (r < 0)
                return r;

        log_dhcp_client(client, "REQUEST");

        return 0;
}

static int client_timeout_resend(sd_event_source *s, uint64_t usec,
                                 void *userdata) {
        sd_dhcp_client *client = userdata;
        usec_t next_timeout = 0;
        uint64_t time_now;
        uint32_t time_left;
        int r;

        assert(s);
        assert(client);
        assert(client->event);

        r = sd_event_now(client->event, CLOCK_MONOTONIC, &time_now);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_RENEWING:

                time_left = (client->lease->t2 - client->lease->t1) / 2;
                if (time_left < 60)
                        time_left = 60;

                next_timeout = time_now + time_left * USEC_PER_SEC;

                break;

        case DHCP_STATE_REBINDING:

                time_left = (client->lease->lifetime - client->lease->t2) / 2;
                if (time_left < 60)
                        time_left = 60;

                next_timeout = time_now + time_left * USEC_PER_SEC;
                break;

        case DHCP_STATE_REBOOTING:
                /* start over as we did not receive a timely ack or nak */
                client->state = DHCP_STATE_INIT;
                client->attempt = 1;
                client->xid = random_u32();

                /* fall through */
        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_SELECTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_BOUND:

                if (client->attempt < 64)
                        client->attempt *= 2;

                next_timeout = time_now + (client->attempt - 1) * USEC_PER_SEC;

                break;
        }

        next_timeout += (random_u32() & 0x1fffff);

        client->timeout_resend = sd_event_source_unref(client->timeout_resend);

        r = sd_event_add_time(client->event,
                              &client->timeout_resend,
                              CLOCK_MONOTONIC,
                              next_timeout, 10 * USEC_PER_MSEC,
                              client_timeout_resend, client);
        if (r < 0)
                goto error;

        r = sd_event_source_set_priority(client->timeout_resend,
                                         client->event_priority);
        if (r < 0)
                goto error;

        switch (client->state) {
        case DHCP_STATE_INIT:
                r = client_send_discover(client);
                if (r >= 0) {
                        client->state = DHCP_STATE_SELECTING;
                        client->attempt = 1;
                } else {
                        if (client->attempt >= 64)
                                goto error;
                }

                break;

        case DHCP_STATE_SELECTING:
                r = client_send_discover(client);
                if (r < 0 && client->attempt >= 64)
                        goto error;

                break;

        case DHCP_STATE_INIT_REBOOT:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
                r = client_send_request(client);
                if (r < 0 && client->attempt >= 64)
                         goto error;

                if (client->state == DHCP_STATE_INIT_REBOOT)
                        client->state = DHCP_STATE_REBOOTING;

                client->request_sent = time_now;

                break;

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
                                    sd_event_io_handler_t io_callback) {
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

        r = sd_event_add_time(client->event,
                              &client->timeout_resend,
                              CLOCK_MONOTONIC,
                              0, 0,
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

static int client_start(sd_dhcp_client *client) {
        int r;

        assert_return(client, -EINVAL);
        assert_return(client->event, -EINVAL);
        assert_return(client->index > 0, -EINVAL);
        assert_return(client->fd < 0, -EBUSY);
        assert_return(client->xid == 0, -EINVAL);
        assert_return(client->state == DHCP_STATE_INIT ||
                      client->state == DHCP_STATE_INIT_REBOOT, -EBUSY);

        client->xid = random_u32();

        r = dhcp_network_bind_raw_socket(client->index, &client->link);

        if (r < 0) {
                client_stop(client, r);
                return r;
        }
        client->fd = r;

        if (client->state == DHCP_STATE_INIT) {
                client->start_time = now(CLOCK_MONOTONIC);
                client->secs = 0;
        }

        log_dhcp_client(client, "STARTED");

        return client_initialize_events(client, client_receive_message_raw);
}

static int client_timeout_expire(sd_event_source *s, uint64_t usec,
                                 void *userdata) {
        sd_dhcp_client *client = userdata;

        log_dhcp_client(client, "EXPIRED");

        client_notify(client, DHCP_EVENT_EXPIRED);

        /* start over as the lease was lost */
        client_initialize(client);
        client_start(client);

        return 0;
}

static int client_timeout_t2(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_dhcp_client *client = userdata;
        int r;

        client->receive_message = sd_event_source_unref(client->receive_message);
        client->fd = safe_close(client->fd);

        client->state = DHCP_STATE_REBINDING;
        client->attempt = 1;

        r = dhcp_network_bind_raw_socket(client->index, &client->link);
        if (r < 0) {
                client_stop(client, r);
                return 0;
        }

        client->fd = r;

        log_dhcp_client(client, "TIMEOUT T2");

        return client_initialize_events(client, client_receive_message_raw);
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

        return client_initialize_events(client, client_receive_message_udp);
}

static int client_handle_offer(sd_dhcp_client *client, DHCPMessage *offer,
                               size_t len) {
        _cleanup_dhcp_lease_unref_ sd_dhcp_lease *lease = NULL;
        int r;

        r = dhcp_lease_new(&lease);
        if (r < 0)
                return r;

        r = dhcp_option_parse(offer, len, dhcp_lease_parse_options, lease);
        if (r != DHCP_OFFER) {
                log_dhcp_client(client, "receieved message was not an OFFER, ignoring");
                return -ENOMSG;
        }

        lease->next_server = offer->siaddr;

        lease->address = offer->yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->lifetime == 0) {
                log_dhcp_client(client, "receieved lease lacks address, server "
                                "address or lease lifetime, ignoring");
                return -ENOMSG;
        }

        if (lease->subnet_mask == INADDR_ANY) {
                r = dhcp_lease_set_default_subnet_mask(lease);
                if (r < 0) {
                        log_dhcp_client(client, "receieved lease lacks subnet "
                                        "mask, and a fallback one can not be "
                                        "generated, ignoring");
                        return -ENOMSG;
                }
        }

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

        if (r != DHCP_ACK) {
                log_dhcp_client(client, "receieved message was not an ACK, ignoring");
                return -ENOMSG;
        }

        lease->next_server = ack->siaddr;

        lease->address = ack->yiaddr;

        if (lease->address == INADDR_ANY ||
            lease->server_address == INADDR_ANY ||
            lease->lifetime == 0) {
                log_dhcp_client(client, "receieved lease lacks address, server "
                                "address or lease lifetime, ignoring");
                return -ENOMSG;
        }

        if (lease->subnet_mask == INADDR_ANY) {
                r = dhcp_lease_set_default_subnet_mask(lease);
                if (r < 0) {
                        log_dhcp_client(client, "receieved lease lacks subnet "
                                        "mask, and a fallback one can not be "
                                        "generated, ignoring");
                        return -ENOMSG;
                }
        }

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

static uint64_t client_compute_timeout(sd_dhcp_client *client,
                                       uint32_t lifetime, double factor) {
        assert(client);
        assert(client->request_sent);
        assert(lifetime);

        return client->request_sent + ((lifetime - 3) * USEC_PER_SEC * factor) +
                + (random_u32() & 0x1fffff);
}

static int client_set_lease_timeouts(sd_dhcp_client *client) {
        usec_t time_now;
        uint64_t lifetime_timeout;
        uint64_t t2_timeout;
        uint64_t t1_timeout;
        char time_string[FORMAT_TIMESPAN_MAX];
        int r;

        assert(client);
        assert(client->event);
        assert(client->lease);
        assert(client->lease->lifetime);

        client->timeout_t1 = sd_event_source_unref(client->timeout_t1);
        client->timeout_t2 = sd_event_source_unref(client->timeout_t2);
        client->timeout_expire = sd_event_source_unref(client->timeout_expire);

        /* don't set timers for infinite leases */
        if (client->lease->lifetime == 0xffffffff)
                return 0;

        r = sd_event_now(client->event, CLOCK_MONOTONIC, &time_now);
        if (r < 0)
                return r;
        assert(client->request_sent <= time_now);

        /* convert the various timeouts from relative (secs) to absolute (usecs) */
        lifetime_timeout = client_compute_timeout(client, client->lease->lifetime, 1);
        if (client->lease->t1 && client->lease->t2) {
                /* both T1 and T2 are given */
                if (client->lease->t1 < client->lease->t2 &&
                    client->lease->t2 < client->lease->lifetime) {
                        /* they are both valid */
                        t2_timeout = client_compute_timeout(client, client->lease->t2, 1);
                        t1_timeout = client_compute_timeout(client, client->lease->t1, 1);
                } else {
                        /* discard both */
                        t2_timeout = client_compute_timeout(client, client->lease->lifetime, 7.0 / 8.0);
                        client->lease->t2 = (client->lease->lifetime * 7) / 8;
                        t1_timeout = client_compute_timeout(client, client->lease->lifetime, 0.5);
                        client->lease->t1 = client->lease->lifetime / 2;
                }
        } else if (client->lease->t2 && client->lease->t2 < client->lease->lifetime) {
                /* only T2 is given, and it is valid */
                t2_timeout = client_compute_timeout(client, client->lease->t2, 1);
                t1_timeout = client_compute_timeout(client, client->lease->lifetime, 0.5);
                client->lease->t1 = client->lease->lifetime / 2;
                if (t2_timeout <= t1_timeout) {
                        /* the computed T1 would be invalid, so discard T2 */
                        t2_timeout = client_compute_timeout(client, client->lease->lifetime, 7.0 / 8.0);
                        client->lease->t2 = (client->lease->lifetime * 7) / 8;
                }
        } else if (client->lease->t1 && client->lease->t1 < client->lease->lifetime) {
                /* only T1 is given, and it is valid */
                t1_timeout = client_compute_timeout(client, client->lease->t1, 1);
                t2_timeout = client_compute_timeout(client, client->lease->lifetime, 7.0 / 8.0);
                client->lease->t2 = (client->lease->lifetime * 7) / 8;
                if (t2_timeout <= t1_timeout) {
                        /* the computed T2 would be invalid, so discard T1 */
                        t2_timeout = client_compute_timeout(client, client->lease->lifetime, 0.5);
                        client->lease->t2 = client->lease->lifetime / 2;
                }
        } else {
                /* fall back to the default timeouts */
                t1_timeout = client_compute_timeout(client, client->lease->lifetime, 0.5);
                client->lease->t1 = client->lease->lifetime / 2;
                t2_timeout = client_compute_timeout(client, client->lease->lifetime, 7.0 / 8.0);
                client->lease->t2 = (client->lease->lifetime * 7) / 8;
        }

        /* arm lifetime timeout */
        r = sd_event_add_time(client->event, &client->timeout_expire,
                              CLOCK_MONOTONIC,
                              lifetime_timeout, 10 * USEC_PER_MSEC,
                              client_timeout_expire, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_expire,
                                         client->event_priority);
        if (r < 0)
                return r;

        log_dhcp_client(client, "lease expires in %s",
                        format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                        lifetime_timeout - time_now, 0));

        /* don't arm earlier timeouts if this has already expired */
        if (lifetime_timeout <= time_now)
                return 0;

        /* arm T2 timeout */
        r = sd_event_add_time(client->event,
                              &client->timeout_t2,
                              CLOCK_MONOTONIC,
                              t2_timeout,
                              10 * USEC_PER_MSEC,
                              client_timeout_t2, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_t2,
                                         client->event_priority);
        if (r < 0)
                return r;

        log_dhcp_client(client, "T2 expires in %s",
                        format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                        t2_timeout - time_now, 0));

        /* don't arm earlier timeout if this has already expired */
        if (t2_timeout <= time_now)
                return 0;

        /* arm T1 timeout */
        r = sd_event_add_time(client->event,
                              &client->timeout_t1,
                              CLOCK_MONOTONIC,
                              t1_timeout, 10 * USEC_PER_MSEC,
                              client_timeout_t1, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(client->timeout_t1,
                                         client->event_priority);
        if (r < 0)
                return r;

        log_dhcp_client(client, "T1 expires in %s",
                        format_timespan(time_string, FORMAT_TIMESPAN_MAX,
                        t1_timeout - time_now, 0));

        return 0;
}

static int client_handle_message(sd_dhcp_client *client, DHCPMessage *message,
                                 int len) {
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

        if (memcmp(&message->chaddr[0], &client->client_id.mac_addr,
                   ETH_ALEN)) {
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

                        r = sd_event_add_time(client->event,
                                              &client->timeout_resend,
                                              CLOCK_MONOTONIC,
                                              0, 0,
                                              client_timeout_resend, client);
                        if (r < 0)
                                goto error;

                        r = sd_event_source_set_priority(client->timeout_resend,
                                                         client->event_priority);
                        if (r < 0)
                                goto error;
                } else if (r == -ENOMSG)
                        /* invalid message, let's ignore it */
                        return 0;

                break;

        case DHCP_STATE_REBOOTING:
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:

                r = client_handle_ack(client, message, len);
                if (r == DHCP_EVENT_NO_LEASE) {

                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        if (client->state == DHCP_STATE_REBOOTING) {
                                r = client_initialize(client);
                                if (r < 0)
                                        goto error;

                                r = client_start(client);
                                if (r < 0)
                                        goto error;
                        }

                        goto error;
                } else if (r >= 0) {
                        client->timeout_resend =
                                sd_event_source_unref(client->timeout_resend);

                        if (IN_SET(client->state, DHCP_STATE_REQUESTING,
                                   DHCP_STATE_REBOOTING))
                                notify_event = DHCP_EVENT_IP_ACQUIRE;
                        else if (r != DHCP_EVENT_IP_ACQUIRE)
                                notify_event = r;

                        client->state = DHCP_STATE_BOUND;
                        client->attempt = 1;

                        client->last_addr = client->lease->address;

                        r = client_set_lease_timeouts(client);
                        if (r < 0)
                                goto error;

                        if (notify_event)
                                client_notify(client, notify_event);

                        client->receive_message =
                                sd_event_source_unref(client->receive_message);
                        client->fd = safe_close(client->fd);
                } else if (r == -ENOMSG)
                        /* invalid message, let's ignore it */
                        return 0;

                break;

        case DHCP_STATE_INIT:
        case DHCP_STATE_INIT_REBOOT:
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

        assert(s);
        assert(client);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0 || buflen <= 0)
                buflen = sizeof(DHCPMessage) + DHCP_MIN_OPTIONS_SIZE;

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        len = read(fd, message, buflen);
        if (len < 0)
                return 0;

        return client_handle_message(client, message, len);
}

static int client_receive_message_raw(sd_event_source *s, int fd,
                                      uint32_t revents, void *userdata) {
        sd_dhcp_client *client = userdata;
        _cleanup_free_ DHCPPacket *packet = NULL;
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

        return client_handle_message(client, &packet->dhcp, len);
}

int sd_dhcp_client_start(sd_dhcp_client *client) {
        int r;

        assert_return(client, -EINVAL);

        r = client_initialize(client);
        if (r < 0)
                return r;

        if (client->last_addr)
                client->state = DHCP_STATE_INIT_REBOOT;

        return client_start(client);
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
