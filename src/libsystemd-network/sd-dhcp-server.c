/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include <sys/ioctl.h>
#include <netinet/if_ether.h>

#include "sd-dhcp-server.h"
#include "dhcp-server-internal.h"
#include "dhcp-internal.h"

sd_dhcp_server *sd_dhcp_server_ref(sd_dhcp_server *server) {
        if (server)
                assert_se(REFCNT_INC(server->n_ref) >= 2);

        return server;
}

sd_dhcp_server *sd_dhcp_server_unref(sd_dhcp_server *server) {
        if (server && REFCNT_DEC(server->n_ref) <= 0) {
                log_dhcp_server(server, "UNREF");

                sd_dhcp_server_stop(server);

                sd_event_unref(server->event);
                free(server);
        }

        return NULL;
}

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex) {
        _cleanup_dhcp_server_unref_ sd_dhcp_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new0(sd_dhcp_server, 1);
        if (!server)
                return -ENOMEM;

        server->n_ref = REFCNT_INIT;
        server->fd = -1;
        server->index = ifindex;

        *ret = server;
        server = NULL;

        return 0;
}

int sd_dhcp_server_attach_event(sd_dhcp_server *server, sd_event *event, int priority) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        if (event)
                server->event = sd_event_ref(event);
        else {
                r = sd_event_default(&server->event);
                if (r < 0)
                        return r;
        }

        server->event_priority = priority;

        return 0;
}

int sd_dhcp_server_detach_event(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        server->event = sd_event_unref(server->event);

        return 0;
}

sd_event *sd_dhcp_server_get_event(sd_dhcp_server *server) {
        assert_return(server, NULL);

        return server->event;
}

int sd_dhcp_server_stop(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        server->receive_message =
                sd_event_source_unref(server->receive_message);

        server->fd = safe_close(server->fd);

        log_dhcp_server(server, "STOPPED");

        return 0;
}

static int parse_request(uint8_t code, uint8_t len, const uint8_t *option,
                         void *user_data) {
        DHCPRequest *req = user_data;

        assert(req);

        switch(code) {
        case DHCP_OPTION_SERVER_IDENTIFIER:
                if (len == 4)
                        req->server_id = *(be32_t*)option;

                break;
        case DHCP_OPTION_CLIENT_IDENTIFIER:
                if (len >= 2) {
                        uint8_t *data;

                        data = memdup(option, len);
                        if (!data)
                                return -ENOMEM;

                        free(req->client_id.data);
                        req->client_id.data = data;
                        req->client_id.length = len;
                }

                break;
        case DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:
                if (len == 2)
                        req->max_optlen = be16toh(*(be16_t*)option) -
                                          - sizeof(DHCPPacket);

                break;
        }

        return 0;
}

static void dhcp_request_free(DHCPRequest *req) {
        if (!req)
                return;

        free(req->client_id.data);
        free(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCPRequest*, dhcp_request_free);
#define _cleanup_dhcp_request_free_ _cleanup_(dhcp_request_freep)

static int ensure_sane_request(DHCPRequest *req, DHCPMessage *message) {
        assert(req);
        assert(message);

        req->message = message;

        /* set client id based on mac address if client did not send an explicit one */
        if (!req->client_id.data) {
                uint8_t *data;

                data = new0(uint8_t, ETH_ALEN + 1);
                if (!data)
                        return -ENOMEM;

                req->client_id.length = ETH_ALEN + 1;
                req->client_id.data = data;
                req->client_id.data[0] = 0x01;
                memcpy(&req->client_id.data[1], &message->chaddr, ETH_ALEN);
        }

        if (req->max_optlen < DHCP_MIN_OPTIONS_SIZE)
                req->max_optlen = DHCP_MIN_OPTIONS_SIZE;

        return 0;
}

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message,
                               size_t length) {
        _cleanup_dhcp_request_free_ DHCPRequest *req = NULL;
        int type, r;

        assert(server);
        assert(message);

        if (message->op != BOOTREQUEST ||
            message->htype != ARPHRD_ETHER ||
            message->hlen != ETHER_ADDR_LEN)
                return 0;

        req = new0(DHCPRequest, 1);
        if (!req)
                return -ENOMEM;

        type = dhcp_option_parse(message, length, parse_request, req);
        if (type < 0)
                return 0;

        r = ensure_sane_request(req, message);
        if (r < 0)
                /* this only fails on critical errors */
                return r;

        log_dhcp_server(server, "received message of type %d", type);

        return 1;
}

static int server_receive_message(sd_event_source *s, int fd,
                                  uint32_t revents, void *userdata) {
        _cleanup_free_ DHCPMessage *message = NULL;
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct in_pktinfo))];
        sd_dhcp_server *server = userdata;
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        int buflen = 0, len, r;

        assert(server);

        r = ioctl(fd, FIONREAD, &buflen);
        if (r < 0)
                return r;
        if (buflen < 0)
                return -EIO;

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        iov.iov_base = message;
        iov.iov_len = buflen;

        len = recvmsg(fd, &msg, 0);
        if (len < buflen)
                return 0;
        else if ((size_t)len < sizeof(DHCPMessage))
                return 0;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IP &&
                    cmsg->cmsg_type == IP_PKTINFO &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo))) {
                        struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(cmsg);

                        /* TODO figure out if this can be done as a filter on the socket, like for IPv6 */
                        if (server->index != info->ipi_ifindex)
                                return 0;

                        break;
                }
        }

        return dhcp_server_handle_message(server, message, (size_t)len);
}

int sd_dhcp_server_start(sd_dhcp_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);
        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd == -1, -EBUSY);

        r = dhcp_network_bind_udp_socket(INADDR_ANY, DHCP_PORT_SERVER);
        if (r < 0) {
                sd_dhcp_server_stop(server);
                return r;
        }
        server->fd = r;

        r = sd_event_add_io(server->event, &server->receive_message,
                            server->fd, EPOLLIN,
                            server_receive_message, server);
        if (r < 0) {
                sd_dhcp_server_stop(server);
                return r;
        }

        r = sd_event_source_set_priority(server->receive_message,
                                         server->event_priority);
        if (r < 0) {
                sd_dhcp_server_stop(server);
                return r;
        }

        log_dhcp_server(server, "STARTED");

        return 0;
}
