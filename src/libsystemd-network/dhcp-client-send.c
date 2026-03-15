/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "dhcp-client-internal.h"
#include "dhcp-client-send.h"
#include "dhcp-lease-internal.h"  /* IWYU pragma: keep */
#include "dhcp-network.h"
#include "dhcp-packet.h"
#include "fd-util.h"
#include "socket-util.h"

static int client_get_socket(sd_dhcp_client *client, int domain) {
        int r, d, fd;

        assert(client);
        assert(IN_SET(domain, AF_PACKET, AF_INET));

        if (!client->receive_message)
                return -EBADF;

        fd = sd_event_source_get_io_fd(client->receive_message);
        if (fd < 0)
                return fd;

        r = getsockopt_int(fd, SOL_SOCKET, SO_DOMAIN, &d);
        if (r < 0)
                return r;

        if (d != domain)
                return -EBADF;

        return fd;
}

static int client_setup_io_event(
                sd_dhcp_client *client,
                int fd,
                sd_event_io_handler_t callback,
                const char *description) {

        int r;

        assert(client);
        assert(fd >= 0);
        assert(callback);
        assert(description);

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(client->event, &s, fd, EPOLLIN, callback, client);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(s, client->event_priority);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, description);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return r;

        sd_event_source_disable_unref(client->receive_message);
        client->receive_message = TAKE_PTR(s);
        return 0;
}

int dhcp_client_send_raw(
                sd_dhcp_client *client,
                bool expect_reply,
                DHCPPacket *packet,
                size_t optoffset) {

        _cleanup_close_ int fd_close = -EBADF;
        int r, fd;

        assert(client);
        assert(packet);

        fd = client_get_socket(client, AF_PACKET);
        if (fd < 0) {
                fd = dhcp_network_bind_raw_socket(
                                client->ifindex,
                                &client->link,
                                client->xid,
                                &client->hw_addr,
                                &client->bcast_addr,
                                client->arp_type,
                                client->port,
                                client->socket_priority_set,
                                client->socket_priority);
                if (fd < 0)
                        return fd;

                fd_close = fd;
        }

        r = dhcp_packet_append_ip_headers(
                        packet,
                        INADDR_ANY,
                        client->port,
                        INADDR_BROADCAST,
                        client->server_port,
                        sizeof(DHCPPacket) + optoffset,
                        client->ip_service_type);
        if (r < 0)
                return r;

        r = dhcp_network_send_raw_socket(
                        fd,
                        &client->link,
                        packet,
                        sizeof(DHCPPacket) + optoffset);
        if (r < 0)
                return r;

        if (!expect_reply) {
                /* We do not expect any replies, hence stop the IO event source if enabled. */
                client->receive_message = sd_event_source_disable_unref(client->receive_message);
                return 0;
        }

        if (fd_close < 0)
                return 0; /* Already opened socket is reused. Not necessary to setup new IO event source. */

        r = client_setup_io_event(client, fd, client_receive_message_raw, "dhcp4-receive-message-raw");
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}

int dhcp_client_send_udp(
                sd_dhcp_client *client,
                bool expect_reply,
                DHCPPacket *packet,
                size_t optoffset) {

        _cleanup_close_ int fd_close = -EBADF;
        int r, fd;

        assert(client);
        assert(packet);

        if (!client->lease || client->lease->address == 0)
                return -EADDRNOTAVAIL;

        fd = client_get_socket(client, AF_INET);
        if (fd < 0) {
                fd = dhcp_network_bind_udp_socket(
                                client->ifindex,
                                client->lease->address,
                                client->port,
                                client->ip_service_type);
                if (fd < 0)
                        return fd;

                fd_close = fd;
        }

        r = dhcp_network_send_udp_socket(
                        fd,
                        client->lease->server_address,
                        client->server_port,
                        &packet->dhcp,
                        sizeof(DHCPMessage) + optoffset);
        if (r < 0)
                return r;

        if (!expect_reply) {
                /* We do not expect any replies, hence stop the IO event source if enabled. */
                client->receive_message = sd_event_source_disable_unref(client->receive_message);
                return 0;
        }

        if (fd_close < 0)
                return 0; /* Already opened socket is reused. Not necessary to setup new IO event source. */

        r = client_setup_io_event(client, fd, client_receive_message_udp, "dhcp4-receive-message-udp");
        if (r < 0)
                return r;

        TAKE_FD(fd_close);
        return 0;
}
