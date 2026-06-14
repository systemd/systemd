/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-request.h"
#include "dhcp-server-send.h"
#include "errno-util.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "random-util.h"
#include "set.h"
#include "socket-util.h"

static int server_acquire_raw_socket(sd_dhcp_server *server) {
        int r;

        assert(server);

        if (server->socket_fd >= 0)
                /* When a socket fd is given externally, unconditionally use it and do not close the socket. */
                return server->socket_fd;

        if (server->raw_socket_fd >= 0)
                /* Already opened. */
                return server->raw_socket_fd;

        /* This is a send-only socket, hence it is opened with protocol=0, and do not call bind().
         * The interface binding will be done on send. */
        _cleanup_close_ int fd = RET_NERRNO(socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (fd < 0)
                return fd;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, tos_to_priority(server->ip_service_type));
        if (r < 0)
                return r;

        return server->raw_socket_fd = TAKE_FD(fd);
}

static int dhcp_server_send_unicast_raw(
                sd_dhcp_server *server,
                const struct hw_addr_data *hw_addr,
                sd_dhcp_message *message) {

        assert(server);
        assert(server->ifindex > 0);
        assert(server->address != 0);
        assert(hw_addr);
        assert(message);

        int fd = server_acquire_raw_socket(server);
        if (fd < 0)
                return fd;

        return dhcp_message_send_raw(
                        message,
                        fd,
                        server->ifindex,
                        server->address,
                        DHCP_PORT_SERVER,
                        hw_addr,
                        message->header.yiaddr,
                        DHCP_PORT_CLIENT,
                        server->ip_service_type);
}

static int dhcp_server_send_udp(
                sd_dhcp_server *server,
                be32_t address,
                uint16_t port,
                sd_dhcp_message *message) {

        assert(server);
        assert(message);

        int fd = sd_event_source_get_io_fd(server->io_event_source);
        if (fd < 0)
                return fd;

        return dhcp_message_send_udp(
                        message,
                        fd,
                        server->address,
                        address,
                        port);
}

static int dhcp_server_send_message(
                sd_dhcp_server *server,
                uint8_t type,
                sd_dhcp_message *message) {

        int r;

        assert(server);
        assert(message);

        /* RFC 2131 Section 4.1 */

        /* If the ’giaddr’ field in a DHCP message from a client is non-zero, the server sends any
         * return messages to the ’DHCP server’ port on the BOOTP relay agent whose address appears
         * in ’giaddr’. */
        if (message->header.giaddr != INADDR_ANY)
                return dhcp_server_send_udp(
                                server,
                                message->header.giaddr,
                                DHCP_PORT_SERVER,
                                message);

        /* when ’giaddr’ is zero, the server broadcasts any DHCPNAK messages to 0xffffffff. */
        if (type == DHCP_NAK)
                return dhcp_server_send_udp(
                                server,
                                INADDR_BROADCAST,
                                DHCP_PORT_CLIENT,
                                message);

        /* If the ’giaddr’ field is zero and the ’ciaddr’ field is nonzero, then the server unicasts
         * DHCPOFFER and DHCPACK messages to the address in ’ciaddr’. */
        if (message->header.ciaddr != INADDR_ANY)
                return dhcp_server_send_udp(
                                server,
                                message->header.ciaddr,
                                DHCP_PORT_CLIENT,
                                message);

        /* If ’giaddr’ is zero and ’ciaddr’ is zero, and the broadcast bit is set, then the server
         * broadcasts DHCPOFFER and DHCPACK messages to 0xffffffff.
         *
         * (Note, even the broadcast flag is unset, we may not know the client hardware address, e.g.
         * InfiniBand. In that case, we cannot unicast in the below, so need to broadcast. Also, broadcast
         * the message if 'yiaddr' is zero.) */
        struct hw_addr_data hw_addr = {};
        if (!dhcp_message_has_broadcast_flag(message) &&
            message->header.yiaddr != INADDR_ANY) {
                r = dhcp_message_get_hw_addr(message, &hw_addr);
                if (r < 0)
                        return r;
        }

        if (hw_addr_is_null(&hw_addr))
                return dhcp_server_send_udp(
                                server,
                                INADDR_BROADCAST,
                                DHCP_PORT_CLIENT,
                                message);

        /* If the broadcast bit is not set and ’giaddr’ is zero and ’ciaddr’ is zero, then the server
         * unicasts DHCPOFFER and DHCPACK messages to the client’s hardware address and ’yiaddr’ address. */
        return dhcp_server_send_unicast_raw(
                        server,
                        &hw_addr,
                        message);
}

static int dhcp_server_new_reply(
                sd_dhcp_server *server,
                DHCPRequest *req,
                uint8_t type,
                sd_dhcp_message **ret) {

        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));
        assert(ret);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        r = dhcp_message_init_header(
                        message,
                        BOOTREPLY,
                        be32toh(req->message->header.xid),
                        req->message->header.htype,
                        &req->hw_addr);
        if (r < 0)
                return r;

        message->header.giaddr = req->message->header.giaddr;

        /* RFC 2131 Section 4.3.2
         *
         * If ’giaddr’ is set in the DHCPREQUEST message, the client is on a different subnet. The server
         * MUST set the broadcast bit in the DHCPNAK, so that the relay agent will broadcast the DHCPNAK to
         * the client, because the client may not have a correct network address or subnet mask, and the
         * client may not be answering ARP requests. */
        dhcp_message_set_broadcast_flag(
                        message,
                        dhcp_message_has_broadcast_flag(req->message) ||
                        req->message->header.giaddr != INADDR_ANY ||
                        type == DHCP_NAK);

        /* DHCP Message Type (53): Mandatory. */
        r = dhcp_message_append_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, type);
        if (r < 0)
                return r;

        /* Server Identifier */
        r = dhcp_message_append_option_be32(
                        message,
                        SD_DHCP_OPTION_SERVER_IDENTIFIER,
                        server->address);
        if (r < 0)
                return r;

        if (type == DHCP_NAK) {
                *ret = TAKE_PTR(message);
                return 0;
        }

        assert(req->address != INADDR_ANY);
        message->header.yiaddr = req->address;
        message->header.siaddr = server->boot_server_address.s_addr;

        if (type == DHCP_ACK)
                message->header.ciaddr = req->message->header.ciaddr;

        r = dhcp_message_append_option_be32(
                        message,
                        SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
                        usec_to_be32_sec(req->lifetime));
        if (r < 0)
                return r;

        r = dhcp_message_append_option_be32(
                        message,
                        SD_DHCP_OPTION_SUBNET_MASK,
                        server->netmask);
        if (r < 0)
                return r;

        if (server->emit_router) {
                r = dhcp_message_append_option_be32(
                                message,
                                SD_DHCP_OPTION_ROUTER,
                                in4_addr_is_set(&server->router_address) ?
                                server->router_address.s_addr :
                                server->address);
                if (r < 0)
                        return r;
        }

        if (server->boot_server_name) {
                r = dhcp_message_append_option_string(
                                message,
                                SD_DHCP_OPTION_BOOT_SERVER_NAME,
                                server->boot_server_name);
                if (r < 0)
                        return r;
        }

        if (server->boot_filename) {
                r = dhcp_message_append_option_string(
                                message,
                                SD_DHCP_OPTION_BOOT_FILENAME,
                                server->boot_filename);
                if (r < 0)
                        return r;
        }

        static const uint8_t option_map[_SD_DHCP_LEASE_SERVER_TYPE_MAX] = {
                [SD_DHCP_LEASE_DNS]  = SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                [SD_DHCP_LEASE_NTP]  = SD_DHCP_OPTION_NTP_SERVER,
                [SD_DHCP_LEASE_SIP]  = SD_DHCP_OPTION_SIP_SERVER,
                [SD_DHCP_LEASE_POP3] = SD_DHCP_OPTION_POP3_SERVER,
                [SD_DHCP_LEASE_SMTP] = SD_DHCP_OPTION_SMTP_SERVER,
                [SD_DHCP_LEASE_LPR]  = SD_DHCP_OPTION_LPR_SERVER,
        };

        for (sd_dhcp_lease_server_type_t k = 0; k < _SD_DHCP_LEASE_SERVER_TYPE_MAX; k++) {
                if (server->servers[k].size <= 0)
                        continue;

                r = dhcp_message_append_option_addresses(
                                message,
                                option_map[k],
                                server->servers[k].size,
                                server->servers[k].addr);
                if (r < 0)
                        return r;
        }

        if (server->timezone) {
                r = dhcp_message_append_option_string(
                                message,
                                SD_DHCP_OPTION_TZDB_TIMEZONE,
                                server->timezone);
                if (r < 0)
                        return r;
        }

        if (server->domain_name) {
                r = dhcp_message_append_option_string(
                                message,
                                SD_DHCP_OPTION_DOMAIN_NAME,
                                server->domain_name);
                if (r < 0)
                        return r;
        }

        /* RFC 8925 section 3.3. DHCPv4 Server Behavior
         * The server MUST NOT include the IPv6-Only Preferred option in the DHCPOFFER or DHCPACK message if
         * the option was not present in the Parameter Request List sent by the client. */
        if (set_contains(req->parameter_request_list, UINT_TO_PTR(SD_DHCP_OPTION_IPV6_ONLY_PREFERRED)) &&
            server->ipv6_only_preferred_usec > 0) {
                r = dhcp_message_append_option_be32(
                                message,
                                SD_DHCP_OPTION_IPV6_ONLY_PREFERRED,
                                usec_to_be32_sec(server->ipv6_only_preferred_usec));
                if (r < 0)
                        return r;
        }

        r = dhcp_message_append_option_sub_tlv(
                        message,
                        SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                        server->vendor_options);
        if (r < 0)
                return r;

        if (req->static_lease) {
                /* Hostname (12) or FQDN (81)
                 * Flags: S=0 (will not update RR), O=1 (are overriding client), N=1 (will not update DNS) */
                r = dhcp_message_append_option_hostname(
                                message,
                                DHCP_FQDN_FLAG_O | DHCP_FQDN_FLAG_N,
                                /* is_client= */ false,
                                req->static_lease->hostname);
                if (r < 0)
                        return r;
        }

        _cleanup_(tlv_unrefp) TLV *agent_info = NULL;
        r = dhcp_message_get_option_sub_tlv(
                        req->message,
                        SD_DHCP_OPTION_RELAY_AGENT_INFORMATION,
                        TLV_DHCP4_SUBOPTION,
                        &agent_info);
        if (r < 0 && r != -ENODATA)
                log_dhcp_server_errno(server, r, "Failed to parse %s option, ignoring: %m",
                                      dhcp_option_code_to_string(SD_DHCP_OPTION_RELAY_AGENT_INFORMATION));

        if (agent_info) {
                r = dhcp_message_append_option_sub_tlv(
                                message,
                                SD_DHCP_OPTION_RELAY_AGENT_INFORMATION,
                                agent_info);
                if (r < 0)
                        return r;
        }

        if (type == DHCP_ACK && req->type == DHCP_DISCOVER) {
                assert(server->rapid_commit);
                r = dhcp_message_append_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return r;
        }

        r = dhcp_message_append_option_tlv(message, server->extra_options);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_server_send_reply(
                sd_dhcp_server *server,
                DHCPRequest *req,
                uint8_t type) {

        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_server_new_reply(server, req, type, &message);
        if (r < 0)
                return r;

        if (dhcp_message_packet_size(message) > req->max_message_size)
                return -E2BIG;

        r = dhcp_server_send_message(server, type, message);
        if (r < 0)
                return r;

        log_dhcp_server(server, "%s (0x%x)", dhcp_message_type_to_string(type), be32toh(message->header.xid));
        return type; /* Return the sent message type. To make the test easier. */
}

static int dhcp_server_send_forcerenew(
                sd_dhcp_server *server,
                sd_dhcp_server_lease *lease) {

        int r;

        assert(server);
        assert(lease);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_new(&message);
        if (r < 0)
                return r;

        r = dhcp_message_init_header(
                        message,
                        BOOTREPLY,
                        random_u32(),
                        lease->htype,
                        &lease->hw_addr);
        if (r < 0)
                return r;

        /* DHCP Message Type (53): Mandatory. */
        r = dhcp_message_append_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_FORCERENEW);
        if (r < 0)
                return r;

        /* Server Identifier */
        r = dhcp_message_append_option_be32(
                        message,
                        SD_DHCP_OPTION_SERVER_IDENTIFIER,
                        server->address);
        if (r < 0)
                return r;

        r = dhcp_server_send_udp(server, lease->address, DHCP_PORT_CLIENT, message);
        if (r < 0)
                return r;

        log_dhcp_server(server, "%s (0x%x)", dhcp_message_type_to_string(DHCP_FORCERENEW), be32toh(message->header.xid));
        return 0;
}

int sd_dhcp_server_forcerenew(sd_dhcp_server *server) {
        sd_dhcp_server_lease *lease;
        int r = 0;

        assert_return(server, -EINVAL);

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id)
                RET_GATHER(r, dhcp_server_send_forcerenew(server, lease));
        return r;
}
