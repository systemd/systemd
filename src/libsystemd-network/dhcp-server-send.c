/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dhcp-network.h"
#include "dhcp-protocol.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-send.h"
#include "errno-util.h"
#include "in-addr-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "random-util.h"
#include "set.h"
#include "socket-util.h"

static int dhcp_server_send_unicast_raw(
                sd_dhcp_server *server,
                const struct hw_addr_data *hw_addr,
                sd_dhcp_message *message) {
        int r;

        assert(server);
        assert(server->ifindex > 0);
        assert(server->address != 0);
        assert(!hw_addr_is_null(hw_addr));
        assert(message);

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        struct iphdr ip;
        struct udphdr udp;
        r = udp_packet_build(
                        server->address,
                        DHCP_PORT_SERVER,
                        message->header.yiaddr,
                        DHCP_PORT_CLIENT,
                        /* ip_service_type= */ -1,
                        &payload,
                        &ip,
                        &udp);
        if (r < 0)
                return r;

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        r = iovw_put(&iovw, &ip, sizeof(struct iphdr));
        if (r < 0)
                return r;

        r = iovw_put(&iovw, &udp, sizeof(struct udphdr));
        if (r < 0)
                return r;

        r = iovw_put_iovw(&iovw, &payload);
        if (r < 0)
                return r;

        union sockaddr_union link = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = server->ifindex,
                .ll.sll_halen = hw_addr->length,
        };

        memcpy(link.ll.sll_addr, hw_addr->bytes, hw_addr->length);

        return dhcp_network_send_raw_socket(server->fd_raw, &link, &iovw);
}

int dhcp_server_send_udp(
                sd_dhcp_server *server,
                be32_t destination,
                uint16_t destination_port,
                sd_dhcp_message *message) {

        int r;

        assert(server);
        assert(server->fd >= 0);
        assert(message);

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        union sockaddr_union dest = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(destination_port),
                .in.sin_addr.s_addr = destination,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        struct msghdr msg = {
                .msg_name = &dest,
                .msg_namelen = sizeof(dest.in),
                .msg_iov = payload.iovec,
                .msg_iovlen = payload.count,
        };
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;

        if (server->bind_to_interface) {
                msg.msg_control = &control;
                msg.msg_controllen = sizeof(control);

                cmsg = CMSG_FIRSTHDR(&msg);
                assert(cmsg);

                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

                /* we attach source interface and address info to the message
                   rather than binding the socket. This will be mostly useful
                   when we gain support for arbitrary number of server addresses
                 */
                pktinfo = CMSG_TYPED_DATA(cmsg, struct in_pktinfo);
                assert(pktinfo);

                pktinfo->ipi_ifindex = server->ifindex;
                pktinfo->ipi_spec_dst.s_addr = server->address;
        }

        if (sendmsg(server->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

int dhcp_server_send_message(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
                uint8_t type,
                sd_dhcp_message *message) {

        assert(server);
        assert(req);
        assert(req->message);
        assert(message);

        /* RFC 2131 Section 4.1 */

        /* If the ’giaddr’ field in a DHCP message from a client is non-zero, the server sends any
         * return messages to the ’DHCP server’ port on the BOOTP relay agent whose address appears
         * in ’giaddr’.
         *
         * Note, when we are in the relay mode, giaddr is our address. Do not send the mssage to us. */
        if (req->message->header.giaddr != INADDR_ANY &&
            req->message->header.giaddr != server->address)
                return dhcp_server_send_udp(
                                server,
                                req->message->header.giaddr,
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
        if (req->message->header.ciaddr != INADDR_ANY)
                return dhcp_server_send_udp(
                                server,
                                req->message->header.ciaddr,
                                DHCP_PORT_CLIENT,
                                message);

        /* If ’giaddr’ is zero and ’ciaddr’ is zero, and the broadcast bit is set, then the server
         * broadcasts DHCPOFFER and DHCPACK messages to 0xffffffff. */
        if (FLAGS_SET(be16toh(req->message->header.flags), 0x8000))
                return dhcp_server_send_udp(
                                server,
                                INADDR_BROADCAST,
                                DHCP_PORT_CLIENT,
                                message);

        /* If the broadcast bit is not set and ’giaddr’ is zero and ’ciaddr’ is zero, then the server
         * unicasts DHCPOFFER and DHCPACK messages to the client’s hardware address and ’yiaddr’ address. */
        return dhcp_server_send_unicast_raw(
                        server,
                        &req->hw_addr,
                        message);
}

static int dhcp_server_new_reply(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
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

        message->header.flags = req->message->header.flags;
        message->header.giaddr = req->message->header.giaddr;

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
                /* RFC 2131 Section 4.3.2
                 *
                 * If ’giaddr’ is set in the DHCPREQUEST message, the client is on a different subnet. The
                 * server MUST set the broadcast bit in the DHCPNAK, so that the relay agent will broadcast
                 * the DHCPNAK to the client, because the client may not have a correct network address or
                 * subnet mask, and the client may not be answering ARP requests. */
                if (req->message->header.giaddr != 0)
                        message->header.flags = htobe16(0x8000);

                *ret = TAKE_PTR(message);
                return 0;
        }

        assert(req->address != INADDR_ANY);
        message->header.yiaddr = req->address;
        message->header.siaddr = server->boot_server_address.s_addr;

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

        r = dhcp_message_append_option_vendor_specific(message, server->vendor_options);
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

        if (type == DHCP_ACK &&
            server->rapid_commit &&
            dhcp_message_get_option_flag(req->message, SD_DHCP_OPTION_RAPID_COMMIT) >= 0) {
                r = dhcp_message_append_option_flag(message, SD_DHCP_OPTION_RAPID_COMMIT);
                if (r < 0)
                        return r;
        }

        r = dhcp_message_append_options(message, server->extra_options);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(message);
        return 0;
}

int dhcp_server_send_reply(
                sd_dhcp_server *server,
                sd_dhcp_request *req,
                uint8_t type) {

        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_server_new_reply(server, req, type, &message);
        if (r < 0)
                return r;

        r = dhcp_server_send_message(server, req, type, message);
        if (r < 0)
                return r;

        log_dhcp_server(server, "%s (0x%x)", dhcp_message_type_to_string(type), be32toh(message->header.xid));
        return 0;
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
