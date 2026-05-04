/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-send.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "socket-util.h"

static int dhcp_server_send_unicast_raw(
                sd_dhcp_server *server,
                uint8_t hlen,
                const uint8_t *chaddr,
                DHCPPacket *packet,
                size_t len) {

        union sockaddr_union link = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = server->ifindex,
                .ll.sll_halen = hlen,
        };
        int r;

        assert(server);
        assert(server->ifindex > 0);
        assert(server->address != 0);
        assert(hlen > 0);
        assert(chaddr);
        assert(packet);
        assert(len > sizeof(DHCPPacket));

        memcpy(link.ll.sll_addr, chaddr, hlen);

        if (len > UINT16_MAX)
                return -EOVERFLOW;

        r = dhcp_packet_append_ip_headers(
                        packet,
                        server->address,
                        DHCP_PORT_SERVER,
                        packet->dhcp.yiaddr,
                        DHCP_PORT_CLIENT,
                        len,
                        /* ip_service_type= */ -1);
        if (r < 0)
                return r;

        return dhcp_network_send_raw_socket(
                        server->fd_raw,
                        &link,
                        &(struct iovec_wrapper) {
                                .iovec = &IOVEC_MAKE(packet, len),
                                .count = 1,
                        });
}

static int dhcp_server_send_udp(sd_dhcp_server *server, be32_t destination,
                                uint16_t destination_port,
                                DHCPMessage *message, size_t len) {
        union sockaddr_union dest = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(destination_port),
                .in.sin_addr.s_addr = destination,
        };
        struct iovec iov = {
                .iov_base = message,
                .iov_len = len,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        struct msghdr msg = {
                .msg_name = &dest,
                .msg_namelen = sizeof(dest.in),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;

        assert(server);
        assert(server->fd >= 0);
        assert(message);
        assert(len >= sizeof(DHCPMessage));

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

        if (sendmsg(server->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

static bool requested_broadcast(DHCPMessage *message) {
        assert(message);
        return message->flags & htobe16(0x8000);
}

static int dhcp_server_send(
                sd_dhcp_server *server,
                uint8_t hlen,
                const uint8_t *chaddr,
                be32_t destination,
                uint16_t destination_port,
                DHCPPacket *packet,
                size_t optoffset,
                bool l2_broadcast) {

        if (destination != INADDR_ANY)
                return dhcp_server_send_udp(server, destination,
                                            destination_port, &packet->dhcp,
                                            sizeof(DHCPMessage) + optoffset);
        else if (l2_broadcast)
                return dhcp_server_send_udp(server, INADDR_BROADCAST,
                                            destination_port, &packet->dhcp,
                                            sizeof(DHCPMessage) + optoffset);
        else
                /* we cannot send UDP packet to specific MAC address when the
                   address is not yet configured, so must fall back to raw
                   packets */
                return dhcp_server_send_unicast_raw(server, hlen, chaddr, packet,
                                                    sizeof(DHCPPacket) + optoffset);
}

static int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset) {
        be32_t destination = INADDR_ANY;
        uint16_t destination_port = DHCP_PORT_CLIENT;
        int r;

        assert(server);
        assert(req);
        assert(req->max_optlen > 0);
        assert(req->message);
        assert(optoffset <= req->max_optlen);
        assert(packet);

        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &optoffset, 0,
                               SD_DHCP_OPTION_SERVER_IDENTIFIER,
                               4, &server->address);
        if (r < 0)
                return r;

        if (req->agent_info_option) {
                size_t opt_full_length = *(req->agent_info_option + 1) + 2;
                /* there must be space left for SD_DHCP_OPTION_END */
                if (optoffset + opt_full_length < req->max_optlen) {
                        memcpy(packet->dhcp.options + optoffset, req->agent_info_option, opt_full_length);
                        optoffset += opt_full_length;
                }
        }

        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        /* RFC 2131 Section 4.1

           If the ’giaddr’ field in a DHCP message from a client is non-zero,
           the server sends any return messages to the ’DHCP server’ port on the
           BOOTP relay agent whose address appears in ’giaddr’. If the ’giaddr’
           field is zero and the ’ciaddr’ field is nonzero, then the server
           unicasts DHCPOFFER and DHCPACK messages to the address in ’ciaddr’.
           If ’giaddr’ is zero and ’ciaddr’ is zero, and the broadcast bit is
           set, then the server broadcasts DHCPOFFER and DHCPACK messages to
           0xffffffff. If the broadcast bit is not set and ’giaddr’ is zero and
           ’ciaddr’ is zero, then the server unicasts DHCPOFFER and DHCPACK
           messages to the client’s hardware address and ’yiaddr’ address. In
           all cases, when ’giaddr’ is zero, the server broadcasts any DHCPNAK
           messages to 0xffffffff.

           Section 4.3.2

           If ’giaddr’ is set in the DHCPREQUEST message, the client is on a
           different subnet. The server MUST set the broadcast bit in the
           DHCPNAK, so that the relay agent will broadcast the DHCPNAK to the
           client, because the client may not have a correct network address
           or subnet mask, and the client may not be answering ARP requests.
         */
        if (req->message->giaddr != 0) {
                destination = req->message->giaddr;
                destination_port = DHCP_PORT_SERVER;
                if (type == DHCP_NAK)
                        packet->dhcp.flags = htobe16(0x8000);
        } else if (req->message->ciaddr != 0 && type != DHCP_NAK)
                destination = req->message->ciaddr;

        bool l2_broadcast = requested_broadcast(req->message) || type == DHCP_NAK;
        return dhcp_server_send(server, req->message->hlen, req->message->chaddr,
                                destination, destination_port, packet, optoffset, l2_broadcast);
}

static int server_message_init(
                sd_dhcp_server *server,
                DHCPPacket **ret,
                uint8_t type,
                size_t *ret_optoffset,
                DHCPRequest *req) {

        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t optoffset = 0;
        int r;

        assert(server);
        assert(ret);
        assert(ret_optoffset);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));
        assert(req);

        packet = malloc0(sizeof(DHCPPacket) + req->max_optlen);
        if (!packet)
                return -ENOMEM;

        r = dhcp_message_init(&packet->dhcp, BOOTREPLY,
                              be32toh(req->message->xid),
                              req->message->htype, req->message->hlen, req->message->chaddr,
                              type, req->max_optlen, &optoffset);
        if (r < 0)
                return r;

        packet->dhcp.flags = req->message->flags;
        packet->dhcp.giaddr = req->message->giaddr;

        *ret_optoffset = optoffset;
        *ret = TAKE_PTR(packet);

        return 0;
}

static int dhcp_server_append_static_hostname(
                sd_dhcp_server *server,
                DHCPPacket *packet,
                size_t *offset,
                DHCPRequest *req) {

        sd_dhcp_server_lease *static_lease;
        int r;

        assert(server);
        assert(packet);
        assert(offset);
        assert(req);

        static_lease = dhcp_server_get_static_lease(server, req);
        if (!static_lease || !static_lease->hostname)
                return 0;

        if (dns_name_is_single_label(static_lease->hostname))
                /* Option 12 */
                return dhcp_option_append(
                                &packet->dhcp,
                                req->max_optlen,
                                offset,
                                /* overload= */ 0,
                                SD_DHCP_OPTION_HOST_NAME,
                                strlen(static_lease->hostname),
                                static_lease->hostname);


        /* Option 81 */
        uint8_t buffer[DHCP_MAX_FQDN_LENGTH + 3];

        /* Flags: S=0 (will not update RR), O=1 (are overriding client),
         * E=1 (using DNS wire format), N=1 (will not update DNS) */
        buffer[0] = DHCP_FQDN_FLAG_O | DHCP_FQDN_FLAG_E | DHCP_FQDN_FLAG_N;

        /* RFC 4702: A server SHOULD set these to 255 when sending the option and MUST ignore them on
         * receipt. */
        buffer[1] = 255;
        buffer[2] = 255;

        r = dns_name_to_wire_format(static_lease->hostname, buffer + 3, sizeof(buffer) - 3, false);
        if (r < 0)
                return log_dhcp_server_errno(server, r, "Failed to encode FQDN for static lease: %m");
        if (r > DHCP_MAX_FQDN_LENGTH)
                return log_dhcp_server_errno(server, SYNTHETIC_ERRNO(EINVAL), "FQDN for static lease too long");

        return dhcp_option_append(
                        &packet->dhcp,
                        req->max_optlen,
                        offset,
                        /* overload= */ 0,
                        SD_DHCP_OPTION_FQDN,
                        3 + r,
                        buffer);
}

static bool dhcp_request_contains(DHCPRequest *req, uint8_t option) {
        assert(req);

        if (!req->parameter_request_list)
                return false;

        return memchr(req->parameter_request_list, option, req->parameter_request_list_len);
}

int server_send_offer_or_ack(
                sd_dhcp_server *server,
                DHCPRequest *req,
                be32_t address,
                uint8_t type) {

        static const uint8_t option_map[_SD_DHCP_LEASE_SERVER_TYPE_MAX] = {
                [SD_DHCP_LEASE_DNS]  = SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                [SD_DHCP_LEASE_NTP]  = SD_DHCP_OPTION_NTP_SERVER,
                [SD_DHCP_LEASE_SIP]  = SD_DHCP_OPTION_SIP_SERVER,
                [SD_DHCP_LEASE_POP3] = SD_DHCP_OPTION_POP3_SERVER,
                [SD_DHCP_LEASE_SMTP] = SD_DHCP_OPTION_SMTP_SERVER,
                [SD_DHCP_LEASE_LPR]  = SD_DHCP_OPTION_LPR_SERVER,
        };

        _cleanup_free_ DHCPPacket *packet = NULL;
        be32_t lease_time;
        size_t offset;
        int r;

        assert(server);
        assert(req);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK));

        r = server_message_init(server, &packet, type, &offset, req);
        if (r < 0)
                return r;

        packet->dhcp.yiaddr = address;
        packet->dhcp.siaddr = server->boot_server_address.s_addr;

        lease_time = usec_to_be32_sec(req->lifetime);
        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                               SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, 4,
                               &lease_time);
        if (r < 0)
                return r;

        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                               SD_DHCP_OPTION_SUBNET_MASK, 4, &server->netmask);
        if (r < 0)
                return r;

        if (server->emit_router) {
                r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                                       SD_DHCP_OPTION_ROUTER, 4,
                                       in4_addr_is_set(&server->router_address) ?
                                       &server->router_address.s_addr :
                                       &server->address);
                if (r < 0)
                        return r;
        }

        if (server->boot_server_name) {
                r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                                       SD_DHCP_OPTION_BOOT_SERVER_NAME,
                                       strlen(server->boot_server_name), server->boot_server_name);
                if (r < 0)
                        return r;
        }

        if (server->boot_filename) {
                r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                                       SD_DHCP_OPTION_BOOT_FILENAME,
                                       strlen(server->boot_filename), server->boot_filename);
                if (r < 0)
                        return r;
        }

        for (sd_dhcp_lease_server_type_t k = 0; k < _SD_DHCP_LEASE_SERVER_TYPE_MAX; k++) {
                if (server->servers[k].size <= 0)
                        continue;

                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                option_map[k],
                                sizeof(struct in_addr) * server->servers[k].size,
                                server->servers[k].addr);
                if (r < 0)
                        return r;
        }

        if (server->timezone) {
                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_TZDB_TIMEZONE,
                                strlen(server->timezone), server->timezone);
                if (r < 0)
                        return r;
        }

        if (server->domain_name) {
                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_DOMAIN_NAME,
                                strlen(server->domain_name), server->domain_name);
                if (r < 0)
                        return r;
        }

        /* RFC 8925 section 3.3. DHCPv4 Server Behavior
         * The server MUST NOT include the IPv6-Only Preferred option in the DHCPOFFER or DHCPACK message if
         * the option was not present in the Parameter Request List sent by the client. */
        if (dhcp_request_contains(req, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED) &&
            server->ipv6_only_preferred_usec > 0) {
                be32_t sec = usec_to_be32_sec(server->ipv6_only_preferred_usec);

                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_IPV6_ONLY_PREFERRED,
                                sizeof(sec), &sec);
                if (r < 0)
                        return r;
        }

        if (server->extra_options) {
                void *key;
                struct iovec_wrapper *iovw;
                HASHMAP_FOREACH_KEY(iovw, key, server->extra_options->entries) {
                        uint32_t tag = PTR_TO_UINT32(key);

                        FOREACH_ARRAY(iov, iovw->iovec, iovw->count) {
                                r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                                                       tag, iov->iov_len, iov->iov_base);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (server->vendor_options) {
                _cleanup_(iovec_done) struct iovec iov = {};
                r = tlv_build(server->vendor_options, &iov);
                if (r < 0)
                        return r;

                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                                iov.iov_len, iov.iov_base);
                if (r < 0)
                        return r;
        }

        if (server->rapid_commit && req->rapid_commit && type == DHCP_ACK) {
                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_RAPID_COMMIT,
                                0, NULL);
                if (r < 0)
                        return r;
        }

        r = dhcp_server_append_static_hostname(server, packet, &offset, req);
        if (r < 0)
                return r;

        return dhcp_server_send_packet(server, req, packet, type, offset);
}

int server_send_nak_or_ignore(sd_dhcp_server *server, bool init_reboot, DHCPRequest *req) {
        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t offset;
        int r;

        /* When a request is refused, RFC 2131, section 4.3.2 mentioned we should send NAK when the
         * client is in INITREBOOT. If the client is in other state, there is nothing mentioned in the
         * RFC whether we should send NAK or not. Hence, let's silently ignore the request. */

        if (!init_reboot)
                return 0;

        r = server_message_init(server, &packet, DHCP_NAK, &offset, req);
        if (r < 0)
                return log_dhcp_server_errno(server, r, "Failed to create NAK message: %m");

        r = dhcp_server_send_packet(server, req, packet, DHCP_NAK, offset);
        if (r < 0)
                return log_dhcp_server_errno(server, r, "Could not send NAK message: %m");

        log_dhcp_server(server, "NAK (0x%x)", be32toh(req->message->xid));
        return DHCP_NAK;
}

static int server_send_forcerenew(
                sd_dhcp_server *server,
                be32_t address,
                be32_t gateway,
                uint8_t htype,
                uint8_t hlen,
                const uint8_t *chaddr) {

        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t optoffset = 0;
        int r;

        assert(server);
        assert(address != INADDR_ANY);
        assert(chaddr);

        packet = malloc0(sizeof(DHCPPacket) + DHCP_MIN_OPTIONS_SIZE);
        if (!packet)
                return -ENOMEM;

        r = dhcp_message_init(&packet->dhcp, BOOTREPLY, 0,
                              htype, hlen, chaddr, DHCP_FORCERENEW,
                              DHCP_MIN_OPTIONS_SIZE, &optoffset);
        if (r < 0)
                return r;

        r = dhcp_option_append(&packet->dhcp, DHCP_MIN_OPTIONS_SIZE,
                               &optoffset, 0, SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        return dhcp_server_send_udp(server, address, DHCP_PORT_CLIENT,
                                    &packet->dhcp,
                                    sizeof(DHCPMessage) + optoffset);
}

int sd_dhcp_server_forcerenew(sd_dhcp_server *server) {
        sd_dhcp_server_lease *lease;
        int r = 0;

        assert_return(server, -EINVAL);

        log_dhcp_server(server, "FORCERENEW");

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id)
                RET_GATHER(r,
                           server_send_forcerenew(server, lease->address, lease->gateway,
                                                  lease->htype, lease->hlen, lease->chaddr));
        return r;
}
