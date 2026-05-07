/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-send.h"
#include "dns-domain.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "set.h"
#include "socket-util.h"

static int server_open_raw_socket(sd_dhcp_server *server) {
        int r;

        assert(server);

        _cleanup_close_ int fd = RET_NERRNO(socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (fd < 0)
                return fd;

        /* While bind() with sockaddr_ll is strictly sufficient for AF_PACKET, we also set SO_BINDTOIFINDEX
         * to initialize the kernel's sk_bound_dev_if state. This ensures compatibility with cgroup/eBPF
         * filters and maintains consistency. */
        r = socket_bind_to_ifindex(fd, server->ifindex);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, tos_to_priority(server->ip_service_type));
        if (r < 0)
                return r;

        union sockaddr_union sa = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = server->ifindex,
        };

        if (bind(fd, &sa.sa, sockaddr_ll_len(&sa.ll)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int dhcp_server_send_unicast_raw(
                sd_dhcp_server *server,
                const struct hw_addr_data *hw_addr,
                DHCPPacket *packet,
                size_t len) {

        int r;

        assert(server);
        assert(server->ifindex > 0);
        assert(server->address != 0);
        assert(hw_addr);
        assert(packet);
        assert(len > sizeof(DHCPPacket));

        if (len > UINT16_MAX)
                return -EOVERFLOW;

        _cleanup_close_ int fd_close = -EBADF;
        int fd;
        if (server->socket_fd >= 0)
                /* When a socket fd is given externally, unconditionally use it and do not close the socket. */
                fd = server->socket_fd;
        else {
                fd = fd_close = server_open_raw_socket(server);
                if (fd < 0)
                        return fd;
        }

        r = dhcp_packet_append_ip_headers(
                        packet,
                        server->address,
                        DHCP_PORT_SERVER,
                        packet->dhcp.yiaddr,
                        DHCP_PORT_CLIENT,
                        len,
                        server->ip_service_type);
        if (r < 0)
                return r;

        union sockaddr_union sa = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = server->ifindex,
                .ll.sll_halen = hw_addr->length,
        };

        memcpy_safe(sa.ll.sll_addr, hw_addr->bytes, hw_addr->length);

        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sockaddr_ll_len(&sa.ll),
                .msg_iov = &IOVEC_MAKE(packet, len),
                .msg_iovlen = 1,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int dhcp_server_send_udp(sd_dhcp_server *server, be32_t destination,
                                uint16_t destination_port,
                                DHCPMessage *message, size_t len) {

        assert(server);
        assert(message);
        assert(len >= sizeof(DHCPMessage));

        int fd = sd_event_source_get_io_fd(server->io_event_source);
        if (fd < 0)
                return fd;

        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(destination_port),
                .in.sin_addr.s_addr = destination,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        struct msghdr msg = {
                .msg_name = &sa,
                .msg_namelen = sizeof(sa.in),
                .msg_iov = &IOVEC_MAKE(message, len),
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        struct cmsghdr *cmsg = ASSERT_PTR(CMSG_FIRSTHDR(&msg));
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        struct in_pktinfo *pktinfo = ASSERT_PTR(CMSG_TYPED_DATA(cmsg, struct in_pktinfo));
        pktinfo->ipi_ifindex = server->ifindex;
        pktinfo->ipi_spec_dst.s_addr = server->address;

        if (sendmsg(fd, &msg, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

static int dhcp_server_send_message(
                sd_dhcp_server *server,
                DHCPRequest *req,
                uint8_t type,
                DHCPPacket *packet,
                size_t optoffset) {

        assert(server);
        assert(req);
        assert(req->message);
        assert(packet);

        /* RFC 2131 Section 4.1 */

        /* If the ’giaddr’ field in a DHCP message from a client is non-zero, the server sends any
         * return messages to the ’DHCP server’ port on the BOOTP relay agent whose address appears
         * in ’giaddr’. */
        if (req->message->header.giaddr != INADDR_ANY)
                return dhcp_server_send_udp(
                                server,
                                req->message->header.giaddr,
                                DHCP_PORT_SERVER,
                                &packet->dhcp,
                                sizeof(DHCPMessage) + optoffset);

        /* when ’giaddr’ is zero, the server broadcasts any DHCPNAK messages to 0xffffffff. */
        if (type == DHCP_NAK)
                return dhcp_server_send_udp(
                                server,
                                INADDR_BROADCAST,
                                DHCP_PORT_CLIENT,
                                &packet->dhcp,
                                sizeof(DHCPMessage) + optoffset);

        /* If the ’giaddr’ field is zero and the ’ciaddr’ field is nonzero, then the server unicasts
         * DHCPOFFER and DHCPACK messages to the address in ’ciaddr’. */
        if (req->message->header.ciaddr != INADDR_ANY)
                return dhcp_server_send_udp(
                                server,
                                req->message->header.ciaddr,
                                DHCP_PORT_CLIENT,
                                &packet->dhcp,
                                sizeof(DHCPMessage) + optoffset);

        /* If ’giaddr’ is zero and ’ciaddr’ is zero, and the broadcast bit is set, then the server
         * broadcasts DHCPOFFER and DHCPACK messages to 0xffffffff.
         *
         * Note, even the broadcast flag is unset, we may not know the client hardware address (e.g.
         * InfiniBand). In that case, we cannot unicast in the below, so need to broadcast. */
        if (FLAGS_SET(be16toh(req->message->header.flags), 0x8000) ||
            hw_addr_is_null(&req->hw_addr))
                return dhcp_server_send_udp(
                                server,
                                INADDR_BROADCAST,
                                DHCP_PORT_CLIENT,
                                &packet->dhcp,
                                sizeof(DHCPMessage) + optoffset);

        /* If the broadcast bit is not set and ’giaddr’ is zero and ’ciaddr’ is zero, then the server
         * unicasts DHCPOFFER and DHCPACK messages to the client’s hardware address and ’yiaddr’ address. */
        return dhcp_server_send_unicast_raw(
                        server,
                        &req->hw_addr,
                        packet,
                        sizeof(DHCPPacket) + optoffset);
}

static int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset) {
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

        _cleanup_(iovec_done) struct iovec iov = {};
        if (dhcp_message_get_option_alloc(req->message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION, &iov) >= 0 &&
            iov.iov_len <= UINT8_MAX)
                (void) dhcp_option_append(&packet->dhcp, req->max_optlen, &optoffset, 0,
                                          SD_DHCP_OPTION_RELAY_AGENT_INFORMATION,
                                          iov.iov_len, iov.iov_base);

        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &optoffset, 0,
                               SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        return dhcp_server_send_message(server, req, type, packet, optoffset);
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
                              be32toh(req->message->header.xid),
                              req->message->header.htype, req->hw_addr.length, req->hw_addr.bytes,
                              type, req->max_optlen, &optoffset);
        if (r < 0)
                return r;

        packet->dhcp.flags = req->message->header.flags;
        packet->dhcp.giaddr = req->message->header.giaddr;

        *ret_optoffset = optoffset;
        *ret = TAKE_PTR(packet);

        return 0;
}

static int dhcp_server_append_static_hostname(
                sd_dhcp_server *server,
                DHCPPacket *packet,
                size_t *offset,
                DHCPRequest *req) {

        int r;

        assert(server);
        assert(packet);
        assert(offset);
        assert(req);

        if (!req->static_lease || !req->static_lease->hostname)
                return 0;

        if (dns_name_is_single_label(req->static_lease->hostname))
                /* Option 12 */
                return dhcp_option_append(
                                &packet->dhcp,
                                req->max_optlen,
                                offset,
                                /* overload= */ 0,
                                SD_DHCP_OPTION_HOST_NAME,
                                strlen(req->static_lease->hostname),
                                req->static_lease->hostname);


        /* Option 81 */
        uint8_t buffer[DHCP_MAX_FQDN_LENGTH + 3];

        /* Flags: S=0 (will not update RR), O=1 (are overriding client),
         * E=1 (using DNS wire format), N=1 (will not update DNS) */
        buffer[0] = DHCP_FQDN_FLAG_O | DHCP_FQDN_FLAG_E | DHCP_FQDN_FLAG_N;

        /* RFC 4702: A server SHOULD set these to 255 when sending the option and MUST ignore them on
         * receipt. */
        buffer[1] = 255;
        buffer[2] = 255;

        r = dns_name_to_wire_format(req->static_lease->hostname, buffer + 3, sizeof(buffer) - 3, false);
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

int server_send_offer_or_ack(
                sd_dhcp_server *server,
                DHCPRequest *req,
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

        packet->dhcp.yiaddr = req->address;
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
        if (set_contains(req->parameter_request_list, UINT_TO_PTR(SD_DHCP_OPTION_IPV6_ONLY_PREFERRED)) &&
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

        if (type == DHCP_ACK &&
            server->rapid_commit &&
            dhcp_message_get_option_flag(req->message, SD_DHCP_OPTION_RAPID_COMMIT) >= 0) {
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

        log_dhcp_server(server, "NAK (0x%x)", be32toh(req->message->header.xid));
        return DHCP_NAK;
}

static int dhcp_server_send_forcerenew(
                sd_dhcp_server *server,
                sd_dhcp_server_lease *lease) {

        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t optoffset = 0;
        int r;

        assert(server);
        assert(lease);

        packet = malloc0(sizeof(DHCPPacket) + DHCP_MIN_OPTIONS_SIZE);
        if (!packet)
                return -ENOMEM;

        r = dhcp_message_init(&packet->dhcp, BOOTREPLY, 0,
                              lease->htype, lease->hw_addr.length, lease->hw_addr.bytes, DHCP_FORCERENEW,
                              DHCP_MIN_OPTIONS_SIZE, &optoffset);
        if (r < 0)
                return r;

        r = dhcp_option_append(&packet->dhcp, DHCP_MIN_OPTIONS_SIZE,
                               &optoffset, 0, SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        return dhcp_server_send_udp(server, lease->address, DHCP_PORT_CLIENT,
                                    &packet->dhcp,
                                    sizeof(DHCPMessage) + optoffset);
}

int sd_dhcp_server_forcerenew(sd_dhcp_server *server) {
        sd_dhcp_server_lease *lease;
        int r = 0;

        assert_return(server, -EINVAL);

        log_dhcp_server(server, "FORCERENEW");

        HASHMAP_FOREACH(lease, server->bound_leases_by_client_id)
                RET_GATHER(r, dhcp_server_send_forcerenew(server, lease));
        return r;
}
