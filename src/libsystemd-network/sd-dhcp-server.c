/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "sd-dhcp-server.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "dhcp-network.h"
#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dns-domain.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "memory-util.h"
#include "network-common.h"
#include "ordered-set.h"
#include "path-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "unaligned.h"
#include "utf8.h"

#define DHCP_DEFAULT_LEASE_TIME_USEC USEC_PER_HOUR
#define DHCP_MAX_LEASE_TIME_USEC (USEC_PER_HOUR*12)

static void server_on_lease_change(sd_dhcp_server *server) {
        int r;

        assert(server);

        r = dhcp_server_save_leases(server);
        if (r < 0)
                log_dhcp_server_errno(server, r, "Failed to save leases, ignoring: %m");

        if (server->callback)
                server->callback(server, SD_DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);
}

/* configures the server's address and subnet, and optionally the pool's size and offset into the subnet
 * the whole pool must fit into the subnet, and may not contain the first (any) nor last (broadcast) address
 * moreover, the server's own address may be in the pool, and is in that case reserved in order not to
 * accidentally hand it out */
int sd_dhcp_server_configure_pool(
                sd_dhcp_server *server,
                const struct in_addr *address,
                unsigned char prefixlen,
                uint32_t offset,
                uint32_t size) {

        struct in_addr netmask_addr;
        be32_t netmask;
        uint32_t server_off, broadcast_off, size_max;

        assert_return(server, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(address->s_addr != INADDR_ANY, -EINVAL);
        assert_return(prefixlen <= 32, -ERANGE);

        assert_se(in4_addr_prefixlen_to_netmask(&netmask_addr, prefixlen));
        netmask = netmask_addr.s_addr;

        server_off = be32toh(address->s_addr & ~netmask);
        broadcast_off = be32toh(~netmask);

        /* the server address cannot be the subnet address */
        assert_return(server_off != 0, -ERANGE);

        /* nor the broadcast address */
        assert_return(server_off != broadcast_off, -ERANGE);

        /* 0 offset means we should set a default, we skip the first (subnet) address
           and take the next one */
        if (offset == 0)
                offset = 1;

        size_max = (broadcast_off + 1) /* the number of addresses in the subnet */
                   - offset /* exclude the addresses before the offset */
                   - 1; /* exclude the last (broadcast) address */

        /* The pool must contain at least one address */
        assert_return(size_max >= 1, -ERANGE);

        if (size != 0)
                assert_return(size <= size_max, -ERANGE);
        else
                size = size_max;

        if (server->address != address->s_addr || server->netmask != netmask || server->pool_size != size || server->pool_offset != offset) {

                server->pool_offset = offset;
                server->pool_size = size;

                server->address = address->s_addr;
                server->netmask = netmask;
                server->subnet = address->s_addr & netmask;
        }

        return 0;
}

int sd_dhcp_server_is_running(sd_dhcp_server *server) {
        if (!server)
                return false;

        return !!server->receive_message;
}

int sd_dhcp_server_is_in_relay_mode(sd_dhcp_server *server) {
        assert_return(server, -EINVAL);

        return in4_addr_is_set(&server->relay_target);
}

static sd_dhcp_server *dhcp_server_free(sd_dhcp_server *server) {
        assert(server);

        sd_dhcp_server_stop(server);

        sd_event_unref(server->event);

        free(server->boot_server_name);
        free(server->boot_filename);
        free(server->timezone);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(server->servers[i].addr);

        server->bound_leases_by_address = hashmap_free(server->bound_leases_by_address);
        server->bound_leases_by_client_id = hashmap_free(server->bound_leases_by_client_id);
        server->static_leases_by_address = hashmap_free(server->static_leases_by_address);
        server->static_leases_by_client_id = hashmap_free(server->static_leases_by_client_id);

        ordered_set_free(server->extra_options);
        ordered_set_free(server->vendor_options);

        free(server->agent_circuit_id);
        free(server->agent_remote_id);

        safe_close(server->lease_dir_fd);
        free(server->lease_file);

        free(server->ifname);
        return mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_server, sd_dhcp_server, dhcp_server_free);

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new(sd_dhcp_server, 1);
        if (!server)
                return -ENOMEM;

        *server = (sd_dhcp_server) {
                .n_ref = 1,
                .fd_raw = -EBADF,
                .fd = -EBADF,
                .fd_broadcast = -EBADF,
                .address = htobe32(INADDR_ANY),
                .netmask = htobe32(INADDR_ANY),
                .ifindex = ifindex,
                .bind_to_interface = true,
                .default_lease_time = DHCP_DEFAULT_LEASE_TIME_USEC,
                .max_lease_time = DHCP_MAX_LEASE_TIME_USEC,
                .rapid_commit = true,
                .lease_dir_fd = -EBADF,
        };

        *ret = TAKE_PTR(server);

        return 0;
}

int sd_dhcp_server_set_ifname(sd_dhcp_server *server, const char *ifname) {
        assert_return(server, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&server->ifname, ifname);
}

int sd_dhcp_server_get_ifname(sd_dhcp_server *server, const char **ret) {
        int r;

        assert_return(server, -EINVAL);

        r = get_ifname(server->ifindex, &server->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = server->ifname;

        return 0;
}

int sd_dhcp_server_attach_event(sd_dhcp_server *server, sd_event *event, int64_t priority) {
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

int sd_dhcp_server_set_boot_server_address(sd_dhcp_server *server, const struct in_addr *address) {
        assert_return(server, -EINVAL);

        if (address)
                server->boot_server_address = *address;
        else
                server->boot_server_address = (struct in_addr) {};

        return 0;
}

int sd_dhcp_server_set_boot_server_name(sd_dhcp_server *server, const char *name) {
        int r;

        assert_return(server, -EINVAL);

        if (name) {
                r = dns_name_is_valid(name);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;
        }

        return free_and_strdup(&server->boot_server_name, name);
}

int sd_dhcp_server_set_boot_filename(sd_dhcp_server *server, const char *filename) {
        assert_return(server, -EINVAL);

        if (filename && !string_is_safe_ascii(filename))
                return -EINVAL;

        return free_and_strdup(&server->boot_filename, filename);
}

int sd_dhcp_server_stop(sd_dhcp_server *server) {
        bool running;

        if (!server)
                return 0;

        running = sd_dhcp_server_is_running(server);

        server->receive_message = sd_event_source_disable_unref(server->receive_message);
        server->receive_broadcast = sd_event_source_disable_unref(server->receive_broadcast);

        server->fd_raw = safe_close(server->fd_raw);
        server->fd = safe_close(server->fd);
        server->fd_broadcast = safe_close(server->fd_broadcast);

        if (running)
                log_dhcp_server(server, "STOPPED");

        return 0;
}

static bool dhcp_request_contains(DHCPRequest *req, uint8_t option) {
        assert(req);

        if (!req->parameter_request_list)
                return false;

        return memchr(req->parameter_request_list, option, req->parameter_request_list_len);
}

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

        dhcp_packet_append_ip_headers(packet, server->address, DHCP_PORT_SERVER,
                                      packet->dhcp.yiaddr,
                                      DHCP_PORT_CLIENT, len, -1);

        return dhcp_network_send_raw_socket(server->fd_raw, &link, packet, len);
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

int dhcp_server_send_packet(sd_dhcp_server *server,
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
                              be32toh(req->message->xid), type,
                              req->message->htype, req->message->hlen, req->message->chaddr,
                              req->max_optlen, &optoffset);
        if (r < 0)
                return r;

        packet->dhcp.flags = req->message->flags;
        packet->dhcp.giaddr = req->message->giaddr;

        *ret_optoffset = optoffset;
        *ret = TAKE_PTR(packet);

        return 0;
}

static int server_send_offer_or_ack(
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
        sd_dhcp_option *j;
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

        ORDERED_SET_FOREACH(j, server->extra_options) {
                r = dhcp_option_append(&packet->dhcp, req->max_optlen, &offset, 0,
                                       j->option, j->length, j->data);
                if (r < 0)
                        return r;
        }

        if (!ordered_set_isempty(server->vendor_options)) {
                r = dhcp_option_append(
                                &packet->dhcp, req->max_optlen, &offset, 0,
                                SD_DHCP_OPTION_VENDOR_SPECIFIC,
                                ordered_set_size(server->vendor_options), server->vendor_options);
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

        return dhcp_server_send_packet(server, req, packet, type, offset);
}

static int server_send_nak_or_ignore(sd_dhcp_server *server, bool init_reboot, DHCPRequest *req) {
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
                              DHCP_FORCERENEW, htype, hlen, chaddr,
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

static int parse_request(uint8_t code, uint8_t len, const void *option, void *userdata) {
        DHCPRequest *req = ASSERT_PTR(userdata);
        int r;

        switch (code) {
        case SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                if (len == 4)
                        req->lifetime = unaligned_be32_sec_to_usec(option, /* max_as_infinity = */ true);

                break;
        case SD_DHCP_OPTION_REQUESTED_IP_ADDRESS:
                if (len == 4)
                        memcpy(&req->requested_ip, option, sizeof(be32_t));

                break;
        case SD_DHCP_OPTION_SERVER_IDENTIFIER:
                if (len == 4)
                        memcpy(&req->server_id, option, sizeof(be32_t));

                break;
        case SD_DHCP_OPTION_CLIENT_IDENTIFIER:
                if (client_id_size_is_valid(len))
                        (void) sd_dhcp_client_id_set_raw(&req->client_id, option, len);

                break;
        case SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:

                if (len == 2 && unaligned_read_be16(option) >= sizeof(DHCPPacket))
                        req->max_optlen = unaligned_read_be16(option) - sizeof(DHCPPacket);

                break;
        case SD_DHCP_OPTION_RELAY_AGENT_INFORMATION:
                req->agent_info_option = (uint8_t*)option - 2;

                break;
        case SD_DHCP_OPTION_HOST_NAME: {
                _cleanup_free_ char *p = NULL;

                r = dhcp_option_parse_hostname(option, len, &p);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse hostname, ignoring: %m");
                else
                        free_and_replace(req->hostname, p);
                break;
        }
        case SD_DHCP_OPTION_PARAMETER_REQUEST_LIST:
                req->parameter_request_list = option;
                req->parameter_request_list_len = len;
                break;

        case SD_DHCP_OPTION_RAPID_COMMIT:
                req->rapid_commit = true;
                break;
        }

        return 0;
}

static DHCPRequest* dhcp_request_free(DHCPRequest *req) {
        if (!req)
                return NULL;

        free(req->hostname);
        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCPRequest*, dhcp_request_free);

static int ensure_sane_request(sd_dhcp_server *server, DHCPRequest *req, DHCPMessage *message) {
        int r;

        assert(req);
        assert(message);

        req->message = message;

        if (message->hlen > sizeof(message->chaddr))
                return -EBADMSG;

        /* set client id based on MAC address if client did not send an explicit one */
        if (!sd_dhcp_client_id_is_set(&req->client_id)) {
                if (!client_id_data_size_is_valid(message->hlen))
                        return -EBADMSG;

                r = sd_dhcp_client_id_set(&req->client_id, /* type = */ 1, message->chaddr, message->hlen);
                if (r < 0)
                        return r;
        }

        if (message->hlen == 0 || memeqzero(message->chaddr, message->hlen)) {
                uint8_t type;
                const void *data;
                size_t size;

                /* See RFC2131 section 4.1.1.
                 * hlen and chaddr may not be set for non-ethernet interface.
                 * Let's try to retrieve it from the client ID. */

                if (!sd_dhcp_client_id_is_set(&req->client_id))
                        return -EBADMSG;

                r = sd_dhcp_client_id_get(&req->client_id, &type, &data, &size);
                if (r < 0)
                        return r;

                if (type != 1)
                        return -EBADMSG;

                if (size > sizeof(message->chaddr))
                        return -EBADMSG;

                memcpy(message->chaddr, data, size);
                message->hlen = size;
        }

        if (req->max_optlen < DHCP_MIN_OPTIONS_SIZE)
                req->max_optlen = DHCP_MIN_OPTIONS_SIZE;

        if (req->lifetime <= 0)
                req->lifetime = MAX(USEC_PER_SEC, server->default_lease_time);

        if (server->max_lease_time > 0 && req->lifetime > server->max_lease_time)
                req->lifetime = server->max_lease_time;

        return 0;
}

static void request_set_timestamp(DHCPRequest *req, const triple_timestamp *timestamp) {
        assert(req);

        if (timestamp && triple_timestamp_is_set(timestamp))
                req->timestamp = *timestamp;
        else
                triple_timestamp_now(&req->timestamp);
}

static int request_get_lifetime_timestamp(DHCPRequest *req, clockid_t clock, usec_t *ret) {
        assert(req);
        assert(TRIPLE_TIMESTAMP_HAS_CLOCK(clock));
        assert(clock_supported(clock));
        assert(ret);

        if (req->lifetime <= 0)
                return -ENODATA;

        if (!triple_timestamp_is_set(&req->timestamp))
                return -ENODATA;

        *ret = usec_add(triple_timestamp_by_clock(&req->timestamp, clock), req->lifetime);
        return 0;
}

static bool address_is_in_pool(sd_dhcp_server *server, be32_t address) {
        assert(server);

        if (server->pool_size == 0)
                return false;

        if (address == server->address)
                return false;

        if (be32toh(address) < (be32toh(server->subnet) | server->pool_offset) ||
            be32toh(address) >= (be32toh(server->subnet) | (server->pool_offset + server->pool_size)))
                return false;

        if (hashmap_contains(server->static_leases_by_address, UINT32_TO_PTR(address)))
                return false;

        return true;
}

static int append_agent_information_option(sd_dhcp_server *server, DHCPMessage *message, size_t opt_length, size_t size) {
        int r;
        size_t offset;

        assert(server);
        assert(message);

        r = dhcp_option_find_option(message->options, opt_length, SD_DHCP_OPTION_END, &offset);
        if (r < 0)
                return r;

        r = dhcp_option_append(message, size, &offset, 0, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION, 0, server);
        if (r < 0)
                return r;

        r = dhcp_option_append(message, size, &offset, 0, SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;
        return offset;
}

static int dhcp_server_relay_message(sd_dhcp_server *server, DHCPMessage *message, size_t opt_length, size_t buflen) {
        _cleanup_free_ DHCPPacket *packet = NULL;
        int r;

        assert(server);
        assert(message);
        assert(sd_dhcp_server_is_in_relay_mode(server));

        if (message->hlen == 0 || message->hlen > sizeof(message->chaddr) || memeqzero(message->chaddr, message->hlen))
                return log_dhcp_server_errno(server, SYNTHETIC_ERRNO(EBADMSG),
                                             "(relay agent) received message without/invalid hardware address, discarding.");

        if (message->op == BOOTREQUEST) {
                log_dhcp_server(server, "(relay agent) BOOTREQUEST (0x%x)", be32toh(message->xid));
                if (message->hops >= 16)
                        return -ETIME;
                message->hops++;

                /* https://tools.ietf.org/html/rfc1542#section-4.1.1 */
                if (message->giaddr == 0)
                        message->giaddr = server->address;

                if (server->agent_circuit_id || server->agent_remote_id) {
                        r = append_agent_information_option(server, message, opt_length, buflen - sizeof(DHCPMessage));
                        if (r < 0)
                                return log_dhcp_server_errno(server, r, "could not append relay option: %m");
                        opt_length = r;
                }

                return dhcp_server_send_udp(server, server->relay_target.s_addr, DHCP_PORT_SERVER, message, sizeof(DHCPMessage) + opt_length);
        } else if (message->op == BOOTREPLY) {
                log_dhcp_server(server, "(relay agent) BOOTREPLY (0x%x)", be32toh(message->xid));
                if (message->giaddr != server->address)
                        return log_dhcp_server_errno(server, SYNTHETIC_ERRNO(EBADMSG),
                                                     "(relay agent) BOOTREPLY giaddr mismatch, discarding");

                int message_type = dhcp_option_parse(message, sizeof(DHCPMessage) + opt_length, NULL, NULL, NULL);
                if (message_type < 0)
                        return message_type;

                packet = malloc0(sizeof(DHCPPacket) + opt_length);
                if (!packet)
                        return -ENOMEM;
                memcpy(&packet->dhcp, message, sizeof(DHCPMessage) + opt_length);

                r = dhcp_option_remove_option(packet->dhcp.options, opt_length, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION);
                if (r > 0)
                        opt_length = r;

                bool l2_broadcast = requested_broadcast(message) || message_type == DHCP_NAK;
                const be32_t destination = message_type == DHCP_NAK ? INADDR_ANY : message->ciaddr;
                return dhcp_server_send(server, message->hlen, message->chaddr, destination, DHCP_PORT_CLIENT, packet, opt_length, l2_broadcast);
        }
        return -EBADMSG;
}

static int server_ack_request(sd_dhcp_server *server, DHCPRequest *req, be32_t address) {
        usec_t expiration;
        int r;

        assert(server);
        assert(req);
        assert(address != 0);

        r = request_get_lifetime_timestamp(req, CLOCK_BOOTTIME, &expiration);
        if (r < 0)
                return r;

        r = dhcp_server_set_lease(server, address, req, expiration);
        if (r < 0)
                return log_dhcp_server_errno(server, r, "Failed to create new lease: %m");

        r = server_send_offer_or_ack(server, req, address, DHCP_ACK);
        if (r < 0)
                return log_dhcp_server_errno(server, r, "Could not send ACK: %m");

        log_dhcp_server(server, "ACK (0x%x)", be32toh(req->message->xid));

        server_on_lease_change(server);

        return DHCP_ACK;
}

static bool address_available(sd_dhcp_server *server, be32_t address) {
        assert(server);

        if (hashmap_contains(server->bound_leases_by_address, UINT32_TO_PTR(address)) ||
            hashmap_contains(server->static_leases_by_address, UINT32_TO_PTR(address)) ||
            address == server->address)
                return false;

        return true;
}

#define HASH_KEY SD_ID128_MAKE(0d,1d,fe,bd,f1,24,bd,b3,47,f1,dd,6e,73,21,93,30)

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message, size_t length, const triple_timestamp *timestamp) {
        _cleanup_(dhcp_request_freep) DHCPRequest *req = NULL;
        _cleanup_free_ char *error_message = NULL;
        sd_dhcp_server_lease *existing_lease, *static_lease;
        int type, r;

        assert(server);
        assert(message);

        if (message->op != BOOTREQUEST)
                return 0;

        req = new0(DHCPRequest, 1);
        if (!req)
                return -ENOMEM;

        type = dhcp_option_parse(message, length, parse_request, req, &error_message);
        if (type < 0)
                return type;

        r = ensure_sane_request(server, req, message);
        if (r < 0)
                return r;

        request_set_timestamp(req, timestamp);

        r = dhcp_server_cleanup_expired_leases(server);
        if (r < 0)
                return r;

        existing_lease = hashmap_get(server->bound_leases_by_client_id, &req->client_id);
        static_lease = dhcp_server_get_static_lease(server, req);

        switch (type) {

        case DHCP_DISCOVER: {
                be32_t address = INADDR_ANY;

                log_dhcp_server(server, "DISCOVER (0x%x)", be32toh(req->message->xid));

                if (server->pool_size == 0)
                        /* no pool allocated */
                        return 0;

                /* for now pick a random free address from the pool */
                if (static_lease) {
                        if (existing_lease != hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(static_lease->address)))
                                /* The address is already assigned to another host. Refusing. */
                                return 0;

                        /* Found a matching static lease. */
                        address = static_lease->address;

                } else if (existing_lease && address_is_in_pool(server, existing_lease->address))

                        /* If we previously assigned an address to the host, then reuse it. */
                        address = existing_lease->address;

                else {
                        struct siphash state;
                        uint64_t hash;

                        /* even with no persistence of leases, we try to offer the same client
                           the same IP address. we do this by using the hash of the client id
                           as the offset into the pool of leases when finding the next free one */

                        siphash24_init(&state, HASH_KEY.bytes);
                        client_id_hash_func(&req->client_id, &state);
                        hash = htole64(siphash24_finalize(&state));

                        for (unsigned i = 0; i < server->pool_size; i++) {
                                be32_t tmp_address;

                                tmp_address = server->subnet | htobe32(server->pool_offset + (hash + i) % server->pool_size);
                                if (address_available(server, tmp_address)) {
                                        address = tmp_address;
                                        break;
                                }
                        }
                }

                if (address == INADDR_ANY)
                        /* no free addresses left */
                        return 0;

                if (server->rapid_commit && req->rapid_commit)
                        return server_ack_request(server, req, address);

                r = server_send_offer_or_ack(server, req, address, DHCP_OFFER);
                if (r < 0)
                        /* this only fails on critical errors */
                        return log_dhcp_server_errno(server, r, "Could not send offer: %m");

                log_dhcp_server(server, "OFFER (0x%x)", be32toh(req->message->xid));
                return DHCP_OFFER;
        }
        case DHCP_DECLINE:
                log_dhcp_server(server, "DECLINE (0x%x): %s", be32toh(req->message->xid), strna(error_message));

                /* TODO: make sure we don't offer this address again */

                return 1;

        case DHCP_REQUEST: {
                be32_t address;
                bool init_reboot = false;

                /* see RFC 2131, section 4.3.2 */

                if (req->server_id != 0) {
                        log_dhcp_server(server, "REQUEST (selecting) (0x%x)",
                                        be32toh(req->message->xid));

                        /* SELECTING */
                        if (req->server_id != server->address)
                                /* client did not pick us */
                                return 0;

                        if (req->message->ciaddr != 0)
                                /* this MUST be zero */
                                return 0;

                        if (req->requested_ip == 0)
                                /* this must be filled in with the yiaddr
                                   from the chosen OFFER */
                                return 0;

                        address = req->requested_ip;
                } else if (req->requested_ip != 0) {
                        log_dhcp_server(server, "REQUEST (init-reboot) (0x%x)",
                                        be32toh(req->message->xid));

                        /* INIT-REBOOT */
                        if (req->message->ciaddr != 0)
                                /* this MUST be zero */
                                return 0;

                        /* TODO: check more carefully if IP is correct */
                        address = req->requested_ip;
                        init_reboot = true;
                } else {
                        log_dhcp_server(server, "REQUEST (rebinding/renewing) (0x%x)",
                                        be32toh(req->message->xid));

                        /* REBINDING / RENEWING */
                        if (req->message->ciaddr == 0)
                                /* this MUST be filled in with clients IP address */
                                return 0;

                        address = req->message->ciaddr;
                }

                /* Silently ignore Rapid Commit option in REQUEST message. */
                req->rapid_commit = false;

                if (static_lease) {
                        if (static_lease->address != address)
                                /* The client requested an address which is different from the static lease. Refusing. */
                                return server_send_nak_or_ignore(server, init_reboot, req);

                        if (existing_lease != hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(address)))
                                /* The requested address is already assigned to another host. Refusing. */
                                return server_send_nak_or_ignore(server, init_reboot, req);

                        /* Found a static lease for the client ID. */
                        return server_ack_request(server, req, address);
                }

                if (address_is_in_pool(server, address))
                        /* The requested address is in the pool. */
                        return server_ack_request(server, req, address);

                /* Refuse otherwise. */
                return server_send_nak_or_ignore(server, init_reboot, req);
        }

        case DHCP_RELEASE: {
                log_dhcp_server(server, "RELEASE (0x%x)",
                                be32toh(req->message->xid));

                if (!existing_lease)
                        return 0;

                if (existing_lease->address != req->message->ciaddr)
                        return 0;

                sd_dhcp_server_lease_unref(existing_lease);

                server_on_lease_change(server);

                return 0;
        }}

        return 0;
}

static size_t relay_agent_information_length(const char* agent_circuit_id, const char* agent_remote_id) {
        size_t sum = 0;
        if (agent_circuit_id)
                sum += 2 + strlen(agent_circuit_id);
        if (agent_remote_id)
                sum += 2 + strlen(agent_remote_id);
        return sum;
}

static int server_receive_message(sd_event_source *s, int fd,
                                  uint32_t revents, void *userdata) {
        _cleanup_free_ DHCPMessage *message = NULL;
        /* This needs to be initialized with zero. See #20741. */
        CMSG_BUFFER_TYPE(CMSG_SPACE_TIMEVAL +
                         CMSG_SPACE(sizeof(struct in_pktinfo))) control = {};
        sd_dhcp_server *server = ASSERT_PTR(userdata);
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        ssize_t datagram_size, len;
        int r;

        datagram_size = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(datagram_size) || ERRNO_IS_NEG_DISCONNECT(datagram_size))
                return 0;
        if (datagram_size < 0) {
                log_dhcp_server_errno(server, datagram_size, "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        size_t buflen = datagram_size;
        if (sd_dhcp_server_is_in_relay_mode(server))
                /* Preallocate the additional size for DHCP Relay Agent Information Option if needed */
                buflen += relay_agent_information_length(server->agent_circuit_id, server->agent_remote_id) + 2;

        message = malloc0(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, datagram_size);

        len = recvmsg_safe(fd, &msg, 0);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_server_errno(server, len, "Could not receive message, ignoring: %m");
                return 0;
        }

        if ((size_t) len < sizeof(DHCPMessage))
                return 0;

        /* TODO figure out if this can be done as a filter on the socket, like for IPv6 */
        struct in_pktinfo *info = CMSG_FIND_DATA(&msg, IPPROTO_IP, IP_PKTINFO, struct in_pktinfo);
        if (info && info->ipi_ifindex != server->ifindex)
                return 0;

        if (sd_dhcp_server_is_in_relay_mode(server)) {
                r = dhcp_server_relay_message(server, message, len - sizeof(DHCPMessage), buflen);
                if (r < 0)
                        log_dhcp_server_errno(server, r, "Couldn't relay message, ignoring: %m");
        } else {
                r = dhcp_server_handle_message(server, message, (size_t) len, TRIPLE_TIMESTAMP_FROM_CMSG(&msg));
                if (r < 0)
                        log_dhcp_server_errno(server, r, "Couldn't process incoming message, ignoring: %m");
        }
        return 0;
}

static void dhcp_server_update_lease_servers(sd_dhcp_server *server) {
        assert(server);
        assert(server->address != 0);

        /* Convert null address -> server address */

        for (sd_dhcp_lease_server_type_t k = 0; k < _SD_DHCP_LEASE_SERVER_TYPE_MAX; k++)
                for (size_t i = 0; i < server->servers[k].size; i++)
                        if (in4_addr_is_null(&server->servers[k].addr[i]))
                                server->servers[k].addr[i].s_addr = server->address;
}

int sd_dhcp_server_start(sd_dhcp_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);

        if (sd_dhcp_server_is_running(server))
                return 0;

        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd_raw < 0, -EBUSY);
        assert_return(server->fd < 0, -EBUSY);
        assert_return(server->address != htobe32(INADDR_ANY), -EUNATCH);

        dhcp_server_update_lease_servers(server);

        r = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (r < 0) {
                r = -errno;
                goto on_error;
        }
        server->fd_raw = r;

        if (server->bind_to_interface)
                r = dhcp_network_bind_udp_socket(server->ifindex, INADDR_ANY, DHCP_PORT_SERVER, -1);
        else
                r = dhcp_network_bind_udp_socket(0, server->address, DHCP_PORT_SERVER, -1);
        if (r < 0)
                goto on_error;
        server->fd = r;

        r = sd_event_add_io(server->event, &server->receive_message,
                            server->fd, EPOLLIN,
                            server_receive_message, server);
        if (r < 0)
                goto on_error;

        r = sd_event_source_set_priority(server->receive_message,
                                         server->event_priority);
        if (r < 0)
                goto on_error;

        if (!server->bind_to_interface) {
                r = dhcp_network_bind_udp_socket(server->ifindex, INADDR_BROADCAST, DHCP_PORT_SERVER, -1);
                if (r < 0)
                        goto on_error;

                server->fd_broadcast = r;

                r = sd_event_add_io(server->event, &server->receive_broadcast,
                                    server->fd_broadcast, EPOLLIN,
                                    server_receive_message, server);
                if (r < 0)
                        goto on_error;

                r = sd_event_source_set_priority(server->receive_broadcast,
                                                 server->event_priority);
                if (r < 0)
                        goto on_error;
        }

        r = dhcp_server_load_leases(server);
        if (r < 0)
                log_dhcp_server_errno(server, r, "Failed to load lease file %s, ignoring: %m", strna(server->lease_file));

        log_dhcp_server(server, "STARTED");

        return 0;

on_error:
        sd_dhcp_server_stop(server);
        return r;
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

int sd_dhcp_server_set_bind_to_interface(sd_dhcp_server *server, int enabled) {
        assert_return(server, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (!!enabled == server->bind_to_interface)
                return 0;

        server->bind_to_interface = enabled;

        return 1;
}

int sd_dhcp_server_set_timezone(sd_dhcp_server *server, const char *tz) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(timezone_is_valid(tz, LOG_DEBUG), -EINVAL);

        if (streq_ptr(tz, server->timezone))
                return 0;

        r = free_and_strdup(&server->timezone, tz);
        if (r < 0)
                return r;

        return 1;
}

int sd_dhcp_server_set_max_lease_time(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->max_lease_time = t;
        return 0;
}

int sd_dhcp_server_set_default_lease_time(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        server->default_lease_time = t;
        return 0;
}

int sd_dhcp_server_set_ipv6_only_preferred_usec(sd_dhcp_server *server, uint64_t t) {
        assert_return(server, -EINVAL);

        /* When 0 is set, disables the IPv6 only mode. */

        /* Refuse too short timespan unless test mode is enabled. */
        if (t > 0 && t < MIN_V6ONLY_WAIT_USEC && !network_test_mode_enabled())
                 return -EINVAL;

        server->ipv6_only_preferred_usec = t;
        return 0;
}

int sd_dhcp_server_set_rapid_commit(sd_dhcp_server *server, int enabled) {
        assert_return(server, -EINVAL);

        server->rapid_commit = enabled;
        return 0;
}

int sd_dhcp_server_set_servers(
                sd_dhcp_server *server,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr addresses[],
                size_t n_addresses) {

        struct in_addr *c = NULL;

        assert_return(server, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);
        assert_return(addresses || n_addresses == 0, -EINVAL);
        assert_return(what >= 0, -EINVAL);
        assert_return(what < _SD_DHCP_LEASE_SERVER_TYPE_MAX, -EINVAL);

        if (server->servers[what].size == n_addresses &&
            memcmp(server->servers[what].addr, addresses, sizeof(struct in_addr) * n_addresses) == 0)
                return 0;

        if (n_addresses > 0) {
                c = newdup(struct in_addr, addresses, n_addresses);
                if (!c)
                        return -ENOMEM;
        }

        free_and_replace(server->servers[what].addr, c);
        server->servers[what].size = n_addresses;
        return 1;
}

int sd_dhcp_server_set_dns(sd_dhcp_server *server, const struct in_addr dns[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_DNS, dns, n);
}
int sd_dhcp_server_set_ntp(sd_dhcp_server *server, const struct in_addr ntp[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_NTP, ntp, n);
}
int sd_dhcp_server_set_sip(sd_dhcp_server *server, const struct in_addr sip[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_SIP, sip, n);
}
int sd_dhcp_server_set_pop3(sd_dhcp_server *server, const struct in_addr pop3[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_POP3, pop3, n);
}
int sd_dhcp_server_set_smtp(sd_dhcp_server *server, const struct in_addr smtp[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_SMTP, smtp, n);
}
int sd_dhcp_server_set_lpr(sd_dhcp_server *server, const struct in_addr lpr[], size_t n) {
        return sd_dhcp_server_set_servers(server, SD_DHCP_LEASE_LPR, lpr, n);
}

int sd_dhcp_server_set_router(sd_dhcp_server *server, const struct in_addr *router) {
        assert_return(server, -EINVAL);

        /* router is NULL: router option will not be appended.
         * router is null address (0.0.0.0): the server address will be used as the router address.
         * otherwise: the specified address will be used as the router address. */

        server->emit_router = router;
        if (router)
                server->router_address = *router;

        return 0;
}

int sd_dhcp_server_add_option(sd_dhcp_server *server, sd_dhcp_option *v) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_set_ensure_put(&server->extra_options, &dhcp_option_hash_ops, v);
        if (r < 0)
                return r;

        sd_dhcp_option_ref(v);
        return 0;
}

int sd_dhcp_server_add_vendor_option(sd_dhcp_server *server, sd_dhcp_option *v) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(v, -EINVAL);

        r = ordered_set_ensure_put(&server->vendor_options, &dhcp_option_hash_ops, v);
        if (r < 0)
                return r;

        sd_dhcp_option_ref(v);

        return 1;
}

int sd_dhcp_server_set_callback(sd_dhcp_server *server, sd_dhcp_server_callback_t cb, void *userdata) {
        assert_return(server, -EINVAL);

        server->callback = cb;
        server->callback_userdata = userdata;

        return 0;
}

int sd_dhcp_server_set_relay_target(sd_dhcp_server *server, const struct in_addr *address) {
        assert_return(server, -EINVAL);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (memcmp(address, &server->relay_target, sizeof(struct in_addr)) == 0)
                return 0;

        server->relay_target = *address;
        return 1;
}

int sd_dhcp_server_set_relay_agent_information(
                sd_dhcp_server *server,
                const char *agent_circuit_id,
                const char *agent_remote_id) {
        _cleanup_free_ char *circuit_id_dup = NULL, *remote_id_dup = NULL;

        assert_return(server, -EINVAL);

        if (relay_agent_information_length(agent_circuit_id, agent_remote_id) > UINT8_MAX)
                return -ENOBUFS;

        if (agent_circuit_id) {
                circuit_id_dup = strdup(agent_circuit_id);
                if (!circuit_id_dup)
                        return -ENOMEM;
        }

        if (agent_remote_id) {
                remote_id_dup = strdup(agent_remote_id);
                if (!remote_id_dup)
                        return -ENOMEM;
        }

        free_and_replace(server->agent_circuit_id, circuit_id_dup);
        free_and_replace(server->agent_remote_id, remote_id_dup);
        return 0;
}

int sd_dhcp_server_set_lease_file(sd_dhcp_server *server, int dir_fd, const char *path) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(!path || (dir_fd >= 0 || dir_fd == AT_FDCWD), -EBADF);
        assert_return(!sd_dhcp_server_is_running(server), -EBUSY);

        if (!path) {
                /* When NULL, clear the previous assignment. */
                server->lease_file = mfree(server->lease_file);
                server->lease_dir_fd = safe_close(server->lease_dir_fd);
                return 0;
        }

        if (!path_is_safe(path))
                return -EINVAL;

        _cleanup_close_ int fd = fd_reopen(dir_fd, O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (fd < 0)
                return fd;

        r = free_and_strdup(&server->lease_file, path);
        if (r < 0)
                return r;

        close_and_replace(server->lease_dir_fd, fd);

        return 0;
}
