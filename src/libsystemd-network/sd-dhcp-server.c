/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "sd-dhcp-server.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "dhcp-internal.h"
#include "dhcp-server-internal.h"
#include "fd-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "ordered-set.h"
#include "siphash24.h"
#include "string-util.h"
#include "unaligned.h"

#define DHCP_DEFAULT_LEASE_TIME_USEC USEC_PER_HOUR
#define DHCP_MAX_LEASE_TIME_USEC (USEC_PER_HOUR*12)

static DHCPLease *dhcp_lease_free(DHCPLease *lease) {
        if (!lease)
                return NULL;

        free(lease->client_id.data);
        return mfree(lease);
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

                free(server->bound_leases);
                server->bound_leases = new0(DHCPLease*, size);
                if (!server->bound_leases)
                        return -ENOMEM;

                server->pool_offset = offset;
                server->pool_size = size;

                server->address = address->s_addr;
                server->netmask = netmask;
                server->subnet = address->s_addr & netmask;

                if (server_off >= offset && server_off - offset < size)
                        server->bound_leases[server_off - offset] = &server->invalid_lease;

                /* Drop any leases associated with the old address range */
                hashmap_clear(server->leases_by_client_id);

                if (server->callback)
                        server->callback(server, SD_DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);
        }

        return 0;
}

int sd_dhcp_server_is_running(sd_dhcp_server *server) {
        assert_return(server, false);

        return !!server->receive_message;
}

void client_id_hash_func(const DHCPClientId *id, struct siphash *state) {
        assert(id);
        assert(id->length);
        assert(id->data);

        siphash24_compress(&id->length, sizeof(id->length), state);
        siphash24_compress(id->data, id->length, state);
}

int client_id_compare_func(const DHCPClientId *a, const DHCPClientId *b) {
        int r;

        assert(!a->length || a->data);
        assert(!b->length || b->data);

        r = CMP(a->length, b->length);
        if (r != 0)
                return r;

        return memcmp(a->data, b->data, a->length);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(dhcp_lease_hash_ops, DHCPClientId, client_id_hash_func, client_id_compare_func,
                                              DHCPLease, dhcp_lease_free);

static sd_dhcp_server *dhcp_server_free(sd_dhcp_server *server) {
        assert(server);

        log_dhcp_server(server, "UNREF");

        sd_dhcp_server_stop(server);

        sd_event_unref(server->event);

        free(server->timezone);

        for (sd_dhcp_lease_server_type_t i = 0; i < _SD_DHCP_LEASE_SERVER_TYPE_MAX; i++)
                free(server->servers[i].addr);

        hashmap_free(server->leases_by_client_id);

        ordered_set_free(server->extra_options);
        ordered_set_free(server->vendor_options);

        free(server->bound_leases);
        return mfree(server);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp_server, sd_dhcp_server, dhcp_server_free);

int sd_dhcp_server_new(sd_dhcp_server **ret, int ifindex) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;

        assert_return(ret, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        server = new0(sd_dhcp_server, 1);
        if (!server)
                return -ENOMEM;

        server->n_ref = 1;
        server->fd_raw = -1;
        server->fd = -1;
        server->address = htobe32(INADDR_ANY);
        server->netmask = htobe32(INADDR_ANY);
        server->ifindex = ifindex;

        server->leases_by_client_id = hashmap_new(&dhcp_lease_hash_ops);
        if (!server->leases_by_client_id)
                return -ENOMEM;

        server->default_lease_time = DIV_ROUND_UP(DHCP_DEFAULT_LEASE_TIME_USEC, USEC_PER_SEC);
        server->max_lease_time = DIV_ROUND_UP(DHCP_MAX_LEASE_TIME_USEC, USEC_PER_SEC);

        *ret = TAKE_PTR(server);

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

int sd_dhcp_server_stop(sd_dhcp_server *server) {
        if (!server)
                return 0;

        server->receive_message =
                sd_event_source_unref(server->receive_message);

        server->fd_raw = safe_close(server->fd_raw);
        server->fd = safe_close(server->fd);

        log_dhcp_server(server, "STOPPED");

        return 0;
}

static int dhcp_server_send_unicast_raw(sd_dhcp_server *server,
                                        DHCPPacket *packet, size_t len) {
        union sockaddr_union link = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = server->ifindex,
                .ll.sll_halen = ETH_ALEN,
        };

        assert(server);
        assert(server->ifindex > 0);
        assert(server->address);
        assert(packet);
        assert(len > sizeof(DHCPPacket));

        memcpy(&link.ll.sll_addr, &packet->dhcp.chaddr, ETH_ALEN);

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
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        struct in_pktinfo *pktinfo;

        assert(server);
        assert(server->fd >= 0);
        assert(message);
        assert(len > sizeof(DHCPMessage));

        cmsg = CMSG_FIRSTHDR(&msg);
        assert(cmsg);

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        /* we attach source interface and address info to the message
           rather than binding the socket. This will be mostly useful
           when we gain support for arbitrary number of server addresses
         */
        pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
        assert(pktinfo);

        pktinfo->ipi_ifindex = server->ifindex;
        pktinfo->ipi_spec_dst.s_addr = server->address;

        if (sendmsg(server->fd, &msg, 0) < 0)
                return -errno;

        return 0;
}

static bool requested_broadcast(DHCPRequest *req) {
        assert(req);

        return req->message->flags & htobe16(0x8000);
}

int dhcp_server_send_packet(sd_dhcp_server *server,
                            DHCPRequest *req, DHCPPacket *packet,
                            int type, size_t optoffset) {
        be32_t destination = INADDR_ANY;
        uint16_t destination_port = DHCP_PORT_CLIENT;
        int r;

        assert(server);
        assert(req);
        assert(req->max_optlen);
        assert(optoffset <= req->max_optlen);
        assert(packet);

        r = dhcp_option_append(&packet->dhcp, req->max_optlen, &optoffset, 0,
                               SD_DHCP_OPTION_SERVER_IDENTIFIER,
                               4, &server->address);
        if (r < 0)
                return r;

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
        if (req->message->giaddr) {
                destination = req->message->giaddr;
                destination_port = DHCP_PORT_SERVER;
                if (type == DHCP_NAK)
                        packet->dhcp.flags = htobe16(0x8000);
        } else if (req->message->ciaddr && type != DHCP_NAK)
                destination = req->message->ciaddr;

        if (destination != INADDR_ANY)
                return dhcp_server_send_udp(server, destination,
                                            destination_port, &packet->dhcp,
                                            sizeof(DHCPMessage) + optoffset);
        else if (requested_broadcast(req) || type == DHCP_NAK)
                return dhcp_server_send_udp(server, INADDR_BROADCAST,
                                            destination_port, &packet->dhcp,
                                            sizeof(DHCPMessage) + optoffset);
        else
                /* we cannot send UDP packet to specific MAC address when the
                   address is not yet configured, so must fall back to raw
                   packets */
                return dhcp_server_send_unicast_raw(server, packet,
                                                    sizeof(DHCPPacket) + optoffset);
}

static int server_message_init(sd_dhcp_server *server, DHCPPacket **ret,
                               uint8_t type, size_t *_optoffset,
                               DHCPRequest *req) {
        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t optoffset = 0;
        int r;

        assert(server);
        assert(ret);
        assert(_optoffset);
        assert(IN_SET(type, DHCP_OFFER, DHCP_ACK, DHCP_NAK));

        packet = malloc0(sizeof(DHCPPacket) + req->max_optlen);
        if (!packet)
                return -ENOMEM;

        r = dhcp_message_init(&packet->dhcp, BOOTREPLY,
                              be32toh(req->message->xid), type, ARPHRD_ETHER,
                              req->max_optlen, &optoffset);
        if (r < 0)
                return r;

        packet->dhcp.flags = req->message->flags;
        packet->dhcp.giaddr = req->message->giaddr;
        memcpy(&packet->dhcp.chaddr, &req->message->chaddr, ETH_ALEN);

        *_optoffset = optoffset;
        *ret = TAKE_PTR(packet);

        return 0;
}

static int server_send_offer_or_ack(
                sd_dhcp_server *server,
                DHCPRequest *req,
                be32_t address,
                uint8_t type) {

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

        lease_time = htobe32(req->lifetime);
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
                                       SD_DHCP_OPTION_ROUTER, 4, &server->address);
                if (r < 0)
                        return r;
        }

        if (type == DHCP_ACK) {
                static const uint8_t option_map[_SD_DHCP_LEASE_SERVER_TYPE_MAX] = {
                        [SD_DHCP_LEASE_DNS] = SD_DHCP_OPTION_DOMAIN_NAME_SERVER,
                        [SD_DHCP_LEASE_NTP] = SD_DHCP_OPTION_NTP_SERVER,
                        [SD_DHCP_LEASE_SIP] = SD_DHCP_OPTION_SIP_SERVER,
                        [SD_DHCP_LEASE_POP3] = SD_DHCP_OPTION_POP3_SERVER,
                        [SD_DHCP_LEASE_SMTP] = SD_DHCP_OPTION_SMTP_SERVER,
                        [SD_DHCP_LEASE_LPR] = SD_DHCP_OPTION_LPR_SERVER,
                };

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
                                        SD_DHCP_OPTION_NEW_TZDB_TIMEZONE,
                                        strlen(server->timezone), server->timezone);
                        if (r < 0)
                                return r;
                }
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

        r = dhcp_server_send_packet(server, req, packet, type, offset);
        if (r < 0)
                return r;

        return 0;
}

static int server_send_nak(sd_dhcp_server *server, DHCPRequest *req) {
        _cleanup_free_ DHCPPacket *packet = NULL;
        size_t offset;
        int r;

        r = server_message_init(server, &packet, DHCP_NAK, &offset, req);
        if (r < 0)
                return r;

        return dhcp_server_send_packet(server, req, packet, DHCP_NAK, offset);
}

static int server_send_forcerenew(sd_dhcp_server *server, be32_t address,
                                  be32_t gateway, const uint8_t chaddr[]) {
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
                              DHCP_FORCERENEW, ARPHRD_ETHER,
                              DHCP_MIN_OPTIONS_SIZE, &optoffset);
        if (r < 0)
                return r;

        r = dhcp_option_append(&packet->dhcp, DHCP_MIN_OPTIONS_SIZE,
                               &optoffset, 0, SD_DHCP_OPTION_END, 0, NULL);
        if (r < 0)
                return r;

        memcpy(&packet->dhcp.chaddr, chaddr, ETH_ALEN);

        r = dhcp_server_send_udp(server, address, DHCP_PORT_CLIENT,
                                 &packet->dhcp,
                                 sizeof(DHCPMessage) + optoffset);
        if (r < 0)
                return r;

        return 0;
}

static int parse_request(uint8_t code, uint8_t len, const void *option, void *userdata) {
        DHCPRequest *req = userdata;

        assert(req);

        switch(code) {
        case SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                if (len == 4)
                        req->lifetime = unaligned_read_be32(option);

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
        case SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:

                if (len == 2 && unaligned_read_be16(option) >= sizeof(DHCPPacket))
                        req->max_optlen = unaligned_read_be16(option) - sizeof(DHCPPacket);

                break;
        }

        return 0;
}

static DHCPRequest* dhcp_request_free(DHCPRequest *req) {
        if (!req)
                return NULL;

        free(req->client_id.data);
        return mfree(req);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DHCPRequest*, dhcp_request_free);

static int ensure_sane_request(sd_dhcp_server *server, DHCPRequest *req, DHCPMessage *message) {
        assert(req);
        assert(message);

        req->message = message;

        /* set client id based on MAC address if client did not send an explicit
           one */
        if (!req->client_id.data) {
                void *data;

                data = malloc0(ETH_ALEN + 1);
                if (!data)
                        return -ENOMEM;

                ((uint8_t*) data)[0] = 0x01;
                memcpy((uint8_t*) data + 1, &message->chaddr, ETH_ALEN);

                req->client_id.length = ETH_ALEN + 1;
                req->client_id.data = data;
        }

        if (req->max_optlen < DHCP_MIN_OPTIONS_SIZE)
                req->max_optlen = DHCP_MIN_OPTIONS_SIZE;

        if (req->lifetime <= 0)
                req->lifetime = MAX(1ULL, server->default_lease_time);

        if (server->max_lease_time > 0 && req->lifetime > server->max_lease_time)
                req->lifetime = server->max_lease_time;

        return 0;
}

static int get_pool_offset(sd_dhcp_server *server, be32_t requested_ip) {
        assert(server);

        if (!server->pool_size)
                return -EINVAL;

        if (be32toh(requested_ip) < (be32toh(server->subnet) | server->pool_offset) ||
            be32toh(requested_ip) >= (be32toh(server->subnet) | (server->pool_offset + server->pool_size)))
                return -ERANGE;

        return be32toh(requested_ip & ~server->netmask) - server->pool_offset;
}

#define HASH_KEY SD_ID128_MAKE(0d,1d,fe,bd,f1,24,bd,b3,47,f1,dd,6e,73,21,93,30)

int dhcp_server_handle_message(sd_dhcp_server *server, DHCPMessage *message,
                               size_t length) {
        _cleanup_(dhcp_request_freep) DHCPRequest *req = NULL;
        _cleanup_free_ char *error_message = NULL;
        DHCPLease *existing_lease;
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

        type = dhcp_option_parse(message, length, parse_request, req, &error_message);
        if (type < 0)
                return 0;

        r = ensure_sane_request(server, req, message);
        if (r < 0)
                /* this only fails on critical errors */
                return r;

        existing_lease = hashmap_get(server->leases_by_client_id,
                                     &req->client_id);

        switch(type) {

        case DHCP_DISCOVER: {
                be32_t address = INADDR_ANY;
                unsigned i;

                log_dhcp_server(server, "DISCOVER (0x%x)",
                                be32toh(req->message->xid));

                if (!server->pool_size)
                        /* no pool allocated */
                        return 0;

                /* for now pick a random free address from the pool */
                if (existing_lease)
                        address = existing_lease->address;
                else {
                        struct siphash state;
                        uint64_t hash;
                        uint32_t next_offer;

                        /* even with no persistence of leases, we try to offer the same client
                           the same IP address. we do this by using the hash of the client id
                           as the offset into the pool of leases when finding the next free one */

                        siphash24_init(&state, HASH_KEY.bytes);
                        client_id_hash_func(&req->client_id, &state);
                        hash = htole64(siphash24_finalize(&state));
                        next_offer = hash % server->pool_size;

                        for (i = 0; i < server->pool_size; i++) {
                                if (!server->bound_leases[next_offer]) {
                                        address = server->subnet | htobe32(server->pool_offset + next_offer);
                                        break;
                                }

                                next_offer = (next_offer + 1) % server->pool_size;
                        }
                }

                if (address == INADDR_ANY)
                        /* no free addresses left */
                        return 0;

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
                int pool_offset;

                /* see RFC 2131, section 4.3.2 */

                if (req->server_id) {
                        log_dhcp_server(server, "REQUEST (selecting) (0x%x)",
                                        be32toh(req->message->xid));

                        /* SELECTING */
                        if (req->server_id != server->address)
                                /* client did not pick us */
                                return 0;

                        if (req->message->ciaddr)
                                /* this MUST be zero */
                                return 0;

                        if (!req->requested_ip)
                                /* this must be filled in with the yiaddr
                                   from the chosen OFFER */
                                return 0;

                        address = req->requested_ip;
                } else if (req->requested_ip) {
                        log_dhcp_server(server, "REQUEST (init-reboot) (0x%x)",
                                        be32toh(req->message->xid));

                        /* INIT-REBOOT */
                        if (req->message->ciaddr)
                                /* this MUST be zero */
                                return 0;

                        /* TODO: check more carefully if IP is correct */
                        address = req->requested_ip;
                        init_reboot = true;
                } else {
                        log_dhcp_server(server, "REQUEST (rebinding/renewing) (0x%x)",
                                        be32toh(req->message->xid));

                        /* REBINDING / RENEWING */
                        if (!req->message->ciaddr)
                                /* this MUST be filled in with clients IP address */
                                return 0;

                        address = req->message->ciaddr;
                }

                pool_offset = get_pool_offset(server, address);

                /* verify that the requested address is from the pool, and either
                   owned by the current client or free */
                if (pool_offset >= 0 &&
                    server->bound_leases[pool_offset] == existing_lease) {
                        DHCPLease *lease;
                        usec_t time_now = 0;

                        if (!existing_lease) {
                                lease = new0(DHCPLease, 1);
                                if (!lease)
                                        return -ENOMEM;
                                lease->address = address;
                                lease->client_id.data = memdup(req->client_id.data,
                                                               req->client_id.length);
                                if (!lease->client_id.data) {
                                        free(lease);
                                        return -ENOMEM;
                                }
                                lease->client_id.length = req->client_id.length;
                                memcpy(&lease->chaddr, &req->message->chaddr,
                                       ETH_ALEN);
                                lease->gateway = req->message->giaddr;
                        } else
                                lease = existing_lease;

                        r = sd_event_now(server->event,
                                         clock_boottime_or_monotonic(),
                                         &time_now);
                        if (r < 0) {
                                if (!existing_lease)
                                        dhcp_lease_free(lease);
                                return r;
                        }

                        lease->expiration = req->lifetime * USEC_PER_SEC + time_now;

                        r = server_send_offer_or_ack(server, req, address, DHCP_ACK);
                        if (r < 0) {
                                /* this only fails on critical errors */
                                log_dhcp_server_errno(server, r, "Could not send ack: %m");

                                if (!existing_lease)
                                        dhcp_lease_free(lease);

                                return r;
                        } else {
                                log_dhcp_server(server, "ACK (0x%x)",
                                                be32toh(req->message->xid));

                                server->bound_leases[pool_offset] = lease;
                                hashmap_put(server->leases_by_client_id,
                                            &lease->client_id, lease);

                                if (server->callback)
                                        server->callback(server, SD_DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);

                                return DHCP_ACK;
                        }

                } else if (init_reboot) {
                        r = server_send_nak(server, req);
                        if (r < 0)
                                /* this only fails on critical errors */
                                return log_dhcp_server_errno(server, r, "Could not send nak: %m");

                        log_dhcp_server(server, "NAK (0x%x)", be32toh(req->message->xid));
                        return DHCP_NAK;
                }

                break;
        }

        case DHCP_RELEASE: {
                int pool_offset;

                log_dhcp_server(server, "RELEASE (0x%x)",
                                be32toh(req->message->xid));

                if (!existing_lease)
                        return 0;

                if (existing_lease->address != req->message->ciaddr)
                        return 0;

                pool_offset = get_pool_offset(server, req->message->ciaddr);
                if (pool_offset < 0)
                        return 0;

                if (server->bound_leases[pool_offset] == existing_lease) {
                        server->bound_leases[pool_offset] = NULL;
                        hashmap_remove(server->leases_by_client_id, existing_lease);
                        dhcp_lease_free(existing_lease);

                        if (server->callback)
                                server->callback(server, SD_DHCP_SERVER_EVENT_LEASE_CHANGED, server->callback_userdata);
                }

                return 0;
        }}

        return 0;
}

static int server_receive_message(sd_event_source *s, int fd,
                                  uint32_t revents, void *userdata) {
        _cleanup_free_ DHCPMessage *message = NULL;
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct in_pktinfo))) control;
        sd_dhcp_server *server = userdata;
        struct iovec iov = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        ssize_t buflen, len;
        int r;

        assert(server);

        buflen = next_datagram_size_fd(fd);
        if (buflen < 0)
                return buflen;

        message = malloc(buflen);
        if (!message)
                return -ENOMEM;

        iov = IOVEC_MAKE(message, buflen);

        len = recvmsg_safe(fd, &msg, 0);
        if (IN_SET(len, -EAGAIN, -EINTR))
                return 0;
        if (len < 0)
                return len;
        if ((size_t) len < sizeof(DHCPMessage))
                return 0;

        CMSG_FOREACH(cmsg, &msg) {
                if (cmsg->cmsg_level == IPPROTO_IP &&
                    cmsg->cmsg_type == IP_PKTINFO &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo))) {
                        struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(cmsg);

                        /* TODO figure out if this can be done as a filter on
                         * the socket, like for IPv6 */
                        if (server->ifindex != info->ipi_ifindex)
                                return 0;

                        break;
                }
        }

        r = dhcp_server_handle_message(server, message, (size_t) len);
        if (r < 0)
                log_dhcp_server_errno(server, r, "Couldn't process incoming message: %m");

        return 0;
}

int sd_dhcp_server_start(sd_dhcp_server *server) {
        int r;

        assert_return(server, -EINVAL);
        assert_return(server->event, -EINVAL);
        assert_return(!server->receive_message, -EBUSY);
        assert_return(server->fd_raw < 0, -EBUSY);
        assert_return(server->fd < 0, -EBUSY);
        assert_return(server->address != htobe32(INADDR_ANY), -EUNATCH);

        r = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (r < 0) {
                r = -errno;
                sd_dhcp_server_stop(server);
                return r;
        }
        server->fd_raw = r;

        r = dhcp_network_bind_udp_socket(server->ifindex, INADDR_ANY, DHCP_PORT_SERVER, -1);
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

int sd_dhcp_server_forcerenew(sd_dhcp_server *server) {
        int r = 0;

        assert_return(server, -EINVAL);
        assert(server->bound_leases);

        for (uint32_t i = 0; i < server->pool_size; i++) {
                DHCPLease *lease = server->bound_leases[i];

                if (!lease || lease == &server->invalid_lease)
                        continue;

                r = server_send_forcerenew(server, lease->address,
                                           lease->gateway,
                                           lease->chaddr);
                if (r < 0)
                        return r;

                log_dhcp_server(server, "FORCERENEW");
        }

        return r;
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

int sd_dhcp_server_set_max_lease_time(sd_dhcp_server *server, uint32_t t) {
        assert_return(server, -EINVAL);

        if (t == server->max_lease_time)
                return 0;

        server->max_lease_time = t;
        return 1;
}

int sd_dhcp_server_set_default_lease_time(sd_dhcp_server *server, uint32_t t) {
        assert_return(server, -EINVAL);

        if (t == server->default_lease_time)
                return 0;

        server->default_lease_time = t;
        return 1;
}

int sd_dhcp_server_set_servers(
                sd_dhcp_server *server,
                sd_dhcp_lease_server_type_t what,
                const struct in_addr addresses[],
                size_t n_addresses) {

        struct in_addr *c = NULL;

        assert_return(server, -EINVAL);
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

        free(server->servers[what].addr);
        server->servers[what].addr = c;
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

int sd_dhcp_server_set_emit_router(sd_dhcp_server *server, int enabled) {
        assert_return(server, -EINVAL);

        if (enabled == server->emit_router)
                return 0;

        server->emit_router = enabled;

        return 1;
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
