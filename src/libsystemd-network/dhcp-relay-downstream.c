/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/filter.h>
#include <net/if_arp.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"
#include "errno-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "ip-util.h"
#include "siphash24.h"
#include "socket-util.h"

int sd_dhcp_relay_downstream_set_broadcast_address(
                sd_dhcp_relay_interface *interface,
                uint16_t arp_type,
                size_t length,
                const uint8_t *address) {

        assert_return(interface, -EINVAL);
        assert_return(length == 0 || address, -EINVAL);

        hw_addr_set(&interface->broadcast_address, address, length);
        return broadcast_address_ensure(&interface->broadcast_address, arp_type);
}

int sd_dhcp_relay_downstream_set_circuit_id(sd_dhcp_relay_interface *interface, const struct iovec *iov) {
        assert_return(interface, -EINVAL);
        assert_return(!interface->upstream, -EINVAL);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        return iovec_done_and_memdup(&interface->circuit_id, iov);
}

int sd_dhcp_relay_downstream_set_virtual_subnet_selection(sd_dhcp_relay_interface *interface, const struct iovec *iov) {
        assert_return(interface, -EINVAL);
        assert_return(!interface->upstream, -EINVAL);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        return iovec_done_and_memdup(&interface->vss, iov);
}

int downstream_set_extra_options(sd_dhcp_relay_interface *interface, TLV *options) {
        assert(interface);
        assert(!interface->upstream);
        assert(!sd_dhcp_relay_interface_is_running(interface));

        return unref_and_replace_full(interface->extra_options, options, tlv_ref, tlv_unref);
}

int sd_dhcp_relay_downstream_set_gateway_address(sd_dhcp_relay_interface *interface, const struct in_addr *address) {
        assert_return(interface, -EINVAL);
        assert_return(!interface->upstream, -EINVAL);
        assert_return(!sd_dhcp_relay_interface_is_running(interface), -EBUSY);

        if (address)
                interface->gateway_address = *address;
        else
                interface->gateway_address = (struct in_addr) {};

        return 0;
}

static void downstream_hash_func(const sd_dhcp_relay_interface *interface, struct siphash *state) {
        int b;

        assert(interface);
        assert(!interface->upstream);
        assert(state);

        siphash24_compress_typesafe(interface->gateway_address, state);

        b = iovec_is_set(&interface->circuit_id);
        siphash24_compress_typesafe(b, state);
        if (b)
                siphash24_compress_iovec(&interface->circuit_id, state);

        b = iovec_is_set(&interface->vss);
        siphash24_compress_typesafe(b, state);
        if (b)
                siphash24_compress_iovec(&interface->vss, state);
}

static int downstream_compare_func(const sd_dhcp_relay_interface *a, const sd_dhcp_relay_interface *b) {
        int r;

        assert(a);
        assert(!a->upstream);
        assert(b);
        assert(!b->upstream);

        r = CMP(a->gateway_address.s_addr, b->gateway_address.s_addr);
        if (r != 0)
                return r;

        r = iovec_memcmp(&a->circuit_id, &b->circuit_id);
        if (r != 0)
                return r;

        return iovec_memcmp(&a->vss, &b->vss);
}

DEFINE_PRIVATE_HASH_OPS(
                downstream_hash_ops,
                sd_dhcp_relay_interface,
                downstream_hash_func,
                downstream_compare_func);

int downstream_register(sd_dhcp_relay_interface *interface) {
        assert(interface);
        assert(interface->relay);
        assert(!interface->upstream);
        assert(in4_addr_is_set(&interface->address));
        assert(!sd_dhcp_relay_interface_is_running(interface));

        if (!in4_addr_is_set(&interface->gateway_address))
                interface->gateway_address = interface->address;

        /* Do not use a Set; otherwise, we cannot deduplicate entries. */
        return hashmap_ensure_put(&interface->relay->downstream_interfaces, &downstream_hash_ops, interface, interface);
}

void downstream_unregister(sd_dhcp_relay_interface *interface) {
        assert(interface);
        assert(interface->relay);
        assert(!interface->upstream);

        hashmap_remove_value(interface->relay->downstream_interfaces, interface, interface);
}

void downstream_done(sd_dhcp_relay_interface *interface) {
        assert(interface);
        assert(!interface->upstream);

        downstream_unregister(interface);
        iovec_done(&interface->circuit_id);
        iovec_done(&interface->vss);
        interface->extra_options = tlv_unref(interface->extra_options);
}

int downstream_get(sd_dhcp_relay *relay, sd_dhcp_message *message, sd_dhcp_relay_interface **ret) {
        int r;

        assert(relay);
        assert(message);

        /* RFC 3046 section 2.2:
         * DHCP servers claiming to support the Relay Agent Information option SHALL echo the entire contents
         * of the Relay Agent Information option in all replies.
         *
         * So, first try to find the suitable downstream interface by the gateway address and circuit ID in
         * the reply message. */
        sd_dhcp_relay_interface key = {
                .gateway_address.s_addr = message->header.giaddr,
        };

        _cleanup_(tlv_unrefp) TLV *agent_info = NULL;
        r = dhcp_message_get_option_sub_tlv(
                        message,
                        SD_DHCP_OPTION_RELAY_AGENT_INFORMATION,
                        TLV_DHCP4_SUBOPTION,
                        &agent_info);
        if (r < 0 && r != -ENODATA)
                return r;

        if (agent_info) {
                r = tlv_get(agent_info, SD_DHCP_RELAY_AGENT_CIRCUIT_ID, &key.circuit_id);
                if (r < 0 && r != -ENODATA)
                        return r;

                r = tlv_get(agent_info, SD_DHCP_RELAY_AGENT_VIRTUAL_SUBNET_SELECTION, &key.vss);
                if (r < 0 && r != -ENODATA)
                        return r;
        }

        sd_dhcp_relay_interface *interface = hashmap_get(relay->downstream_interfaces, &key);
        if (!interface) {
                /* Some DHCP servers may not understand the Relay Agent Information option and may not echo
                 * it back. To support this case, we fall back to finding a suitable downstream interface
                 * using only the gateway address. Note that if the downstream network uses VRF or the Link
                 * Selection sub-option, multiple interfaces may share the same gateway address. In such
                 * cases, we cannot reliably determine the correct downstream interface, so we must drop the
                 * packet. */
                sd_dhcp_relay_interface *i;
                HASHMAP_FOREACH(i, relay->downstream_interfaces) {
                        if (i->gateway_address.s_addr != message->header.giaddr)
                                continue;

                        if (interface)
                                /* multiple interfaces have the same gateway address?? */
                                return -ENOTUNIQ;

                        interface = i;
                }
        }
        if (!interface)
                return -ENODEV;

        assert(!interface->upstream);

        if (!interface->io_event_source)
                return -ENETDOWN;

        if (ret)
                *ret = interface;
        return 0;
}

static int downstream_append_relay_agent_information(
                sd_dhcp_relay_interface *interface,
                sd_dhcp_message *message,
                const struct in_pktinfo *pktinfo) {

        int r;

        assert(interface);
        assert(interface->relay);
        assert(!interface->upstream);
        assert(message);

        _cleanup_(tlv_done) TLV tlv = TLV_INIT(TLV_DHCP4_SUBOPTION);

        /* First, set per-interface options. */
        if (iovec_is_set(&interface->circuit_id)) {
                r = tlv_append_iov(&tlv, SD_DHCP_RELAY_AGENT_CIRCUIT_ID, &interface->circuit_id);
                if (r < 0)
                        return r;
        }

        if (iovec_is_set(&interface->vss)) {
                r = tlv_append_iov(&tlv, SD_DHCP_RELAY_AGENT_VIRTUAL_SUBNET_SELECTION, &interface->vss);
                if (r < 0)
                        return r;
        }

        if (!in4_addr_equal(&interface->address, &interface->gateway_address)) {
                /* RFC 3527 section 3
                 * The link-selection sub-option is used by any DHCP relay agent that desires to specify a
                 * subnet/link for a DHCP client request that it is relaying but needs the subnet/link
                 * specification to be different from the IP address the DHCP server should use when
                 * communicating with the relay agent. */
                r = tlv_append(&tlv, SD_DHCP_RELAY_AGENT_LINK_SELECTION, sizeof(struct in_addr), &interface->address);
                if (r < 0)
                        return r;
        }

        r = tlv_append_tlv(&tlv, interface->extra_options);
        if (r < 0)
                return r;

        /* Then, set agent-wide options. */
        if (iovec_is_set(&interface->relay->remote_id)) {
                r = tlv_append_iov(&tlv, SD_DHCP_RELAY_AGENT_REMOTE_ID, &interface->relay->remote_id);
                if (r < 0)
                        return r;
        }

        if (interface->relay->server_identifier_override) {
                /* RFC 5107 section 1:
                 * This DHCP relay agent suboption, Server Identifier Override, allows the relay agent to
                 * tell the DHCP server what value to place into the Server Identifier option. Using this,
                 * the relay agent can force a host in RENEWING state to send DHCPREQUEST messages to the
                 * relay agent instead of directly to the server. */
                r = tlv_append(&tlv, SD_DHCP_RELAY_AGENT_SERVER_IDENTIFIER_OVERRIDE, sizeof(struct in_addr), &interface->address);
                if (r < 0)
                        return r;

                /* RFC 5107 section 4:
                 * DHCP relay agents implementing this suboption SHOULD also implement and use the DHCPv4
                 * Relay Agent Flags Suboption in order to specify whether the DHCP relay agent received the
                 * original message as a broadcast or unicast. */
                uint8_t flags = 0;
                SET_FLAG(flags, DHCP_RELAY_AGENT_FLAG_UNICAST,
                         pktinfo && pktinfo->ipi_addr.s_addr != INADDR_BROADCAST);
                r = tlv_append(&tlv, SD_DHCP_RELAY_AGENT_FLAGS, sizeof(uint8_t), &flags);
                if (r < 0)
                        return r;
        }

        r = tlv_append_tlv(&tlv, interface->relay->extra_options);
        if (r < 0)
                return r;

        if (tlv_isempty(&tlv))
                return 0;

        return dhcp_message_append_option_sub_tlv(message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION, &tlv);
}

int downstream_process_message(
                sd_dhcp_relay_interface *interface,
                const struct iovec *iov,
                const struct in_pktinfo *pktinfo) {

        int r;

        assert(interface);
        assert(interface->relay);
        assert(!interface->upstream);
        assert(in4_addr_is_set(&interface->address));
        assert(in4_addr_is_set(&interface->gateway_address));
        assert(iov);

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *message = NULL;
        r = dhcp_message_parse(
                        iov,
                        BOOTREQUEST,
                        /* xid= */ NULL,
                        ARPHRD_NONE,
                        /* hw_addr= */ NULL,
                        &message);
        if (r < 0)
                return r;

        /* RFC 1542 section 4.1.1:
         * The relay agent MUST silently discard BOOTREQUEST messages whose 'hops' field exceeds the value 16. */
        if (message->header.hops >= 16)
                return 0;
        message->header.hops++;

        /* RFC 3046 section 2.1.1:
         * Relay agents configured to add a Relay Agent option which receive a client DHCP packet with a
         * nonzero giaddr SHALL discard the packet if the giaddr spoofs a giaddr address implemented by the
         * local agent itself. */
        if (message->header.giaddr == interface->address.s_addr ||
            message->header.giaddr == interface->gateway_address.s_addr)
                return -EBADMSG;

        /* RFC 1542 section 4.1.1:
         * If the relay agent does decide to relay the request, it MUST examine the 'giaddr' ("gateway" IP
         * address) field. If this field is zero, the relay agent MUST fill this field with the IP address of
         * the interface on which the request was received. (snip) If the 'giaddr' field contains some
         * non-zero value, the 'giaddr' field MUST NOT be modified.
         *
         * RFC 3046 section 2.1.1:
         * the relay agent SHALL forward any received DHCP packet with a valid non-zero giaddr WITHOUT adding
         * any relay agent options. Per RFC 2131, it shall also NOT modify the giaddr value.
         *
         * Therefore, we set giaddr and the Relay Agent Information option here only when the giaddr in the
         * received message is zero. */
        if (message->header.giaddr == INADDR_ANY) {
                message->header.giaddr = interface->gateway_address.s_addr;

                /* RFC 3046 section 2.1:
                 * Relay agents receiving a DHCP packet from an untrusted circuit with giaddr set to zero
                 * (indicating that they are the first-hop router) but with a Relay Agent Information option
                 * already present in the packet SHALL discard the packet and increment an error count. */
                if (dhcp_message_has_option(message, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION))
                        return -EBADMSG;

                r = downstream_append_relay_agent_information(interface, message, pktinfo);
                if (r < 0)
                        return r;
        }

        log_dhcp_relay_interface(interface, "Received BOOTREQUEST (0x%"PRIx32")", be32toh(message->header.xid));

        sd_dhcp_relay_interface *upstream;
        r = upstream_get(interface->relay, &upstream);
        if (r < 0)
                return r;

        return upstream_send_message(upstream, message);
}

static int downstream_open_raw_socket(sd_dhcp_relay_interface *interface) {
        int r;

        assert(interface);
        assert(!interface->upstream);

        _cleanup_close_ int fd = RET_NERRNO(socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (fd < 0)
                return fd;

        /* While bind() with sockaddr_ll is strictly sufficient for AF_PACKET, we also set SO_BINDTOIFINDEX
         * to initialize the kernel's sk_bound_dev_if state. This ensures compatibility with cgroup/eBPF
         * filters and maintains consistency. */
        r = socket_bind_to_ifindex(fd, interface->ifindex);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, tos_to_priority(interface->ip_service_type));
        if (r < 0)
                return r;

        union sockaddr_union sa = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_ifindex = interface->ifindex,
        };

        if (bind(fd, &sa.sa, sockaddr_ll_len(&sa.ll)) < 0)
                return -errno;

        return TAKE_FD(fd);
}

static int downstream_send_l2_unicast(
                sd_dhcp_relay_interface *interface,
                sd_dhcp_message *message,
                const struct hw_addr_data *hw_addr) {

        int r;

        assert(interface);
        assert(message);
        assert(message->header.yiaddr != INADDR_ANY);
        assert(!hw_addr_is_null(hw_addr));

        _cleanup_close_ int fd_close = -EBADF;
        int fd;
        if (interface->socket_fd >= 0)
                /* When a socket fd is given externally, unconditionally use it and do not close the socket. */
                fd = interface->socket_fd;
        else {
                fd = fd_close = downstream_open_raw_socket(interface);
                if (fd < 0)
                        return fd;
        }

        r = dhcp_message_send_raw(
                        message,
                        fd,
                        interface->ifindex,
                        interface->address.s_addr,
                        interface->port,
                        hw_addr,
                        message->header.yiaddr,
                        DHCP_PORT_CLIENT,
                        interface->ip_service_type);
        if (r < 0)
                return r;

        log_dhcp_relay_interface(interface, "Forwarded BOOTREPLY (0x%"PRIx32") to %s (L2 unicast).",
                                 be32toh(message->header.xid),
                                 IN4_ADDR_TO_STRING(&(struct in_addr) { .s_addr = message->header.yiaddr }));
        return 0;
}

static int downstream_send_udp(
                sd_dhcp_relay_interface *interface,
                sd_dhcp_message *message,
                be32_t address) {

        int r;

        assert(interface);
        assert(message);
        assert(address != INADDR_ANY);

        int fd = sd_event_source_get_io_fd(interface->io_event_source);
        if (fd < 0)
                return fd;

        r = dhcp_message_send_udp(
                        message,
                        fd,
                        interface->address.s_addr,
                        address,
                        DHCP_PORT_CLIENT);
        if (r < 0)
                return r;

        log_dhcp_relay_interface(interface, "Forwarded BOOTREQUEST (0x%"PRIx32") to %s (UDP).",
                                 be32toh(message->header.xid),
                                 IN4_ADDR_TO_STRING(&(struct in_addr) { .s_addr = address }));
        return 0;
}

int downstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message) {
        int r;

        assert(interface);
        assert(!interface->upstream);
        assert(message);
        assert(message->header.op == BOOTREPLY);

        /* See RFC 2131 Section 4.1
         *
         * (Note, we are a relay agent, hence conditions for giaddr in the statements are ignored.) */

        uint8_t type;
        r = dhcp_message_get_option_u8(message, SD_DHCP_OPTION_MESSAGE_TYPE, &type);
        if (r < 0)
                return r;

        /* the server broadcasts any DHCPNAK messages to 0xffffffff. */
        if (type == DHCP_NAK)
                return downstream_send_udp(interface, message, INADDR_BROADCAST);

        /* If (...) the ’ciaddr’ field is nonzero, then the server unicasts DHCPOFFER and DHCPACK messages
         * to the address in ’ciaddr’. */
        if (message->header.ciaddr != INADDR_ANY)
                return downstream_send_udp(interface, message, message->header.ciaddr);

        /* If (...) ’ciaddr’ is zero, and the broadcast bit is set, then the server broadcasts DHCPOFFER
         * and DHCPACK messages to 0xffffffff.
         *
         * (Note, even the broadcast flag is unset, we may not know the client hardware address, e.g.
         * InfiniBand. In that case, we cannot unicast in the below, so need to broadcast. Also, for other
         * message types mentioned in the RFC, also broadcast if 'yiaddr' is zero.) */
        struct hw_addr_data hw_addr = {};
        if (!FLAGS_SET(be16toh(message->header.flags), 0x8000) &&
            message->header.yiaddr != INADDR_ANY) {
                r = dhcp_message_get_hw_addr(message, &hw_addr);
                if (r < 0)
                        return r;
        }

        if (hw_addr_is_null(&hw_addr))
                return downstream_send_udp(interface, message, INADDR_BROADCAST);

        /* If the broadcast bit is not set (...) and ’ciaddr’ is zero, then the server unicasts DHCPOFFER
         * and DHCPACK messages to the client’s hardware address and ’yiaddr’ address. */
        return downstream_send_l2_unicast(interface, message, &hw_addr);
}
