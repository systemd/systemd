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
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "siphash24.h"
#include "socket-util.h"

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
                siphash24_compress(interface->circuit_id.iov_base, interface->circuit_id.iov_len, state);

        b = iovec_is_set(&interface->vss);
        siphash24_compress_typesafe(b, state);
        if (b)
                siphash24_compress(interface->vss.iov_base, interface->vss.iov_len, state);
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
                        TLV_DHCP4_RELAY_AGENT_INFORMATION,
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

static int downstream_set_bpf(sd_dhcp_relay_interface *interface, int fd) {
        assert(interface);
        assert(!interface->upstream);
        assert(fd >= 0);

        /* The minimal DHCP message size: IP header (without options, 20 bytes) + UDP header (8 bytes) + DHCP
         * header (without options). */
        size_t min_length =
                sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct DHCPMessageHeader);

        struct sock_filter filter[] = {
                /* 1. Basic packet length check.
                 * Check against the minimum possible length. */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                 /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, min_length, 1, 0),                 /* packet length >= min_length ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* 2. Protocol check (Fixed offset in IPv4 header) */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, protocol)),  /* A <- IP protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                /* IP protocol == UDP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* 3. IP Fragmentation checks.
                 * When an IP packet is larger than the MTU, it is fragmented into smaller pieces. The UDP
                 * header is ONLY present in the very first fragment. Since BPF filters are stateless and
                 * cannot reassemble fragments, we must explicitly drop any packet that is part of a
                 * fragmented sequence to avoid parsing raw payload data as if it were a UDP/DHCP header. */

                /* 3a. Check the 'More Fragments' (MF) bit.
                 * If the bit is set, it means there are more fragments following this one. Hence, the packet
                 * must be dropped. */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, frag_off)),
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x20),                             /* A <- A & 0x20 (More Fragments bit) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                          /* A == 0 ? (No more fragments) */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore packet if MF == 1 */

                /* 3b. Check the 'Fragment Offset' field.
                 * This indicates the position of this specific fragment relative to the beginning of the
                 * original, unfragmented packet. If the offset is greater than 0, it means this is a
                 * subsequent fragment (e.g., the 2nd or later piece), hence it must be dropped. */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct iphdr, frag_off)),
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x1fff),                           /* A <- A & 0x1fff (Fragment offset) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                          /* A == 0 ? (This is the first fragment) */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore packet if Offset != 0 */

                /* -------------------------------------------------------------------------
                 * 4. Variable Offset Processing (Support for IP Options)
                 * ------------------------------------------------------------------------- */
                /* Load the IP header length (IHL field) from the first byte of the IP header.
                 * BPF_MSH extracts the lower 4 bits (IHL) and multiplies by 4 to get the byte length.
                 * The result is stored in the 'X' index register. */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                /* X <- IP header length in bytes */

                /* Check UDP destination port using indirect load (X + offset) */
                BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct udphdr, dest)),     /* A <- (UDP destination port) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, interface->port, 1, 0),            /* UDP destination port == 67 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* Check DHCP operation code (op) using indirect load (X + UDP header len + op offset) */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, op)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTREQUEST, 1, 0),                /* op == BOOTREQUEST ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* Check DHCP magic cookie using indirect load (X + UDP header len + magic cookie offset) */
                BPF_STMT(BPF_LD + BPF_W + BPF_IND, sizeof(struct udphdr) + offsetof(DHCPMessageHeader, magic)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_MAGIC_COOKIE, 1, 0),          /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* All checks passed, accept the entire packet. */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                 /* accept */
        };

        struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = filter
        };

        return RET_NERRNO(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)));
}

int downstream_open_socket(sd_dhcp_relay_interface *interface) {
        int r;

        assert(interface);
        assert(!interface->upstream);

        _cleanup_close_ int fd = RET_NERRNO(socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        if (fd < 0)
                return fd;

        r = socket_bind_to_ifindex(fd, interface->ifindex);
        if (r < 0)
                return r;

        r = downstream_set_bpf(interface, fd);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_SOCKET, SO_PRIORITY, tos_to_priority(interface->ip_service_type));
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_PACKET, PACKET_AUXDATA, true);
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

static int downstream_append_relay_agent_information(
                sd_dhcp_relay_interface *interface,
                sd_dhcp_message *message,
                bool unicast) {

        int r;

        assert(interface);
        assert(interface->relay);
        assert(!interface->upstream);
        assert(message);

        _cleanup_(tlv_done) TLV tlv = TLV_INIT(TLV_DHCP4_RELAY_AGENT_INFORMATION | TLV_TEMPORAL);

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
                SET_FLAG(flags, DHCP_RELAY_AGENT_FLAG_UNICAST, unicast);
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

static int downstream_process_message(sd_dhcp_relay_interface *interface, const struct iovec *iov, bool unicast) {
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

                r = downstream_append_relay_agent_information(interface, message, unicast);
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

int downstream_receive_message(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_relay_interface *interface = ASSERT_PTR(userdata);
        int r;

        assert(!interface->upstream);
        assert(fd >= 0);

        ssize_t buflen = next_datagram_size_fd(fd);
        if (ERRNO_IS_NEG_TRANSIENT(buflen) || ERRNO_IS_NEG_DISCONNECT(buflen))
                return 0;
        if (buflen < 0) {
                log_dhcp_relay_interface_errno(
                                interface, buflen,
                                "Failed to determine datagram size to read, ignoring: %m");
                return 0;
        }

        _cleanup_free_ void *buf = malloc0(buflen);
        if (!buf)
                return log_oom_debug();

        union sockaddr_union sa = {};
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct tpacket_auxdata))) control;
        struct msghdr msg = {
                .msg_name = &sa.sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };

        ssize_t len = recvmsg_safe(fd, &msg, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(len) || ERRNO_IS_NEG_DISCONNECT(len))
                return 0;
        if (len < 0) {
                log_dhcp_relay_interface_errno(
                                interface, len,
                                "Could not receive message, ignoring: %m");
                return 0;
        }

        struct tpacket_auxdata *aux = CMSG_FIND_DATA(&msg, SOL_PACKET, PACKET_AUXDATA, struct tpacket_auxdata);
        bool checksum = !aux || !(aux->tp_status & TP_STATUS_CSUMNOTREADY);

        struct iovec payload;
        if (udp_packet_verify(&IOVEC_MAKE(buf, len), interface->port, checksum, &payload) < 0)
                return 0;

        bool unicast = sa.sa.sa_family == AF_PACKET && sa.ll.sll_pkttype == PACKET_HOST;

        r = downstream_process_message(interface, &payload, unicast);
        if (r < 0)
                log_dhcp_relay_interface_errno(
                                interface, r,
                                "Could not process message, ignoring: %m");

        return 0;
}

int downstream_send_message(sd_dhcp_relay_interface *interface, sd_dhcp_message *message) {
        int r;

        assert(interface);
        assert(!interface->upstream);
        assert(message);
        assert(message->header.op == BOOTREPLY);

        int fd = sd_event_source_get_io_fd(interface->io_event_source);
        if (fd < 0)
                return fd;

        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        r = dhcp_message_build(message, &payload);
        if (r < 0)
                return r;

        struct iphdr ip;
        struct udphdr udp;
        r = udp_packet_build(
                        interface->address.s_addr,
                        interface->port,
                        INADDR_BROADCAST,
                        DHCP_PORT_CLIENT,
                        interface->ip_service_type,
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

        /* If the broadcast flag is set, or if the message lacks a valid hardware address (e.g., InfiniBand
         * where hlen == 0), we leave hw_addr empty. This ensures that sll_halen is set to 0, signaling the
         * kernel to broadcast the packet. Otherwise, we unicast the reply to the client's hardware address. */
        struct hw_addr_data hw_addr = {};
        if (!FLAGS_SET(be16toh(message->header.flags), 0x8000)) {
                r = dhcp_message_get_hw_addr(message, &hw_addr);
                if (r < 0)
                        return r;
        }

        union sockaddr_union sa = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_ifindex = interface->ifindex,
                .ll.sll_protocol = htobe16(ETH_P_IP),
                .ll.sll_hatype = message->header.htype,
                .ll.sll_halen = hw_addr.length,
        };

        memcpy_safe(sa.ll.sll_addr, hw_addr.bytes, hw_addr.length);

        struct msghdr mh = {
                .msg_name = &sa.sa,
                .msg_namelen = sockaddr_ll_len(&sa.ll),
                .msg_iov = iovw.iovec,
                .msg_iovlen = iovw.count,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        log_dhcp_relay_interface(interface, "Forwarded BOOTREPLY (0x%"PRIx32")", be32toh(message->header.xid));
        return 0;
}
