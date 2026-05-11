/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dhcp-protocol.h"
#include "dhcp-relay-internal.h"  /* IWYU pragma: keep */
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "ip-util.h"
#include "socket-util.h"
#include "tests.h"

static uint32_t xid = 12345;

static const struct hw_addr_data hw_addr = {
        .length = ETH_ALEN,
        .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
}, bcast_addr = {
        .length = ETH_ALEN,
        .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
};

static unsigned fake_server_message_count = 0;
static unsigned fake_client_message_count = 0;

TEST(sd_dhcp_relay_ref_unref) {
        _cleanup_(sd_dhcp_relay_unrefp) sd_dhcp_relay *relay = NULL;
        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *upstream = NULL, *downstream = NULL;

        ASSERT_OK(sd_dhcp_relay_new(&relay));
        ASSERT_NOT_NULL(relay);

        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4242, /* is_upstream= */ true, &upstream));
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4343, /* is_upstream= */ false, &downstream));
        ASSERT_PTR_EQ(hashmap_get(relay->interfaces, INT_TO_PTR(4242)), upstream);
        ASSERT_PTR_EQ(hashmap_get(relay->interfaces, INT_TO_PTR(4343)), downstream);

        /* Each interface holds a reference to the sd_dhcp_relay object, so we can safely drop our reference. */
        relay = sd_dhcp_relay_unref(relay);
        ASSERT_PTR_EQ(hashmap_get(upstream->relay->interfaces, INT_TO_PTR(4242)), upstream);
        ASSERT_PTR_EQ(hashmap_get(downstream->relay->interfaces, INT_TO_PTR(4343)), downstream);

        /* Still upstream interface has the reference. */
        downstream = sd_dhcp_relay_interface_unref(downstream);
        ASSERT_PTR_EQ(hashmap_get(upstream->relay->interfaces, INT_TO_PTR(4242)), upstream);
        ASSERT_FALSE(hashmap_contains(upstream->relay->interfaces, INT_TO_PTR(4343)));

        /* Everything should be freed with this. */
        upstream = sd_dhcp_relay_interface_unref(upstream);

        /* Let's check the inverse order. */
        ASSERT_OK(sd_dhcp_relay_new(&relay));
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4242, /* is_upstream= */ true, &upstream));
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4343, /* is_upstream= */ false, &downstream));
        ASSERT_PTR_EQ(hashmap_get(relay->interfaces, INT_TO_PTR(4242)), upstream);
        ASSERT_PTR_EQ(hashmap_get(relay->interfaces, INT_TO_PTR(4343)), downstream);

        downstream = sd_dhcp_relay_interface_unref(downstream);
        ASSERT_PTR_EQ(hashmap_get(relay->interfaces, INT_TO_PTR(4242)), upstream);
        ASSERT_FALSE(hashmap_contains(relay->interfaces, INT_TO_PTR(4343)));

        upstream = sd_dhcp_relay_interface_unref(upstream);
        ASSERT_FALSE(hashmap_contains(relay->interfaces, INT_TO_PTR(4242)));
        ASSERT_FALSE(hashmap_contains(relay->interfaces, INT_TO_PTR(4343)));
}

static void send_message(int fd, sd_dhcp_message *m) {
        ASSERT_OK(dhcp_message_send_udp(
                                  m,
                                  fd,
                                  /* src_addr= */ INADDR_ANY,
                                  /* dst_addr= */ INADDR_ANY,
                                  /* dst_port= */ 0));
}

static int fake_server_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_relay *relay = ASSERT_PTR(userdata);

        fake_server_message_count++;
        log_debug("%s: count=%u", __func__, fake_server_message_count);

        ssize_t buflen = ASSERT_OK_POSITIVE(next_datagram_size_fd(fd));
        _cleanup_free_ void *buf = ASSERT_NOT_NULL(malloc0(buflen));

        struct msghdr msg = {
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
        };
        ssize_t len = ASSERT_OK_ERRNO(recvmsg_safe(fd, &msg, MSG_DONTWAIT));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_parse(
                                  &IOVEC_MAKE(buf, len),
                                  BOOTREQUEST,
                                  &xid,
                                  ARPHRD_ETHER,
                                  &hw_addr,
                                  &m));

        ASSERT_EQ(m->header.hops, 1u);

        sd_dhcp_relay_interface *downstream;
        ASSERT_OK(downstream_get(relay, m, &downstream));
        ASSERT_FALSE(downstream->upstream);

        ASSERT_EQ(m->header.giaddr, downstream->gateway_address.s_addr);

        _cleanup_(tlv_unrefp) TLV *agent_info = NULL;
        ASSERT_OK(dhcp_message_get_option_sub_tlv(
                                  m,
                                  SD_DHCP_OPTION_RELAY_AGENT_INFORMATION,
                                  TLV_DHCP4_SUBOPTION,
                                  &agent_info));

        void *key, *value;
        HASHMAP_FOREACH_KEY(value, key, agent_info->entries) {
                uint32_t tag = PTR_TO_UINT32(key);
                _cleanup_(iovec_done) struct iovec iov = {};
                ASSERT_OK(tlv_get_alloc(agent_info, tag, &iov));

                switch (tag) {
                case SD_DHCP_RELAY_AGENT_CIRCUIT_ID:
                        ASSERT_TRUE(iovec_equal(&iov, &downstream->circuit_id));
                        break;
                case SD_DHCP_RELAY_AGENT_REMOTE_ID:
                        ASSERT_TRUE(iovec_equal(&iov, &relay->remote_id));
                        break;
                case SD_DHCP_RELAY_AGENT_LINK_SELECTION:
                        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE(&downstream->address, sizeof(struct in_addr))));
                        break;
                case SD_DHCP_RELAY_AGENT_FLAGS: {
                        ASSERT_TRUE(relay->server_identifier_override);
                        ASSERT_EQ(iov.iov_len, 1u);
                        uint8_t flags = *(uint8_t*) iov.iov_base;
                        /* In the unit test, we cannot detect if the message is broadcast or unicast because
                         * AF_UNIX is used; therefore, the unicast flag is not set. */
                        ASSERT_FALSE(FLAGS_SET(flags, DHCP_RELAY_AGENT_FLAG_UNICAST));
                        break;
                }
                case SD_DHCP_RELAY_AGENT_SERVER_IDENTIFIER_OVERRIDE:
                        ASSERT_TRUE(relay->server_identifier_override);
                        ASSERT_TRUE(iovec_equal(&iov, &IOVEC_MAKE(&downstream->address, sizeof(struct in_addr))));
                        break;
                case SD_DHCP_RELAY_AGENT_VIRTUAL_SUBNET_SELECTION:
                        ASSERT_TRUE(iovec_equal(&iov, &downstream->vss));
                        break;
                default:
                        assert_not_reached();
                }
        }

        uint8_t t;
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &t));

        switch (fake_server_message_count) {
        case 1:
                ASSERT_EQ(t, DHCP_DISCOVER);
                break;
        case 2:
                ASSERT_EQ(t, DHCP_REQUEST);
                break;
        case 3:
                ASSERT_EQ(t, DHCP_RELEASE);

                if (fake_client_message_count == 3)
                        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static void fake_client_verify(int fd, uint8_t type, bool raw) {
        ssize_t buflen = ASSERT_OK_POSITIVE(next_datagram_size_fd(fd));
        _cleanup_free_ void *buf = ASSERT_NOT_NULL(malloc0(buflen));

        struct msghdr msg = {
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
        };
        ssize_t len = ASSERT_OK_ERRNO(recvmsg_safe(fd, &msg, MSG_DONTWAIT));

        struct iovec payload = IOVEC_MAKE(buf, len);
        if (raw)
                ASSERT_OK(udp_packet_verify(&payload, DHCP_PORT_CLIENT, /* checksum= */ true, &payload));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_parse(
                                  &payload,
                                  BOOTREPLY,
                                  &xid,
                                  ARPHRD_ETHER,
                                  &hw_addr,
                                  &m));

        ASSERT_EQ(m->header.hops, 0u);
        ASSERT_FALSE(dhcp_message_has_option(m, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION));

        uint8_t t;
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &t));
        ASSERT_EQ(t, type);
}

static int fake_client_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        fake_client_message_count++;
        log_debug("%s: count=%u", __func__, fake_client_message_count);

        switch (fake_client_message_count) {
        case 1:
                fake_client_verify(fd, DHCP_OFFER, /* raw= */ true);
                break;
        case 2:
                fake_client_verify(fd, DHCP_ACK, /* raw= */ false);
                break;
        case 3:
                fake_client_verify(fd, DHCP_NAK, /* raw= */ false);

                if (fake_server_message_count == 3)
                        ASSERT_OK(sd_event_exit(sd_event_source_get_event(s), 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(forwarding) {
        union in_addr_union a;

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        _cleanup_(sd_dhcp_relay_unrefp) sd_dhcp_relay *relay = NULL;
        ASSERT_OK(sd_dhcp_relay_new(&relay));
        ASSERT_OK(sd_dhcp_relay_attach_event(relay, e, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_OK(in_addr_from_string(AF_INET, "198.51.100.1", &a));
        ASSERT_OK(sd_dhcp_relay_set_server_address(relay, &a.in));
        ASSERT_OK(sd_dhcp_relay_set_remote_id(relay, &IOVEC_MAKE_STRING("test-remote-id")));
        ASSERT_OK(sd_dhcp_relay_set_server_identifier_override(relay, true));

        /* Setting up an upstream interface. */
        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *upstream = NULL;
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4242, /* is_upstream= */ true, &upstream));
        ASSERT_OK(sd_dhcp_relay_interface_set_ifname(upstream, "test-upstream"));
        ASSERT_OK_ZERO(sd_dhcp_relay_interface_get_address(upstream, /* ret= */ NULL));
        ASSERT_OK(in_addr_from_string(AF_INET, "198.51.100.2", &a));
        ASSERT_OK(sd_dhcp_relay_interface_set_address(upstream, &a.in));
        ASSERT_OK_POSITIVE(sd_dhcp_relay_interface_get_address(upstream, /* ret= */ NULL));

        _cleanup_close_pair_ int upstream_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, upstream_fd));
        upstream->socket_fd = TAKE_FD(upstream_fd[0]);
        ASSERT_OK(sd_dhcp_relay_interface_start(upstream));

        /* IO event source for the server side. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *fake_server = NULL;
        ASSERT_OK(sd_event_add_io(e, &fake_server, upstream_fd[1], EPOLLIN, fake_server_handler, relay));
        ASSERT_OK(sd_event_source_set_priority(fake_server, SD_EVENT_PRIORITY_IMPORTANT));
        ASSERT_OK(sd_event_source_set_description(fake_server, "fake-server-io-event-source"));

        /* Setting up a downstream interface. */
        _cleanup_(sd_dhcp_relay_interface_unrefp) sd_dhcp_relay_interface *downstream = NULL;
        ASSERT_OK(sd_dhcp_relay_add_interface(relay, 4343, /* is_upstream= */ false, &downstream));
        ASSERT_OK(sd_dhcp_relay_interface_set_ifname(downstream, "test-downstream"));
        ASSERT_OK(in_addr_from_string(AF_INET, "192.0.2.1", &a));
        ASSERT_OK(sd_dhcp_relay_interface_set_address(downstream, &a.in));

        ASSERT_OK(sd_dhcp_relay_downstream_set_broadcast_address(downstream, ARPHRD_ETHER, bcast_addr.length, bcast_addr.bytes));
        ASSERT_OK(in_addr_from_string(AF_INET, "203.0.113.1", &a));
        ASSERT_OK(sd_dhcp_relay_downstream_set_gateway_address(downstream, &a.in));
        ASSERT_OK(sd_dhcp_relay_downstream_set_circuit_id(downstream, &IOVEC_MAKE_STRING("test-circuit-id")));
        ASSERT_OK(sd_dhcp_relay_downstream_set_virtual_subnet_selection(downstream, &IOVEC_MAKE_STRING("test-virtual-net")));

        _cleanup_close_pair_ int downstream_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, downstream_fd));
        downstream->socket_fd = TAKE_FD(downstream_fd[0]);
        ASSERT_OK(sd_dhcp_relay_interface_start(downstream));

        /* IO event source for the client side. */
        _cleanup_(sd_event_source_unrefp) sd_event_source *fake_client = NULL;
        ASSERT_OK(sd_event_add_io(e, &fake_client, downstream_fd[1], EPOLLIN, fake_client_handler, relay));
        ASSERT_OK(sd_event_source_set_priority(fake_client, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_OK(sd_event_source_set_description(fake_client, "fake-client-io-event-source"));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREQUEST,
                                  xid,
                                  ARPHRD_ETHER,
                                  &hw_addr));

        /* Test: downstream -> upstream */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);

        /* Invalid message (unexpected BOOTP operation). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 100));
        m->header.op = BOOTREPLY;
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.op = BOOTREQUEST;

        /* Invalid message (too large hops). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 101));
        m->header.hops = 16;
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.hops = 0;

        /* Invalid message (invalid giaddr). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 102));
        m->header.giaddr = downstream->address.s_addr;
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.giaddr = INADDR_ANY;

        /* invalid message (unexpected relay agent information). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 103));
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION));
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_RELAY_AGENT_INFORMATION);

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_RELEASE));
        send_message(downstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);

        /* Test: upstream -> downstream */
        m->header.op = BOOTREPLY;
        m->header.giaddr = downstream->gateway_address.s_addr;
        m->header.yiaddr = 0x12345678;

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_OFFER));
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_ACK));
        m->header.ciaddr = 0x12345678;
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.ciaddr = 0;

        /* Invalid message (unexpected BOOTP operation). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 200));
        m->header.op = BOOTREQUEST;
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.op = BOOTREPLY;

        /* Invalid message (NULL giaddr). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 201));
        m->header.giaddr = INADDR_ANY;
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.giaddr = downstream->gateway_address.s_addr;

        /* Invalid message (unexpected giaddr). */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, 202));
        m->header.giaddr = 1234567;
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        m->header.giaddr = downstream->gateway_address.s_addr;

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_NAK));
        send_message(upstream_fd[1], m);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);

        ASSERT_OK(sd_event_loop(e));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
