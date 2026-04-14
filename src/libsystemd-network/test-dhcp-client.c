/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-dhcp-client.h"
#include "sd-dhcp-lease.h"
#include "sd-event.h"

#include "dhcp-client-internal.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "ip-util.h"
#include "log.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

static const struct hw_addr_data hw_addr = {
        .length = ETH_ALEN,
        .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
}, bcast_addr = {
        .length = ETH_ALEN,
        .ether = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }},
};

static const uint16_t server_port = 1067;
static const uint16_t client_port = 1068;
static const int ip_service_type = IPTOS_CLASS_CS3;

static const union in_addr_union prefix = {
        .bytes = { 198, 51, 100, 0 },
}, server_address = {
        .bytes = { 198, 51, 100, 1 },
}, client_address = {
        .bytes = { 198, 51, 100, 100 },
}, broadcast = {
        .bytes = { 198, 51, 100, 255 },
}, netmask = {
        .bytes = { 255, 255, 255, 0 },
};

static const usec_t lifetime = USEC_PER_DAY;

static const sd_dhcp_client_id client_id_generic = {
        .size = 10,
        .id.type = 0,
        .id.data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, },
};

/* options sent by client */
static const char * const *user_class_strv = STRV_MAKE_CONST("user-class-hoge", "user-class-foo");
static const char * const *vendor_specific_strv = STRV_MAKE_CONST("vendor-specific-hoge", "vendor-specific-foo");
static const char *vendor_class = "vendor-class";
static const char *mud_url = "https://mud-url.example.com";
static const char *hostname = "hogehoge.example.com";
static const uint32_t mtu = 3000;
static const char *extra_option_163 = "private_option_163";
static const char *extra_option_164 = "private_option_164";

static void setup(sd_event_io_handler_t io_handler, sd_dhcp_client_callback_t client_handler, sd_dhcp_client **ret) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_NOT_NULL(e);

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));

        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        ASSERT_OK(sd_dhcp_client_new(&client));

        client->socket_fd = TAKE_FD(socket_fd[0]);

        /* Set a fake socket address, as the client will never call dhcp_network_bind_raw_socket() when
         * socket_fd is set. */
        client->link.ll = (struct sockaddr_ll) {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = 42,
                .sll_hatype = ARPHRD_ETHER,
                .sll_halen = bcast_addr.length,
        };
        memcpy(client->link.ll.sll_addr, bcast_addr.bytes, bcast_addr.length);

        ASSERT_OK(sd_dhcp_client_attach_event(client, e, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_OK(sd_dhcp_client_set_ifindex(client, 42));
        ASSERT_OK(sd_dhcp_client_set_mac(client, hw_addr.bytes, bcast_addr.bytes, hw_addr.length, ARPHRD_ETHER));
        ASSERT_OK(sd_dhcp_client_set_callback(client, client_handler, e));
        ASSERT_OK(sd_dhcp_client_set_port(client, server_port));
        ASSERT_OK(sd_dhcp_client_set_client_port(client, client_port));
        ASSERT_OK(sd_dhcp_client_set_ip_service_type(client, ip_service_type));

        /* options */
        for (uint8_t i = 178; i <= 207; i++) /* These are currently unassigned. See sd-dhcp-protocol.h. */
                ASSERT_OK(sd_dhcp_client_set_request_option(client, i));

        ASSERT_OK(sd_dhcp_client_set_client_id(client, client_id_generic.id.type, client_id_generic.id.data, client_id_generic.size - 1));
        ASSERT_OK(sd_dhcp_client_set_mtu(client, mtu));
        ASSERT_OK(sd_dhcp_client_set_mud_url(client, mud_url));
        ASSERT_OK(sd_dhcp_client_set_hostname(client, hostname));
        ASSERT_OK(sd_dhcp_client_set_vendor_class_identifier(client, vendor_class));

        _cleanup_(tlv_unrefp) TLV *vendor_specific =
                ASSERT_NOT_NULL(tlv_new(TLV_DHCP4_SUBOPTION));
        uint8_t c = 0;
        STRV_FOREACH(s, vendor_specific_strv)
                ASSERT_OK(tlv_append(vendor_specific, ++c, strlen(*s), *s));
        ASSERT_OK(dhcp_client_set_vendor_options(client, vendor_specific));

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        STRV_FOREACH(s, user_class_strv)
                ASSERT_OK(iovw_put(&iovw, (void*) *s, strlen(*s)));
        ASSERT_OK(dhcp_client_set_user_class(client, &iovw));

        _cleanup_(tlv_unrefp) TLV *extra_options = ASSERT_NOT_NULL(tlv_new(TLV_DHCP4));
        ASSERT_OK(tlv_append(extra_options, 163, strlen(extra_option_163), extra_option_163));
        ASSERT_OK(tlv_append(extra_options, 164, strlen(extra_option_164), extra_option_164));
        ASSERT_OK(dhcp_client_set_extra_options(client, extra_options));

        /* IO event source for the fake server side */
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        ASSERT_OK(sd_event_add_io(e, &s, socket_fd[1], EPOLLIN, io_handler, client));
        ASSERT_OK(sd_event_source_set_priority(s, SD_EVENT_PRIORITY_IMPORTANT));
        ASSERT_OK(sd_event_source_set_description(s, "fake-server-io-event-source"));
        ASSERT_OK(sd_event_source_set_io_fd_own(s, true));
        TAKE_FD(socket_fd[1]);
        ASSERT_OK(sd_event_source_set_floating(s, true));

        *ret = TAKE_PTR(client);
}

static void receive_message(int fd, bool raw, bool check_xid, sd_dhcp_client *client, sd_dhcp_message **ret) {
        ssize_t buflen = ASSERT_OK_POSITIVE(next_datagram_size_fd(fd));
        _cleanup_free_ void *buf = ASSERT_NOT_NULL(malloc0(buflen));

        struct msghdr msg = {
                .msg_iov = &IOVEC_MAKE(buf, buflen),
                .msg_iovlen = 1,
        };
        ssize_t len = ASSERT_OK_ERRNO(recvmsg_safe(fd, &msg, MSG_DONTWAIT));

        struct iovec payload = IOVEC_MAKE(buf, len);
        if (raw)
                ASSERT_OK(udp_packet_verify(
                                          &payload,
                                          client->server_port,
                                          /* checksum= */ true,
                                          &payload));

        ASSERT_OK(dhcp_message_parse(
                                  &payload,
                                  BOOTREQUEST,
                                  check_xid ? &client->xid : NULL,
                                  ARPHRD_ETHER,
                                  &hw_addr,
                                  ret));
}

static void iovw_send(int fd, struct iovec_wrapper *iovw) {
        struct msghdr mh = {
                .msg_iov = iovw->iovec,
                .msg_iovlen = iovw->count,
        };
        ASSERT_OK_ERRNO(sendmsg(fd, &mh, MSG_NOSIGNAL));
}

static void send_message(int fd, bool raw, sd_dhcp_client *client, sd_dhcp_message *m) {
        _cleanup_(iovw_done_free) struct iovec_wrapper payload = {};
        ASSERT_OK(dhcp_message_build(m, &payload));

        if (!raw) {
                iovw_send(fd, &payload);
                return;
        }

        struct iphdr ip;
        struct udphdr udp;
        ASSERT_OK(udp_packet_build(
                                  server_address.in.s_addr,
                                  client->server_port,
                                  m->header.yiaddr,
                                  client->port,
                                  client->ip_service_type,
                                  &payload,
                                  &ip,
                                  &udp));

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        ASSERT_OK(iovw_put(&iovw, &ip, sizeof(struct iphdr)));
        ASSERT_OK(iovw_put(&iovw, &udp, sizeof(struct udphdr)));
        ASSERT_OK(iovw_put_iovw(&iovw, &payload));
        iovw_send(fd, &iovw);
}

static void create_reply(sd_dhcp_client *client, sd_dhcp_message *request, uint8_t type, sd_dhcp_message **ret) {
        assert(ret);

        struct hw_addr_data hw;
        ASSERT_OK(dhcp_message_get_hw_addr(request, &hw));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREPLY,
                                  be32toh(request->header.xid),
                                  request->header.htype,
                                  &hw));

        if (client->bootp) {
                m->header.yiaddr = client_address.in.s_addr;
                m->header.siaddr = server_address.in.s_addr;
                ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_SUBNET_MASK, &netmask.in));
                ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_BROADCAST, &broadcast.in));

                *ret = TAKE_PTR(m);
                return;
        }

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, type));
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, &server_address.in));

        switch (type) {
        case DHCP_OFFER:
        case DHCP_ACK:
                m->header.yiaddr = client_address.in.s_addr;
                ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_SUBNET_MASK, &netmask.in));
                ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_BROADCAST, &broadcast.in));
                ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, usec_to_be32_sec(lifetime)));
                /* The following two options are intentionally set with spurious values, to test the adjusting logic. */
                ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REBINDING_TIME, usec_to_be32_sec(lifetime + USEC_PER_SEC)));
                ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_RENEWAL_TIME, usec_to_be32_sec(lifetime - USEC_PER_SEC)));
                break;

        case DHCP_NAK:
                ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_ERROR_MESSAGE, "test error message"));
                break;

        default:
                ;
        }

        *ret = TAKE_PTR(m);
}

static void verify_header(sd_dhcp_message *m) {
        ASSERT_EQ(m->header.op, BOOTREQUEST);
        ASSERT_EQ(m->header.htype, ARPHRD_ETHER);
        ASSERT_EQ(memcmp_nn(m->header.chaddr, m->header.hlen, hw_addr.bytes, hw_addr.length), 0);
}

static void verify_basic_options(sd_dhcp_message *m, uint8_t type) {
        uint8_t t;
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &t));
        ASSERT_EQ(t, type);

        sd_dhcp_client_id id;
        ASSERT_OK(dhcp_message_get_option_client_id(m, &id));
        ASSERT_EQ(client_id_compare_func(&id, &client_id_generic), 0);
}

static void verify_request(sd_dhcp_message *m, uint8_t type) {
        verify_header(m);
        verify_basic_options(m, type);

        _cleanup_set_free_ Set *prl = NULL;
        ASSERT_OK(dhcp_message_get_option_parameter_request_list(m, &prl));

        for (uint8_t i = 178; i <= 207; i++)
                ASSERT_TRUE(set_contains(prl, UINT_TO_PTR(i)));

        uint16_t sz;
        ASSERT_OK(dhcp_message_get_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &sz));
        ASSERT_EQ(sz, mtu);

        _cleanup_free_ char *str = NULL;
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_MUD_URL, &str));
        ASSERT_STREQ(str, mud_url);

        str = mfree(str);
        ASSERT_OK(dhcp_message_get_option_hostname(m, &str));
        ASSERT_STREQ(str, hostname);

        str = mfree(str);
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, &str));
        ASSERT_STREQ(str, vendor_class);

        _cleanup_(tlv_unrefp) TLV *vendor_specific = NULL;
        ASSERT_OK(dhcp_message_get_option_sub_tlv(
                                  m,
                                  SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                                  TLV_DHCP4_SUBOPTION,
                                  &vendor_specific));
        ASSERT_EQ(hashmap_size(vendor_specific->entries), strv_length((char**) vendor_specific_strv));
        uint8_t c = 0;
        STRV_FOREACH(s, vendor_specific_strv) {
                struct iovec v;
                ASSERT_OK(tlv_get(vendor_specific, ++c, &v));
                ASSERT_EQ(memcmp_nn(v.iov_base, v.iov_len, *s, strlen(*s)), 0);
        }

        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
        STRV_FOREACH(s, user_class_strv)
                ASSERT_OK(iovw_put(&iovw, (void*) *s, strlen(*s)));
        _cleanup_(iovw_done_free) struct iovec_wrapper user_class = {};
        ASSERT_OK(dhcp_message_get_option_length_prefixed_data(m, SD_DHCP_OPTION_USER_CLASS, /* length_size= */ 1, &user_class));
        ASSERT_TRUE(iovw_equal(&user_class, &iovw));

        str = mfree(str);
        ASSERT_OK(dhcp_message_get_option_string(m, 163, &str));
        ASSERT_STREQ(str, extra_option_163);

        str = mfree(str);
        ASSERT_OK(dhcp_message_get_option_string(m, 164, &str));
        ASSERT_STREQ(str, extra_option_164);
}

static void verify_anonymized_request(sd_dhcp_message *m, uint8_t type) {
        verify_header(m);
        verify_basic_options(m, type);

        _cleanup_set_free_ Set *prl = NULL;
        ASSERT_OK(dhcp_message_get_option_parameter_request_list(m, &prl));

        for (uint8_t i = 178; i <= 207; i++)
                ASSERT_FALSE(set_contains(prl, UINT_TO_PTR(i)));

        uint8_t code;
        FOREACH_ARGUMENT(code,
                         SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
                         SD_DHCP_OPTION_MUD_URL,
                         SD_DHCP_OPTION_HOST_NAME,
                         SD_DHCP_OPTION_FQDN,
                         SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER,
                         SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                         SD_DHCP_OPTION_USER_CLASS,
                         163,
                         164)
                ASSERT_FALSE(dhcp_message_has_option(m, code));
}

static void verify_request_server_address(sd_dhcp_message *m) {
        struct in_addr a;
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, &a));
        ASSERT_TRUE(in4_addr_equal(&a, &server_address.in));
}

static void verify_request_client_address(sd_dhcp_message *m, bool header) {
        if (header)
                ASSERT_EQ(m->header.ciaddr, client_address.in.s_addr);
        else {
                struct in_addr a;
                ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a));
                ASSERT_TRUE(in4_addr_equal(&a, &client_address.in));
        }
}

static void verify_reply(sd_dhcp_client *client, DHCPState state) {
        ASSERT_EQ(client->state, state);

        sd_dhcp_lease *lease;
        ASSERT_OK(sd_dhcp_client_get_lease(client, &lease));

        struct in_addr a;
        ASSERT_OK(sd_dhcp_lease_get_address(lease, &a));
        ASSERT_TRUE(in4_addr_equal(&a, &client_address.in));

        ASSERT_OK(sd_dhcp_lease_get_server_identifier(lease, &a));
        ASSERT_TRUE(in4_addr_equal(&a, &server_address.in));

        ASSERT_OK(sd_dhcp_lease_get_broadcast(lease, &a));
        ASSERT_TRUE(in4_addr_equal(&a, &broadcast.in));

        ASSERT_OK(sd_dhcp_lease_get_netmask(lease, &a));
        ASSERT_TRUE(in4_addr_equal(&a, &netmask.in));

        uint8_t prefixlen;
        ASSERT_OK(sd_dhcp_lease_get_prefix(lease, &a, &prefixlen));
        ASSERT_TRUE(in4_addr_equal(&a, &prefix.in));
        ASSERT_EQ(prefixlen, 24u);

        if (client->bootp) {
                usec_t t;
                ASSERT_OK(sd_dhcp_lease_get_lifetime(lease, &t));
                ASSERT_EQ(t, USEC_INFINITY);
        } else {
                usec_t t;
                ASSERT_OK(sd_dhcp_lease_get_lifetime(lease, &t));
                ASSERT_EQ(t, lifetime);
                ASSERT_OK(sd_dhcp_lease_get_t1(lease, &t));
                ASSERT_EQ(t, lifetime / 2);
                ASSERT_OK(sd_dhcp_lease_get_t2(lease, &t));
                ASSERT_EQ(t, lifetime * 7 / 8);
        }
}

static int basic_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        switch (count) {
        case 1: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_DISCOVER);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_OFFER, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 2: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (selecting) */
                verify_request(request, DHCP_REQUEST);
                verify_request_server_address(request);
                verify_request_client_address(request, /* header= */ false);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 3: {
                /* In this stage, client is already restarted and a new xid is picked. */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ false, client, &request);

                verify_header(request);
                verify_basic_options(request, DHCP_DECLINE);
                verify_request_server_address(request);
                verify_request_client_address(request, /* header= */ false);
                break;
        }
        case 4: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_DISCOVER);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_OFFER, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 5: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (selecting) */
                verify_request(request, DHCP_REQUEST);
                verify_request_server_address(request);
                verify_request_client_address(request, /* header= */ false);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 6: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ false, /* check_xid= */ true, client, &request);

                /* REQUEST (renewing) */
                verify_request(request, DHCP_REQUEST);
                verify_request_client_address(request, /* header= */ true);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ false, client, reply);
                break;
        }
        case 7: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ false, /* check_xid= */ true, client, &request);

                /* REQUEST (renewing) */
                verify_request(request, DHCP_REQUEST);
                verify_request_client_address(request, /* header= */ true);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ false, client, reply);
                break;
        }
        case 8: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (rebinding) */
                verify_request(request, DHCP_REQUEST);
                verify_request_client_address(request, /* header= */ true);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 9: {
                /* In this stage, client is already stopped and the xid has been cleared. */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ false, /* check_xid= */ false, client, &request);

                verify_header(request);
                verify_basic_options(request, DHCP_RELEASE);
                verify_request_server_address(request);
                verify_request_client_address(request, /* header= */ true);

                ASSERT_OK(sd_event_exit(sd_dhcp_client_get_event(client), 0));
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int restart_now_defer_handler(sd_event_source *s, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);

        ASSERT_OK(sd_event_source_set_time_relative(client->timeout_resend, /* usec= */ 0));
        return 0;
}

static int basic_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                /* decline the bound lease, and restart the cycle. */
                ASSERT_OK(sd_dhcp_client_send_decline(client));
                break;
        case 3:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_EXPIRED);
                verify_reply(client, DHCP_STATE_BOUND);
                /* on decline, the client will be restarted with a delay. Let's boost the restart timer. */
                ASSERT_OK(sd_event_add_defer(e, /* ret= */ NULL, restart_now_defer_handler, client));
                break;
        case 4:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                break;
        case 5:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                /* renew the lease manually */
                ASSERT_OK(sd_dhcp_client_send_renew(client));
                break;
        case 6:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_RENEW);
                verify_reply(client, DHCP_STATE_BOUND);
                /* renew the lease by timer, triggering the corresponding timer event source now. */
                ASSERT_OK(sd_event_source_set_time_relative(client->timeout_t1, /* usec= */ 0));
                break;
        case 7:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_RENEW);
                verify_reply(client, DHCP_STATE_BOUND);
                /* rebind the lease, triggering the corresponding timer event source now. */
                ASSERT_OK(sd_event_source_set_time_relative(client->timeout_t2, /* usec= */ 0));
                break;
        case 8:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_RENEW);
                verify_reply(client, DHCP_STATE_BOUND);
                /* release and stop. */
                ASSERT_OK(sd_dhcp_client_stop(client));
                break;
        case 9:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_STOP);
                verify_reply(client, DHCP_STATE_BOUND);
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(basic) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        setup(basic_io_handler, basic_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_send_release(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int anonymize_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        switch (count) {
        case 1: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_anonymized_request(request, DHCP_DISCOVER);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_OFFER, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 2: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (selecting) */
                verify_anonymized_request(request, DHCP_REQUEST);
                verify_request_server_address(request);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int anonymize_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(anonymize) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        setup(anonymize_io_handler, anonymize_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_anonymize(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int rapid_commit_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        switch (count) {
        case 1: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_DISCOVER);
                ASSERT_TRUE(dhcp_message_has_option(request, SD_DHCP_OPTION_RAPID_COMMIT));

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);
                ASSERT_OK(dhcp_message_append_option_flag(reply, SD_DHCP_OPTION_RAPID_COMMIT));

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int rapid_commit_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(rapid_commit) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        setup(rapid_commit_io_handler, rapid_commit_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_rapid_commit(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int init_reboot_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        switch (count) {
        case 1: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_REQUEST);
                verify_request_client_address(request, /* header= */ false);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int init_reboot_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(init_reboot) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        setup(init_reboot_io_handler, init_reboot_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_address(client, &client_address.in));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int bootp_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        switch (count) {
        case 1: {
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_header(request);
                ASSERT_TRUE(tlv_isempty(&request->options));

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int bootp_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(bootp) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;
        setup(bootp_io_handler, bootp_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_bootp(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int ipv6_only_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u", __func__, count);

        /* This is used multiple times. */
        switch (count) {
        case 1:   /* test case: before discover */
        case 2:   /* test case: after offer */
        case 3:   /* test case: before request */
        case 4:   /* test case: before ack */
        case 6: { /* test case: after ack */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_DISCOVER);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_OFFER, &reply);

                ASSERT_OK(dhcp_message_append_option_be32(reply, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED, usec_to_be32_sec(10 * USEC_PER_SEC)));

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 5:   /* test case: before ack */
        case 7: { /* test case: after ack */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (selecting) */
                verify_request(request, DHCP_REQUEST);
                verify_request_server_address(request);
                verify_request_client_address(request, /* header= */ false);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                ASSERT_OK(dhcp_message_append_option_be32(reply, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED, usec_to_be32_sec(10 * USEC_PER_SEC)));

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 8: { /* test case: init-reboot */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                /* REQUEST (init-reboot) */
                verify_request(request, DHCP_REQUEST);
                verify_request_client_address(request, /* header= */ false);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);

                ASSERT_OK(dhcp_message_append_option_be32(reply, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED, usec_to_be32_sec(10 * USEC_PER_SEC)));

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        case 9: { /* test case: rapid commit */
                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *request = NULL;
                receive_message(fd, /* raw= */ true, /* check_xid= */ true, client, &request);

                verify_request(request, DHCP_DISCOVER);

                _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *reply = NULL;
                create_reply(client, request, DHCP_ACK, &reply);
                ASSERT_OK(dhcp_message_append_option_flag(reply, SD_DHCP_OPTION_RAPID_COMMIT));

                ASSERT_OK(dhcp_message_append_option_be32(reply, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED, usec_to_be32_sec(10 * USEC_PER_SEC)));

                send_message(fd, /* raw= */ true, client, reply);
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_before_discover_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_STOP);
                verify_reply(client, DHCP_STATE_REQUESTING);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_after_offer_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_STOP);
                verify_reply(client, DHCP_STATE_REQUESTING);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_before_request_defer_handler(sd_event_source *s, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);

        ASSERT_EQ(client->state, DHCP_STATE_REQUESTING);
        ASSERT_EQ(client->request_attempt, 0u);

        ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
        ASSERT_EQ(client->state, DHCP_STATE_STOPPED);

        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));
        return 0;
}

static int ipv6_only_before_request_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                ASSERT_OK(sd_event_add_defer(e, /* ret= */ NULL, ipv6_only_before_request_defer_handler, client));
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_STOP);
                verify_reply(client, DHCP_STATE_REQUESTING);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_before_ack_post_handler(sd_event_source *s, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);

        if (sd_dhcp_client_is_waiting_for_ipv6_connectivity(client))
                /* Boost the time for sending DHCPREQUEST */
                ASSERT_OK(sd_event_source_set_time_relative(client->timeout_resend, /* usec= */ 0));

        else if (client->state == DHCP_STATE_REQUESTING) {
                ASSERT_EQ(client->request_attempt, 1u);

                /* Set IPv6 connectivity after a DHCPREQUEST sent. */
                ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
                /* Still running */
                ASSERT_EQ(client->state, DHCP_STATE_REQUESTING);

        } else if (client->state == DHCP_STATE_BOUND)
                ASSERT_OK(sd_dhcp_client_stop(client));

        return 0;
}

static int ipv6_only_before_ack_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);

        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                ASSERT_OK(sd_event_add_post(e, /* ret= */ NULL, ipv6_only_before_ack_post_handler, client));
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                break;
        case 3:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_STOP);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_after_ack_defer_handler(sd_event_source *s, void *userdata) {
        sd_dhcp_client *client = ASSERT_PTR(userdata);

        ASSERT_EQ(client->state, DHCP_STATE_REQUESTING);
        /* Boost the time for sending DHCPREQUEST */
        ASSERT_OK(sd_event_source_set_time_relative(client->timeout_resend, /* usec= */ 0));
        return 0;
}

static int ipv6_only_after_ack_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_SELECTING);
                verify_reply(client, DHCP_STATE_SELECTING);
                ASSERT_OK(sd_event_add_defer(e, /* ret= */ NULL, ipv6_only_after_ack_defer_handler, client));
                break;
        case 2:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
                /* still running */
                ASSERT_EQ(client->state, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_init_reboot_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

static int ipv6_only_rapid_commit_client_handler(sd_dhcp_client *client, int event, void *userdata) {
        sd_event *e = ASSERT_PTR(userdata);
        static unsigned count = 0;

        count++;
        log_debug("%s: count=%u, event=%i", __func__, count, event);

        switch (count) {
        case 1:
                ASSERT_EQ(event, SD_DHCP_CLIENT_EVENT_IP_ACQUIRE);
                verify_reply(client, DHCP_STATE_BOUND);
                ASSERT_OK(sd_event_exit(e, 0));
                break;
        default:
                assert_not_reached();
        }

        return 0;
}

TEST(ipv6_only) {
        _cleanup_(sd_dhcp_client_unrefp) sd_dhcp_client *client = NULL;

        /* case 1: IPv6 connectivity is acquired before starting the client. */
        setup(ipv6_only_io_handler, ipv6_only_before_discover_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 2: IPv6 connectivity is acquired after DHCPOFFER received. */
        setup(ipv6_only_io_handler, ipv6_only_after_offer_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 3: IPv6 connectivity is acquired before sending DHCPREQUEST. */
        setup(ipv6_only_io_handler, ipv6_only_before_request_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 4: IPv6 connectivity is acquired before DHCPACK received. */
        setup(ipv6_only_io_handler, ipv6_only_before_ack_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 5: IPv6 connectivity is acquired after DHCPACK received. */
        setup(ipv6_only_io_handler, ipv6_only_after_ack_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 6: IPv6 connectivity is acquired on reboot. */
        setup(ipv6_only_io_handler, ipv6_only_init_reboot_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_set_request_address(client, &client_address.in));
        ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));

        client = sd_dhcp_client_unref(client);

        /* case 7: IPv6 connectivity is acquired on rapid commit. */
        setup(ipv6_only_io_handler, ipv6_only_rapid_commit_client_handler, &client);
        ASSERT_OK(sd_dhcp_client_set_rapid_commit(client, true));
        ASSERT_OK(sd_dhcp_client_set_request_option(client, SD_DHCP_OPTION_IPV6_ONLY_PREFERRED));
        ASSERT_OK(sd_dhcp_client_set_ipv6_connectivity(client, true));
        ASSERT_OK(sd_dhcp_client_start(client));
        ASSERT_OK(sd_event_loop(sd_dhcp_client_get_event(client)));
}

static int intro(void) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", /* overwrite= */ true));
        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
