/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "dhcp-server-internal.h"
#include "dhcp-server-request.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "tests.h"

TEST(basic) {
        struct in_addr address_lo = {
                .s_addr = htobe32(INADDR_LOOPBACK),
        };
        struct in_addr address_any = {
                .s_addr = htobe32(INADDR_ANY),
        };

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));
        ASSERT_NOT_NULL(server);

        ASSERT_OK(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL), EBUSY));
        ASSERT_PTR_EQ(sd_dhcp_server_get_event(server), event);
        ASSERT_OK(sd_dhcp_server_detach_event(server));
        ASSERT_NULL(sd_dhcp_server_get_event(server));
        ASSERT_OK(sd_dhcp_server_attach_event(server, NULL, SD_EVENT_PRIORITY_NORMAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_attach_event(server, NULL, SD_EVENT_PRIORITY_NORMAL), EBUSY));

        ASSERT_TRUE(sd_dhcp_server_ref(server) == server);
        ASSERT_NULL(sd_dhcp_server_unref(server));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_start(server), EUNATCH));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_configure_pool(server, &address_any, 28, 0, 0), EINVAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_configure_pool(server, &address_lo, 38, 0, 0), ERANGE));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_configure_pool(server, &address_any, 8, 0, 1), EINVAL));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 1));

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));

        server->socket_fd = TAKE_FD(socket_fd[0]);

        ASSERT_OK(sd_dhcp_server_start(server));
        ASSERT_OK(sd_dhcp_server_start(server));
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_start(server));
}

static void test_dhcp_server_process_message_one(sd_dhcp_server *server, sd_dhcp_message *message, int error) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        ASSERT_OK(dhcp_message_build(message, &iovw));

        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(iovw_concat(&iovw, &iov));
        if (error == 0)
                ASSERT_OK(dhcp_server_process_message(server, &iov, /* timestamp= */ NULL));
        else
                ASSERT_ERROR(dhcp_server_process_message(server, &iov, /* timestamp= */ NULL), error);
}

TEST(dhcp_server_process_message) {
        static const struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
                .ether = {{ 'A', 'B', 'C', 'D', 'E', 'F' }},
        };

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREQUEST,
                                  0x12345678,
                                  ARPHRD_ETHER,
                                  &hw_addr));

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, "TESTHN"));

        struct in_addr address_lo = {
                .s_addr = htobe32(INADDR_LOOPBACK),
        };
        struct in_addr static_lease_address = {
                .s_addr = htobe32(INADDR_LOOPBACK + 42),
        };
        static uint8_t static_lease_client_id[7] = {0x01, 'A', 'B', 'C', 'D', 'E', 'G' };

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &static_lease_address,
                        static_lease_client_id,
                        ELEMENTSOF(static_lease_client_id),
                        /* hostname= */ NULL));
        ASSERT_OK(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL));
        server->socket_fd = TAKE_FD(socket_fd[0]);
        ASSERT_OK(sd_dhcp_server_start(server));

        test_dhcp_server_process_message_one(server, m, 0);

        /* Missing Message Type option */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        test_dhcp_server_process_message_one(server, m, ENODATA);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));

        /* Invalid op */
        m->header.op = 0;
        test_dhcp_server_process_message_one(server, m, EBADMSG);
        m->header.op = BOOTREQUEST;

        /* Invalid htype */
        m->header.htype = 0;
        test_dhcp_server_process_message_one(server, m, EBADMSG);
        m->header.htype = ARPHRD_ETHER;

        /* Invalid hlen */
        m->header.hlen = 0;
        test_dhcp_server_process_message_one(server, m, EBADMSG);
        m->header.hlen = ETHER_ADDR_LEN;

        /* DHCPREQUEST (init-reboot) without Requested IP Address option */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        test_dhcp_server_process_message_one(server, m, ENODATA);

        /* DHCPREQUEST (init-reboot) with an invalid Requested IP Address option */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(0x12345678)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* DHCPREQUEST (init-reboot) with Requested IP address and Server Identifier option */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(INADDR_LOOPBACK)));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 3)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* DHCPREQUEST (init-reboot) with unmatching server address (silently ignored). */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_SERVER_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(0x12345678)));
        test_dhcp_server_process_message_one(server, m, 0);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_SERVER_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(INADDR_LOOPBACK)));

        /* DHCPREQUEST (init-reboot) with another address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 4)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* Request the previous address again. */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 3)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* With client ID */
        struct sd_dhcp_client_id client_id = {
                .size = 7,
                .id.type = 1,
                .id.eth.haddr = { 'A', 'B', 'C', 'D', 'E', 'F' },
        };
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        test_dhcp_server_process_message_one(server, m, 0);

        /* Request a different address with client ID */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 30)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* add the static lease for the client ID */
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = htobe32(INADDR_LOOPBACK + 31) },
                        (uint8_t[7]) { 0x01, 'A', 'B', 'C', 'D', 'E', 'F' },
                        7,
                        /* hostname= */ NULL));
        ASSERT_OK(sd_dhcp_server_start(server));

        /* discover */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request neither bound nor static address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 29)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request the currently assigned address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 30)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request the new static address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 31)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* release the bound static lease */
        m->header.ciaddr = htobe32(INADDR_LOOPBACK + 31);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_RELEASE));
        test_dhcp_server_process_message_one(server, m, 0);
        m->header.ciaddr = 0;
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));

        /* drop the static lease for the client ID */
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        /* address= */ NULL,
                        (uint8_t[7]) { 0x01, 'A', 'B', 'C', 'D', 'E', 'F' },
                        7,
                        /* hostname= */ NULL));
        ASSERT_OK(sd_dhcp_server_start(server));

        /* request a new non-static address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 29)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request address reserved for static lease (unmatching client ID) */
        client_id.id.eth.haddr[5] = 'H';
        dhcp_message_remove_option(m, SD_DHCP_OPTION_CLIENT_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request unmatching address */
        client_id.id.eth.haddr[5] = 'G';
        dhcp_message_remove_option(m, SD_DHCP_OPTION_CLIENT_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 41)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* request matching address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        test_dhcp_server_process_message_one(server, m, 0);

        /* try again */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        test_dhcp_server_process_message_one(server, m, 0);
}

TEST(sd_dhcp_server_set_static_lease) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));

        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x01020304 },
                        (uint8_t *) &(uint32_t) { 0x01020304 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Duplicated entry. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(
                                     server,
                                     &(struct in_addr) { .s_addr = 0x01020304 },
                                     (uint8_t *) &(uint32_t) { 0x01020304 },
                                     sizeof(uint32_t),
                                     /* hostname= */ NULL),
                     EEXIST);
        /* Address is conflicted. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(
                                     server,
                                     &(struct in_addr) { .s_addr = 0x01020304 },
                                     (uint8_t *) &(uint32_t) { 0x01020305 },
                                     sizeof(uint32_t),
                                     /* hostname= */ NULL),
                     EEXIST);
        /* Client ID is conflicted. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(
                                     server,
                                     &(struct in_addr) { .s_addr = 0x01020305 },
                                     (uint8_t *) &(uint32_t) { 0x01020304 },
                                     sizeof(uint32_t),
                                     /* hostname= */ NULL),
                     EEXIST);

        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x01020305 },
                        (uint8_t *) &(uint32_t) { 0x01020305 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Remove the previous entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x00000000 },
                        (uint8_t *) &(uint32_t) { 0x01020305 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Then, set a different address. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x01020306 },
                        (uint8_t *) &(uint32_t) { 0x01020305 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Remove again. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x00000000 },
                        (uint8_t *) &(uint32_t) { 0x01020305 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Try to remove non-existent entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x00000000 },
                        (uint8_t *) &(uint32_t) { 0x01020305 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
        /* Try to remove non-existent entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = 0x00000000 },
                        (uint8_t *) &(uint32_t) { 0x01020306 },
                        sizeof(uint32_t),
                        /* hostname= */ NULL));
}

TEST(sd_dhcp_server_set_domain_name) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));

        /* Test setting domain name */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, "example.com"));

        /* Test setting same domain name (should return 0 - no change) */
        ASSERT_OK_ZERO(sd_dhcp_server_set_domain_name(server, "example.com"));

        /* Test changing domain name */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, "test.local"));

        /* Test clearing domain name */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, NULL));

        /* Test clearing again (should return 0 - already cleared) */
        ASSERT_OK_ZERO(sd_dhcp_server_set_domain_name(server, NULL));

        /* Test invalid domain name */
        ASSERT_ERROR(sd_dhcp_server_set_domain_name(server, "invalid..domain"), EINVAL);

        /* Test empty string (treated differently from NULL) */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, ""));

        /* Test clearing domain name with NULL */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, NULL));

        /* Test valid domain with subdomain */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, "sub.example.com"));

        /* Test single-label domain */
        ASSERT_OK_POSITIVE(sd_dhcp_server_set_domain_name(server, "local"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
