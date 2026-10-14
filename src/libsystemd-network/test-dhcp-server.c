/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "dhcp-server-internal.h"
#include "dhcp-server-lease-internal.h"
#include "dhcp-server-request.h"
#include "fd-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "set.h"
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

TEST(sd_dhcp_server_configure_pool) {
        struct in_addr address = {
                .s_addr = htobe32(0xC0000201), /* 192.0.2.1 */
        };

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));

        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 24, 0, 0));
        ASSERT_EQ(server->pool_offset, 1u);
        ASSERT_EQ(server->pool_size, 254u);

        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 24, 0, 254));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 0, 255),
                        ERANGE));

        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 24, 254, 0));
        ASSERT_EQ(server->pool_offset, 254u);
        ASSERT_EQ(server->pool_size, 1u);

        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 24, 254, 1));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 254, 2),
                        ERANGE));
        ASSERT_EQ(server->pool_offset, 254u);
        ASSERT_EQ(server->pool_size, 1u);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 255, 0),
                        ERANGE));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 255, 1),
                        ERANGE));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 256, 0),
                        ERANGE));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, 256, 1),
                        ERANGE));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, UINT32_MAX, 0),
                        ERANGE));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 24, UINT32_MAX, 1),
                        ERANGE));

        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address, 30, 2, 1));
        ASSERT_EQ(server->pool_offset, 2u);
        ASSERT_EQ(server->pool_size, 1u);

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(
                        sd_dhcp_server_configure_pool(server, &address, 30, 3, 0),
                        ERANGE));
        ASSERT_EQ(server->pool_offset, 2u);
        ASSERT_EQ(server->pool_size, 1u);
}

static int process_one(sd_dhcp_server *server, sd_dhcp_message *message) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        ASSERT_OK(dhcp_message_build(message, &iovw));

        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(iovw_concat(&iovw, &iov));
        return dhcp_server_process_message(server, &iov, /* mh= */ NULL);
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

        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        ASSERT_OK_EQ(process_one(server, m), DHCP_OFFER);

        /* Missing Message Type option */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_ERROR(process_one(server, m), ENODATA);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));

        /* Invalid op */
        m->header.op = 0;
        ASSERT_ERROR(process_one(server, m), EBADMSG);
        m->header.op = BOOTREQUEST;

        /* Invalid htype */
        m->header.htype = 0;
        ASSERT_ERROR(process_one(server, m), EBADMSG);
        m->header.htype = ARPHRD_ETHER;

        /* Invalid hlen */
        m->header.hlen = 0;
        ASSERT_ERROR(process_one(server, m), EBADMSG);
        m->header.hlen = ETHER_ADDR_LEN;

        /* DHCPREQUEST (init-reboot) without Requested IP Address option */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        ASSERT_ERROR(process_one(server, m), ENODATA);

        /* DHCPREQUEST (init-reboot) with an invalid Requested IP Address option */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(0x12345678)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);

        /* DHCPREQUEST (selecting) with Requested IP address */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(INADDR_LOOPBACK)));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 3)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* DHCPREQUEST (selecting) with unmatching server address (silently ignored). */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_SERVER_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(0x12345678)));
        ASSERT_OK_ZERO(process_one(server, m));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_SERVER_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER, htobe32(INADDR_LOOPBACK)));

        /* DHCPREQUEST (selecting) with another address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 4)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* Request the previous address again. */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 3)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* With client ID */
        struct sd_dhcp_client_id client_id = {
                .size = 7,
                .id.type = 1,
                .id.eth.haddr = { 'A', 'B', 'C', 'D', 'E', 'F' },
        };
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* Request a different address with client ID */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 30)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

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
        ASSERT_OK_EQ(process_one(server, m), DHCP_OFFER);

        /* request neither bound nor static address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 29)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);

        /* request the currently assigned address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 30)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);

        /* request the new static address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 31)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* release the bound static lease */
        m->header.ciaddr = htobe32(INADDR_LOOPBACK + 31);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_RELEASE));
        ASSERT_OK_ZERO(process_one(server, m));
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
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* request address reserved for static lease (unmatching client ID) */
        client_id.id.eth.haddr[5] = 'H';
        dhcp_message_remove_option(m, SD_DHCP_OPTION_CLIENT_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);

        /* request unmatching address */
        client_id.id.eth.haddr[5] = 'G';
        dhcp_message_remove_option(m, SD_DHCP_OPTION_CLIENT_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_client_id(m, &client_id));
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 41)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);

        /* request matching address */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* try again */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, htobe32(INADDR_LOOPBACK + 42)));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);
}

TEST(dhcp_server_rapid_commit_ipv6_only_preferred) {
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
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));

        struct in_addr address_lo = {
                .s_addr = htobe32(INADDR_LOOPBACK),
        };

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_OK(sd_dhcp_server_set_ipv6_only_preferred_usec(server, MIN_V6ONLY_WAIT_USEC));
        ASSERT_OK(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL));
        server->socket_fd = TAKE_FD(socket_fd[0]);
        ASSERT_OK(sd_dhcp_server_start(server));

        /* Client does not request option 108, rapid commit is honored. */
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);

        /* Client requests option 108, the reply would contain it, so rapid commit must not be honored. */
        _cleanup_set_free_ Set *prl = NULL;
        ASSERT_OK(set_ensure_put(&prl, /* hash_ops= */ NULL, UINT_TO_PTR(SD_DHCP_OPTION_IPV6_ONLY_PREFERRED)));
        ASSERT_OK(dhcp_message_append_option_parameter_request_list(m, prl));
        ASSERT_OK_EQ(process_one(server, m), DHCP_OFFER);

        /* Option 108 disabled on the server, rapid commit is honored again. */
        ASSERT_OK(sd_dhcp_server_set_ipv6_only_preferred_usec(server, 0));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);
}

static void set_message_type(sd_dhcp_message *m, uint8_t type) {
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, type));
}

static void set_client_id(sd_dhcp_message *m, const sd_dhcp_client_id *client_id) {
        dhcp_message_remove_option(m, SD_DHCP_OPTION_CLIENT_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_client_id(m, client_id));
}

static void check_bound_lease(sd_dhcp_server *server, be32_t address, const sd_dhcp_client_id *client_id) {
        sd_dhcp_server_lease *lease = hashmap_get(server->bound_leases_by_address, UINT32_TO_PTR(address));
        ASSERT_NOT_NULL(lease);
        ASSERT_TRUE(client_id_equal(&lease->client_id, client_id));
        ASSERT_EQ(hashmap_size(server->bound_leases_by_client_id), 1u);
}

TEST(dhcp_server_static_lease_client_id_change) {
        static const struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
                .ether = {{ 'A', 'B', 'C', 'D', 'E', 'F' }},
        };
        be32_t static_address = htobe32(INADDR_LOOPBACK + 42);

        /* The client ID generated from the hardware address, e.g. sent by dhclient without -i. */
        sd_dhcp_client_id client_id_mac = {
                .size = 7,
                .id.type = 1,
                .id.eth.haddr = { 'A', 'B', 'C', 'D', 'E', 'F' },
        };
        /* Node-specific client IDs (RFC 4361), e.g. sent by dhclient -i or by systemd-networkd. */
        sd_dhcp_client_id client_id_duid, client_id_duid_other;
        ASSERT_OK(sd_dhcp_client_id_set_raw(
                        &client_id_duid,
                        (const uint8_t[]) { 0xff, 0x12, 0x34, 0x56, 0x78, 0x00, 0x04, 0xde, 0xad },
                        9));
        ASSERT_OK(sd_dhcp_client_id_set_raw(
                        &client_id_duid_other,
                        (const uint8_t[]) { 0xff, 0x12, 0x34, 0x56, 0x78, 0x00, 0x04, 0xbe, 0xef },
                        9));

        _cleanup_close_pair_ int socket_fd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, socket_fd));

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_new(&event));

        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        ASSERT_OK(sd_dhcp_server_new(&server, 4242));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &(struct in_addr) { htobe32(INADDR_LOOPBACK) },
                                                8, 0, 0));
        ASSERT_OK(sd_dhcp_server_set_static_lease(
                        server,
                        &(struct in_addr) { .s_addr = static_address },
                        client_id_mac.raw,
                        client_id_mac.size,
                        /* hostname= */ NULL));
        ASSERT_OK(sd_dhcp_server_attach_event(server, event, SD_EVENT_PRIORITY_NORMAL));
        server->socket_fd = TAKE_FD(socket_fd[0]);
        ASSERT_OK(sd_dhcp_server_start(server));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;
        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_OK(dhcp_message_init_header(m, BOOTREQUEST, 0x12345678, ARPHRD_ETHER, &hw_addr));
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_SERVER_IDENTIFIER,
                                                  htobe32(INADDR_LOOPBACK)));
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, static_address));

        /* The host acquires the static address with the client ID generated from its hardware address. */
        set_client_id(m, &client_id_mac);
        set_message_type(m, DHCP_DISCOVER);
        ASSERT_OK_EQ(process_one(server, m), DHCP_OFFER);
        set_message_type(m, DHCP_REQUEST);
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);
        check_bound_lease(server, static_address, &client_id_mac);

        /* The same host requests the static address with a node-specific client ID. The bound lease with
         * the old client ID must not prevent the host from acquiring its static address. */
        set_client_id(m, &client_id_duid);
        set_message_type(m, DHCP_DISCOVER);
        ASSERT_OK_EQ(process_one(server, m), DHCP_OFFER);
        set_message_type(m, DHCP_REQUEST);
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);
        check_bound_lease(server, static_address, &client_id_duid);

        /* Another host with the same hardware address and another node-specific client ID, e.g. an ipvlan
         * L2 child, must not take over the address. */
        set_client_id(m, &client_id_duid_other);
        set_message_type(m, DHCP_DISCOVER);
        ASSERT_ERROR(process_one(server, m), EADDRINUSE);
        set_message_type(m, DHCP_REQUEST);
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);
        check_bound_lease(server, static_address, &client_id_duid);

        /* Another host with the client ID previously used by the host must not take over the address. */
        m->header.chaddr[5] = 'X';
        set_client_id(m, &client_id_mac);
        set_message_type(m, DHCP_DISCOVER);
        ASSERT_ERROR(process_one(server, m), EADDRINUSE);
        set_message_type(m, DHCP_REQUEST);
        ASSERT_OK_EQ(process_one(server, m), DHCP_NAK);
        check_bound_lease(server, static_address, &client_id_duid);
        m->header.chaddr[5] = 'F';

        /* The host goes back to the client ID generated from its hardware address, with Rapid Commit. */
        set_client_id(m, &client_id_mac);
        set_message_type(m, DHCP_DISCOVER);
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK_EQ(process_one(server, m), DHCP_ACK);
        check_bound_lease(server, static_address, &client_id_mac);
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
