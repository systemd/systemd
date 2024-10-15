/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <net/if_arp.h>

#include "sd-dhcp-server.h"
#include "sd-event.h"

#include "dhcp-server-internal.h"
#include "tests.h"

static void test_pool(struct in_addr *address, unsigned size, int ret) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;

        ASSERT_OK(sd_dhcp_server_new(&server, 1));

        if (ret >= 0)
                ASSERT_RETURN_IS_CRITICAL(true, ASSERT_OK_EQ(sd_dhcp_server_configure_pool(server, address, 8, 0, size), ret));
        else
                ASSERT_RETURN_IS_CRITICAL(false, ASSERT_ERROR(sd_dhcp_server_configure_pool(server, address, 8, 0, size), -ret));
}

static int test_basic(bool bind_to_interface) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        struct in_addr address_lo = {
                .s_addr = htobe32(INADDR_LOOPBACK),
        };
        struct in_addr address_any = {
                .s_addr = htobe32(INADDR_ANY),
        };
        int r;

        log_debug("/* %s(bind_to_interface=%s) */", __func__, yes_no(bind_to_interface));

        ASSERT_OK(sd_event_new(&event));

        /* attach to loopback interface */
        ASSERT_OK(sd_dhcp_server_new(&server, 1));
        ASSERT_NOT_NULL(server);
        server->bind_to_interface = bind_to_interface;

        ASSERT_OK(sd_dhcp_server_attach_event(server, event, 0));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_attach_event(server, event, 0), EBUSY));
        ASSERT_TRUE(sd_dhcp_server_get_event(server) == event); /* ASSERT_EQ() doesn't work here. */
        ASSERT_OK(sd_dhcp_server_detach_event(server));
        ASSERT_NULL(sd_dhcp_server_get_event(server));
        ASSERT_OK(sd_dhcp_server_attach_event(server, NULL, 0));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_attach_event(server, NULL, 0), EBUSY));

        ASSERT_TRUE(sd_dhcp_server_ref(server) == server);
        ASSERT_NULL(sd_dhcp_server_unref(server));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_start(server), EUNATCH));

        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_configure_pool(server, &address_any, 28, 0, 0), EINVAL));
        ASSERT_RETURN_EXPECTED(ASSERT_ERROR(sd_dhcp_server_configure_pool(server, &address_lo, 38, 0, 0), ERANGE));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));

        test_pool(&address_any, 1, -EINVAL);
        test_pool(&address_lo, 1, 0);

        r = sd_dhcp_server_start(server);
        /* skip test if running in an environment with no full networking support, CONFIG_PACKET not
         * compiled in kernel, nor af_packet module available. */
        if (r == -EPERM || r == -EAFNOSUPPORT)
                return r;
        ASSERT_OK(r);

        ASSERT_OK(sd_dhcp_server_start(server));
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_stop(server));
        ASSERT_OK(sd_dhcp_server_start(server));

        return 0;
}

static void test_message_handler(void) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;
        struct {
                DHCPMessage message;
                struct {
                        uint8_t code;
                        uint8_t length;
                        uint8_t type;
                } _packed_ option_type;
                struct {
                        uint8_t code;
                        uint8_t length;
                        be32_t address;
                } _packed_ option_requested_ip;
                struct {
                        uint8_t code;
                        uint8_t length;
                        be32_t address;
                } _packed_ option_server_id;
                struct {
                        uint8_t code;
                        uint8_t length;
                        uint8_t id[7];
                } _packed_ option_client_id;
                struct {
                        uint8_t code;
                        uint8_t length;
                        uint8_t hostname[6];
                } _packed_ option_hostname;
                uint8_t end;
        } _packed_ test = {
                .message.op = BOOTREQUEST,
                .message.htype = ARPHRD_ETHER,
                .message.hlen = ETHER_ADDR_LEN,
                .message.xid = htobe32(0x12345678),
                .message.chaddr = { 'A', 'B', 'C', 'D', 'E', 'F' },
                .option_type.code = SD_DHCP_OPTION_MESSAGE_TYPE,
                .option_type.length = 1,
                .option_type.type = DHCP_DISCOVER,
                .option_hostname.code = SD_DHCP_OPTION_HOST_NAME,
                .option_hostname.length = 6,
                .option_hostname.hostname = { 'T', 'E', 'S', 'T', 'H', 'N' },
                .end = SD_DHCP_OPTION_END,
        };
        struct in_addr address_lo = {
                .s_addr = htobe32(INADDR_LOOPBACK),
        };
        struct in_addr static_lease_address = {
                .s_addr = htobe32(INADDR_LOOPBACK + 42),
        };
        static uint8_t static_lease_client_id[7] = {0x01, 'A', 'B', 'C', 'D', 'E', 'G' };
        int r;

        log_debug("/* %s */", __func__);

        ASSERT_OK(sd_dhcp_server_new(&server, 1));
        ASSERT_OK(sd_dhcp_server_configure_pool(server, &address_lo, 8, 0, 0));
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &static_lease_address, static_lease_client_id,
                                                  ELEMENTSOF(static_lease_client_id)));
        ASSERT_OK(sd_dhcp_server_attach_event(server, NULL, 0));
        ASSERT_OK(sd_dhcp_server_start(server));

        r = dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL);
        if (r == -ENETDOWN)
                return (void) log_tests_skipped("Network is not available");
        ASSERT_OK_EQ(r, DHCP_OFFER);

        test.end = 0;
        /* TODO, shouldn't this fail? */
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);
        test.end = SD_DHCP_OPTION_END;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);

        test.option_type.code = 0;
        test.option_type.length = 0;
        test.option_type.type = 0;
        ASSERT_ERROR(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), ENOMSG);
        test.option_type.code = SD_DHCP_OPTION_MESSAGE_TYPE;
        test.option_type.length = 1;
        test.option_type.type = DHCP_DISCOVER;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);

        test.message.op = 0;
        ASSERT_OK_ZERO(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL));
        test.message.op = BOOTREQUEST;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);

        test.message.htype = 0;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);
        test.message.htype = ARPHRD_ETHER;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);

        test.message.hlen = 0;
        ASSERT_ERROR(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), EBADMSG);
        test.message.hlen = ETHER_ADDR_LEN;
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_OFFER);

        test.option_type.type = DHCP_REQUEST;
        ASSERT_OK_ZERO(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL));
        test.option_requested_ip.code = SD_DHCP_OPTION_REQUESTED_IP_ADDRESS;
        test.option_requested_ip.length = 4;
        test.option_requested_ip.address = htobe32(0x12345678);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_NAK);
        test.option_server_id.code = SD_DHCP_OPTION_SERVER_IDENTIFIER;
        test.option_server_id.length = 4;
        test.option_server_id.address = htobe32(INADDR_LOOPBACK);
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 3);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);

        test.option_server_id.address = htobe32(0x12345678);
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 3);
        ASSERT_OK_ZERO(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL));
        test.option_server_id.address = htobe32(INADDR_LOOPBACK);
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 4);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 3);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);

        test.option_client_id.code = SD_DHCP_OPTION_CLIENT_IDENTIFIER;
        test.option_client_id.length = 7;
        test.option_client_id.id[0] = 0x01;
        test.option_client_id.id[1] = 'A';
        test.option_client_id.id[2] = 'B';
        test.option_client_id.id[3] = 'C';
        test.option_client_id.id[4] = 'D';
        test.option_client_id.id[5] = 'E';
        test.option_client_id.id[6] = 'F';
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);

        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 30);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);

        /* request address reserved for static lease (unmatching client ID) */
        test.option_client_id.id[6] = 'H';
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 42);
        ASSERT_OK_ZERO(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL));

        /* request unmatching address */
        test.option_client_id.id[6] = 'G';
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 41);
        ASSERT_OK_ZERO(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL));

        /* request matching address */
        test.option_client_id.id[6] = 'G';
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 42);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);

        /* try again */
        test.option_client_id.id[6] = 'G';
        test.option_requested_ip.address = htobe32(INADDR_LOOPBACK + 42);
        ASSERT_OK_EQ(dhcp_server_handle_message(server, (DHCPMessage*)&test, sizeof(test), NULL), DHCP_ACK);
}

static uint64_t client_id_hash_helper(sd_dhcp_client_id *id, uint8_t key[HASH_KEY_SIZE]) {
        struct siphash state;

        siphash24_init(&state, key);
        client_id_hash_func(id, &state);

        return htole64(siphash24_finalize(&state));
}

static void test_client_id_hash(void) {
        sd_dhcp_client_id a = {
                .size = 4,
        }, b = {
                .size = 4,
        };
        uint8_t hash_key[HASH_KEY_SIZE] = {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        };

        log_debug("/* %s */", __func__);

        memcpy(a.raw, "abcd", 4);
        memcpy(b.raw, "abcd", 4);

        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));
        a.size = 3;
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
        a.size = 4;
        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));

        b.size = 3;
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
        b.size = 4;
        ASSERT_EQ(client_id_compare_func(&a, &b), 0);
        ASSERT_EQ(client_id_hash_helper(&a, hash_key), client_id_hash_helper(&b, hash_key));

        memcpy(b.raw, "abce", 4);
        ASSERT_NE(client_id_compare_func(&a, &b), 0);
}

static void test_static_lease(void) {
        _cleanup_(sd_dhcp_server_unrefp) sd_dhcp_server *server = NULL;

        log_debug("/* %s */", __func__);

        ASSERT_OK(sd_dhcp_server_new(&server, 1));

        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020304 },
                                                  (uint8_t*) &(uint32_t) { 0x01020304 }, sizeof(uint32_t)));
        /* Duplicated entry. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020304 },
                                                     (uint8_t*) &(uint32_t) { 0x01020304 }, sizeof(uint32_t)), EEXIST);
        /* Address is conflicted. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020304 },
                                                     (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)), EEXIST);
        /* Client ID is conflicted. */
        ASSERT_ERROR(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020305 },
                                                     (uint8_t*) &(uint32_t) { 0x01020304 }, sizeof(uint32_t)), EEXIST);

        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020305 },
                                                  (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)));
        /* Remove the previous entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x00000000 },
                                                  (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)));
        /* Then, set a different address. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x01020306 },
                                                  (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)));
        /* Remove again. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x00000000 },
                                                  (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)));
        /* Try to remove non-existent entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x00000000 },
                                                  (uint8_t*) &(uint32_t) { 0x01020305 }, sizeof(uint32_t)));
        /* Try to remove non-existent entry. */
        ASSERT_OK(sd_dhcp_server_set_static_lease(server, &(struct in_addr) { .s_addr = 0x00000000 },
                                                  (uint8_t*) &(uint32_t) { 0x01020306 }, sizeof(uint32_t)));
}

int main(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_DEBUG);

        test_client_id_hash();
        test_static_lease();

        r = test_basic(true);
        if (r < 0)
                return log_tests_skipped_errno(r, "cannot start dhcp server(bound to interface)");

        r = test_basic(false);
        if (r < 0)
                return log_tests_skipped_errno(r, "cannot start dhcp server(non-bound to interface)");

        test_message_handler();

        return 0;
}
