/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "random-util.h"
#include "tests.h"

static void verify_header(sd_dhcp_message *m, uint32_t xid, const struct hw_addr_data *hw_addr) {
        ASSERT_EQ(be32toh(m->header.xid), xid);

        ASSERT_FALSE(dhcp_message_has_broadcast_flag(m));
        dhcp_message_set_broadcast_flag(m, true);
        ASSERT_TRUE(dhcp_message_has_broadcast_flag(m));
        dhcp_message_set_broadcast_flag(m, false);
        ASSERT_FALSE(dhcp_message_has_broadcast_flag(m));

        struct hw_addr_data a;
        ASSERT_OK(dhcp_message_get_hw_addr(m, &a));
        ASSERT_TRUE(hw_addr_equal(&a, hw_addr));
}

static void verify_flag(sd_dhcp_message *m) {
        ASSERT_TRUE(dhcp_message_has_option(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_RAPID_COMMIT, NULL), ENODATA); /* size mismatch */
}

static void verify_u8(sd_dhcp_message *m, uint8_t expected) {
        uint8_t u;
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &u));
        ASSERT_EQ(u, expected);
}

static void verify_u16(sd_dhcp_message *m, uint16_t expected) {
        uint16_t u;
        ASSERT_OK(dhcp_message_get_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &u));
        ASSERT_EQ(u, expected);
}

static void verify_address(sd_dhcp_message *m, const struct in_addr *expected) {
        struct in_addr a;
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a.s_addr));
        ASSERT_EQ(a.s_addr, expected->s_addr);
}

TEST(dhcp_message) {
        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;

        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_NOT_NULL(m);

        uint32_t xid = random_u32();

        struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
                .ether = {{ 'A', 'B', 'C', '1', '2', '3' }},
        };

        /* 192.0.2.42 */
        struct in_addr addr = { .s_addr = htobe32(0xC000022a) };

        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREQUEST,
                                  xid,
                                  ARPHRD_ETHER,
                                  &hw_addr));

        /* header */
        verify_header(m, xid, &hw_addr);

        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_PAD, 0, NULL), EINVAL);
        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_END, 0, NULL), EINVAL);

        /* flag */
        ASSERT_ERROR(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT), ENODATA);
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_ERROR(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT), EEXIST);
        verify_flag(m);

        /* u8 */
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, NULL), ENODATA);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        ASSERT_ERROR(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST), EEXIST);
        verify_u8(m, DHCP_DISCOVER);

        /* u16 */
        ASSERT_OK(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 512));
        ASSERT_ERROR(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 1024), EEXIST);
        ASSERT_ERROR(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 32), EEXIST);
        verify_u16(m, 512);

        /* address */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr));
        ASSERT_ERROR(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr), EEXIST);
        verify_address(m, &addr);

        /* build and parse */
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        ASSERT_OK(dhcp_message_build(m, &iovw));

        _cleanup_(iovec_done) struct iovec joined = {};
        ASSERT_OK(iovw_concat(&iovw, &joined));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m2 = NULL;
        ASSERT_OK(dhcp_message_parse(
                                  &joined,
                                  BOOTREQUEST,
                                  &xid,
                                  ARPHRD_ETHER,
                                  &hw_addr,
                                  &m2));

        ASSERT_EQ(memcmp(&m2->header, &m->header, sizeof(m->header)), 0);

        /* verify parsed message */
        verify_header(m2, xid, &hw_addr);
        verify_flag(m2);
        verify_u8(m2, DHCP_DISCOVER);
        verify_u16(m2, 512);
        verify_address(m2, &addr);

        /* build again, and verify the packet */
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw2 = {};
        ASSERT_OK(dhcp_message_build(m2, &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
