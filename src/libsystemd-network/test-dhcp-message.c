/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "ether-addr-util.h"
#include "iovec-util.h"
#include "random-util.h"
#include "tests.h"

TEST(dhcp_message) {
        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;

        ASSERT_OK(dhcp_message_new_empty(&m));
        ASSERT_NOT_NULL(m);

        uint32_t xid = random_u32();

        struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
        };
        random_bytes(hw_addr.bytes, hw_addr.length);

        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREQUEST,
                                  xid,
                                  ARPHRD_ETHER,
                                  &hw_addr));

        ASSERT_EQ(be32toh(m->header.xid), xid);

        /* 192.0.2.42 */
        struct in_addr addr = { .s_addr = 0xC000022a };

        /* 192.0.2.1 - 4 */
        struct in_addr ntp[4] = {
                (struct in_addr) { .s_addr = 0xC0000201 },
                (struct in_addr) { .s_addr = 0xC0000202 },
                (struct in_addr) { .s_addr = 0xC0000203 },
                (struct in_addr) { .s_addr = 0xC0000204 },
        };

        /* 192.0.2.17 - 20 */
        struct in_addr sip[4] = {
                (struct in_addr) { .s_addr = 0xC0000211 },
                (struct in_addr) { .s_addr = 0xC0000212 },
                (struct in_addr) { .s_addr = 0xC0000213 },
                (struct in_addr) { .s_addr = 0xC0000214 },
        };

        uint8_t private_data[512];
        random_bytes(private_data, sizeof(private_data));

        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_PAD, 0, NULL), EINVAL);
        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_END, 0, NULL), EINVAL);

        /* string */
        _cleanup_free_ char *s = NULL;
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_HOST_NAME, &s), ENOENT);
        ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_HOST_NAME, "hogehoge"));
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_HOST_NAME, &s));
        ASSERT_STREQ(s, "hogehoge");

        /* multiple strings */
        s = mfree(s);
        ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_ROOT_PATH, "/path/to/root"));
        ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_ROOT_PATH, "/hogehoge/foofoo"));
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_ROOT_PATH, &s));
        ASSERT_STREQ(s, "/path/to/root/hogehoge/foofoo");

        /* flag */
        ASSERT_ERROR(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT), ENOENT);
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_RAPID_COMMIT, NULL), EBADMSG); /* size mismatch */

        /* u8 */
        uint8_t u8;
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, NULL), ENOENT);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &u8));
        ASSERT_EQ(u8, (uint8_t) DHCP_DISCOVER);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &u8));
        ASSERT_EQ(u8, (uint8_t) DHCP_DISCOVER); /* the first option is used */
        dhcp_message_remove_option(m, SD_DHCP_OPTION_MESSAGE_TYPE);
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, NULL), ENOENT);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, &u8));
        ASSERT_EQ(u8, (uint8_t) DHCP_REQUEST);

        /* u16 */
        uint16_t u16;
        ASSERT_OK(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 512));
        ASSERT_OK(dhcp_message_get_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &u16));
        ASSERT_EQ(u16, 512u);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 32));
        ASSERT_OK(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 1024));
        ASSERT_OK(dhcp_message_get_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &u16));
        ASSERT_EQ(u16, 512u); /* the first option is used, hence the invalid later option is ignored. */
        /* If we search options with 1 byte data (of course that's wrong for the Maximum Message Size
         * option), then the later option is provided, and the first and the third option are ignored, as
         * they have 2 bytes data. */
        ASSERT_OK(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &u8));
        ASSERT_EQ(u8, 32u);

        /* address */
        struct in_addr a;
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr));
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a.s_addr));
        ASSERT_EQ(a.s_addr, addr.s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a));
        ASSERT_EQ(a.s_addr, addr.s_addr);

        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &ntp[0]));
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_NTP_SERVER, &a.s_addr));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &a));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);

        /* multiple addresses */
        _cleanup_free_ struct in_addr *addrs = NULL;
        size_t n_addrs;
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &ntp[1]));
        ASSERT_OK(dhcp_message_append_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, 2, ntp + 2));
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_NTP_SERVER, &a.s_addr));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &a));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);
        ASSERT_OK(dhcp_message_get_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, 4u);
        ASSERT_EQ(memcmp(addrs, ntp, sizeof(struct in_addr) * 4), 0);
        addrs = mfree(addrs);
        ASSERT_OK(dhcp_message_append_option_addresses(m, SD_DHCP_OPTION_SIP_SERVER, 4, sip));
        ASSERT_ERROR(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_SIP_SERVER, NULL), EBADMSG);
        ASSERT_ERROR(dhcp_message_get_option_address(m, SD_DHCP_OPTION_SIP_SERVER, NULL), EBADMSG);
        ASSERT_OK(dhcp_message_get_option_addresses(m, SD_DHCP_OPTION_SIP_SERVER, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, 4u);
        ASSERT_EQ(memcmp(addrs, sip, sizeof(struct in_addr) * 4), 0);

        /* long data */
        size_t n;
        _cleanup_free_ void *p = NULL;
        ASSERT_OK(dhcp_message_append_option(m, /* code= */ 254, sizeof(private_data), private_data));
        ASSERT_OK(dhcp_message_get_option_alloc(m, /* code= */ 254, /* chunk= */ 1, &n, &p));
        ASSERT_EQ(n, sizeof(private_data));
        ASSERT_EQ(memcmp(p, private_data, sizeof(private_data)), 0);
        memzero(p, n);
        ASSERT_OK(dhcp_message_get_option(m, /* code= */ 254, n, p));
        ASSERT_EQ(memcmp(p, private_data, sizeof(private_data)), 0);

        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(dhcp_message_build(m, &iov));

        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m2 = NULL;
        ASSERT_OK(dhcp_message_new(iov.iov_base, iov.iov_len, &m2));

        ASSERT_EQ(memcmp(&m2->header, &m->header, sizeof(m->header)), 0);

        /* string */
        s = mfree(s);
        ASSERT_OK(dhcp_message_get_option_string(m2, SD_DHCP_OPTION_HOST_NAME, &s));
        ASSERT_STREQ(s, "hogehoge");

        /* multiple strings */
        s = mfree(s);
        ASSERT_OK(dhcp_message_get_option_string(m2, SD_DHCP_OPTION_ROOT_PATH, &s));
        ASSERT_STREQ(s, "/path/to/root/hogehoge/foofoo");

        /* flag */
        ASSERT_OK(dhcp_message_get_option_flag(m2, SD_DHCP_OPTION_RAPID_COMMIT));

        /* u8 */
        ASSERT_OK(dhcp_message_get_option_u8(m2, SD_DHCP_OPTION_MESSAGE_TYPE, &u8));
        ASSERT_EQ(u8, (uint8_t) DHCP_REQUEST);

        /* u16 */
        ASSERT_OK(dhcp_message_get_option_u16(m2, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, &u16));
        ASSERT_EQ(u16, 512u);

        /* address */
        ASSERT_OK(dhcp_message_get_option_address(m2, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a));
        ASSERT_EQ(a.s_addr, addr.s_addr);

        /* multiple addresses */
        ASSERT_OK(dhcp_message_get_option_be32(m2, SD_DHCP_OPTION_NTP_SERVER, &a.s_addr));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m2, SD_DHCP_OPTION_NTP_SERVER, &a));
        ASSERT_EQ(a.s_addr, ntp[0].s_addr);
        addrs = mfree(addrs);
        ASSERT_OK(dhcp_message_get_option_addresses(m2, SD_DHCP_OPTION_NTP_SERVER, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, 4u);
        ASSERT_EQ(memcmp(addrs, ntp, sizeof(struct in_addr) * 4), 0);
        addrs = mfree(addrs);
        ASSERT_OK(dhcp_message_get_option_addresses(m2, SD_DHCP_OPTION_SIP_SERVER, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, 4u);
        ASSERT_EQ(memcmp(addrs, sip, sizeof(struct in_addr) * 4), 0);

        /* long data */
        p = mfree(p);
        ASSERT_OK(dhcp_message_get_option_alloc(m2, /* code= */ 254, /* chunk= */ 1, &n, &p));
        ASSERT_EQ(n, sizeof(private_data));
        ASSERT_EQ(memcmp(p, private_data, sizeof(private_data)), 0);
        memzero(p, n);
        ASSERT_OK(dhcp_message_get_option(m2, /* code= */ 254, n, p));
        ASSERT_EQ(memcmp(p, private_data, sizeof(private_data)), 0);

        _cleanup_(iovec_done) struct iovec iov2 = {};
        ASSERT_OK(dhcp_message_build(m2, &iov2));
        ASSERT_EQ(iovec_memcmp(&iov, &iov2), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
