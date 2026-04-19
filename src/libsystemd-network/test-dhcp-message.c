/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-client-id-internal.h"
#include "dhcp-message.h"
#include "dhcp-protocol.h"
#include "ether-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "random-util.h"
#include "set.h"
#include "strv.h"
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

static void verify_sec(sd_dhcp_message *m, usec_t expected) {
        usec_t t;
        ASSERT_OK(dhcp_message_get_option_sec(m, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, /* max_as_infinity= */ false, &t));
        ASSERT_EQ(t, expected);
        ASSERT_OK(dhcp_message_get_option_sec(m, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, /* max_as_infinity= */ true, &t));
        ASSERT_EQ(t, expected);
        ASSERT_OK(dhcp_message_get_option_sec(m, SD_DHCP_OPTION_RENEWAL_TIME, /* max_as_infinity= */ false, &t));
        ASSERT_EQ(t, UINT32_MAX * USEC_PER_SEC);
        ASSERT_OK(dhcp_message_get_option_sec(m, SD_DHCP_OPTION_RENEWAL_TIME, /* max_as_infinity= */ true, &t));
        ASSERT_EQ(t, USEC_INFINITY);
}

static void verify_address(sd_dhcp_message *m, const struct in_addr *expected) {
        struct in_addr a;
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a.s_addr));
        ASSERT_EQ(a.s_addr, expected->s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a));
        ASSERT_EQ(a.s_addr, expected->s_addr);
}

static void verify_addresses(
                sd_dhcp_message *m,
                size_t n_ntp, const struct in_addr *ntp) {

        struct in_addr a;
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_NTP_SERVER, &a.s_addr));
        ASSERT_EQ(a.s_addr, ntp->s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &a));
        ASSERT_EQ(a.s_addr, ntp->s_addr);

        size_t n;
        _cleanup_free_ struct in_addr *addrs = NULL;
        ASSERT_OK(dhcp_message_get_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, &n, &addrs));
        ASSERT_EQ(n, n_ntp);
        ASSERT_EQ(memcmp(addrs, ntp, sizeof(struct in_addr) * n), 0);
}

static void verify_string(sd_dhcp_message *m, const char *expected) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, &s));
        ASSERT_STREQ(s, expected);
}

static void verify_multiple_strings(sd_dhcp_message *m, char * const *expected) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_ROOT_PATH, &s));
        _cleanup_free_ char *joined = ASSERT_NOT_NULL(strv_join(expected, /* separator= */ ""));
        ASSERT_STREQ(s, joined);
}

static void verify_client_id(sd_dhcp_message *m, const sd_dhcp_client_id *expected) {
        sd_dhcp_client_id id = {};
        ASSERT_OK(dhcp_message_get_option_client_id(m, &id));
        ASSERT_EQ(client_id_compare_func(&id, expected), 0);
}

static void verify_prl(sd_dhcp_message *m, Set *expected) {
        _cleanup_set_free_ Set *set = NULL;
        ASSERT_OK(dhcp_message_get_option_parameter_request_list(m, &set));
        ASSERT_TRUE(set_equal(set, expected));
}

static void verify_hostname(sd_dhcp_message *m, const char *expected) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(dhcp_message_get_option_hostname(m, &s));
        ASSERT_STREQ(s, expected);
}

static void verify_sub_tlv(sd_dhcp_message *m, TLV *expected) {
        _cleanup_(tlv_unrefp) TLV *tlv = NULL;
        ASSERT_OK(dhcp_message_get_option_sub_tlv(
                                  m,
                                  SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION,
                                  TLV_DHCP4_SUBOPTION,
                                  &tlv));

        _cleanup_(iovec_done) struct iovec iov = {}, iov_expected = {};
        ASSERT_OK(tlv_build(tlv, &iov));
        ASSERT_OK(tlv_build(expected, &iov_expected));
        ASSERT_TRUE(iovec_equal(&iov, &iov_expected));
}

static void verify_length_prefixed_data(sd_dhcp_message *m, const struct iovec_wrapper *expected) {
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw = {};
        ASSERT_OK(dhcp_message_get_option_length_prefixed_data(m, SD_DHCP_OPTION_USER_CLASS, 1, &iovw));
        ASSERT_TRUE(iovw_equal(&iovw, expected));
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

        usec_t lease_time = USEC_PER_DAY;

        /* 192.0.2.42 */
        struct in_addr addr = { .s_addr = htobe32(0xC000022a) };

        /* 192.0.2.1 - 4 */
        struct in_addr ntp[4] = {
                { .s_addr = htobe32(0xC0000201) },
                { .s_addr = htobe32(0xC0000202) },
                { .s_addr = htobe32(0xC0000203) },
                { .s_addr = htobe32(0xC0000204) },
        };

        sd_dhcp_client_id id = {
                .raw = { 1, 3, 3, 3, 3, 3, 3, },
                .size = 7,
        };

        _cleanup_set_free_ Set *prl = NULL;
        for (uint8_t i = SD_DHCP_OPTION_PRIVATE_BASE; i <= SD_DHCP_OPTION_PRIVATE_LAST; i++)
                ASSERT_OK(set_ensure_put(&prl, /* hash_ops= */ NULL, UINT_TO_PTR(i)));

        const char *hostname = "test-node.example.com";
        const char *vendor_class = "hogehoge";
        char **root_path = STRV_MAKE("/path/to/root", "/hogehoge/foofoo");

        _cleanup_(iovw_done_free) struct iovec_wrapper user_class = {}, user_class_1 = {}, user_class_2 = {};
        FOREACH_STRING(s, "hoge", "foo", "bar") {
                ASSERT_OK(iovw_extend(&user_class, s, strlen(s)));
                ASSERT_OK(iovw_extend(&user_class_1, s, strlen(s)));
        }
        FOREACH_STRING(s, "aaa", "bbb", "ccc") {
                ASSERT_OK(iovw_extend(&user_class, s, strlen(s)));
                ASSERT_OK(iovw_extend(&user_class_2, s, strlen(s)));
        }

        _cleanup_(tlv_done) TLV vendor = TLV_INIT(TLV_DHCP4_SUBOPTION);
        for (unsigned i = 0; i < 3; i++) {
                uint8_t buf[255];
                memset(buf, 42 + i, sizeof(buf));
                ASSERT_OK(tlv_append(&vendor, i + 1, 255, buf));
        }

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

        /* multiple strings */
        STRV_FOREACH(s, root_path)
                ASSERT_OK(dhcp_message_append_option(m, SD_DHCP_OPTION_ROOT_PATH, strlen(*s), *s));
        verify_multiple_strings(m, root_path);

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

        /* sec */
        ASSERT_OK(dhcp_message_append_option_sec(m, SD_DHCP_OPTION_IP_ADDRESS_LEASE_TIME, lease_time));
        ASSERT_OK(dhcp_message_append_option_sec(m, SD_DHCP_OPTION_RENEWAL_TIME, USEC_INFINITY));
        verify_sec(m, lease_time);

        /* address */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr));
        ASSERT_ERROR(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr), EEXIST);
        ASSERT_ERROR(dhcp_message_append_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &addr), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS);
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &addr));
        verify_address(m, &addr);

        /* multiple addresses */
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &ntp[0]));
        ASSERT_OK(dhcp_message_append_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, ELEMENTSOF(ntp) - 1, ntp + 1));
        verify_addresses(m, ELEMENTSOF(ntp), ntp);

        /* string */
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, NULL), ENODATA);
        ASSERT_OK(dhcp_message_append_option(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, 0, NULL));
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, NULL), ENODATA);
        ASSERT_OK(dhcp_message_append_option(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, 1, "\0"));
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, NULL), ENODATA);
        ASSERT_OK(dhcp_message_append_option(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, 9, "hoge\0hoge"));
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, NULL), EBADMSG);
        ASSERT_ERROR(dhcp_message_append_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, vendor_class), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER);
        ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, vendor_class));
        verify_string(m, vendor_class);

        /* client ID */
        ASSERT_OK(dhcp_message_append_option_client_id(m, &id));
        verify_client_id(m, &id);

        /* parameter request list */
        ASSERT_OK(dhcp_message_append_option_parameter_request_list(m, prl));
        ASSERT_OK(dhcp_message_append_option_parameter_request_list(m, prl));
        verify_prl(m, prl);

        /* hostname */
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, "hogehoge"));
        ASSERT_ERROR(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_FQDN);
        ASSERT_ERROR(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_HOST_NAME);
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, "hogehoge.example.com"));
        ASSERT_ERROR(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_HOST_NAME);
        ASSERT_ERROR(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname), EEXIST);
        dhcp_message_remove_option(m, SD_DHCP_OPTION_FQDN);
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname));
        verify_hostname(m, hostname);

        /* vendor specific */
        ASSERT_OK(dhcp_message_append_option_sub_tlv(m, SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION, &vendor));
        ASSERT_ERROR(dhcp_message_append_option_sub_tlv(m, SD_DHCP_OPTION_VENDOR_SPECIFIC_INFORMATION, &vendor), EEXIST);
        verify_sub_tlv(m, &vendor);

        /* user class */
        ASSERT_OK(dhcp_message_append_option_length_prefixed_data(m, SD_DHCP_OPTION_USER_CLASS, 1, &user_class_1));
        ASSERT_OK(dhcp_message_append_option_length_prefixed_data(m, SD_DHCP_OPTION_USER_CLASS, 1, &user_class_2));
        verify_length_prefixed_data(m, &user_class);

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
        verify_multiple_strings(m2, root_path);
        verify_flag(m2);
        verify_u8(m2, DHCP_DISCOVER);
        verify_u16(m2, 512);
        verify_sec(m2, lease_time);
        verify_address(m2, &addr);
        verify_addresses(m2, ELEMENTSOF(ntp), ntp);
        verify_string(m2, vendor_class);
        verify_client_id(m2, &id);
        verify_prl(m2, prl);
        verify_hostname(m2, hostname);
        verify_sub_tlv(m2, &vendor);
        verify_length_prefixed_data(m2, &user_class);

        /* build again, and verify the packet */
        _cleanup_(iovw_done_free) struct iovec_wrapper iovw2 = {};
        ASSERT_OK(dhcp_message_build(m2, &iovw2));
        ASSERT_TRUE(iovw_equal(&iovw, &iovw2));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
