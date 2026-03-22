/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>

#include "alloc-util.h"
#include "dhcp-message.h"
#include "dhcp-option.h"
#include "ether-addr-util.h"
#include "iovec-util.h"
#include "iovec-wrapper.h"
#include "random-util.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

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

static void verify_flag(sd_dhcp_message *m) {
        ASSERT_OK(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_RAPID_COMMIT, NULL), EBADMSG); /* size mismatch */
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
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, &a));
        ASSERT_EQ(a.s_addr, expected->s_addr);
}

static void verify_addresses(sd_dhcp_message *m, size_t n_expected, const struct in_addr *expected) {
        struct in_addr a;
        ASSERT_OK(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_NTP_SERVER, &a.s_addr));
        ASSERT_EQ(a.s_addr, expected->s_addr);
        ASSERT_OK(dhcp_message_get_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &a));
        ASSERT_EQ(a.s_addr, expected->s_addr);

        size_t n_addrs;
        _cleanup_free_ struct in_addr *addrs = NULL;
        ASSERT_OK(dhcp_message_get_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, n_expected);
        ASSERT_EQ(memcmp(addrs, expected, sizeof(struct in_addr) * n_expected), 0);
}

static void verify_sip(sd_dhcp_message *m, size_t n_expected, const struct in_addr *expected) {
        ASSERT_ERROR(dhcp_message_get_option_be32(m, SD_DHCP_OPTION_SIP_SERVER, NULL), EBADMSG);
        ASSERT_ERROR(dhcp_message_get_option_address(m, SD_DHCP_OPTION_SIP_SERVER, NULL), EBADMSG);
        ASSERT_ERROR(dhcp_message_get_option_addresses(m, SD_DHCP_OPTION_SIP_SERVER, NULL, NULL), EBADMSG);

        size_t n_addrs;
        _cleanup_free_ struct in_addr *addrs = NULL;
        ASSERT_OK(dhcp_message_get_option_sip_addresses(m, &n_addrs, &addrs));
        ASSERT_EQ(n_addrs, n_expected);
        ASSERT_EQ(memcmp(addrs, expected, sizeof(struct in_addr) * n_expected), 0);
}

static void verify_prl(sd_dhcp_message *m, Set *expected) {
        _cleanup_set_free_ Set *set = NULL;
        ASSERT_OK(dhcp_message_get_option_parameter_request_list(m, &set));
        ASSERT_TRUE(set_equal(set, expected));
}

static void verify_hostname(sd_dhcp_message *m, const char *hostname, const char *fqdn) {
        uint8_t u;
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(dhcp_message_get_option_hostname(m, &u, &s));
        ASSERT_EQ(u, (uint8_t) DHCP_FQDN_FLAG_E);
        ASSERT_STREQ(s, fqdn);
        s = mfree(s);
        ASSERT_OK(dhcp_message_get_option_string(m, SD_DHCP_OPTION_HOST_NAME, &s));
        ASSERT_STREQ(s, hostname);
}

static void verify_vendor(sd_dhcp_message *m, Hashmap *expected) {
        _cleanup_(iovec_done) struct iovec iov1 = {}, iov2 = {}, iov_expected = {};

        ASSERT_OK(dhcp_options_build(expected, &iov_expected));

        ASSERT_OK(dhcp_message_get_option_alloc_iovec(m, SD_DHCP_OPTION_VENDOR_SPECIFIC, &iov1));
        ASSERT_EQ(iovec_memcmp(&iov1, &iov_expected), 0);

        _cleanup_hashmap_free_ Hashmap *v = NULL;
        ASSERT_OK(dhcp_message_get_option_vendor_specific(m, &v));
        ASSERT_EQ(hashmap_size(v), hashmap_size(expected));
        sd_dhcp_option *option;
        HASHMAP_FOREACH(option, expected) {
                sd_dhcp_option *o = ASSERT_NOT_NULL(hashmap_get(v, UINT8_TO_PTR(option->option)));
                ASSERT_EQ(memcmp_nn(o->data, o->length, option->data, option->length), 0);
        }

        ASSERT_OK(dhcp_options_build(v, &iov2));
        ASSERT_EQ(iovec_memcmp(&iov2, &iov_expected), 0);
}

static void verify_user_class(sd_dhcp_message *m, char * const *expected) {
        _cleanup_strv_free_ char **v = NULL;
        ASSERT_OK(dhcp_message_get_option_user_class(m, &v));
        ASSERT_TRUE(strv_equal(v, expected));
}

TEST(dhcp_message) {
        _cleanup_(sd_dhcp_message_unrefp) sd_dhcp_message *m = NULL;

        ASSERT_OK(dhcp_message_new(&m));
        ASSERT_NOT_NULL(m);

        uint32_t xid = random_u32();

        struct hw_addr_data hw_addr = {
                .length = ETH_ALEN,
        };
        random_bytes(hw_addr.bytes, hw_addr.length);

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

        _cleanup_set_free_ Set *prl = NULL;
        for (unsigned i = 0; i < 10; i++)
                ASSERT_OK(set_ensure_put(&prl, /* hash_ops= */ NULL, UINT8_TO_PTR((uint8_t) random_u64_range(UINT8_MAX))));

        const char *hostname = "test-hostname";
        const char *fqdn = "test-node.example.com";
        const char *vendor_class = "hogehoge";
        char **root_path = STRV_MAKE("/path/to/root", "/hogehoge/foofoo");
        char **user_class = STRV_MAKE("hoge", "foo", "bar");


        _cleanup_hashmap_free_ Hashmap *vendor = NULL;
        for (unsigned i = 0; i < 3; i++) {
                uint8_t buf[255];
                random_bytes(buf, 255);
                ASSERT_OK(dhcp_options_append(&vendor, i + 1, 255, buf));
        }

        ASSERT_OK(dhcp_message_init_header(
                                  m,
                                  BOOTREQUEST,
                                  xid,
                                  ARPHRD_ETHER,
                                  &hw_addr));

        ASSERT_EQ(be32toh(m->header.xid), xid);

        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_PAD, 0, NULL), EINVAL);
        ASSERT_ERROR(dhcp_message_append_option(m, SD_DHCP_OPTION_END, 0, NULL), EINVAL);

        /* string */
        ASSERT_ERROR(dhcp_message_get_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, NULL), ENOENT);
        ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, vendor_class));
        verify_string(m, vendor_class);

        /* multiple strings */
        STRV_FOREACH(s, root_path)
                ASSERT_OK(dhcp_message_append_option_string(m, SD_DHCP_OPTION_ROOT_PATH, *s));
        verify_multiple_strings(m, root_path);

        /* flag */
        ASSERT_ERROR(dhcp_message_get_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT), ENOENT);
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        ASSERT_OK(dhcp_message_append_option_flag(m, SD_DHCP_OPTION_RAPID_COMMIT));
        verify_flag(m);

        /* u8 */
        ASSERT_ERROR(dhcp_message_get_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, NULL), ENOENT);
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_DISCOVER));
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MESSAGE_TYPE, DHCP_REQUEST));
        verify_u8(m, DHCP_DISCOVER); /* the first option is used */

        /* u16 */
        ASSERT_OK(dhcp_message_append_option_u8(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 32));
        ASSERT_OK(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 512));
        ASSERT_OK(dhcp_message_append_option_u16(m, SD_DHCP_OPTION_MAXIMUM_MESSAGE_SIZE, 1024));
        verify_u16(m, 512); /* the first valid option is used */

        /* address */
        ASSERT_OK(dhcp_message_append_option_be32(m, SD_DHCP_OPTION_REQUESTED_IP_ADDRESS, addr.s_addr));
        verify_address(m, &addr);

        /* multiple addresses */
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &ntp[0]));
        ASSERT_OK(dhcp_message_append_option_address(m, SD_DHCP_OPTION_NTP_SERVER, &ntp[1]));
        ASSERT_OK(dhcp_message_append_option_addresses(m, SD_DHCP_OPTION_NTP_SERVER, 2, ntp + 2));
        verify_addresses(m, 4, ntp);

        /* sip server addresses */
        ASSERT_OK(dhcp_message_append_option_sip_addresses(m, 4, sip));
        verify_sip(m, 4, sip);

        /* parameter request list */
        ASSERT_OK(dhcp_message_append_option_parameter_request_list(m, prl));
        verify_prl(m, prl);

        /* hostname */
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, hostname));
        ASSERT_OK(dhcp_message_append_option_hostname(m, /* flags= */ 0, /* is_client= */ false, fqdn));
        verify_hostname(m, hostname, fqdn);

        /* vendor specific */
        ASSERT_OK(dhcp_message_append_option_vendor_specific(m, vendor));
        verify_vendor(m, vendor);

        /* user class */
        ASSERT_OK(dhcp_message_append_option_user_class(m, user_class));
        verify_user_class(m, user_class);

        /* build and parse */
        _cleanup_(iovw_done) struct iovec_wrapper iovw = {};
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

        /* verify options */
        verify_string(m2, vendor_class);
        verify_multiple_strings(m2, root_path);
        verify_flag(m2);
        verify_u8(m2, DHCP_DISCOVER);
        verify_u16(m2, 512);
        verify_address(m2, &addr);
        verify_addresses(m2, 4, ntp);
        verify_sip(m2, 4, sip);
        verify_prl(m2, prl);
        verify_hostname(m2, hostname, fqdn);
        verify_vendor(m2, vendor);
        verify_user_class(m2, user_class);

        /* build again, and verify the packet */
        _cleanup_(iovw_done) struct iovec_wrapper iovw2 = {};
        ASSERT_OK(dhcp_message_build(m2, &iovw2));
        ASSERT_EQ(iovw.count, iovw2.count);
        for (size_t i = 0; i < iovw.count; i++)
                ASSERT_EQ(iovec_memcmp(iovw.iovec + i, iovw2.iovec + i), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
