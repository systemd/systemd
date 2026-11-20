/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "ip-protocol-list.h"
#include "stdio-util.h"
#include "strv.h"
#include "tests.h"

static void test_int(int i) {
        char str[DECIMAL_STR_MAX(int)];

        ASSERT_EQ(ip_protocol_from_name(ip_protocol_to_name(i)), i);

        xsprintf(str, "%i", i);
        ASSERT_EQ(ip_protocol_from_name(ip_protocol_to_name(parse_ip_protocol(str))), i);
}

static void test_int_fail(int i, int error) {
        char str[DECIMAL_STR_MAX(int)];

        ASSERT_NULL(ip_protocol_to_name(i));

        xsprintf(str, "%i", i);
        ASSERT_EQ(parse_ip_protocol(str), error);
}

static void test_str(const char *s) {
        ASSERT_STREQ(ip_protocol_to_name(ip_protocol_from_name(s)), s);
        ASSERT_STREQ(ip_protocol_to_name(parse_ip_protocol(s)), s);
}

static void test_str_fail(const char *s, int error) {
        ASSERT_ERROR(ip_protocol_from_name(s), EINVAL);
        ASSERT_EQ(parse_ip_protocol(s), error);
}

TEST(integer) {
        test_int(IPPROTO_TCP);
        test_int(IPPROTO_DCCP);
        test_int_fail(-1, -ERANGE);
        test_int_fail(1024 * 1024, -EPROTONOSUPPORT);
}

TEST(string) {
        test_str("sctp");
        test_str("udp");
        test_str_fail("hoge", -EINVAL);
        test_str_fail("-1", -ERANGE);
        test_str_fail("1000000000", -EPROTONOSUPPORT);
}

TEST(parse_ip_protocol) {
        ASSERT_OK_EQ(parse_ip_protocol("sctp"), IPPROTO_SCTP);
        ASSERT_OK_EQ(parse_ip_protocol("ScTp"), IPPROTO_SCTP);
        ASSERT_OK_EQ(parse_ip_protocol("mptcp"), IPPROTO_MPTCP);
        ASSERT_OK_EQ(parse_ip_protocol("MPTCP"), IPPROTO_MPTCP);
        ASSERT_OK_EQ(parse_ip_protocol("ip"), IPPROTO_IP);
        ASSERT_OK_EQ(parse_ip_protocol(""), IPPROTO_IP);
        ASSERT_OK_EQ(parse_ip_protocol("1"), 1);
        ASSERT_OK_EQ(parse_ip_protocol("0"), 0);
        ASSERT_ERROR(parse_ip_protocol("-10"), ERANGE);
        ASSERT_ERROR(parse_ip_protocol("100000000"), EPROTONOSUPPORT);
}

TEST(parse_ip_protocol_full) {
        ASSERT_ERROR(parse_ip_protocol_full("-1", /* relaxed= */ true), ERANGE);
        ASSERT_OK_EQ(parse_ip_protocol_full("0", /* relaxed= */ true), 0);
        ASSERT_OK_EQ(parse_ip_protocol_full("11", /* relaxed= */ true), 11);
}

TEST(socket_protocol_from_string) {
        ASSERT_OK_EQ(socket_protocol_from_string(""), IPPROTO_IP);
        ASSERT_OK_EQ(socket_protocol_from_string("sctp"), IPPROTO_SCTP);
        ASSERT_OK_EQ(socket_protocol_from_string("udplite"), IPPROTO_UDPLITE);
        ASSERT_OK_EQ(socket_protocol_from_string("mptcp"), IPPROTO_MPTCP);
        ASSERT_OK_EQ(socket_protocol_from_string("mptcp-auto"), IPPROTO_MPTCP | SOCKET_PROTOCOL_AUTO);
        ASSERT_OK_EQ(socket_protocol_from_string("MPTCP-auto"), IPPROTO_MPTCP | SOCKET_PROTOCOL_AUTO);
        ASSERT_OK_EQ(socket_protocol_from_string("mptcp-AUTO"), IPPROTO_MPTCP | SOCKET_PROTOCOL_AUTO);
        ASSERT_ERROR(socket_protocol_from_string("262-auto"), EINVAL);
        ASSERT_ERROR(socket_protocol_from_string("sctp-auto"), EINVAL);
        ASSERT_ERROR(socket_protocol_from_string("tcp-auto"), EINVAL);
        ASSERT_ERROR(socket_protocol_from_string("-auto"), EINVAL);
        ASSERT_ERROR(socket_protocol_from_string("hoge"), EINVAL);
        ASSERT_ERROR(socket_protocol_from_string("mptcp-auto-auto"), EINVAL);
}

TEST(socket_protocol_to_string) {
        ASSERT_STREQ(socket_protocol_to_string(IPPROTO_IP), "ip");
        ASSERT_STREQ(socket_protocol_to_string(IPPROTO_SCTP), "sctp");
        ASSERT_STREQ(socket_protocol_to_string(IPPROTO_MPTCP), "mptcp");
        ASSERT_STREQ(socket_protocol_to_string(IPPROTO_MPTCP | SOCKET_PROTOCOL_AUTO), "mptcp-auto");
        ASSERT_NULL(socket_protocol_to_string(IPPROTO_SCTP | SOCKET_PROTOCOL_AUTO));
        ASSERT_NULL(socket_protocol_to_string(SOCKET_PROTOCOL_AUTO));
        ASSERT_NULL(socket_protocol_to_string(-1));

        FOREACH_STRING(s, "sctp", "udplite", "mptcp", "mptcp-auto")
                ASSERT_STREQ(socket_protocol_to_string(socket_protocol_from_string(s)), s);
}

DEFINE_TEST_MAIN(LOG_INFO);
