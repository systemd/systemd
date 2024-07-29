/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ip-protocol-list.h"
#include "macro.h"
#include "missing_network.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"

static void test_int(int i) {
        char str[DECIMAL_STR_MAX(int)];

        assert_se(ip_protocol_from_name(ip_protocol_to_name(i)) == i);

        xsprintf(str, "%i", i);
        assert_se(ip_protocol_from_name(ip_protocol_to_name(parse_ip_protocol(str))) == i);
}

static void test_int_fail(int i, int error) {
        char str[DECIMAL_STR_MAX(int)];

        assert_se(!ip_protocol_to_name(i));

        xsprintf(str, "%i", i);
        assert_se(parse_ip_protocol(str) == error);
}

static void test_str(const char *s) {
        ASSERT_STREQ(ip_protocol_to_name(ip_protocol_from_name(s)), s);
        ASSERT_STREQ(ip_protocol_to_name(parse_ip_protocol(s)), s);
}

static void test_str_fail(const char *s, int error) {
        assert_se(ip_protocol_from_name(s) == -EINVAL);
        assert_se(parse_ip_protocol(s) == error);
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
        assert_se(parse_ip_protocol("sctp") == IPPROTO_SCTP);
        assert_se(parse_ip_protocol("ScTp") == IPPROTO_SCTP);
        assert_se(parse_ip_protocol("mptcp") == IPPROTO_MPTCP);
        assert_se(parse_ip_protocol("MPTCP") == IPPROTO_MPTCP);
        assert_se(parse_ip_protocol("ip") == IPPROTO_IP);
        assert_se(parse_ip_protocol("") == IPPROTO_IP);
        assert_se(parse_ip_protocol("1") == 1);
        assert_se(parse_ip_protocol("0") == 0);
        assert_se(parse_ip_protocol("-10") == -ERANGE);
        assert_se(parse_ip_protocol("100000000") == -EPROTONOSUPPORT);
}

TEST(parse_ip_protocol_full) {
        assert_se(parse_ip_protocol_full("-1", true) == -ERANGE);
        assert_se(parse_ip_protocol_full("0", true) == 0);
        assert_se(parse_ip_protocol_full("11", true) == 11);
}

DEFINE_TEST_MAIN(LOG_INFO);
