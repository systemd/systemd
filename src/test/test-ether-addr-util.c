/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ether-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(ether_addr_helpers) {
        struct ether_addr a;

        a = ETHER_ADDR_NULL;
        assert_se(ether_addr_is_null(&a));
        assert_se(!ether_addr_is_broadcast(&a));
        assert_se(!ether_addr_is_multicast(&a));
        assert_se(ether_addr_is_unicast(&a));
        assert_se(!ether_addr_is_local(&a));
        assert_se(ether_addr_is_global(&a));

        memset(a.ether_addr_octet, 0xff, sizeof(a));
        assert_se(!ether_addr_is_null(&a));
        assert_se(ether_addr_is_broadcast(&a));
        assert_se(ether_addr_is_multicast(&a));
        assert_se(!ether_addr_is_unicast(&a));
        assert_se(ether_addr_is_local(&a));
        assert_se(!ether_addr_is_global(&a));

        a = (struct ether_addr) { { 0x01, 0x23, 0x34, 0x56, 0x78, 0x9a } };
        assert_se(!ether_addr_is_null(&a));
        assert_se(!ether_addr_is_broadcast(&a));
        assert_se(ether_addr_is_multicast(&a));
        assert_se(!ether_addr_is_unicast(&a));
        assert_se(!ether_addr_is_local(&a));
        assert_se(ether_addr_is_global(&a));
}

#define INFINIBAD_ADDR_1 ((const struct hw_addr_data){ .length = 20, .infiniband = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20} })

TEST(HW_ADDR_TO_STRING) {
        const char *s = HW_ADDR_TO_STR(&(const struct hw_addr_data){6});
        log_info("null: %s", s);

        log_info("null×2: %s, %s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}),
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}));
        log_info("null×3: %s, %s, %s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}),
                 s,
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){6}));

        log_info("infiniband: %s", HW_ADDR_TO_STR(&INFINIBAD_ADDR_1));

        /* Let's nest function calls in a stupid way. */
        _cleanup_free_ char *t = NULL;
        log_info("infiniband×3: %s\n%14s%s\n%14s%s",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){20}), "",
                 t = strdup(HW_ADDR_TO_STR(&INFINIBAD_ADDR_1)), "",
                 HW_ADDR_TO_STR(&(const struct hw_addr_data){20}));

        const char *p;
        /* Let's use a separate selection statement */
        if ((p = HW_ADDR_TO_STR(&(const struct hw_addr_data){6})))
                log_info("joint: %s, %s", s, p);
}

static void test_parse_hw_addr_full_one(const char *in, size_t expected_len, const char *expected) {
        struct hw_addr_data h;
        int r;

        r = parse_hw_addr_full(in, expected_len, &h);
        log_debug_errno(r, "parse_hw_addr(\"%s\", len=%zu) → \"%s\" (expected: \"%s\") : %d/%m",
                        in, expected_len, r >= 0 ? HW_ADDR_TO_STR(&h) : "n/a", strna(expected), r);
        assert_se((r >= 0) == !!expected);
        if (r >= 0) {
                if (!IN_SET(expected_len, 0, SIZE_MAX))
                        assert_se(h.length == expected_len);
                ASSERT_STREQ(HW_ADDR_TO_STR(&h), expected);
        }
}

TEST(parse_hw_addr) {
        /* IPv4 */
        test_parse_hw_addr_full_one("10.0.0.1", 0, "0a:00:00:01");
        test_parse_hw_addr_full_one("10.0.0.1", 4, "0a:00:00:01");
        test_parse_hw_addr_full_one("192.168.0.1", 0, "c0:a8:00:01");
        test_parse_hw_addr_full_one("192.168.0.1", 4, "c0:a8:00:01");
        /* IPv6 */
        test_parse_hw_addr_full_one("::", 0, "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        test_parse_hw_addr_full_one("::", 16, "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        test_parse_hw_addr_full_one("::1", 0, "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01");
        test_parse_hw_addr_full_one("::1", 16, "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01");
        test_parse_hw_addr_full_one("1234::", 0, "12:34:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        test_parse_hw_addr_full_one("1234::", 16, "12:34:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        test_parse_hw_addr_full_one("12:34::56", 0, "00:12:00:34:00:00:00:00:00:00:00:00:00:00:00:56");
        test_parse_hw_addr_full_one("12:34::56", 16, "00:12:00:34:00:00:00:00:00:00:00:00:00:00:00:56");
        test_parse_hw_addr_full_one("12aa:34::56", 0, "12:aa:00:34:00:00:00:00:00:00:00:00:00:00:00:56");
        test_parse_hw_addr_full_one("12aa:34::56", 16, "12:aa:00:34:00:00:00:00:00:00:00:00:00:00:00:56");
        test_parse_hw_addr_full_one("1234:5678:90ab:cdef:1234:5678:90ab:cdef", 0, "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("1234:5678:90ab:cdef:1234:5678:90ab:cdef", 16, "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef");
        /* Dot */
        test_parse_hw_addr_full_one("12.34", 0, "00:12:00:34");
        test_parse_hw_addr_full_one("12.34", 4, "00:12:00:34");
        test_parse_hw_addr_full_one("12.34", SIZE_MAX, "00:12:00:34");
        test_parse_hw_addr_full_one("12.34.56", 0, "00:12:00:34:00:56");
        test_parse_hw_addr_full_one("12.34.56", 6, "00:12:00:34:00:56");
        test_parse_hw_addr_full_one("12.34.56", SIZE_MAX, "00:12:00:34:00:56");
        test_parse_hw_addr_full_one("12.34.56.78", 0, "0c:22:38:4e"); /* IPv4 address */
        test_parse_hw_addr_full_one("12.34.56.78", 4, "0c:22:38:4e"); /* IPv4 address */
        test_parse_hw_addr_full_one("12.34.56.78", 8, "00:12:00:34:00:56:00:78");
        test_parse_hw_addr_full_one("12.34.56.78", SIZE_MAX, "00:12:00:34:00:56:00:78");
        test_parse_hw_addr_full_one("12.34.56.78.90", 0, NULL);
        test_parse_hw_addr_full_one("12.34.56.78.90", 10, "00:12:00:34:00:56:00:78:00:90");
        test_parse_hw_addr_full_one("12.34.56.78.90", SIZE_MAX, "00:12:00:34:00:56:00:78:00:90");
        test_parse_hw_addr_full_one("aabb.ccdd", 0, "aa:bb:cc:dd");
        test_parse_hw_addr_full_one("aabb.ccdd", 4, "aa:bb:cc:dd");
        test_parse_hw_addr_full_one("aabb.ccdd", SIZE_MAX, "aa:bb:cc:dd");
        test_parse_hw_addr_full_one("aabb.ccdd.eeff", 0, "aa:bb:cc:dd:ee:ff");
        test_parse_hw_addr_full_one("aabb.ccdd.eeff", 6, "aa:bb:cc:dd:ee:ff");
        test_parse_hw_addr_full_one("aabb.ccdd.eeff", SIZE_MAX, "aa:bb:cc:dd:ee:ff");
        /* Colon */
        test_parse_hw_addr_full_one("12:34", 0, NULL);
        test_parse_hw_addr_full_one("12:34", 2, "12:34");
        test_parse_hw_addr_full_one("12:34", SIZE_MAX, "12:34");
        test_parse_hw_addr_full_one("12:34:56:78:90:ab", 0, "12:34:56:78:90:ab");
        test_parse_hw_addr_full_one("12:34:56:78:90:ab", 6, "12:34:56:78:90:ab");
        test_parse_hw_addr_full_one("12:34:56:78:90:ab", SIZE_MAX, "12:34:56:78:90:ab");
        test_parse_hw_addr_full_one("12:34:56:78:90:ab:cd:ef", 0, "00:12:00:34:00:56:00:78:00:90:00:ab:00:cd:00:ef"); /* IPv6 */
        test_parse_hw_addr_full_one("12:34:56:78:90:ab:cd:ef", 8, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12:34:56:78:90:ab:cd:ef", 16, "00:12:00:34:00:56:00:78:00:90:00:ab:00:cd:00:ef"); /* IPv6 */
        test_parse_hw_addr_full_one("12:34:56:78:90:ab:cd:ef", SIZE_MAX, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12:34:56:78:90:AB:CD:EF", 0, "00:12:00:34:00:56:00:78:00:90:00:ab:00:cd:00:ef"); /* IPv6 */
        test_parse_hw_addr_full_one("12:34:56:78:90:AB:CD:EF", 8, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12:34:56:78:90:AB:CD:EF", 16, "00:12:00:34:00:56:00:78:00:90:00:ab:00:cd:00:ef"); /* IPv6 */
        test_parse_hw_addr_full_one("12:34:56:78:90:AB:CD:EF", SIZE_MAX, "12:34:56:78:90:ab:cd:ef");
        /* Hyphen */
        test_parse_hw_addr_full_one("12-34", 0, NULL);
        test_parse_hw_addr_full_one("12-34", 2, "12:34");
        test_parse_hw_addr_full_one("12-34", SIZE_MAX, "12:34");
        test_parse_hw_addr_full_one("12-34-56-78-90-ab-cd-ef", 0, NULL);
        test_parse_hw_addr_full_one("12-34-56-78-90-ab-cd-ef", 8, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12-34-56-78-90-ab-cd-ef", SIZE_MAX, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12-34-56-78-90-AB-CD-EF", 0, NULL);
        test_parse_hw_addr_full_one("12-34-56-78-90-AB-CD-EF", 8, "12:34:56:78:90:ab:cd:ef");
        test_parse_hw_addr_full_one("12-34-56-78-90-AB-CD-EF", SIZE_MAX, "12:34:56:78:90:ab:cd:ef");

        /* Invalid */
        test_parse_hw_addr_full_one("", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("12", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("12.", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("12.34.", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one(".12", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one(".12.34", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("12.34:56", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("1234:56", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("1234:56", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("12:34:", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one(":12:34", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("::1", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("aa:bb-cc", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("aa:xx", SIZE_MAX, NULL);
        test_parse_hw_addr_full_one("aa bb", SIZE_MAX, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
