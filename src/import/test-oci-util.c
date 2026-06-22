/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "oci-util.h"

static void test_urlescape_one(const char *s, const char *expected) {
        _cleanup_free_ char *t = ASSERT_PTR(urlescape(s));

        ASSERT_STREQ(t, expected);
}

TEST(urlescape) {
        test_urlescape_one(NULL, "");
        test_urlescape_one("", "");
        test_urlescape_one("a", "a");
        test_urlescape_one(" ", "%20");
        test_urlescape_one("     ", "%20%20%20%20%20");
        test_urlescape_one("foo\tfoo\aqux", "foo%09foo%07qux");
        test_urlescape_one("müffel", "m%c3%bcffel");
}

TEST(oci_registry_is_valid) {
        /* plain hostname — valid */
        assert_se(oci_registry_is_valid("localhost") > 0);
        assert_se(oci_registry_is_valid("registry.example.com") > 0);

        /* host:port — valid */
        assert_se(oci_registry_is_valid("localhost:5000") > 0);
        assert_se(oci_registry_is_valid("registry.example.com:443") > 0);
        assert_se(oci_registry_is_valid("registry.io:1") > 0);
        assert_se(oci_registry_is_valid("registry.io:65535") > 0);

        /* port 0 — invalid */
        assert_se(oci_registry_is_valid("localhost:0") == 0);

        /* port overflow */
        assert_se(oci_registry_is_valid("localhost:65536") == 0);

        /* non-decimal port forms — rejected */
        assert_se(oci_registry_is_valid("localhost:0x50") == 0);   /* hex */
        assert_se(oci_registry_is_valid("localhost:017") == 0);    /* leading zero */
        assert_se(oci_registry_is_valid("localhost:+80") == 0);    /* plus sign */
        assert_se(oci_registry_is_valid("localhost: 80") == 0);    /* leading space */

        /* invalid hostname */
        assert_se(oci_registry_is_valid(":5000") <= 0);
        assert_se(oci_registry_is_valid("") <= 0);
        assert_se(oci_registry_is_valid(NULL) <= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
