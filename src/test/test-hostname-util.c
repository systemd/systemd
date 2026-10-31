/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hostname-util.h"
#include "string-util.h"
#include "tests.h"

TEST(hostname_is_valid) {
        ASSERT_TRUE(hostname_is_valid("foobar", /* flags= */ 0));
        ASSERT_TRUE(hostname_is_valid("foobar.com", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("foobar.com.", /* flags= */ 0));
        ASSERT_TRUE(hostname_is_valid("fooBAR", /* flags= */ 0));
        ASSERT_TRUE(hostname_is_valid("fooBAR.com", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("fooBAR.", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("fooBAR.com.", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("fööbar", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid(".", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("..", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("foobar.", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid(".foobar", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("foo..bar", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("foo.bar..", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", /* flags= */ 0));
        ASSERT_FALSE(hostname_is_valid("au-xph5-rvgrdsb5hcxc-47et3a5vvkrc-server-wyoz4elpdpe3.openstack.local", /* flags= */ 0));

        ASSERT_TRUE(hostname_is_valid("foobar", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_TRUE(hostname_is_valid("foobar.com", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_TRUE(hostname_is_valid("foobar.com.", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_TRUE(hostname_is_valid("fooBAR", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_TRUE(hostname_is_valid("fooBAR.com", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("fooBAR.", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_TRUE(hostname_is_valid("fooBAR.com.", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("fööbar", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid(".", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("..", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("foobar.", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid(".foobar", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("foo..bar", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("foo.bar..", VALID_HOSTNAME_TRAILING_DOT));
        ASSERT_FALSE(hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", VALID_HOSTNAME_TRAILING_DOT));

        ASSERT_FALSE(hostname_is_valid("foo??bar", /* flags= */ 0));
        ASSERT_TRUE(hostname_is_valid("foo??bar", VALID_HOSTNAME_QUESTION_MARK));
}

TEST(hostname_cleanup) {
        char *s;

        s = strdupa_safe("foobar");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foobar.com");
        ASSERT_STREQ(hostname_cleanup(s), "foobar.com");
        s = strdupa_safe("foobar.com.");
        ASSERT_STREQ(hostname_cleanup(s), "foobar.com");
        s = strdupa_safe("foo-bar.-com-.");
        ASSERT_STREQ(hostname_cleanup(s), "foo-bar.com");
        s = strdupa_safe("foo-bar-.-com-.");
        ASSERT_STREQ(hostname_cleanup(s), "foo-bar--com");
        s = strdupa_safe("--foo-bar.-com");
        ASSERT_STREQ(hostname_cleanup(s), "foo-bar.com");
        s = strdupa_safe("fooBAR");
        ASSERT_STREQ(hostname_cleanup(s), "fooBAR");
        s = strdupa_safe("fooBAR.com");
        ASSERT_STREQ(hostname_cleanup(s), "fooBAR.com");
        s = strdupa_safe("fooBAR.");
        ASSERT_STREQ(hostname_cleanup(s), "fooBAR");
        s = strdupa_safe("fooBAR.com.");
        ASSERT_STREQ(hostname_cleanup(s), "fooBAR.com");
        s = strdupa_safe("fööbar");
        ASSERT_STREQ(hostname_cleanup(s), "fbar");
        s = strdupa_safe("");
        ASSERT_STREQ(hostname_cleanup(s), "");
        s = strdupa_safe(".");
        ASSERT_STREQ(hostname_cleanup(s), "");
        s = strdupa_safe("..");
        ASSERT_STREQ(hostname_cleanup(s), "");
        s = strdupa_safe("foobar.");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe(".foobar");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foo..bar");
        ASSERT_STREQ(hostname_cleanup(s), "foo.bar");
        s = strdupa_safe("foo.bar..");
        ASSERT_STREQ(hostname_cleanup(s), "foo.bar");
        s = strdupa_safe("foobar--");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foobar-.");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foobar.-");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foobar-.-");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        ASSERT_STREQ(hostname_cleanup(s), "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        s = strdupa_safe("xxxx........xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        ASSERT_STREQ(hostname_cleanup(s), "xxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

static void test_split_user_at_host_one(const char *s, const char *expected_user, const char *expected_host, int ret) {
        _cleanup_free_ char *u = NULL, *h = NULL;

        ASSERT_OK_EQ(split_user_at_host(s, &u, &h), ret);
        ASSERT_STREQ(u, expected_user);
        ASSERT_STREQ(h, expected_host);

        u = mfree(u);
        h = mfree(h);

        ASSERT_OK_EQ(split_user_at_host(s, &u, /* ret_host= */ NULL), ret);
        ASSERT_STREQ(u, expected_user);

        ASSERT_OK_EQ(split_user_at_host(s, /* ret_user= */ NULL, &h), ret);
        ASSERT_STREQ(h, expected_host);
}

TEST(split_user_at_host) {
        ASSERT_ERROR(split_user_at_host("", /* ret_user= */ NULL, /* ret_host= */ NULL), EINVAL);

        test_split_user_at_host_one("@", /* expected_user= */ NULL, /* expected_host= */ NULL, 1);
        test_split_user_at_host_one("a", /* expected_user= */ NULL, "a", /* ret= */ 0);
        test_split_user_at_host_one("a@b", "a", "b", 1);
        test_split_user_at_host_one("@b", /* expected_user= */ NULL, "b", 1);
        test_split_user_at_host_one("a@", "a", /* expected_host= */ NULL, 1);
        test_split_user_at_host_one("aa@@@bb", "aa", "@@bb", 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
