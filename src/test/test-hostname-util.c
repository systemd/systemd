/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hostname-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(hostname_is_valid) {
        assert_se(hostname_is_valid("foobar", 0));
        assert_se(hostname_is_valid("foobar.com", 0));
        assert_se(!hostname_is_valid("foobar.com.", 0));
        assert_se(hostname_is_valid("fooBAR", 0));
        assert_se(hostname_is_valid("fooBAR.com", 0));
        assert_se(!hostname_is_valid("fooBAR.", 0));
        assert_se(!hostname_is_valid("fooBAR.com.", 0));
        assert_se(!hostname_is_valid("fööbar", 0));
        assert_se(!hostname_is_valid("", 0));
        assert_se(!hostname_is_valid(".", 0));
        assert_se(!hostname_is_valid("..", 0));
        assert_se(!hostname_is_valid("foobar.", 0));
        assert_se(!hostname_is_valid(".foobar", 0));
        assert_se(!hostname_is_valid("foo..bar", 0));
        assert_se(!hostname_is_valid("foo.bar..", 0));
        assert_se(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0));
        assert_se(!hostname_is_valid("au-xph5-rvgrdsb5hcxc-47et3a5vvkrc-server-wyoz4elpdpe3.openstack.local", 0));

        assert_se(hostname_is_valid("foobar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("foobar.com", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("foobar.com.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR.com", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("fooBAR.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(hostname_is_valid("fooBAR.com.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("fööbar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid(".", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("..", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foobar.", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid(".foobar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foo..bar", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("foo.bar..", VALID_HOSTNAME_TRAILING_DOT));
        assert_se(!hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", VALID_HOSTNAME_TRAILING_DOT));

        ASSERT_FALSE(hostname_is_valid("foo??bar", 0));
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
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe(".");
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe("..");
        assert_se(isempty(hostname_cleanup(s)));
        s = strdupa_safe("foobar.");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe(".foobar");
        ASSERT_STREQ(hostname_cleanup(s), "foobar");
        s = strdupa_safe("foo..bar");
        ASSERT_STREQ(hostname_cleanup(s), "foo.bar");
        s = strdupa_safe("foo.bar..");
        ASSERT_STREQ(hostname_cleanup(s), "foo.bar");
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

        ASSERT_OK_EQ(split_user_at_host(s, &u, NULL), ret);
        ASSERT_STREQ(u, expected_user);

        ASSERT_OK_EQ(split_user_at_host(s, NULL, &h), ret);
        ASSERT_STREQ(h, expected_host);
}

TEST(split_user_at_host) {
        ASSERT_ERROR(split_user_at_host("", NULL, NULL), EINVAL);

        test_split_user_at_host_one("@", NULL, NULL, 1);
        test_split_user_at_host_one("a", NULL, "a", 0);
        test_split_user_at_host_one("a@b", "a", "b", 1);
        test_split_user_at_host_one("@b", NULL, "b", 1);
        test_split_user_at_host_one("a@", "a", NULL, 1);
        test_split_user_at_host_one("aa@@@bb", "aa", "@@bb", 1);
}

TEST(machine_tag_is_valid) {
        assert_se(machine_tag_is_valid("foo"));
        assert_se(machine_tag_is_valid("foo-bar.baz"));
        assert_se(machine_tag_is_valid("Webserver01"));
        assert_se(machine_tag_is_valid("a"));
        assert_se(machine_tag_is_valid("a="));         /* empty value is OK */
        assert_se(machine_tag_is_valid("a=b"));
        assert_se(machine_tag_is_valid("foo.bar="));
        assert_se(machine_tag_is_valid("foo.bar-baz=zuziuziuz"));
        assert_se(machine_tag_is_valid("foo=bar.baz")); /* "." and "-" are fine inside a value */
        assert_se(machine_tag_is_valid("foo=bar-"));    /* even as the very last char of a value */
        assert_se(machine_tag_is_valid("foo=.bar"));    /* and as the very first char of a value */
        assert_se(machine_tag_is_valid("foo=bar="));    /* a value may itself contain a "=" */
        assert_se(machine_tag_is_valid("a=b=c"));       /* only the first "=" is the separator */

        assert_se(!machine_tag_is_valid(NULL));
        assert_se(!machine_tag_is_valid(""));
        assert_se(!machine_tag_is_valid("foo:bar"));   /* colon is the separator */
        assert_se(!machine_tag_is_valid("foo bar"));
        assert_se(!machine_tag_is_valid("fööbar"));    /* non-ASCII */
        assert_se(!machine_tag_is_valid("foo/bar"));
        assert_se(!machine_tag_is_valid("foo_bar"));
        assert_se(!machine_tag_is_valid("-foo"));
        assert_se(!machine_tag_is_valid("foo-"));
        assert_se(!machine_tag_is_valid(".foo"));
        assert_se(!machine_tag_is_valid("foo."));
        assert_se(!machine_tag_is_valid("=b"));
        assert_se(!machine_tag_is_valid("="));
        assert_se(!machine_tag_is_valid(".foo=asd"));  /* "." not allowed as first char */
        assert_se(!machine_tag_is_valid("foo.=asd"));  /* "." not allowed as last char of key */
        assert_se(!machine_tag_is_valid("foo-=asd"));  /* "-" not allowed as last char of key */
        assert_se(!machine_tag_is_valid("_foo=asd"));  /* "_" is not in the charset */
        assert_se(!machine_tag_is_valid("foo_=sda"));
        assert_se(!machine_tag_is_valid("foo=a_b"));   /* ... not even in the value */
        assert_se(!machine_tag_is_valid("foo=a:b"));   /* colon is the separator, not allowed in a value */

        /* Length boundary: 255 characters is fine, 256 is too long */
        _cleanup_free_ char *max = strrep("a", 255), *over = strrep("a", 256);
        assert_se(max);
        assert_se(over);
        assert_se(machine_tag_is_valid(max));
        assert_se(!machine_tag_is_valid(over));
}

TEST(machine_tag_list_is_valid) {
        assert_se(machine_tag_list_is_valid(NULL));    /* empty list is valid */
        assert_se(machine_tag_list_is_valid(STRV_MAKE("a")));
        assert_se(machine_tag_list_is_valid(STRV_MAKE("foo", "bar", "c-d.e")));
        assert_se(machine_tag_list_is_valid(STRV_MAKE("foo=uuu", "bar=qqqq", "c-d.e")));
        assert_se(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=aa")));     /* same key + same value is OK */
        assert_se(machine_tag_list_is_valid(STRV_MAKE("foo", "foo=aa")));        /* bare key and assignment coexist */
        assert_se(machine_tag_list_is_valid(STRV_MAKE("foo=1", "foobar=2")));    /* one key is a prefix of the other */
        assert_se(machine_tag_list_is_valid(STRV_MAKE("ab=1", "a=2")));          /* ... and the other way around */

        assert_se(!machine_tag_list_is_valid(STRV_MAKE("foo", "b:c")));
        assert_se(!machine_tag_list_is_valid(STRV_MAKE("foo", "")));
        assert_se(!machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=b")));     /* same key, different value */
        assert_se(!machine_tag_list_is_valid(STRV_MAKE("a=1", "b=2", "a=3")));   /* ... also when not adjacent */
        assert_se(!machine_tag_list_is_valid(STRV_MAKE("foo=aa", "bar", "foo=aa", "foo=b")));
        assert_se(!machine_tag_list_is_valid(STRV_MAKE("=aa")));
}

TEST(machine_tags_from_string) {
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(machine_tags_from_string(NULL, /* graceful= */ false, &l));
        assert_se(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("", /* graceful= */ true, &l));
        assert_se(strv_isempty(l));
        l = strv_free(l);

        /* Sorted and deduplicated */
        ASSERT_OK(machine_tags_from_string("foo:bar:foo:baz", /* graceful= */ false, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "baz", "foo")));
        l = strv_free(l);

        /* Graceful: invalid tags are dropped, valid ones kept (sorted/deduplicated) */
        ASSERT_OK(machine_tags_from_string("foo:in valid:bar:foo", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "foo")));
        l = strv_free(l);

        /* Graceful: all tags invalid → empty list */
        ASSERT_OK(machine_tags_from_string("in valid:also invalid", /* graceful= */ true, &l));
        assert_se(strv_isempty(l));
        l = strv_free(l);

        /* Fatal: a single invalid tag fails the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo:in valid:bar", /* graceful= */ false, &l), EINVAL);
        assert_se(!l);

        /* With assignment */
        ASSERT_OK(machine_tags_from_string("foo=aa:bar=aaa:foo2=x:baz", /* graceful= */ false, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar=aaa", "baz", "foo2=x", "foo=aa")));
        l = strv_free(l);

        /* Graceful: a duplicate key is suppressed, keeping the first (i.e. lexicographically smallest) value */
        ASSERT_OK(machine_tags_from_string("foo=zzz:foo=aaa:foo=mmm", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo=aaa")));
        l = strv_free(l);

        /* Graceful: a bare key and an assignment for the same name are not considered duplicates */
        ASSERT_OK(machine_tags_from_string("foo:foo=aaa", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo", "foo=aaa")));
        l = strv_free(l);

        /* Graceful: an invalid value is dropped, conflicting keys that remain are deduplicated */
        ASSERT_OK(machine_tags_from_string("foo=a_b:foo=good:foo=zzz", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo=good")));
        l = strv_free(l);

        /* Fatal: conflicting values for the same key fail the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo=a:foo=b", /* graceful= */ false, &l), EINVAL);
        assert_se(!l);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
