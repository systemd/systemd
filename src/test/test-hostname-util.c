/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hostname-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(hostname_is_valid) {
        ASSERT_TRUE(hostname_is_valid("foobar", 0));
        ASSERT_TRUE(hostname_is_valid("foobar.com", 0));
        ASSERT_FALSE(hostname_is_valid("foobar.com.", 0));
        ASSERT_TRUE(hostname_is_valid("fooBAR", 0));
        ASSERT_TRUE(hostname_is_valid("fooBAR.com", 0));
        ASSERT_FALSE(hostname_is_valid("fooBAR.", 0));
        ASSERT_FALSE(hostname_is_valid("fooBAR.com.", 0));
        ASSERT_FALSE(hostname_is_valid("fööbar", 0));
        ASSERT_FALSE(hostname_is_valid("", 0));
        ASSERT_FALSE(hostname_is_valid(".", 0));
        ASSERT_FALSE(hostname_is_valid("..", 0));
        ASSERT_FALSE(hostname_is_valid("foobar.", 0));
        ASSERT_FALSE(hostname_is_valid(".foobar", 0));
        ASSERT_FALSE(hostname_is_valid("foo..bar", 0));
        ASSERT_FALSE(hostname_is_valid("foo.bar..", 0));
        ASSERT_FALSE(hostname_is_valid("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0));
        ASSERT_FALSE(hostname_is_valid("au-xph5-rvgrdsb5hcxc-47et3a5vvkrc-server-wyoz4elpdpe3.openstack.local", 0));

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
        ASSERT_TRUE(machine_tag_is_valid("foo"));
        ASSERT_TRUE(machine_tag_is_valid("foo-bar.baz"));
        ASSERT_TRUE(machine_tag_is_valid("Webserver01"));
        ASSERT_TRUE(machine_tag_is_valid("a"));
        ASSERT_TRUE(machine_tag_is_valid("a="));         /* empty value is OK */
        ASSERT_TRUE(machine_tag_is_valid("a=b"));
        ASSERT_TRUE(machine_tag_is_valid("foo.bar="));
        ASSERT_TRUE(machine_tag_is_valid("foo.bar-baz=zuziuziuz"));
        ASSERT_TRUE(machine_tag_is_valid("foo=bar.baz")); /* "." and "-" are fine inside a value */
        ASSERT_TRUE(machine_tag_is_valid("foo=bar-"));    /* even as the very last char of a value */
        ASSERT_TRUE(machine_tag_is_valid("foo=.bar"));    /* and as the very first char of a value */
        ASSERT_TRUE(machine_tag_is_valid("foo=bar="));    /* a value may itself contain a "=" */
        ASSERT_TRUE(machine_tag_is_valid("a=b=c"));       /* only the first "=" is the separator */

        ASSERT_FALSE(machine_tag_is_valid(NULL));
        ASSERT_FALSE(machine_tag_is_valid(""));
        ASSERT_FALSE(machine_tag_is_valid("foo:bar"));   /* colon is the separator */
        ASSERT_FALSE(machine_tag_is_valid("foo bar"));
        ASSERT_FALSE(machine_tag_is_valid("fööbar"));    /* non-ASCII */
        ASSERT_FALSE(machine_tag_is_valid("foo/bar"));
        ASSERT_FALSE(machine_tag_is_valid("foo_bar"));
        ASSERT_FALSE(machine_tag_is_valid("-foo"));
        ASSERT_FALSE(machine_tag_is_valid("foo-"));
        ASSERT_FALSE(machine_tag_is_valid(".foo"));
        ASSERT_FALSE(machine_tag_is_valid("foo."));
        ASSERT_FALSE(machine_tag_is_valid("=b"));
        ASSERT_FALSE(machine_tag_is_valid("="));
        ASSERT_FALSE(machine_tag_is_valid(".foo=asd"));  /* "." not allowed as first char */
        ASSERT_FALSE(machine_tag_is_valid("foo.=asd"));  /* "." not allowed as last char of key */
        ASSERT_FALSE(machine_tag_is_valid("foo-=asd"));  /* "-" not allowed as last char of key */
        ASSERT_FALSE(machine_tag_is_valid("_foo=asd"));  /* "_" is not in the charset */
        ASSERT_FALSE(machine_tag_is_valid("foo_=sda"));
        ASSERT_FALSE(machine_tag_is_valid("foo=a_b"));   /* ... not even in the value */
        ASSERT_FALSE(machine_tag_is_valid("foo=a:b"));   /* colon is the separator, not allowed in a value */

        /* Length boundary: 255 characters is fine, 256 is too long */
        _cleanup_free_ char *max = strrep("a", 255), *over = strrep("a", 256);
        ASSERT_NOT_NULL(max);
        ASSERT_NOT_NULL(over);
        ASSERT_TRUE(machine_tag_is_valid(max));
        ASSERT_FALSE(machine_tag_is_valid(over));
}

TEST(machine_tag_list_is_valid) {
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(NULL));    /* empty list is valid */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("a")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo", "bar", "c-d.e")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo=uuu", "bar=qqqq", "c-d.e")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo", "foo=aa")));        /* bare key and assignment coexist */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo=1", "foobar=2")));    /* one key is a prefix of the other */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("ab=1", "a=2")));          /* ... and the other way around */

        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=aa")));     /* same key + same value is OK */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo", "b:c")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo", "")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=b")));          /* same key, different value */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("a=1", "b=2", "a=3")));        /* ... also when not adjacent */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "bar", "foo=aa", "foo=b")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("=aa")));
}

TEST(machine_tag_prefix_is_valid) {
        ASSERT_TRUE(machine_tag_prefix_is_valid("a"));
        ASSERT_TRUE(machine_tag_prefix_is_valid("acp"));
        ASSERT_TRUE(machine_tag_prefix_is_valid("acp."));    /* unlike for tags, "." and "-" are OK at the end */
        ASSERT_TRUE(machine_tag_prefix_is_valid("acp-"));
        ASSERT_TRUE(machine_tag_prefix_is_valid("foo="));
        ASSERT_TRUE(machine_tag_prefix_is_valid("foo.=")); /* not a valid prefix of any valid tag, but harmless */
        ASSERT_TRUE(machine_tag_prefix_is_valid("foo=bar"));

        ASSERT_FALSE(machine_tag_prefix_is_valid(NULL));
        ASSERT_FALSE(machine_tag_prefix_is_valid(""));
        ASSERT_FALSE(machine_tag_prefix_is_valid(".acp"));
        ASSERT_FALSE(machine_tag_prefix_is_valid("-acp"));
        ASSERT_FALSE(machine_tag_prefix_is_valid("=acp"));
        ASSERT_FALSE(machine_tag_prefix_is_valid("acp*"));
        ASSERT_FALSE(machine_tag_prefix_is_valid("a cp"));
        ASSERT_FALSE(machine_tag_prefix_is_valid("a:b"));

        _cleanup_free_ char *max = strrep("a", 255), *over = strrep("a", 256);
        ASSERT_NOT_NULL(max);
        ASSERT_NOT_NULL(over);
        ASSERT_TRUE(machine_tag_prefix_is_valid(max));
        ASSERT_FALSE(machine_tag_prefix_is_valid(over));

        ASSERT_TRUE(machine_tag_prefix_list_is_valid(NULL));
        ASSERT_TRUE(machine_tag_prefix_list_is_valid(STRV_MAKE("acp.", "foo=")));
        ASSERT_FALSE(machine_tag_prefix_list_is_valid(STRV_MAKE("acp.", "")));
}

TEST(machine_tags_from_string) {
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(machine_tags_from_string(NULL, /* graceful= */ false, &l));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        /* Sorted and deduplicated */
        ASSERT_OK(machine_tags_from_string("foo:bar:foo:baz", /* graceful= */ false, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("bar", "baz", "foo")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo:bar:baz", /* graceful= */ false, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "baz", "foo")));
        l = strv_free(l);

        /* Graceful: invalid tags are dropped, valid ones kept (sorted/deduplicated) */
        ASSERT_OK(machine_tags_from_string("foo:in valid:bar:foo", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("bar", "foo")));
        l = strv_free(l);

        /* Graceful: all tags invalid → empty list */
        ASSERT_OK(machine_tags_from_string("in valid:also invalid", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_isempty(l));
        l = strv_free(l);

        /* Fatal: a single invalid tag fails the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo:in valid:bar", /* graceful= */ false, &l), EINVAL);
        ASSERT_NULL(l);

        /* With assignment */
        ASSERT_OK(machine_tags_from_string("foo=aa:bar=aaa:foo2=x:baz", /* graceful= */ false, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("bar=aaa", "baz", "foo2=x", "foo=aa")));
        l = strv_free(l);

        /* Graceful: duplicate keys are suppressed, keeping the value specified last */
        ASSERT_OK(machine_tags_from_string("foo=zzz:foo=aaa:foo=mmm", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("foo=mmm")));
        l = strv_free(l);

        /* Graceful: deduplication follows the order in which the tags were specified, sorting happens afterwards */
        ASSERT_OK(machine_tags_from_string("b=1:a=2:b=3:a=4:c", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("a=4", "b=3", "c")));
        l = strv_free(l);

        /* Graceful: a bare key and an assignment for the same name are not considered duplicates */
        ASSERT_OK(machine_tags_from_string("foo:foo=aaa", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("foo", "foo=aaa")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo:foo=aaa", /* graceful= */ false, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("foo", "foo=aaa")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo=x:foo:foo=y", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("foo", "foo=y")));
        l = strv_free(l);

        /* Graceful: an invalid value is dropped, conflicting keys that remain are deduplicated */
        ASSERT_OK(machine_tags_from_string("foo=a_b:foo=good:foo=zzz", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("foo=zzz")));
        l = strv_free(l);

        /* Fatal: conflicting values for the same key fail the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo=a:foo=b", /* graceful= */ false, &l), EINVAL);
        ASSERT_NULL(l);

        /* Fatal: ... and so does repeating the very same assignment */
        ASSERT_OK(machine_tags_from_string("foo=a:bar:foo=a", /* graceful= */ false, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("bar", "foo=a")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo=a:bar:foo=a", /* graceful= */ true, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("bar", "foo=a")));
        l = strv_free(l);

        /* At most MACHINE_TAGS_MAX valid tags are accepted, in both modes, repeated keys included */
        _cleanup_free_ char *many = NULL;
        for (size_t i = 0; i <= MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strextendf_with_separator(&many, ":", "t%zu", i));
        ASSERT_ERROR(machine_tags_from_string(many, /* graceful= */ false, &l), E2BIG);
        ASSERT_ERROR(machine_tags_from_string(many, /* graceful= */ true, &l), E2BIG);
        ASSERT_NULL(l);

        many = mfree(many);
        for (size_t i = 0; i < MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strextendf_with_separator(&many, ":", "k%zu=1", i));
        ASSERT_OK(machine_tags_from_string(many, /* graceful= */ false, &l));
        ASSERT_EQ(strv_length(l), MACHINE_TAGS_MAX);
        l = strv_free(l);

        ASSERT_OK(strextendf_with_separator(&many, ":", "k%u=1", MACHINE_TAGS_MAX));
        ASSERT_ERROR(machine_tags_from_string(many, /* graceful= */ false, &l), E2BIG);
        ASSERT_NULL(l);
}

static void test_machine_tags_edit_one(
                char **base,
                char **remove_prefix,
                char **add,
                char **remove,
                char **expected) {

        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(machine_tags_edit(base, remove_prefix, add, remove, &l));
        ASSERT_TRUE(strv_equal(l, expected));
}

TEST(machine_tags_edit) {
        test_machine_tags_edit_one(NULL, NULL, NULL, NULL, NULL);
        test_machine_tags_edit_one(STRV_MAKE("foo", "bar"), NULL, NULL, NULL, STRV_MAKE("bar", "foo"));
        test_machine_tags_edit_one(STRV_MAKE("foo"), NULL, STRV_MAKE("bar", "foo"), NULL, STRV_MAKE("bar", "foo"));
        test_machine_tags_edit_one(STRV_MAKE("foo", "bar"), NULL, NULL, STRV_MAKE("foo", "nonexistent"), STRV_MAKE("bar"));
        test_machine_tags_edit_one(STRV_MAKE("foo", "bar"), NULL, NULL, STRV_MAKE("foo", "bar"), NULL);

        /* Removal wins over addition */
        test_machine_tags_edit_one(NULL, NULL, STRV_MAKE("foo", "bar"), STRV_MAKE("foo"), STRV_MAKE("bar"));

        /* An added assignment replaces an existing assignment of the same key, but leaves a bare tag of the
         * same name and assignments of other keys alone */
        test_machine_tags_edit_one(STRV_MAKE("foo=a", "foo", "foobar=x", "bar=b"), NULL, STRV_MAKE("foo=b"), NULL,
                                   STRV_MAKE("bar=b", "foo", "foo=b", "foobar=x"));
        test_machine_tags_edit_one(STRV_MAKE("foo=a"), NULL, STRV_MAKE("foo=a"), NULL, STRV_MAKE("foo=a"));
        test_machine_tags_edit_one(STRV_MAKE("foo=a"), NULL, STRV_MAKE("foo="), NULL, STRV_MAKE("foo="));

        /* Adding a bare tag does not drop an assignment of the same name */
        test_machine_tags_edit_one(STRV_MAKE("foo=a"), NULL, STRV_MAKE("foo"), NULL, STRV_MAKE("foo", "foo=a"));

        /* Removal needs an exact match, a bare tag does not remove an assignment */
        test_machine_tags_edit_one(STRV_MAKE("foo=a"), NULL, NULL, STRV_MAKE("foo", "foo=b"), STRV_MAKE("foo=a"));
        test_machine_tags_edit_one(STRV_MAKE("foo=a"), NULL, STRV_MAKE("foo=b"), STRV_MAKE("foo=b"), NULL);

        /* Prefix removal */
        test_machine_tags_edit_one(STRV_MAKE("acp.x", "acp.bar=old", "acpfoo", "other"), STRV_MAKE("acp."), NULL, NULL,
                                   STRV_MAKE("acpfoo", "other"));
        test_machine_tags_edit_one(STRV_MAKE("a.1", "b.2", "c.3"), STRV_MAKE("a.", "c."), NULL, NULL, STRV_MAKE("b.2"));
        test_machine_tags_edit_one(STRV_MAKE("foo"), STRV_MAKE("nomatch"), NULL, NULL, STRV_MAKE("foo"));
        test_machine_tags_edit_one(STRV_MAKE("foo"), STRV_MAKE("foo"), NULL, NULL, NULL); /* a full match is a prefix too */
        test_machine_tags_edit_one(STRV_MAKE("foo=a", "foo", "foobar=b"), STRV_MAKE("foo="), NULL, NULL,
                                   STRV_MAKE("foo", "foobar=b"));

        /* Prefix removal is applied before additions, so that a set of tags with a common prefix can be
         * replaced atomically */
        test_machine_tags_edit_one(STRV_MAKE("acp.x", "acp.bar=old", "other"), STRV_MAKE("acp."),
                                   STRV_MAKE("acp.foo", "acp.bar=waldo"), NULL,
                                   STRV_MAKE("acp.bar=waldo", "acp.foo", "other"));
        /* ... while explicit removal is applied after them */
        test_machine_tags_edit_one(STRV_MAKE("acp.x"), STRV_MAKE("acp."), STRV_MAKE("acp.foo", "acp.bar"), STRV_MAKE("acp.bar"),
                                   STRV_MAKE("acp.foo"));

        /* Too many tags */
        _cleanup_strv_free_ char **many = NULL;
        size_t n_many = 0;
        for (unsigned i = 0; i <= MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strv_extendf_with_size(&many, &n_many, "tag%u", i));

        _cleanup_strv_free_ char **l = NULL;
        ASSERT_ERROR(machine_tags_edit(NULL, NULL, many, NULL, &l), E2BIG);
        ASSERT_NULL(l);
        ASSERT_OK(machine_tags_edit(NULL, NULL, many, STRV_MAKE("tag0"), &l));
        ASSERT_EQ(strv_length(l), (size_t) MACHINE_TAGS_MAX);

        /* The limit applies to base and additions combined */
        _cleanup_strv_free_ char **full = NULL;
        size_t n_full = 0;
        for (unsigned i = 0; i < MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strv_extendf_with_size(&full, &n_full, "k%u=v", i));

        l = strv_free(l);
        ASSERT_ERROR(machine_tags_edit(full, NULL, STRV_MAKE("extra"), NULL, &l), E2BIG);
        ASSERT_NULL(l);

        /* ... but only after replaced assignments have been dropped from the base */
        ASSERT_OK(machine_tags_edit(full, NULL, STRV_MAKE("k0=w"), NULL, &l));
        ASSERT_EQ(strv_length(l), (size_t) MACHINE_TAGS_MAX);
        ASSERT_TRUE(strv_contains(l, "k0=w"));
        ASSERT_FALSE(strv_contains(l, "k0=v"));

        /* ... and after tags matching a prefix to remove have been dropped from the base */
        l = strv_free(l);
        ASSERT_OK(machine_tags_edit(full, STRV_MAKE("k"), STRV_MAKE("extra"), NULL, &l));
        ASSERT_TRUE(strv_equal(l, STRV_MAKE("extra")));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
