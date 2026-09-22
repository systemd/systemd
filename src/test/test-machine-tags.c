/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "machine-tags.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

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
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(NULL));    /* empty list is valid */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("a")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo", "bar", "c-d.e")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo=uuu", "bar=qqqq", "c-d.e")));
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo", "foo=aa")));        /* bare key and assignment coexist */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("foo=1", "foobar=2")));    /* one key is a prefix of the other */
        ASSERT_OK_POSITIVE(machine_tag_list_is_valid(STRV_MAKE("ab=1", "a=2")));          /* ... and the other way around */

        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=aa")));         /* same key + same value is not OK */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo", "b:c")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo", "")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "foo=b")));          /* same key, different value */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("a=1", "b=2", "a=3")));        /* ... also when not adjacent */
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("foo=aa", "bar", "foo=aa", "foo=b")));
        ASSERT_OK_ZERO(machine_tag_list_is_valid(STRV_MAKE("=aa")));
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
        ASSERT_OK(machine_tags_from_string("foo:bar:foo:baz", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "baz", "foo")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo:bar:baz", /* graceful= */ false, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "baz", "foo")));
        l = strv_free(l);

        /* Fatal: a repeated tag fails the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo:bar:foo:baz", /* graceful= */ false, &l), EINVAL);
        assert_se(!l);

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

        /* Graceful: a duplicate key is suppressed, keeping the value specified last */
        ASSERT_OK(machine_tags_from_string("foo=zzz:foo=aaa:foo=mmm", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo=mmm")));
        l = strv_free(l);

        /* Graceful: deduplication follows the order in which the tags were specified, sorting happens afterwards */
        ASSERT_OK(machine_tags_from_string("b=1:a=2:b=3:a=4:c", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("a=4", "b=3", "c")));
        l = strv_free(l);

        /* Graceful: a bare key and an assignment for the same name are not considered duplicates */
        ASSERT_OK(machine_tags_from_string("foo:foo=aaa", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo", "foo=aaa")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo:foo=aaa", /* graceful= */ false, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo", "foo=aaa")));
        l = strv_free(l);

        ASSERT_OK(machine_tags_from_string("foo=x:foo:foo=y", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo", "foo=y")));
        l = strv_free(l);

        /* Graceful: an invalid value is dropped, conflicting keys that remain are deduplicated */
        ASSERT_OK(machine_tags_from_string("foo=a_b:foo=good:foo=zzz", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("foo=zzz")));
        l = strv_free(l);

        /* Fatal: conflicting values for the same key fail the whole parse */
        ASSERT_ERROR(machine_tags_from_string("foo=a:foo=b", /* graceful= */ false, &l), EINVAL);
        assert_se(!l);

        /* Fatal: ... and so does repeating the very same assignment */
        ASSERT_ERROR(machine_tags_from_string("foo=a:bar:foo=a", /* graceful= */ false, &l), EINVAL);
        assert_se(!l);

        ASSERT_OK(machine_tags_from_string("foo=a:bar:foo=a", /* graceful= */ true, &l));
        assert_se(strv_equal(l, STRV_MAKE("bar", "foo=a")));
        l = strv_free(l);

        /* At most MACHINE_TAGS_MAX valid tags are accepted, in both modes, repeated keys included */
        _cleanup_free_ char *many = NULL;
        for (size_t i = 0; i <= MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strextendf_with_separator(&many, ":", "t%zu", i));
        ASSERT_ERROR(machine_tags_from_string(many, /* graceful= */ false, &l), E2BIG);
        ASSERT_ERROR(machine_tags_from_string(many, /* graceful= */ true, &l), E2BIG);
        assert_se(!l);

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

DEFINE_TEST_MAIN(LOG_DEBUG);
