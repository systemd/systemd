/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "machine-tags.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

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

static void write_tags_file(const char *root, const char *rel, const char *contents) {
        _cleanup_free_ char *p = NULL;

        ASSERT_NOT_NULL(p = path_join(root, rel));
        ASSERT_OK(write_string_file(p, contents, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));
}

static void check(const char *root, char **base, char **expected) {
        _cleanup_strv_free_ char **l = NULL;

        ASSERT_OK(machine_tags_apply_config(root, base, &l));
        ASSERT_TRUE(strv_equal(l, expected));
}

TEST(machine_tags_apply_config) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *p = NULL;

        ASSERT_OK(mkdtemp_malloc("/tmp/test-machine-tags-XXXXXX", &root));

        /* No configuration at all: the base list is returned, sorted. An empty result is NULL. */
        check(root, STRV_MAKE("foo", "bar"), STRV_MAKE("bar", "foo"));
        ASSERT_OK(machine_tags_apply_config(root, NULL, &l));
        ASSERT_NULL(l);

        /* Comments, empty lines, several entries per line, CRLF line endings, an explicit '+' prefix, and
         * files from all directories applied in order of their names. The base tag 'vendor.env=old' is
         * replaced by the vendor file's assignment to the same key, which the local file then removes. */
        write_tags_file(root, "usr/lib/tags.d/10-vendor.tags",
                        "# vendor tags\n"
                        "vendor.role=webserver vendor.env=production\n"
                        "\n"
                        "; also a comment\n"
                        "  \t vendor.region=eu \t \n"
                        "vendor.after-comment\n");
        write_tags_file(root, "usr/lib/tags.d/20-more.tags", "vendor.extra\r\n+plus\r\n");
        write_tags_file(root, "run/tags.d/30-runtime.tags", "runtime");
        write_tags_file(root, "etc/tags.d/70-local.tags",
                        "-vendor.env=* -vendor.region=*\n"
                        "local.rack=7\n");
        check(root, STRV_MAKE("manual", "vendor.env=old"),
              STRV_MAKE("local.rack=7", "manual", "plus", "runtime", "vendor.after-comment", "vendor.extra",
                        "vendor.role=webserver"));

        /* A file in /etc/ replaces one with the same name in /usr/lib/ */
        write_tags_file(root, "etc/tags.d/20-more.tags", "override\n");
        check(root, STRV_MAKE("manual", "vendor.env=old"),
              STRV_MAKE("local.rack=7", "manual", "override", "runtime", "vendor.after-comment",
                        "vendor.role=webserver"));

        /* A /dev/null symlink or an empty file in /etc/ masks a file of the same name elsewhere */
        ASSERT_NOT_NULL(p = path_join(root, "etc/tags.d/10-vendor.tags"));
        ASSERT_OK_ERRNO(symlink("/dev/null", p));
        p = mfree(p);
        ASSERT_NOT_NULL(p = path_join(root, "etc/tags.d/30-runtime.tags"));
        ASSERT_OK(touch(p));
        p = mfree(p);
        check(root, STRV_MAKE("manual", "vendor.env=old"),
              STRV_MAKE("local.rack=7", "manual", "override"));

        /* Assigning a key replaces a previous assignment to the same key, but a bare tag of the same name
         * may coexist with it. Invalid entries are ignored, the rest of the file still applies. Backslashes
         * are not interpreted as escape characters, they simply make an entry invalid. */
        write_tags_file(root, "etc/tags.d/80-keys.tags",
                        "role=a\n"
                        "role role=b\n"
                        "-\n"
                        "+\n"
                        "in/valid --bad zz- -in/valid f\\oo also-good back\\\n");
        check(root, STRV_MAKE("manual", "vendor.env=old"),
              STRV_MAKE("also-good", "local.rack=7", "manual", "override", "role", "role=b"));

        /* Glob removal, of base tags too, and re-adding after removal */
        write_tags_file(root, "etc/tags.d/85-glob.tags",
                        "-role=* -manual role=c\n"
                        "-l* local.rack=8\n"
                        "-also* -nonexistent -xyz*\n");
        check(root, STRV_MAKE("manual", "vendor.env=old"),
              STRV_MAKE("local.rack=8", "override", "role", "role=c"));

        /* "-*" resets the list */
        write_tags_file(root, "etc/tags.d/90-reset.tags", "-* fresh\n");
        check(root, STRV_MAKE("manual", "vendor.env=old"), STRV_MAKE("fresh"));
        check(root, NULL, STRV_MAKE("fresh"));

        /* Too many tags */
        _cleanup_free_ char *many = NULL;
        for (unsigned i = 0; i <= MACHINE_TAGS_MAX; i++)
                ASSERT_OK(strextendf_with_separator(&many, " ", "t%u", i));
        write_tags_file(root, "etc/tags.d/95-many.tags", many);
        ASSERT_ERROR(machine_tags_apply_config(root, NULL, &l), E2BIG);
        ASSERT_NULL(l);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
