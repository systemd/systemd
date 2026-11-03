/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-internal.h"
#include "bus-signature.h"
#include "log.h"
#include "tests.h"

int main(int argc, char *argv[]) {
        char prefix[256];
        int r;

        test_setup_logging(LOG_DEBUG);

        ASSERT_TRUE(signature_is_single("y", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("u", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("v", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("as", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("(ss)", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("()", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("(()()()()())", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("(((())))", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("((((s))))", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_single("{ss}", /* allow_dict_entry= */ true));
        ASSERT_TRUE(signature_is_single("a{ss}", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("uu", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("(", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single(")", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("())", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("((())", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("{)", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("{}", /* allow_dict_entry= */ true));
        ASSERT_FALSE(signature_is_single("{sss}", /* allow_dict_entry= */ true));
        ASSERT_FALSE(signature_is_single("{s}", /* allow_dict_entry= */ true));
        ASSERT_FALSE(signature_is_single("{ss}", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_single("{ass}", /* allow_dict_entry= */ true));
        ASSERT_FALSE(signature_is_single("a}", /* allow_dict_entry= */ true));

        ASSERT_TRUE(signature_is_pair("yy"));
        ASSERT_TRUE(signature_is_pair("ss"));
        ASSERT_TRUE(signature_is_pair("sas"));
        ASSERT_TRUE(signature_is_pair("sv"));
        ASSERT_TRUE(signature_is_pair("sa(vs)"));
        ASSERT_FALSE(signature_is_pair(""));
        ASSERT_FALSE(signature_is_pair("va"));
        ASSERT_FALSE(signature_is_pair("sss"));
        ASSERT_FALSE(signature_is_pair("{s}ss"));

        ASSERT_TRUE(signature_is_valid("ssa{ss}sssub", /* allow_dict_entry= */ true));
        ASSERT_TRUE(signature_is_valid("ssa{ss}sssub", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("{ss}", /* allow_dict_entry= */ true));
        ASSERT_FALSE(signature_is_valid("{ss}", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("", /* allow_dict_entry= */ true));
        ASSERT_TRUE(signature_is_valid("", /* allow_dict_entry= */ false));

        ASSERT_TRUE(signature_is_valid("sssusa(uuubbba(uu)uuuu)a{u(uuuvas)}",
                                       /* allow_dict_entry= */ false));

        ASSERT_FALSE(signature_is_valid("a", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("as", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("aas", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("aaas", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", /* allow_dict_entry= */ false));
        ASSERT_TRUE(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaas", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaau",
                                        /* allow_dict_entry= */ false));

        ASSERT_TRUE(signature_is_valid("((((((((((((((((((((((((((((((((s))))))))))))))))))))))))))))))))", /* allow_dict_entry= */ false));
        ASSERT_FALSE(signature_is_valid("((((((((((((((((((((((((((((((((()))))))))))))))))))))))))))))))))", /* allow_dict_entry= */ false));

        ASSERT_TRUE(namespace_complex_pattern("", ""));
        ASSERT_TRUE(namespace_complex_pattern("foobar", "foobar"));
        ASSERT_TRUE(namespace_complex_pattern("foobar.waldo", "foobar.waldo"));
        ASSERT_TRUE(namespace_complex_pattern("foobar.", "foobar.waldo"));
        ASSERT_TRUE(namespace_complex_pattern("foobar.waldo", "foobar."));
        ASSERT_FALSE(namespace_complex_pattern("foobar.waldo", "foobar"));
        ASSERT_FALSE(namespace_complex_pattern("foobar", "foobar.waldo"));
        ASSERT_FALSE(namespace_complex_pattern("", "foo"));
        ASSERT_FALSE(namespace_complex_pattern("foo", ""));
        ASSERT_FALSE(namespace_complex_pattern("foo.", ""));

        ASSERT_TRUE(path_complex_pattern("", ""));
        ASSERT_FALSE(path_complex_pattern("", "/"));
        ASSERT_FALSE(path_complex_pattern("/", ""));
        ASSERT_TRUE(path_complex_pattern("/", "/"));
        ASSERT_TRUE(path_complex_pattern("/foobar/", "/"));
        ASSERT_FALSE(path_complex_pattern("/foobar/", "/foobar"));
        ASSERT_TRUE(path_complex_pattern("/foobar", "/foobar"));
        ASSERT_FALSE(path_complex_pattern("/foobar", "/foobar/"));
        ASSERT_FALSE(path_complex_pattern("/foobar", "/foobar/waldo"));
        ASSERT_TRUE(path_complex_pattern("/foobar/", "/foobar/waldo"));
        ASSERT_TRUE(path_complex_pattern("/foobar/waldo", "/foobar/"));

        ASSERT_TRUE(path_simple_pattern("/foo/", "/foo/bar/waldo"));

        ASSERT_TRUE(namespace_simple_pattern("", ""));
        ASSERT_TRUE(namespace_simple_pattern("", ".foobar"));
        ASSERT_TRUE(namespace_simple_pattern("foobar", "foobar"));
        ASSERT_TRUE(namespace_simple_pattern("foobar.waldo", "foobar.waldo"));
        ASSERT_TRUE(namespace_simple_pattern("foobar", "foobar.waldo"));
        ASSERT_FALSE(namespace_simple_pattern("foobar.waldo", "foobar"));
        ASSERT_FALSE(namespace_simple_pattern("", "foo"));
        ASSERT_FALSE(namespace_simple_pattern("foo", ""));
        ASSERT_TRUE(namespace_simple_pattern("foo.", "foo.bar.waldo"));

        ASSERT_STREQ(object_path_startswith("/foo/bar", "/foo"), "bar");
        ASSERT_STREQ(object_path_startswith("/foo", "/foo"), "");
        ASSERT_STREQ(object_path_startswith("/foo", "/"), "foo");
        ASSERT_STREQ(object_path_startswith("/", "/"), "");
        ASSERT_NULL(object_path_startswith("/foo", "/bar"));
        ASSERT_NULL(object_path_startswith("/", "/bar"));
        ASSERT_NULL(object_path_startswith("/foo", ""));

        ASSERT_TRUE(object_path_is_valid("/foo/bar"));
        ASSERT_TRUE(object_path_is_valid("/foo"));
        ASSERT_TRUE(object_path_is_valid("/"));
        ASSERT_TRUE(object_path_is_valid("/foo5"));
        ASSERT_TRUE(object_path_is_valid("/foo_5"));
        ASSERT_FALSE(object_path_is_valid(""));
        ASSERT_FALSE(object_path_is_valid("/foo/"));
        ASSERT_FALSE(object_path_is_valid("//"));
        ASSERT_FALSE(object_path_is_valid("//foo"));
        ASSERT_FALSE(object_path_is_valid("/foo//bar"));
        ASSERT_FALSE(object_path_is_valid("/foo/aaaäöä"));

        OBJECT_PATH_FOREACH_PREFIX(prefix, "/") {
                log_info("<%s>", prefix);
                assert_not_reached();
        }

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx") {
                log_info("<%s>", prefix);
                ASSERT_STREQ(prefix, "/");
                ASSERT_EQ(r, 0);
                r++;
        }
        ASSERT_EQ(r, 1);

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx/yyy/zzz") {
                log_info("<%s>", prefix);
                ASSERT_TRUE(r != 0 || streq(prefix, "/xxx/yyy"));
                ASSERT_TRUE(r != 1 || streq(prefix, "/xxx"));
                ASSERT_TRUE(r != 2 || streq(prefix, "/"));
                r++;
        }
        ASSERT_EQ(r, 3);

        return 0;
}
