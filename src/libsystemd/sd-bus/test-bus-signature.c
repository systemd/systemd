/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bus-internal.h"
#include "bus-signature.h"
#include "log.h"
#include "string-util.h"
#include "tests.h"

static void test_signature_is_single(void) {
        log_info("/* %s */", __func__);

        assert_se(signature_is_single("y", false));
        assert_se(signature_is_single("u", false));
        assert_se(signature_is_single("v", false));
        assert_se(signature_is_single("as", false));
        assert_se(signature_is_single("(ss)", false));
        assert_se(!signature_is_single("()", false));
        assert_se(!signature_is_single("(()()()()())", false));
        assert_se(!signature_is_single("(((())))", false));
        assert_se(signature_is_single("((((s))))", false));
        assert_se(signature_is_single("{ss}", true));
        assert_se(signature_is_single("a{ss}", false));
        assert_se(!signature_is_single("uu", false));
        assert_se(!signature_is_single("", false));
        assert_se(!signature_is_single("(", false));
        assert_se(!signature_is_single(")", false));
        assert_se(!signature_is_single("())", false));
        assert_se(!signature_is_single("((())", false));
        assert_se(!signature_is_single("{)", false));
        assert_se(!signature_is_single("{}", true));
        assert_se(!signature_is_single("{sss}", true));
        assert_se(!signature_is_single("{s}", true));
        assert_se(!signature_is_single("{ss}", false));
        assert_se(!signature_is_single("{ass}", true));
        assert_se(!signature_is_single("a}", true));

        assert_se(signature_is_valid("ssa{ss}sssub", true));
        assert_se(signature_is_valid("ssa{ss}sssub", false));
        assert_se(signature_is_valid("{ss}", true));
        assert_se(!signature_is_valid("{ss}", false));
        assert_se(signature_is_valid("", true));
        assert_se(signature_is_valid("", false));

        assert_se(signature_is_valid("sssusa(uuubbba(uu)uuuu)a{u(uuuvas)}", false));

        assert_se(!signature_is_valid("a", false));
        assert_se(signature_is_valid("as", false));
        assert_se(signature_is_valid("aas", false));
        assert_se(signature_is_valid("aaas", false));
        assert_se(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", false));
        assert_se(signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaas", false));
        assert_se(!signature_is_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaau", false));

        assert_se(signature_is_valid("((((((((((((((((((((((((((((((((s))))))))))))))))))))))))))))))))", false));
        assert_se(!signature_is_valid("((((((((((((((((((((((((((((((((()))))))))))))))))))))))))))))))))", false));
}

static void test_signature_is_pair(void) {
        log_info("/* %s */", __func__);

        assert_se(signature_is_pair("yy"));
        assert_se(signature_is_pair("ss"));
        assert_se(signature_is_pair("sas"));
        assert_se(signature_is_pair("sv"));
        assert_se(signature_is_pair("sa(vs)"));
        assert_se(!signature_is_pair(""));
        assert_se(!signature_is_pair("va"));
        assert_se(!signature_is_pair("sss"));
        assert_se(!signature_is_pair("{s}ss"));
}

static void test_namespace_pattern(void) {
        log_info("/* %s */", __func__);

        assert_se(namespace_complex_pattern("", ""));
        assert_se(namespace_complex_pattern("foobar", "foobar"));
        assert_se(namespace_complex_pattern("foobar.waldo", "foobar.waldo"));
        assert_se(namespace_complex_pattern("foobar.", "foobar.waldo"));
        assert_se(namespace_complex_pattern("foobar.waldo", "foobar."));
        assert_se(!namespace_complex_pattern("foobar.waldo", "foobar"));
        assert_se(!namespace_complex_pattern("foobar", "foobar.waldo"));
        assert_se(!namespace_complex_pattern("", "foo"));
        assert_se(!namespace_complex_pattern("foo", ""));
        assert_se(!namespace_complex_pattern("foo.", ""));

        assert_se(path_complex_pattern("", ""));
        assert_se(!path_complex_pattern("", "/"));
        assert_se(!path_complex_pattern("/", ""));
        assert_se(path_complex_pattern("/", "/"));
        assert_se(path_complex_pattern("/foobar/", "/"));
        assert_se(!path_complex_pattern("/foobar/", "/foobar"));
        assert_se(path_complex_pattern("/foobar", "/foobar"));
        assert_se(!path_complex_pattern("/foobar", "/foobar/"));
        assert_se(!path_complex_pattern("/foobar", "/foobar/waldo"));
        assert_se(path_complex_pattern("/foobar/", "/foobar/waldo"));
        assert_se(path_complex_pattern("/foobar/waldo", "/foobar/"));

        assert_se(path_simple_pattern("/foo/", "/foo/bar/waldo"));

        assert_se(namespace_simple_pattern("", ""));
        assert_se(namespace_simple_pattern("", ".foobar"));
        assert_se(namespace_simple_pattern("foobar", "foobar"));
        assert_se(namespace_simple_pattern("foobar.waldo", "foobar.waldo"));
        assert_se(namespace_simple_pattern("foobar", "foobar.waldo"));
        assert_se(!namespace_simple_pattern("foobar.waldo", "foobar"));
        assert_se(!namespace_simple_pattern("", "foo"));
        assert_se(!namespace_simple_pattern("foo", ""));
        assert_se(namespace_simple_pattern("foo.", "foo.bar.waldo"));
}

static void test_object_path(void) {
        log_info("/* %s */", __func__);

        assert_se(streq(object_path_startswith("/foo/bar", "/foo"), "bar"));
        assert_se(streq(object_path_startswith("/foo", "/foo"), ""));
        assert_se(streq(object_path_startswith("/foo", "/"), "foo"));
        assert_se(streq(object_path_startswith("/", "/"), ""));
        assert_se(!object_path_startswith("/foo", "/bar"));
        assert_se(!object_path_startswith("/", "/bar"));
        assert_se(!object_path_startswith("/foo", ""));

        assert_se(object_path_is_valid("/foo/bar"));
        assert_se(object_path_is_valid("/foo"));
        assert_se(object_path_is_valid("/"));
        assert_se(object_path_is_valid("/foo5"));
        assert_se(object_path_is_valid("/foo_5"));
        assert_se(!object_path_is_valid(""));
        assert_se(!object_path_is_valid("/foo/"));
        assert_se(!object_path_is_valid("//"));
        assert_se(!object_path_is_valid("//foo"));
        assert_se(!object_path_is_valid("/foo//bar"));
        assert_se(!object_path_is_valid("/foo/aaaäöä"));
}

static void test_object_path_prefix(void) {
        log_info("/* %s */", __func__);

        char prefix[256];
        int r;

        OBJECT_PATH_FOREACH_PREFIX(prefix, "/") {
                log_info("<%s>", prefix);
                assert_not_reached("???");
        }

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx") {
                log_info("<%s>", prefix);
                assert_se(streq(prefix, "/"));
                assert_se(r == 0);
                r++;
        }
        assert_se(r == 1);

        r = 0;
        OBJECT_PATH_FOREACH_PREFIX(prefix, "/xxx/yyy/zzz") {
                log_info("<%s>", prefix);
                assert_se(r != 0 || streq(prefix, "/xxx/yyy"));
                assert_se(r != 1 || streq(prefix, "/xxx"));
                assert_se(r != 2 || streq(prefix, "/"));
                r++;
        }
        assert_se(r == 3);
}

static void test_signature_element_length(void) {
        size_t l;

        assert_se(signature_element_length(NULL, &l) == -EINVAL);
        assert_se(signature_element_length("", &l) == -EINVAL);

        const char *s = "ybnqiuxtdsogh";
        assert(signature_element_length(s, &l) == 0);

        assert_se(signature_element_length("()", &l) == -EINVAL);
        assert_se(signature_element_length("(x)", &l) == 0);
        assert_se(l == 3);

        for (const char *p = s; *p; p++) {
                char sig[2] = {*p};
                assert_se(signature_element_length(sig, &l) == 0);
                assert_se(l == 1);

                char sig2[3] = {*p, *p};
                assert_se(signature_element_length(sig2, &l) == 0);
                assert_se(l == 1);

                char sig3[3] = {'(', *p, ')'};
                assert_se(signature_element_length(sig3, &l) == 0);
                assert_se(l == 3);
        }

        s = "a((((((((((((((b))))))))))))))";
        assert(signature_element_length(s, &l) == 0);

        s = "(((((((((((((((b)))))))))))))))x";
        assert_se(signature_element_length(s, &l) == 0);
        s = "x(((((((((((((((b)))))))))))))))";
        assert_se(signature_element_length(s, &l) == 0);

        assert_se(signature_element_length("(((((((((((((((b))))))))))))))", &l) == -EINVAL);
        assert_se(signature_element_length("((((((((((((((b))))))))))))))X", &l) == 0);
        assert_se(l == 29);

        s = "a{sv}";
        assert_se(signature_element_length(s, &l) == 0);
        assert_se(l == 5);

        s = "a(sss)";
        assert_se(signature_element_length(s, &l) == 0);
        assert_se(l == 6);
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_signature_is_single();
        test_signature_is_pair();
        test_namespace_pattern();
        test_object_path();
        test_object_path_prefix();
        test_signature_element_length();

        return 0;
}
