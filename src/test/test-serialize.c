/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "serialize.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static char long_string[LONG_LINE_MAX+1];

TEST(serialize_item) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item(f, "a", NULL) == 0);
        assert_se(serialize_item(f, "a", "bbb") == 1);
        assert_se(serialize_item(f, "a", "bbb") == 1);
        assert_se(serialize_bool_elide(f, "c", true) == 1);
        assert_se(serialize_bool_elide(f, "d", false) == 0);
        assert_se(serialize_item(f, "a", long_string) == -EINVAL);
        assert_se(serialize_item(f, long_string, "a") == -EINVAL);
        assert_se(serialize_item(f, long_string, long_string) == -EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL, *line4 = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        ASSERT_STREQ(line1, "a=bbb");
        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        ASSERT_STREQ(line2, "a=bbb");
        assert_se(read_line(f, LONG_LINE_MAX, &line3) > 0);
        ASSERT_STREQ(line3, "c=yes");
        assert_se(read_line(f, LONG_LINE_MAX, &line4) == 0);
        ASSERT_STREQ(line4, "");
}

TEST(serialize_item_escaped) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item_escaped(f, "a", NULL) == 0);
        assert_se(serialize_item_escaped(f, "a", "bbb") == 1);
        assert_se(serialize_item_escaped(f, "a", "bbb") == 1);
        assert_se(serialize_item_escaped(f, "a", long_string) == -EINVAL);
        assert_se(serialize_item_escaped(f, long_string, "a") == -EINVAL);
        assert_se(serialize_item_escaped(f, long_string, long_string) == -EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        ASSERT_STREQ(line1, "a=bbb");
        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        ASSERT_STREQ(line2, "a=bbb");
        assert_se(read_line(f, LONG_LINE_MAX, &line3) == 0);
        ASSERT_STREQ(line3, "");
}

TEST(serialize_usec) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_usec(f, "usec1", USEC_INFINITY) == 0);
        assert_se(serialize_usec(f, "usec2", 0) == 1);
        assert_se(serialize_usec(f, "usec3", USEC_INFINITY-1) == 1);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL;
        usec_t x;

        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        ASSERT_STREQ(line1, "usec2=0");
        assert_se(deserialize_usec(line1 + 6, &x) == 0);
        assert_se(x == 0);

        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        assert_se(startswith(line2, "usec3="));
        assert_se(deserialize_usec(line2 + 6, &x) == 0);
        assert_se(x == USEC_INFINITY-1);
}

TEST(serialize_strv) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        char **strv = STRV_MAKE("a", "b", "foo foo",
                                "nasty1 \"",
                                "\"nasty2 ",
                                "nasty3 '",
                                "\"nasty4 \"",
                                "nasty5\n",
                                "\nnasty5\nfoo=bar",
                                "\nnasty5\nfoo=bar");

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_strv(f, "strv1", NULL) == 0);
        assert_se(serialize_strv(f, "strv2", STRV_MAKE_EMPTY) == 0);
        assert_se(serialize_strv(f, "strv3", strv) == 1);
        assert_se(serialize_strv(f, "strv4", STRV_MAKE(long_string)) == -EINVAL);

        rewind(f);

        _cleanup_strv_free_ char **strv2 = NULL;
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int r;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == 0)
                        break;
                assert_se(r > 0);

                const char *t = startswith(line, "strv3=");
                assert_se(t);
                assert_se(deserialize_strv(t, &strv2) >= 0);
        }

        assert_se(strv_equal(strv, strv2));
}

TEST(deserialize_environment) {
        _cleanup_strv_free_ char **env;

        assert_se(env = strv_new("A=1"));

        assert_se(deserialize_environment("B=2", &env) >= 0);
        assert_se(deserialize_environment("FOO%%=a\\177b\\nc\\td e", &env) >= 0);

        assert_se(strv_equal(env, STRV_MAKE("A=1", "B=2", "FOO%%=a\177b\nc\td e")));

        assert_se(deserialize_environment("foo\\", &env) < 0);
        assert_se(deserialize_environment("bar\\_baz", &env) < 0);
}

TEST(serialize_environment) {
        _cleanup_strv_free_ char **env = NULL, **env2 = NULL;
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-env-util.XXXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(env = strv_new("A=1",
                                 "B=2",
                                 "C=ąęółń",
                                 "D=D=a\\x0Ab",
                                 "FOO%%=a\177b\nc\td e"));

        assert_se(serialize_strv(f, "env", env) == 1);
        assert_se(fflush_and_check(f) == 0);

        rewind(f);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                assert_se(r >= 0);

                if (r == 0)
                        break;

                l = strstrip(line);

                assert_se(startswith(l, "env="));

                r = deserialize_environment(l+4, &env2);
                assert_se(r >= 0);
        }
        assert_se(feof(f));

        assert_se(strv_equal(env, env2));
}

TEST(serialize_item_hexmem) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item_hexmem(f, "a", NULL, 0) == 0);
        assert_se(serialize_item_hexmem(f, "a", (uint8_t []){0xff, 0xff, 0xff}, sizeof(uint8_t) * 3) == 1);

        rewind(f);

        _cleanup_free_ char *line = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line) > 0);
        ASSERT_STREQ(line, "a=ffffff");
}

TEST(serialize_item_base64mem) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(serialize_item_base64mem(f, "a", NULL, 0) == 0);
        assert_se(serialize_item_base64mem(f, "a", (uint8_t []){0xff, 0xff, 0xff}, sizeof(uint8_t) * 3) == 1);

        rewind(f);

        _cleanup_free_ char *line = NULL;
        assert_se(read_line(f, LONG_LINE_MAX, &line) > 0);
        ASSERT_STREQ(line, "a=////");
}

TEST(serialize_string_set) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_set_free_free_ Set *s = NULL;
        _cleanup_free_ char *line1 = NULL, *line2 = NULL;
        char *p, *q;

        assert_se(fmkostemp_safe(fn, "r+", &f) == 0);
        log_info("/* %s (%s) */", __func__, fn);

        assert_se(set_ensure_allocated(&s, &string_hash_ops) >= 0);

        assert_se(serialize_string_set(f, "a", s) == 0);

        assert_se(set_put_strsplit(s, "abc def,ghi jkl", ",", 0) >= 0);

        assert_se(serialize_string_set(f, "a", s) == 1);

        rewind(f);

        assert_se(read_line(f, LONG_LINE_MAX, &line1) > 0);
        assert_se((p = startswith(line1, "a=")));

        assert_se(read_line(f, LONG_LINE_MAX, &line2) > 0);
        assert_se((q = startswith(line2, "a=")));

        assert_se(!streq(p, q));
        assert_se(STR_IN_SET(p, "abc def", "ghi jkl"));
        assert_se(STR_IN_SET(q, "abc def", "ghi jkl"));
}

static int intro(void) {
        memset(long_string, 'x', sizeof(long_string)-1);
        char_array_0(long_string);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
