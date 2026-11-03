/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "extract-word.h"       /* IWYU pragma: keep */
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "serialize.h"
#include "set.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static char long_string[LONG_LINE_MAX+1];

TEST(serialize_item) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_item(f, "a", /* value= */ NULL), 0);
        ASSERT_OK_EQ(serialize_item(f, "a", "bbb"), 1);
        ASSERT_OK_EQ(serialize_item(f, "a", "bbb"), 1);
        ASSERT_OK_EQ(serialize_bool_elide(f, "c", true), 1);
        ASSERT_OK_EQ(serialize_bool_elide(f, "d", false), 0);
        ASSERT_ERROR(serialize_item(f, "a", long_string), EINVAL);
        ASSERT_ERROR(serialize_item(f, long_string, "a"), EINVAL);
        ASSERT_ERROR(serialize_item(f, long_string, long_string), EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL, *line4 = NULL;
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line1));
        ASSERT_STREQ(line1, "a=bbb");
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line2));
        ASSERT_STREQ(line2, "a=bbb");
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line3));
        ASSERT_STREQ(line3, "c=yes");
        ASSERT_OK_EQ(read_line(f, LONG_LINE_MAX, &line4), 0);
        ASSERT_STREQ(line4, "");
}

TEST(serialize_item_escaped) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_item_escaped(f, "a", /* value= */ NULL), 0);
        ASSERT_OK_EQ(serialize_item_escaped(f, "a", "bbb"), 1);
        ASSERT_OK_EQ(serialize_item_escaped(f, "a", "bbb"), 1);
        ASSERT_ERROR(serialize_item_escaped(f, "a", long_string), EINVAL);
        ASSERT_ERROR(serialize_item_escaped(f, long_string, "a"), EINVAL);
        ASSERT_ERROR(serialize_item_escaped(f, long_string, long_string), EINVAL);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL, *line3 = NULL;
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line1));
        ASSERT_STREQ(line1, "a=bbb");
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line2));
        ASSERT_STREQ(line2, "a=bbb");
        ASSERT_OK_EQ(read_line(f, LONG_LINE_MAX, &line3), 0);
        ASSERT_STREQ(line3, "");
}

TEST(serialize_usec) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_usec(f, "usec1", USEC_INFINITY), 0);
        ASSERT_OK_EQ(serialize_usec(f, "usec2", /* usec= */ 0), 1);
        ASSERT_OK_EQ(serialize_usec(f, "usec3", USEC_INFINITY-1), 1);

        rewind(f);

        _cleanup_free_ char *line1 = NULL, *line2 = NULL;
        usec_t x;

        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line1));
        ASSERT_STREQ(line1, "usec2=0");
        ASSERT_OK_ZERO(deserialize_usec(line1 + 6, &x));
        ASSERT_EQ(x, 0U);

        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line2));
        ASSERT_NOT_NULL(startswith(line2, "usec3="));
        ASSERT_OK_ZERO(deserialize_usec(line2 + 6, &x));
        ASSERT_EQ(x, USEC_INFINITY-1);
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

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_strv(f, "strv1", NULL), 0);
        ASSERT_OK_EQ(serialize_strv(f, "strv2", STRV_EMPTY), 0);
        ASSERT_OK_EQ(serialize_strv(f, "strv3", strv), 1);
        ASSERT_ERROR(serialize_strv(f, "strv4", STRV_MAKE(long_string)), EINVAL);

        rewind(f);

        _cleanup_strv_free_ char **strv2 = NULL;
        for (;;) {
                _cleanup_free_ char *line = NULL;
                int r;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == 0)
                        break;
                ASSERT_OK_POSITIVE(r);

                const char *t = ASSERT_NOT_NULL(startswith(line, "strv3="));
                ASSERT_OK(deserialize_strv(t, &strv2));
        }

        ASSERT_STRV_EQ(strv, strv2);
}

TEST(deserialize_environment) {
        _cleanup_strv_free_ char **env;

        ASSERT_NOT_NULL(env = strv_new("A=1"));

        ASSERT_OK(deserialize_environment("B=2", &env));
        ASSERT_OK(deserialize_environment("FOO%%=a\\177b\\nc\\td e", &env));

        ASSERT_STRV_EQ(env, STRV_MAKE("A=1", "B=2", "FOO%%=a\177b\nc\td e"));

        ASSERT_FAIL(deserialize_environment("foo\\", &env));
        ASSERT_FAIL(deserialize_environment("bar\\_baz", &env));
}

TEST(serialize_environment) {
        _cleanup_strv_free_ char **env = NULL, **env2 = NULL;
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-env-util.XXXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_NOT_NULL(env = strv_new("A=1",
                                       "B=2",
                                       "C=ąęółń",
                                       "D=D=a\\x0Ab",
                                       "FOO%%=a\177b\nc\td e"));

        ASSERT_OK_EQ(serialize_strv(f, "env", env), 1);
        ASSERT_OK_ZERO(fflush_and_check(f));

        rewind(f);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *l;

                r = ASSERT_OK(read_line(f, LONG_LINE_MAX, &line));

                if (r == 0)
                        break;

                l = strstrip(line);

                ASSERT_NOT_NULL(startswith(l, "env="));

                ASSERT_OK(deserialize_environment(l+4, &env2));
        }
        ASSERT_TRUE(feof(f));

        ASSERT_STRV_EQ(env, env2);
}

TEST(serialize_item_hexmem) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_item_hexmem(f, "a", NULL, 0), 0);
        ASSERT_OK_EQ(serialize_item_hexmem(f, "a", (uint8_t []){0xff, 0xff, 0xff}, sizeof(uint8_t) * 3), 1);

        rewind(f);

        _cleanup_free_ char *line = NULL;
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line));
        ASSERT_STREQ(line, "a=ffffff");
}

TEST(serialize_item_base64mem) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK_EQ(serialize_item_base64mem(f, "a", NULL, 0), 0);
        ASSERT_OK_EQ(serialize_item_base64mem(f, "a", (uint8_t []){0xff, 0xff, 0xff}, sizeof(uint8_t) * 3), 1);

        rewind(f);

        _cleanup_free_ char *line = NULL;
        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line));
        ASSERT_STREQ(line, "a=////");
}

TEST(serialize_string_set) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-serialize.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_set_free_ Set *s = NULL;
        _cleanup_free_ char *line1 = NULL, *line2 = NULL;
        char *p, *q;

        ASSERT_OK_ZERO(fmkostemp_safe(fn, "r+", &f));
        log_info("/* %s (%s) */", __func__, fn);

        ASSERT_OK(set_ensure_allocated(&s, &string_hash_ops_free));

        ASSERT_OK_EQ(serialize_string_set(f, "a", s), 0);

        ASSERT_OK(set_put_strsplit(s, "abc def,ghi jkl", ",", /* flags= */ 0));

        ASSERT_OK_EQ(serialize_string_set(f, "a", s), 1);

        rewind(f);

        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line1));
        ASSERT_NOT_NULL(p = startswith(line1, "a="));

        ASSERT_OK_POSITIVE(read_line(f, LONG_LINE_MAX, &line2));
        ASSERT_NOT_NULL(q = startswith(line2, "a="));

        ASSERT_NOT_STREQ(p, q);
        ASSERT_TRUE(STR_IN_SET(p, "abc def", "ghi jkl"));
        ASSERT_TRUE(STR_IN_SET(q, "abc def", "ghi jkl"));
}

static int intro(void) {
        memset(long_string, 'x', sizeof(long_string)-1);
        char_array_0(long_string);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
