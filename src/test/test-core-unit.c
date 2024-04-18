/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "tests.h"
#include "unit.h"

static void test_unit_escape_setting_one(
                const char *s,
                const char *expected_exec_env,
                const char *expected_exec,
                const char *expected_c) {

        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL,
                *s_esc = NULL, *a_esc = NULL, *b_esc = NULL, *c_esc = NULL, *d_esc = NULL;
        const char *t;

        if (!expected_exec_env)
                expected_exec_env = s;
        if (!expected_exec)
                expected_exec = expected_exec_env;
        if (!expected_c)
                expected_c = expected_exec;
        assert_se(s_esc = cescape(s));

        assert_se(t = unit_escape_setting(s, 0, &a));
        assert_se(a_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_NULL(a);
        assert_se(t == s);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV, &b));
        assert_se(b_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        assert_se(b == NULL || streq(b, t));
        ASSERT_STREQ(t, expected_exec_env);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_EXEC_SYNTAX, &c));
        assert_se(c_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        assert_se(c == NULL || streq(c, t));
        ASSERT_STREQ(t, expected_exec);

        assert_se(t = unit_escape_setting(s, UNIT_ESCAPE_C, &d));
        assert_se(d_esc = cescape(t));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        assert_se(d == NULL || streq(d, t));
        ASSERT_STREQ(t, expected_c);
}

TEST(unit_escape_setting) {
        test_unit_escape_setting_one("/sbin/sbash", NULL, NULL, NULL);
        test_unit_escape_setting_one("$", "$$", "$", "$");
        test_unit_escape_setting_one("$$", "$$$$", "$$", "$$");
        test_unit_escape_setting_one("'", "'", NULL, "\\'");
        test_unit_escape_setting_one("\"", "\\\"", NULL, NULL);
        test_unit_escape_setting_one("\t", "\\t", NULL, NULL);
        test_unit_escape_setting_one(" ", NULL, NULL, NULL);
        test_unit_escape_setting_one("$;'\"\t\n", "$$;'\\\"\\t\\n", "$;'\\\"\\t\\n", "$;\\'\\\"\\t\\n");
}

static void test_unit_concat_strv_one(
                char **s,
                const char *expected_none,
                const char *expected_exec_env,
                const char *expected_exec,
                const char *expected_c) {

        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *d = NULL,
                *s_ser = NULL, *s_esc = NULL, *a_esc = NULL, *b_esc = NULL, *c_esc = NULL, *d_esc = NULL;

        assert_se(s_ser = strv_join(s, "_"));
        assert_se(s_esc = cescape(s_ser));
        if (!expected_exec_env)
                expected_exec_env = expected_none;
        if (!expected_exec)
                expected_exec = expected_none;
        if (!expected_c)
                expected_c = expected_none;

        assert_se(a = unit_concat_strv(s, 0));
        assert_se(a_esc = cescape(a));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, a_esc);
        ASSERT_STREQ(a, expected_none);

        assert_se(b = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX_ENV));
        assert_se(b_esc = cescape(b));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, b_esc);
        ASSERT_STREQ(b, expected_exec_env);

        assert_se(c = unit_concat_strv(s, UNIT_ESCAPE_EXEC_SYNTAX));
        assert_se(c_esc = cescape(c));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, c_esc);
        ASSERT_STREQ(c, expected_exec);

        assert_se(d = unit_concat_strv(s, UNIT_ESCAPE_C));
        assert_se(d_esc = cescape(d));
        log_debug("%s: [%s] → [%s]", __func__, s_esc, d_esc);
        ASSERT_STREQ(d, expected_c);
}

TEST(unit_concat_strv) {
        test_unit_concat_strv_one(STRV_MAKE("a", "b", "c"),
                                  "\"a\" \"b\" \"c\"",
                                  NULL,
                                  NULL,
                                  NULL);
        test_unit_concat_strv_one(STRV_MAKE("a", " ", "$", "$$", ""),
                                  "\"a\" \" \" \"$\" \"$$\" \"\"",
                                  "\"a\" \" \" \"$$\" \"$$$$\" \"\"",
                                  NULL,
                                  NULL);
        test_unit_concat_strv_one(STRV_MAKE("\n", " ", "\t"),
                                  "\"\n\" \" \" \"\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"",
                                  "\"\\n\" \" \" \"\\t\"");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
