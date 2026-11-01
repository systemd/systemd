/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "env-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "strv.h"
#include "tests.h"

TEST(strv_env_delete) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = ASSERT_NOT_NULL(strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF"));

        b = ASSERT_NOT_NULL(strv_new("PIEP", "FOO"));

        c = ASSERT_NOT_NULL(strv_new("SCHLUMPF"));

        d = ASSERT_NOT_NULL(strv_env_delete(a, 2, b, c));

        ASSERT_STREQ(d[0], "WALDO=WALDO");
        ASSERT_STREQ(d[1], "WALDO=");
        ASSERT_EQ(strv_length(d), 2U);
}

TEST(strv_env_get) {
        char **l = STRV_MAKE("ONE_OR_TWO=1", "THREE=3", "ONE_OR_TWO=2", "FOUR=4");

        ASSERT_STREQ(strv_env_get(l, "ONE_OR_TWO"), "2");
        ASSERT_STREQ(strv_env_get(l, "THREE"), "3");
        ASSERT_STREQ(strv_env_get(l, "FOUR"), "4");
}

TEST(strv_env_pairs_get) {
        char **l = STRV_MAKE("ONE_OR_TWO", "1", "THREE", "3", "ONE_OR_TWO", "2", "FOUR", "4", "FIVE", "5", "SIX", "FIVE", "SEVEN", "7");

        ASSERT_STREQ(strv_env_pairs_get(l, "ONE_OR_TWO"), "2");
        ASSERT_STREQ(strv_env_pairs_get(l, "THREE"), "3");
        ASSERT_STREQ(strv_env_pairs_get(l, "FOUR"), "4");
        ASSERT_STREQ(strv_env_pairs_get(l, "FIVE"), "5");
}

TEST(strv_env_unset) {
        _cleanup_strv_free_ char **l = NULL;

        l = ASSERT_NOT_NULL(strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES"));

        ASSERT_PTR_EQ(strv_env_unset(l, "SCHLUMPF"), l);

        ASSERT_STREQ(l[0], "PIEP");
        ASSERT_STREQ(l[1], "NANANANA=YES");
        ASSERT_EQ(strv_length(l), 2U);
}

TEST(strv_env_merge) {
        char **a = STRV_MAKE("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", "EQ===");
        char **b = STRV_MAKE("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES");

        _cleanup_strv_free_ char **r =
                ASSERT_NOT_NULL(strv_env_merge(NULL, a, NULL, b, NULL, a, b, b, NULL));
        ASSERT_STREQ(r[0], "FOO=");
        ASSERT_STREQ(r[1], "WALDO=");
        ASSERT_STREQ(r[2], "PIEP");
        ASSERT_STREQ(r[3], "SCHLUMPF=SMURFF");
        ASSERT_STREQ(r[4], "EQ===");
        ASSERT_STREQ(r[5], "PIEP=");
        ASSERT_STREQ(r[6], "NANANANA=YES");
        ASSERT_EQ(strv_length(r), 7U);

        ASSERT_PTR_EQ(strv_env_clean(r), r);
        ASSERT_STREQ(r[0], "FOO=");
        ASSERT_STREQ(r[1], "WALDO=");
        ASSERT_STREQ(r[2], "SCHLUMPF=SMURFF");
        ASSERT_STREQ(r[3], "EQ===");
        ASSERT_STREQ(r[4], "PIEP=");
        ASSERT_STREQ(r[5], "NANANANA=YES");
        ASSERT_EQ(strv_length(r), 6U);
}

TEST(strv_env_replace_strdup) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK_EQ(strv_env_replace_strdup(&a, "a=a"), 1);
        ASSERT_OK_EQ(strv_env_replace_strdup(&a, "b=b"), 1);
        ASSERT_OK_EQ(strv_env_replace_strdup(&a, "a=A"), 0);
        ASSERT_ERROR(strv_env_replace_strdup(&a, "c"), EINVAL);

        ASSERT_EQ(strv_length(a), 2U);
        strv_sort(a);
        ASSERT_STREQ(a[0], "a=A");
        ASSERT_STREQ(a[1], "b=b");
}

TEST(strv_env_replace_strdup_passthrough) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "a=a"));
        ASSERT_OK_ZERO_ERRNO(putenv((char*) "b="));
        ASSERT_OK_ERRNO(unsetenv("c"));

        ASSERT_OK_EQ(strv_env_replace_strdup_passthrough(&a, "a"), 1);
        ASSERT_OK_EQ(strv_env_replace_strdup_passthrough(&a, "b"), 1);
        ASSERT_OK_EQ(strv_env_replace_strdup_passthrough(&a, "c"), 1);
        ASSERT_OK_EQ(strv_env_replace_strdup_passthrough(&a, "a"), 0);
        ASSERT_ERROR(strv_env_replace_strdup_passthrough(&a, "$a"), EINVAL);

        ASSERT_EQ(strv_length(a), 3U);
        ASSERT_STREQ(a[0], "a=a");
        ASSERT_STREQ(a[1], "b=");
        ASSERT_STREQ(a[2], "c=");
}

TEST(strv_env_assign) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK_EQ(strv_env_assign(&a, "a", "a"), 1);
        ASSERT_OK_EQ(strv_env_assign(&a, "b", "b"), 1);
        ASSERT_OK_EQ(strv_env_assign(&a, "a", "A"), 0);
        ASSERT_OK_EQ(strv_env_assign(&a, "b", /* value= */ NULL), 0);

        ASSERT_ERROR(strv_env_assign(&a, "a=", "B"), EINVAL);

        ASSERT_EQ(strv_length(a), 1U);
        ASSERT_STREQ(a[0], "a=A");
}

TEST(strv_env_assignf) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK_POSITIVE(strv_env_assignf(&a, "a", "a"));
        ASSERT_OK_EQ(strv_env_assignf(&a, "a", "%c", 'a'), 0);

        ASSERT_OK_POSITIVE(strv_env_assignf(&a, "c", "xxx%iyyy", 5));
        ASSERT_EQ(strv_length(a), 2U);
        ASSERT_STRV_EQ(a, STRV_MAKE("a=a", "c=xxx5yyy"));
        ASSERT_OK_EQ(strv_env_assignf(&a, "c", /* valuef= */ NULL), 0);

        ASSERT_OK_POSITIVE(strv_env_assignf(&a, "b", "b"));
        ASSERT_OK_EQ(strv_env_assignf(&a, "a", "A"), 0);
        ASSERT_OK_EQ(strv_env_assignf(&a, "b", /* valuef= */ NULL), 0);

        ASSERT_ERROR(strv_env_assignf(&a, "a=", "B"), EINVAL);

        ASSERT_EQ(strv_length(a), 1U);
        ASSERT_STREQ(a[0], "a=A");
}

TEST(strv_env_assign_many) {
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK(strv_env_assign_many(&a, "a", "a", "b", "b"));

        ASSERT_EQ(strv_length(a), 2U);
        ASSERT_TRUE(strv_contains(a, "a=a"));
        ASSERT_TRUE(strv_contains(a, "b=b"));

        ASSERT_OK(strv_env_assign_many(&a, "a", "A", "b", "b", "c", "c"));
        ASSERT_EQ(strv_length(a), 3U);
        ASSERT_TRUE(strv_contains(a, "a=A"));
        ASSERT_TRUE(strv_contains(a, "b=b"));
        ASSERT_TRUE(strv_contains(a, "c=c"));

        ASSERT_OK(strv_env_assign_many(&a, "b", NULL, "c", "C"));
        ASSERT_EQ(strv_length(a), 2U);
        ASSERT_TRUE(strv_contains(a, "a=A"));
        ASSERT_TRUE(strv_contains(a, "c=C"));

        ASSERT_ERROR(strv_env_assign_many(&a, "a=", "B"), EINVAL);
        ASSERT_EQ(strv_length(a), 2U);
        ASSERT_TRUE(strv_contains(a, "a=A"));
        ASSERT_TRUE(strv_contains(a, "c=C"));
}

TEST(env_strv_get_n) {
        const char *_env[] = {
                "FOO=NO NO NO",
                "FOO=BAR BAR",
                "BAR=waldo",
                "PATH=unset",
                NULL
        };
        char **env = (char**) _env;

        ASSERT_STREQ(strv_env_get_n(env, "FOO__", 3, /* flags= */ 0), "BAR BAR");
        ASSERT_STREQ(strv_env_get_n(env, "FOO__", 3, REPLACE_ENV_USE_ENVIRONMENT), "BAR BAR");
        ASSERT_STREQ(strv_env_get_n(env, "FOO", 3, /* flags= */ 0), "BAR BAR");
        ASSERT_STREQ(strv_env_get_n(env, "FOO", 3, REPLACE_ENV_USE_ENVIRONMENT), "BAR BAR");

        ASSERT_STREQ(strv_env_get_n(env, "PATH__", 4, /* flags= */ 0), "unset");
        ASSERT_STREQ(strv_env_get_n(env, "PATH", 4, /* flags= */ 0), "unset");
        ASSERT_STREQ(strv_env_get_n(env, "PATH__", 4, REPLACE_ENV_USE_ENVIRONMENT), "unset");
        ASSERT_STREQ(strv_env_get_n(env, "PATH", 4, REPLACE_ENV_USE_ENVIRONMENT), "unset");

        env[3] = NULL; /* kill our $PATH */

        ASSERT_NULL(strv_env_get_n(env, "PATH__", 4, /* flags= */ 0));
        ASSERT_NULL(strv_env_get_n(env, "PATH", 4, /* flags= */ 0));
        ASSERT_STREQ(strv_env_get_n(env, "PATH__", 4, REPLACE_ENV_USE_ENVIRONMENT), getenv("PATH"));
        ASSERT_STREQ(strv_env_get_n(env, "PATH", 4, REPLACE_ENV_USE_ENVIRONMENT), getenv("PATH"));
}

static void test_replace_env1(bool braceless) {
        log_info("/* %s(braceless=%s) */", __func__, yes_no(braceless));

        const char *env[] = {
                "FOO=BAR BAR",
                "BAR=waldo",
                NULL
        };
        _cleanup_free_ char *t = NULL, *s = NULL, *q = NULL, *r = NULL, *p = NULL;
        unsigned flags = REPLACE_ENV_ALLOW_BRACELESS*braceless;

        ASSERT_OK(replace_env("FOO=$FOO=${FOO}", (char**) env, flags, &t));
        ASSERT_STREQ(t, braceless ? "FOO=BAR BAR=BAR BAR" : "FOO=$FOO=BAR BAR");

        ASSERT_OK(replace_env("BAR=$BAR=${BAR}", (char**) env, flags, &s));
        ASSERT_STREQ(s, braceless ? "BAR=waldo=waldo" : "BAR=$BAR=waldo");

        ASSERT_OK(replace_env("BARBAR=$BARBAR=${BARBAR}", (char**) env, flags, &q));
        ASSERT_STREQ(q, braceless ? "BARBAR==" : "BARBAR=$BARBAR=");

        ASSERT_OK(replace_env("BAR=$BAR$BAR${BAR}${BAR}", (char**) env, flags, &r));
        ASSERT_STREQ(r, braceless ? "BAR=waldowaldowaldowaldo" : "BAR=$BAR$BARwaldowaldo");

        ASSERT_OK(replace_env("${BAR}$BAR$BAR", (char**) env, flags, &p));
        ASSERT_STREQ(p, braceless ? "waldowaldowaldo" : "waldo$BAR$BAR");
}

static void test_replace_env2(bool extended) {
        log_info("/* %s(extended=%s) */", __func__, yes_no(extended));

        const char *env[] = {
                "FOO=foo",
                "BAR=bar",
                NULL
        };
        _cleanup_free_ char *t = NULL, *s = NULL, *q = NULL, *r = NULL, *p = NULL, *x = NULL, *y = NULL;
        unsigned flags = REPLACE_ENV_ALLOW_EXTENDED*extended;

        ASSERT_OK(replace_env("FOO=${FOO:-${BAR}}", (char**) env, flags, &t));
        ASSERT_STREQ(t, extended ? "FOO=foo" : "FOO=${FOO:-bar}");

        ASSERT_OK(replace_env("BAR=${XXX:-${BAR}}", (char**) env, flags, &s));
        ASSERT_STREQ(s, extended ? "BAR=bar" : "BAR=${XXX:-bar}");

        ASSERT_OK(replace_env("XXX=${XXX:+${BAR}}", (char**) env, flags, &q));
        ASSERT_STREQ(q, extended ? "XXX=" : "XXX=${XXX:+bar}");

        ASSERT_OK(replace_env("FOO=${FOO:+${BAR}}", (char**) env, flags, &r));
        ASSERT_STREQ(r, extended ? "FOO=bar" : "FOO=${FOO:+bar}");

        ASSERT_OK(replace_env("FOO=${FOO:-${BAR}post}", (char**) env, flags, &p));
        ASSERT_STREQ(p, extended ? "FOO=foo" : "FOO=${FOO:-barpost}");

        ASSERT_OK(replace_env("XXX=${XXX:+${BAR}post}", (char**) env, flags, &x));
        ASSERT_STREQ(x, extended ? "XXX=" : "XXX=${XXX:+barpost}");

        ASSERT_OK(replace_env("FOO=${FOO}between${BAR:-baz}", (char**) env, flags, &y));
        ASSERT_STREQ(y, extended ? "FOO=foobetweenbar" : "FOO=foobetween${BAR:-baz}");
}

TEST(replace_env) {
        test_replace_env1(/* braceless= */ false);
        test_replace_env1(/* braceless= */ true);
        test_replace_env2(/* extended= */ false);
        test_replace_env2(/* extended= */ true);
}

TEST(replace_env_argv) {
        const char *env[] = {
                "FOO=BAR BAR",
                "BAR=waldo",
                NULL
        };
        const char *line[] = {
                "FOO$FOO",
                "FOO$FOOFOO",
                "FOO${FOO}$FOO",
                "FOO${FOO}",
                "${FOO}",
                "$FOO",
                "$FOO$FOO",
                "${FOO}${BAR}",
                "${FOO",
                "FOO$$${FOO}",
                "$$FOO${FOO}",
                "${FOO:-${BAR}}",
                "${QUUX:-${FOO}}",
                "${FOO:+${BAR}}",
                "${QUUX:+${BAR}}",
                "${FOO:+|${BAR}|}}",
                "${FOO:+|${BAR}{|}",
                NULL
        };
        _cleanup_strv_free_ char **r = NULL;

        ASSERT_OK(replace_env_argv((char**) line, (char**) env, &r, /* ret_unset_variables= */ NULL, /* ret_bad_variables= */ NULL));
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r[0], "FOO$FOO");
        ASSERT_STREQ(r[1], "FOO$FOOFOO");
        ASSERT_STREQ(r[2], "FOOBAR BAR$FOO");
        ASSERT_STREQ(r[3], "FOOBAR BAR");
        ASSERT_STREQ(r[4], "BAR BAR");
        ASSERT_STREQ(r[5], "BAR");
        ASSERT_STREQ(r[6], "BAR");
        ASSERT_STREQ(r[7], "BAR BARwaldo");
        ASSERT_STREQ(r[8], "${FOO");
        ASSERT_STREQ(r[9], "FOO$BAR BAR");
        ASSERT_STREQ(r[10], "$FOOBAR BAR");
        ASSERT_STREQ(r[11], "${FOO:-waldo}");
        ASSERT_STREQ(r[12], "${QUUX:-BAR BAR}");
        ASSERT_STREQ(r[13], "${FOO:+waldo}");
        ASSERT_STREQ(r[14], "${QUUX:+waldo}");
        ASSERT_STREQ(r[15], "${FOO:+|waldo|}}");
        ASSERT_STREQ(r[16], "${FOO:+|waldo{|}");
        ASSERT_EQ(strv_length(r), 17U);
}

TEST(replace_env_argv_bad) {

        const char *env[] = {
                "FOO=BAR BAR",
                "BAR=waldo",
                NULL
        };

        const char *line[] = {
                "$FOO",
                "A${FOO}B",
                "a${~}${%}b",
                "x${}y",
                "$UNSET2",
                "z${UNSET3}z${UNSET1}z",
                "piff${UNSET2}piff",
                NULL
        };

        _cleanup_strv_free_ char **bad = NULL, **unset = NULL, **replaced = NULL;

        ASSERT_OK(replace_env_argv((char**) line, (char**) env, &replaced, &unset, &bad));

        ASSERT_STRV_EQ(replaced, STRV_MAKE(
                                       "BAR",
                                       "BAR",
                                       "ABAR BARB",
                                       "ab",
                                       "xy",
                                       "zzz",
                                       "piffpiff"));

        ASSERT_STRV_EQ(unset, STRV_MAKE(
                                       "UNSET1",
                                       "UNSET2",
                                       "UNSET3"));
        ASSERT_STRV_EQ(bad, STRV_MAKE("",
                                      "%",
                                      "~"));
}

TEST(env_clean) {
        _cleanup_strv_free_ char **e = strv_new("FOOBAR=WALDO",
                                                "FOOBAR=WALDO",
                                                "FOOBAR",
                                                "F",
                                                "X=",
                                                "F=F",
                                                "=",
                                                "=F",
                                                "",
                                                "0000=000",
                                                "äöüß=abcd",
                                                "abcd=äöüß",
                                                "xyz\n=xyz",
                                                "xyz=xyz\n",
                                                "another=one",
                                                "another=final one",
                                                "CRLF=\r\n",
                                                "LESS_TERMCAP_mb=\x1b[01;31m",
                                                "BASH_FUNC_foo%%=() {  echo foo\n}");
        ASSERT_NOT_NULL(e);
        ASSERT_FALSE(strv_env_is_valid(e));
        ASSERT_PTR_EQ(strv_env_clean(e), e);
        ASSERT_TRUE(strv_env_is_valid(e));

        ASSERT_STREQ(e[0], "FOOBAR=WALDO");
        ASSERT_STREQ(e[1], "X=");
        ASSERT_STREQ(e[2], "F=F");
        ASSERT_STREQ(e[3], "abcd=äöüß");
        ASSERT_STREQ(e[4], "xyz=xyz\n");
        ASSERT_STREQ(e[5], "another=final one");
        ASSERT_STREQ(e[6], "CRLF=\r\n");
        ASSERT_STREQ(e[7], "LESS_TERMCAP_mb=\x1b[01;31m");
        ASSERT_NULL(e[8]);
}

TEST(env_name_is_valid) {
        ASSERT_TRUE(env_name_is_valid("test"));

        ASSERT_FALSE(env_name_is_valid(NULL));
        ASSERT_FALSE(env_name_is_valid(""));
        ASSERT_FALSE(env_name_is_valid("xxx\a"));
        ASSERT_FALSE(env_name_is_valid("xxx\007b"));
        ASSERT_FALSE(env_name_is_valid("\007\009"));
        ASSERT_FALSE(env_name_is_valid("5_starting_with_a_number_is_wrong"));
        ASSERT_FALSE(env_name_is_valid("#¤%&?_only_numbers_letters_and_underscore_allowed"));
}

TEST(env_value_is_valid) {
        ASSERT_TRUE(env_value_is_valid(""));
        ASSERT_TRUE(env_value_is_valid("głąb kapuściany"));
        ASSERT_TRUE(env_value_is_valid("printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
        ASSERT_TRUE(env_value_is_valid("tab\tcharacter"));
        ASSERT_TRUE(env_value_is_valid("new\nline"));
        ASSERT_TRUE(env_value_is_valid("Show this?\rNope. Show that!"));
        ASSERT_TRUE(env_value_is_valid("new DOS\r\nline"));

        ASSERT_FALSE(env_value_is_valid("\xc5")); /* A truncated utf-8-encoded "ł".
                                                 * We currently disallow that. */
}

TEST(env_assignment_is_valid) {
        ASSERT_TRUE(env_assignment_is_valid("a="));
        ASSERT_TRUE(env_assignment_is_valid("b=głąb kapuściany"));
        ASSERT_TRUE(env_assignment_is_valid("c=\\007\\009\\011"));
        ASSERT_TRUE(env_assignment_is_valid("e=printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
        ASSERT_TRUE(env_assignment_is_valid("f=tab\tcharacter"));
        ASSERT_TRUE(env_assignment_is_valid("g=new\nline"));

        ASSERT_FALSE(env_assignment_is_valid("="));
        ASSERT_FALSE(env_assignment_is_valid("a b="));
        ASSERT_FALSE(env_assignment_is_valid("a ="));
        ASSERT_FALSE(env_assignment_is_valid(" b="));
        /* no dots or dashes: http://tldp.org/LDP/abs/html/gotchas.html */
        ASSERT_FALSE(env_assignment_is_valid("a.b="));
        ASSERT_FALSE(env_assignment_is_valid("a-b="));
        ASSERT_FALSE(env_assignment_is_valid("\007=głąb kapuściany"));
        ASSERT_FALSE(env_assignment_is_valid("c\009=\007\009\011"));
        ASSERT_FALSE(env_assignment_is_valid("głąb=printf \"\x1b]0;<mock-chroot>\x07<mock-chroot>\""));
}

TEST(putenv_dup) {
        ASSERT_OK_ZERO(putenv_dup("A=a1", /* override= */ true));
        ASSERT_STREQ(getenv("A"), "a1");
        ASSERT_OK_ZERO(putenv_dup("A=a1", /* override= */ true));
        ASSERT_STREQ(getenv("A"), "a1");
        ASSERT_OK_ZERO(putenv_dup("A=a2", /* override= */ false));
        ASSERT_STREQ(getenv("A"), "a1");
        ASSERT_OK_ZERO(putenv_dup("A=a2", /* override= */ true));
        ASSERT_STREQ(getenv("A"), "a2");
}

TEST(setenv_systemd_exec_pid) {
        _cleanup_free_ char *saved = NULL;
        const char *e;
        pid_t p;

        e = getenv("SYSTEMD_EXEC_PID");
        if (e)
                ASSERT_NOT_NULL(saved = strdup(e));

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_EXEC_PID"));
        ASSERT_OK_EQ(setenv_systemd_exec_pid(/* update_only= */ true), 0);
        ASSERT_NULL(getenv("SYSTEMD_EXEC_PID"));

        ASSERT_OK_ERRNO(setenv("SYSTEMD_EXEC_PID", "*", 1));
        ASSERT_OK_EQ(setenv_systemd_exec_pid(/* update_only= */ true), 0);
        ASSERT_NOT_NULL(e = getenv("SYSTEMD_EXEC_PID"));
        ASSERT_STREQ(e, "*");

        ASSERT_OK_ERRNO(setenv("SYSTEMD_EXEC_PID", "123abc", 1));
        ASSERT_OK_EQ(setenv_systemd_exec_pid(/* update_only= */ true), 1);
        ASSERT_NOT_NULL(e = getenv("SYSTEMD_EXEC_PID"));
        ASSERT_OK(parse_pid(e, &p));
        ASSERT_EQ(p, getpid_cached());

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_EXEC_PID"));
        ASSERT_OK_EQ(setenv_systemd_exec_pid(/* update_only= */ false), 1);
        ASSERT_NOT_NULL(e = getenv("SYSTEMD_EXEC_PID"));
        ASSERT_OK(parse_pid(e, &p));
        ASSERT_EQ(p, getpid_cached());

        ASSERT_OK(set_unset_env("SYSTEMD_EXEC_PID", saved, 1));
}

TEST(getenv_steal_erase) {
        int r;

        r = pidref_safe_fork("(sd-getenvstealerase)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, /* ret= */ NULL);
        if (r == 0) {
                _cleanup_strv_free_ char **l = NULL;

                /* child */

                ASSERT_OK_EQ(getenv_steal_erase("thisenvvardefinitelywontexist", /* ret= */ NULL), 0);

                l = strv_new("FOO=BAR", "QUUX=PIFF", "ONE=TWO", "A=B");
                ASSERT_EQ(strv_length(l), 4U);

                environ = l;

                STRV_FOREACH(e, environ) {
                        _cleanup_free_ char *n = NULL, *copy1 = NULL, *copy2 = NULL;
                        char *eq;

                        eq = strchr(*e, '=');
                        if (!eq)
                                continue;

                        n = ASSERT_NOT_NULL(strndup(*e, eq - *e));

                        copy1 = ASSERT_NOT_NULL(strdup(eq + 1));

                        ASSERT_STREQ(getenv(n), copy1);
                        ASSERT_PTR_EQ(getenv(n), eq + 1);
                        ASSERT_OK_POSITIVE(getenv_steal_erase(n, &copy2));
                        ASSERT_STREQ(copy1, copy2);
                        ASSERT_STREQ(eq + 1, "");
                        ASSERT_NULL(getenv(n));
                }

                environ = NULL;
                l = strv_free(l);

                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK_POSITIVE(r);
}

TEST(strv_env_name_is_valid) {
        ASSERT_TRUE(strv_env_name_is_valid(STRV_MAKE("HOME", "USER", "SHELL", "PATH")));
        ASSERT_FALSE(strv_env_name_is_valid(STRV_MAKE("", "PATH", "home", "user", "SHELL")));
        ASSERT_FALSE(strv_env_name_is_valid(STRV_MAKE("HOME", "USER", "SHELL", "USER")));
}

TEST(getenv_path_list) {
        _cleanup_strv_free_ char **path_list = NULL;

        /* Empty paths */
        FOREACH_STRING(s, "", ":", ":::::", " : ::: :: :") {
                ASSERT_OK_ERRNO(setenv("TEST_GETENV_PATH_LIST", s, 1));
                ASSERT_ERROR(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list), EINVAL);
                ASSERT_NULL(path_list);
        }

        /* Invalid paths */
        FOREACH_STRING(s, ".", "..", "/../", "/", "/foo/bar/baz/../foo", "foo/bar/baz") {
                ASSERT_OK_ERRNO(setenv("TEST_GETENV_PATH_LIST", s, 1));
                ASSERT_ERROR(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list), EINVAL);
                ASSERT_NULL(path_list);
        }

        /* Valid paths mixed with invalid ones */
        ASSERT_OK_ERRNO(setenv("TEST_GETENV_PATH_LIST", "/foo:/bar/baz:/../:/hello", 1));
        ASSERT_ERROR(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list), EINVAL);
        ASSERT_NULL(path_list);

        /* Finally some valid paths */
        ASSERT_OK_ERRNO(setenv("TEST_GETENV_PATH_LIST", "/foo:/bar/baz:/hello/world:/path with spaces:/final", 1));
        ASSERT_OK(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list));
        ASSERT_STREQ(path_list[0], "/foo");
        ASSERT_STREQ(path_list[1], "/bar/baz");
        ASSERT_STREQ(path_list[2], "/hello/world");
        ASSERT_STREQ(path_list[3], "/path with spaces");
        ASSERT_STREQ(path_list[4], "/final");
        ASSERT_NULL(path_list[5]);

        ASSERT_OK_ERRNO(unsetenv("TEST_GETENV_PATH_LIST"));
}

TEST(strv_env_get_merged) {
        char **l = STRV_MAKE("ONE", "1", "TWO", "2", "THREE", "3", "FOUR", "4", "FIVE", "5"),
                **expected = STRV_MAKE("ONE=1", "TWO=2", "THREE=3", "FOUR=4", "FIVE=5");
        _cleanup_strv_free_ char **m = NULL;

        ASSERT_OK(strv_env_get_merged(NULL, &m));
        ASSERT_NULL(m);
        ASSERT_OK(strv_env_get_merged(l, &m));
        ASSERT_STRV_EQ(m, expected);
}

TEST(replace_env_argv_unterminated) {
        /* A bare unset "$VAR" token expands to nothing and advances neither the write index nor writes a
         * terminator, so the output strv must still be NUL-terminated when such a token leads or is the
         * only word. */

        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        /* Single bare unset variable: result must be a properly terminated empty strv. */
        ASSERT_OK(replace_env_argv(STRV_MAKE("$THIS_IS_UNSET"), STRV_MAKE("FOO=BAR"), &a, /* ret_unset_variables= */ NULL, /* ret_bad_variables= */ NULL));
        ASSERT_TRUE(strv_isempty(a));

        /* Only unset variables. */
        ASSERT_OK(replace_env_argv(STRV_MAKE("$THIS_IS_UNSET", "$ALSO_UNSET"), STRV_MAKE("FOO=BAR"), &b, /* ret_unset_variables= */ NULL, /* ret_bad_variables= */ NULL));
        ASSERT_TRUE(strv_isempty(b));

        /* Trailing bare unset variable after an expanded one. */
        ASSERT_OK(replace_env_argv(STRV_MAKE("$FOO", "$THIS_IS_UNSET"), STRV_MAKE("FOO=BAR"), &c, /* ret_unset_variables= */ NULL, /* ret_bad_variables= */ NULL));
        ASSERT_STRV_EQ(c, STRV_MAKE("BAR"));

        /* Trailing bare unset variable after a literal word. */
        ASSERT_OK(replace_env_argv(STRV_MAKE("hello", "$THIS_IS_UNSET"), STRV_MAKE("FOO=BAR"), &d, /* ret_unset_variables= */ NULL, /* ret_bad_variables= */ NULL));
        ASSERT_STRV_EQ(d, STRV_MAKE("hello"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
