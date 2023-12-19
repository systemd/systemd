/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(strv_env_delete) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF");
        assert_se(a);

        b = strv_new("PIEP", "FOO");
        assert_se(b);

        c = strv_new("SCHLUMPF");
        assert_se(c);

        d = strv_env_delete(a, 2, b, c);
        assert_se(d);

        assert_se(streq(d[0], "WALDO=WALDO"));
        assert_se(streq(d[1], "WALDO="));
        assert_se(strv_length(d) == 2);
}

TEST(strv_env_get) {
        char **l = STRV_MAKE("ONE_OR_TWO=1", "THREE=3", "ONE_OR_TWO=2", "FOUR=4");

        assert_se(streq(strv_env_get(l, "ONE_OR_TWO"), "2"));
        assert_se(streq(strv_env_get(l, "THREE"), "3"));
        assert_se(streq(strv_env_get(l, "FOUR"), "4"));
}

TEST(strv_env_pairs_get) {
        char **l = STRV_MAKE("ONE_OR_TWO", "1", "THREE", "3", "ONE_OR_TWO", "2", "FOUR", "4", "FIVE", "5", "SIX", "FIVE", "SEVEN", "7");

        assert_se(streq(strv_env_pairs_get(l, "ONE_OR_TWO"), "2"));
        assert_se(streq(strv_env_pairs_get(l, "THREE"), "3"));
        assert_se(streq(strv_env_pairs_get(l, "FOUR"), "4"));
        assert_se(streq(strv_env_pairs_get(l, "FIVE"), "5"));
}

TEST(strv_env_unset) {
        _cleanup_strv_free_ char **l = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES");
        assert_se(l);

        assert_se(strv_env_unset(l, "SCHLUMPF") == l);

        assert_se(streq(l[0], "PIEP"));
        assert_se(streq(l[1], "NANANANA=YES"));
        assert_se(strv_length(l) == 2);
}

TEST(strv_env_merge) {
        char **a = STRV_MAKE("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", "EQ===");
        char **b = STRV_MAKE("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES");

        _cleanup_strv_free_ char **r = strv_env_merge(NULL, a, NULL, b, NULL, a, b, b, NULL);
        assert_se(r);
        assert_se(streq(r[0], "FOO="));
        assert_se(streq(r[1], "WALDO="));
        assert_se(streq(r[2], "PIEP"));
        assert_se(streq(r[3], "SCHLUMPF=SMURFF"));
        assert_se(streq(r[4], "EQ==="));
        assert_se(streq(r[5], "PIEP="));
        assert_se(streq(r[6], "NANANANA=YES"));
        assert_se(strv_length(r) == 7);

        assert_se(strv_env_clean(r) == r);
        assert_se(streq(r[0], "FOO="));
        assert_se(streq(r[1], "WALDO="));
        assert_se(streq(r[2], "SCHLUMPF=SMURFF"));
        assert_se(streq(r[3], "EQ==="));
        assert_se(streq(r[4], "PIEP="));
        assert_se(streq(r[5], "NANANANA=YES"));
        assert_se(strv_length(r) == 6);
}

TEST(strv_env_replace_strdup) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_replace_strdup(&a, "a=a") == 1);
        assert_se(strv_env_replace_strdup(&a, "b=b") == 1);
        assert_se(strv_env_replace_strdup(&a, "a=A") == 0);
        assert_se(strv_env_replace_strdup(&a, "c") == -EINVAL);

        assert_se(strv_length(a) == 2);
        strv_sort(a);
        assert_se(streq(a[0], "a=A"));
        assert_se(streq(a[1], "b=b"));
}

TEST(strv_env_replace_strdup_passthrough) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(putenv((char*) "a=a") == 0);
        assert_se(putenv((char*) "b=") == 0);
        assert_se(unsetenv("c") == 0);

        assert_se(strv_env_replace_strdup_passthrough(&a, "a") == 1);
        assert_se(strv_env_replace_strdup_passthrough(&a, "b") == 1);
        assert_se(strv_env_replace_strdup_passthrough(&a, "c") == 1);
        assert_se(strv_env_replace_strdup_passthrough(&a, "a") == 0);
        assert_se(strv_env_replace_strdup_passthrough(&a, "$a") == -EINVAL);

        assert_se(strv_length(a) == 3);
        assert_se(streq(a[0], "a=a"));
        assert_se(streq(a[1], "b="));
        assert_se(streq(a[2], "c="));
}

TEST(strv_env_assign) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_assign(&a, "a", "a") == 1);
        assert_se(strv_env_assign(&a, "b", "b") == 1);
        assert_se(strv_env_assign(&a, "a", "A") == 0);
        assert_se(strv_env_assign(&a, "b", NULL) == 0);

        assert_se(strv_env_assign(&a, "a=", "B") == -EINVAL);

        assert_se(strv_length(a) == 1);
        assert_se(streq(a[0], "a=A"));
}

TEST(strv_env_assignf) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_assignf(&a, "a", "a") > 0);
        assert_se(strv_env_assignf(&a, "a", "%c", 'a') == 0);

        assert_se(strv_env_assignf(&a, "c", "xxx%iyyy", 5) > 0);
        assert_se(strv_length(a) == 2);
        assert_se(strv_equal(a, STRV_MAKE("a=a", "c=xxx5yyy")));
        assert_se(strv_env_assignf(&a, "c", NULL) == 0);

        assert_se(strv_env_assignf(&a, "b", "b") > 0);
        assert_se(strv_env_assignf(&a, "a", "A") == 0);
        assert_se(strv_env_assignf(&a, "b", NULL) == 0);

        assert_se(strv_env_assignf(&a, "a=", "B") == -EINVAL);

        assert_se(strv_length(a) == 1);
        assert_se(streq(a[0], "a=A"));
}

TEST(strv_env_assign_many) {
        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_assign_many(&a, "a", "a", "b", "b") >= 0);

        assert_se(strv_length(a) == 2);
        assert_se(strv_contains(a, "a=a"));
        assert_se(strv_contains(a, "b=b"));

        assert_se(strv_env_assign_many(&a, "a", "A", "b", "b", "c", "c") >= 0);
        assert_se(strv_length(a) == 3);
        assert_se(strv_contains(a, "a=A"));
        assert_se(strv_contains(a, "b=b"));
        assert_se(strv_contains(a, "c=c"));

        assert_se(strv_env_assign_many(&a, "b", NULL, "c", "C") >= 0);
        assert_se(strv_length(a) == 2);
        assert_se(strv_contains(a, "a=A"));
        assert_se(strv_contains(a, "c=C"));

        assert_se(strv_env_assign_many(&a, "a=", "B") == -EINVAL);
        assert_se(strv_length(a) == 2);
        assert_se(strv_contains(a, "a=A"));
        assert_se(strv_contains(a, "c=C"));
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

        assert_se(streq(strv_env_get_n(env, "FOO__", 3, 0), "BAR BAR"));
        assert_se(streq(strv_env_get_n(env, "FOO__", 3, REPLACE_ENV_USE_ENVIRONMENT), "BAR BAR"));
        assert_se(streq(strv_env_get_n(env, "FOO", 3, 0), "BAR BAR"));
        assert_se(streq(strv_env_get_n(env, "FOO", 3, REPLACE_ENV_USE_ENVIRONMENT), "BAR BAR"));

        assert_se(streq(strv_env_get_n(env, "PATH__", 4, 0), "unset"));
        assert_se(streq(strv_env_get_n(env, "PATH", 4, 0), "unset"));
        assert_se(streq(strv_env_get_n(env, "PATH__", 4, REPLACE_ENV_USE_ENVIRONMENT), "unset"));
        assert_se(streq(strv_env_get_n(env, "PATH", 4, REPLACE_ENV_USE_ENVIRONMENT), "unset"));

        env[3] = NULL; /* kill our $PATH */

        assert_se(!strv_env_get_n(env, "PATH__", 4, 0));
        assert_se(!strv_env_get_n(env, "PATH", 4, 0));
        assert_se(streq_ptr(strv_env_get_n(env, "PATH__", 4, REPLACE_ENV_USE_ENVIRONMENT),
                            getenv("PATH")));
        assert_se(streq_ptr(strv_env_get_n(env, "PATH", 4, REPLACE_ENV_USE_ENVIRONMENT),
                            getenv("PATH")));
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

        assert_se(replace_env("FOO=$FOO=${FOO}", (char**) env, flags, &t) >= 0);
        assert_se(streq(t, braceless ? "FOO=BAR BAR=BAR BAR" : "FOO=$FOO=BAR BAR"));

        assert_se(replace_env("BAR=$BAR=${BAR}", (char**) env, flags, &s) >= 0);
        assert_se(streq(s, braceless ? "BAR=waldo=waldo" : "BAR=$BAR=waldo"));

        assert_se(replace_env("BARBAR=$BARBAR=${BARBAR}", (char**) env, flags, &q) >= 0);
        assert_se(streq(q, braceless ? "BARBAR==" : "BARBAR=$BARBAR="));

        assert_se(replace_env("BAR=$BAR$BAR${BAR}${BAR}", (char**) env, flags, &r) >= 0);
        assert_se(streq(r, braceless ? "BAR=waldowaldowaldowaldo" : "BAR=$BAR$BARwaldowaldo"));

        assert_se(replace_env("${BAR}$BAR$BAR", (char**) env, flags, &p) >= 0);
        assert_se(streq(p, braceless ? "waldowaldowaldo" : "waldo$BAR$BAR"));
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

        assert_se(replace_env("FOO=${FOO:-${BAR}}", (char**) env, flags, &t) >= 0);
        assert_se(streq(t, extended ? "FOO=foo" : "FOO=${FOO:-bar}"));

        assert_se(replace_env("BAR=${XXX:-${BAR}}", (char**) env, flags, &s) >= 0);
        assert_se(streq(s, extended ? "BAR=bar" : "BAR=${XXX:-bar}"));

        assert_se(replace_env("XXX=${XXX:+${BAR}}", (char**) env, flags, &q) >= 0);
        assert_se(streq(q, extended ? "XXX=" : "XXX=${XXX:+bar}"));

        assert_se(replace_env("FOO=${FOO:+${BAR}}", (char**) env, flags, &r) >= 0);
        assert_se(streq(r, extended ? "FOO=bar" : "FOO=${FOO:+bar}"));

        assert_se(replace_env("FOO=${FOO:-${BAR}post}", (char**) env, flags, &p) >= 0);
        assert_se(streq(p, extended ? "FOO=foo" : "FOO=${FOO:-barpost}"));

        assert_se(replace_env("XXX=${XXX:+${BAR}post}", (char**) env, flags, &x) >= 0);
        assert_se(streq(x, extended ? "XXX=" : "XXX=${XXX:+barpost}"));

        assert_se(replace_env("FOO=${FOO}between${BAR:-baz}", (char**) env, flags, &y) >= 0);
        assert_se(streq(y, extended ? "FOO=foobetweenbar" : "FOO=foobetween${BAR:-baz}"));
}

TEST(replace_env) {
        test_replace_env1(false);
        test_replace_env1(true);
        test_replace_env2(false);
        test_replace_env2(true);
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

        assert_se(replace_env_argv((char**) line, (char**) env, &r, NULL, NULL) >= 0);
        assert_se(r);
        assert_se(streq(r[0], "FOO$FOO"));
        assert_se(streq(r[1], "FOO$FOOFOO"));
        assert_se(streq(r[2], "FOOBAR BAR$FOO"));
        assert_se(streq(r[3], "FOOBAR BAR"));
        assert_se(streq(r[4], "BAR BAR"));
        assert_se(streq(r[5], "BAR"));
        assert_se(streq(r[6], "BAR"));
        assert_se(streq(r[7], "BAR BARwaldo"));
        assert_se(streq(r[8], "${FOO"));
        assert_se(streq(r[9], "FOO$BAR BAR"));
        assert_se(streq(r[10], "$FOOBAR BAR"));
        assert_se(streq(r[11], "${FOO:-waldo}"));
        assert_se(streq(r[12], "${QUUX:-BAR BAR}"));
        assert_se(streq(r[13], "${FOO:+waldo}"));
        assert_se(streq(r[14], "${QUUX:+waldo}"));
        assert_se(streq(r[15], "${FOO:+|waldo|}}"));
        assert_se(streq(r[16], "${FOO:+|waldo{|}"));
        assert_se(strv_length(r) == 17);
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

        assert_se(replace_env_argv((char**) line, (char**) env, &replaced, &unset, &bad) >= 0);

        assert_se(strv_equal(replaced, STRV_MAKE(
                                             "BAR",
                                             "BAR",
                                             "ABAR BARB",
                                             "ab",
                                             "xy",
                                             "zzz",
                                             "piffpiff")));

        assert_se(strv_equal(unset, STRV_MAKE(
                                             "UNSET1",
                                             "UNSET2",
                                             "UNSET3")));
        assert_se(strv_equal(bad, STRV_MAKE("",
                                            "%",
                                            "~")));
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
        assert_se(e);
        assert_se(!strv_env_is_valid(e));
        assert_se(strv_env_clean(e) == e);
        assert_se(strv_env_is_valid(e));

        assert_se(streq(e[0], "FOOBAR=WALDO"));
        assert_se(streq(e[1], "X="));
        assert_se(streq(e[2], "F=F"));
        assert_se(streq(e[3], "abcd=äöüß"));
        assert_se(streq(e[4], "xyz=xyz\n"));
        assert_se(streq(e[5], "another=final one"));
        assert_se(streq(e[6], "CRLF=\r\n"));
        assert_se(streq(e[7], "LESS_TERMCAP_mb=\x1b[01;31m"));
        assert_se(e[8] == NULL);
}

TEST(env_name_is_valid) {
        assert_se(env_name_is_valid("test"));

        assert_se(!env_name_is_valid(NULL));
        assert_se(!env_name_is_valid(""));
        assert_se(!env_name_is_valid("xxx\a"));
        assert_se(!env_name_is_valid("xxx\007b"));
        assert_se(!env_name_is_valid("\007\009"));
        assert_se(!env_name_is_valid("5_starting_with_a_number_is_wrong"));
        assert_se(!env_name_is_valid("#¤%&?_only_numbers_letters_and_underscore_allowed"));
}

TEST(env_value_is_valid) {
        assert_se(env_value_is_valid(""));
        assert_se(env_value_is_valid("głąb kapuściany"));
        assert_se(env_value_is_valid("printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
        assert_se(env_value_is_valid("tab\tcharacter"));
        assert_se(env_value_is_valid("new\nline"));
        assert_se(env_value_is_valid("Show this?\rNope. Show that!"));
        assert_se(env_value_is_valid("new DOS\r\nline"));

        assert_se(!env_value_is_valid("\xc5")); /* A truncated utf-8-encoded "ł".
                                                 * We currently disallow that. */
}

TEST(env_assignment_is_valid) {
        assert_se(env_assignment_is_valid("a="));
        assert_se(env_assignment_is_valid("b=głąb kapuściany"));
        assert_se(env_assignment_is_valid("c=\\007\\009\\011"));
        assert_se(env_assignment_is_valid("e=printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
        assert_se(env_assignment_is_valid("f=tab\tcharacter"));
        assert_se(env_assignment_is_valid("g=new\nline"));

        assert_se(!env_assignment_is_valid("="));
        assert_se(!env_assignment_is_valid("a b="));
        assert_se(!env_assignment_is_valid("a ="));
        assert_se(!env_assignment_is_valid(" b="));
        /* no dots or dashes: http://tldp.org/LDP/abs/html/gotchas.html */
        assert_se(!env_assignment_is_valid("a.b="));
        assert_se(!env_assignment_is_valid("a-b="));
        assert_se(!env_assignment_is_valid("\007=głąb kapuściany"));
        assert_se(!env_assignment_is_valid("c\009=\007\009\011"));
        assert_se(!env_assignment_is_valid("głąb=printf \"\x1b]0;<mock-chroot>\x07<mock-chroot>\""));
}

TEST(putenv_dup) {
        assert_se(putenv_dup("A=a1", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a1", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a2", false) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a2", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a2"));
}

TEST(setenv_systemd_exec_pid) {
        _cleanup_free_ char *saved = NULL;
        const char *e;
        pid_t p;

        e = getenv("SYSTEMD_EXEC_PID");
        if (e)
                assert_se(saved = strdup(e));

        assert_se(unsetenv("SYSTEMD_EXEC_PID") >= 0);
        assert_se(setenv_systemd_exec_pid(true) == 0);
        assert_se(!getenv("SYSTEMD_EXEC_PID"));

        assert_se(setenv("SYSTEMD_EXEC_PID", "*", 1) >= 0);
        assert_se(setenv_systemd_exec_pid(true) == 0);
        assert_se(e = getenv("SYSTEMD_EXEC_PID"));
        assert_se(streq(e, "*"));

        assert_se(setenv("SYSTEMD_EXEC_PID", "123abc", 1) >= 0);
        assert_se(setenv_systemd_exec_pid(true) == 1);
        assert_se(e = getenv("SYSTEMD_EXEC_PID"));
        assert_se(parse_pid(e, &p) >= 0);
        assert_se(p == getpid_cached());

        assert_se(unsetenv("SYSTEMD_EXEC_PID") >= 0);
        assert_se(setenv_systemd_exec_pid(false) == 1);
        assert_se(e = getenv("SYSTEMD_EXEC_PID"));
        assert_se(parse_pid(e, &p) >= 0);
        assert_se(p == getpid_cached());

        assert_se(set_unset_env("SYSTEMD_EXEC_PID", saved, 1) >= 0);
}

TEST(getenv_steal_erase) {
        int r;

        r = safe_fork("(sd-getenvstealerase)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        if (r == 0) {
                _cleanup_strv_free_ char **l = NULL;

                /* child */

                assert_se(getenv_steal_erase("thisenvvardefinitelywontexist", NULL) == 0);

                l = strv_new("FOO=BAR", "QUUX=PIFF", "ONE=TWO", "A=B");
                assert_se(strv_length(l) == 4);

                environ = l;

                STRV_FOREACH(e, environ) {
                        _cleanup_free_ char *n = NULL, *copy1 = NULL, *copy2 = NULL;
                        char *eq;

                        eq = strchr(*e, '=');
                        if (!eq)
                                continue;

                        n = strndup(*e, eq - *e);
                        assert_se(n);

                        copy1 = strdup(eq + 1);
                        assert_se(copy1);

                        assert_se(streq_ptr(getenv(n), copy1));
                        assert_se(getenv(n) == eq + 1);
                        assert_se(getenv_steal_erase(n, &copy2) > 0);
                        assert_se(streq_ptr(copy1, copy2));
                        assert_se(isempty(eq + 1));
                        assert_se(!getenv(n));
                }

                environ = NULL;
                l = strv_free(l);

                _exit(EXIT_SUCCESS);
        }

        assert_se(r > 0);
}

TEST(strv_env_name_is_valid) {
        assert_se(strv_env_name_is_valid(STRV_MAKE("HOME", "USER", "SHELL", "PATH")));
        assert_se(!strv_env_name_is_valid(STRV_MAKE("", "PATH", "home", "user", "SHELL")));
        assert_se(!strv_env_name_is_valid(STRV_MAKE("HOME", "USER", "SHELL", "USER")));
}

TEST(getenv_path_list) {
        _cleanup_strv_free_ char **path_list = NULL;

        /* Empty paths */
        FOREACH_STRING(s, "", ":", ":::::", " : ::: :: :") {
                assert_se(setenv("TEST_GETENV_PATH_LIST", s, 1) >= 0);
                assert_se(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list) == -EINVAL);
                assert_se(!path_list);
        }

        /* Invalid paths */
        FOREACH_STRING(s, ".", "..", "/../", "/", "/foo/bar/baz/../foo", "foo/bar/baz") {
                assert_se(setenv("TEST_GETENV_PATH_LIST", s, 1) >= 0);
                assert_se(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list) == -EINVAL);
                assert_se(!path_list);
        }

        /* Valid paths mixed with invalid ones */
        assert_se(setenv("TEST_GETENV_PATH_LIST", "/foo:/bar/baz:/../:/hello", 1) >= 0);
        assert_se(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list) == -EINVAL);
        assert_se(!path_list);

        /* Finally some valid paths */
        assert_se(setenv("TEST_GETENV_PATH_LIST", "/foo:/bar/baz:/hello/world:/path with spaces:/final", 1) >= 0);
        assert_se(getenv_path_list("TEST_GETENV_PATH_LIST", &path_list) >= 0);
        assert_se(streq(path_list[0], "/foo"));
        assert_se(streq(path_list[1], "/bar/baz"));
        assert_se(streq(path_list[2], "/hello/world"));
        assert_se(streq(path_list[3], "/path with spaces"));
        assert_se(streq(path_list[4], "/final"));
        assert_se(path_list[5] == NULL);

        assert_se(unsetenv("TEST_GETENV_PATH_LIST") >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
