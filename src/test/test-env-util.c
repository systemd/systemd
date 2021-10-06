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
#include "util.h"

static void test_strv_env_delete(void) {
        log_info("/* %s */", __func__);

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

static void test_strv_env_get(void) {
        log_info("/* %s */", __func__);

        char **l = STRV_MAKE("ONE_OR_TWO=1", "THREE=3", "ONE_OR_TWO=2", "FOUR=4");

        assert_se(streq(strv_env_get(l, "ONE_OR_TWO"), "2"));
        assert_se(streq(strv_env_get(l, "THREE"), "3"));
        assert_se(streq(strv_env_get(l, "FOUR"), "4"));
}

static void test_strv_env_pairs_get(void) {
        log_info("/* %s */", __func__);

        char **l = STRV_MAKE("ONE_OR_TWO", "1", "THREE", "3", "ONE_OR_TWO", "2", "FOUR", "4", "FIVE", "5", "SIX", "FIVE", "SEVEN", "7");

        assert_se(streq(strv_env_pairs_get(l, "ONE_OR_TWO"), "2"));
        assert_se(streq(strv_env_pairs_get(l, "THREE"), "3"));
        assert_se(streq(strv_env_pairs_get(l, "FOUR"), "4"));
        assert_se(streq(strv_env_pairs_get(l, "FIVE"), "5"));
}

static void test_strv_env_unset(void) {
        log_info("/* %s */", __func__);

        _cleanup_strv_free_ char **l = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES");
        assert_se(l);

        assert_se(strv_env_unset(l, "SCHLUMPF") == l);

        assert_se(streq(l[0], "PIEP"));
        assert_se(streq(l[1], "NANANANA=YES"));
        assert_se(strv_length(l) == 2);
}

static void test_strv_env_merge(void) {
        log_info("/* %s */", __func__);

        _cleanup_strv_free_ char **a = NULL, **b = NULL, **r = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF");
        assert_se(a);

        b = strv_new("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES");
        assert_se(b);

        r = strv_env_merge(2, a, b);
        assert_se(r);
        assert_se(streq(r[0], "FOO="));
        assert_se(streq(r[1], "WALDO="));
        assert_se(streq(r[2], "PIEP"));
        assert_se(streq(r[3], "SCHLUMPF=SMURFF"));
        assert_se(streq(r[4], "PIEP="));
        assert_se(streq(r[5], "NANANANA=YES"));
        assert_se(strv_length(r) == 6);

        assert_se(strv_env_clean(r) == r);
        assert_se(streq(r[0], "FOO="));
        assert_se(streq(r[1], "WALDO="));
        assert_se(streq(r[2], "SCHLUMPF=SMURFF"));
        assert_se(streq(r[3], "PIEP="));
        assert_se(streq(r[4], "NANANANA=YES"));
        assert_se(strv_length(r) == 5);
}

static void test_strv_env_replace_strdup(void) {
        log_info("/* %s */", __func__);

        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_replace_strdup(&a, "a=a") == 1);
        assert_se(strv_env_replace_strdup(&a, "b=b") == 1);
        assert_se(strv_env_replace_strdup(&a, "a=A") == 0);

        assert_se(strv_length(a) == 2);
        strv_sort(a);
        assert_se(streq(a[0], "a=A"));
        assert_se(streq(a[1], "b=b"));
}

static void test_strv_env_assign(void) {
        log_info("/* %s */", __func__);

        _cleanup_strv_free_ char **a = NULL;

        assert_se(strv_env_assign(&a, "a", "a") == 1);
        assert_se(strv_env_assign(&a, "b", "b") == 1);
        assert_se(strv_env_assign(&a, "a", "A") == 0);
        assert_se(strv_env_assign(&a, "b", NULL) == 0);

        assert_se(strv_env_assign(&a, "a=", "B") == -EINVAL);

        assert_se(strv_length(a) == 1);
        assert_se(streq(a[0], "a=A"));
}

static void test_env_strv_get_n(void) {
        log_info("/* %s */", __func__);

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

static void test_replace_env(bool braceless) {
        log_info("/* %s(braceless=%s) */", __func__, yes_no(braceless));

        const char *env[] = {
                "FOO=BAR BAR",
                "BAR=waldo",
                NULL
        };
        _cleanup_free_ char *t = NULL, *s = NULL, *q = NULL, *r = NULL, *p = NULL;
        unsigned flags = REPLACE_ENV_ALLOW_BRACELESS*braceless;

        t = replace_env("FOO=$FOO=${FOO}", (char**) env, flags);
        assert_se(streq(t, braceless ? "FOO=BAR BAR=BAR BAR" : "FOO=$FOO=BAR BAR"));

        s = replace_env("BAR=$BAR=${BAR}", (char**) env, flags);
        assert_se(streq(s, braceless ? "BAR=waldo=waldo" : "BAR=$BAR=waldo"));

        q = replace_env("BARBAR=$BARBAR=${BARBAR}", (char**) env, flags);
        assert_se(streq(q, braceless ? "BARBAR==" : "BARBAR=$BARBAR="));

        r = replace_env("BAR=$BAR$BAR${BAR}${BAR}", (char**) env, flags);
        assert_se(streq(r, braceless ? "BAR=waldowaldowaldowaldo" : "BAR=$BAR$BARwaldowaldo"));

        p = replace_env("${BAR}$BAR$BAR", (char**) env, flags);
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

        t = replace_env("FOO=${FOO:-${BAR}}", (char**) env, flags);
        assert_se(streq(t, extended ? "FOO=foo" : "FOO=${FOO:-bar}"));

        s = replace_env("BAR=${XXX:-${BAR}}", (char**) env, flags);
        assert_se(streq(s, extended ? "BAR=bar" : "BAR=${XXX:-bar}"));

        q = replace_env("XXX=${XXX:+${BAR}}", (char**) env, flags);
        assert_se(streq(q, extended ? "XXX=" : "XXX=${XXX:+bar}"));

        r = replace_env("FOO=${FOO:+${BAR}}", (char**) env, flags);
        assert_se(streq(r, extended ? "FOO=bar" : "FOO=${FOO:+bar}"));

        p = replace_env("FOO=${FOO:-${BAR}post}", (char**) env, flags);
        assert_se(streq(p, extended ? "FOO=foo" : "FOO=${FOO:-barpost}"));

        x = replace_env("XXX=${XXX:+${BAR}post}", (char**) env, flags);
        assert_se(streq(x, extended ? "XXX=" : "XXX=${XXX:+barpost}"));

        y = replace_env("FOO=${FOO}between${BAR:-baz}", (char**) env, flags);
        assert_se(streq(y, extended ? "FOO=foobetweenbar" : "FOO=foobetween${BAR:-baz}"));
}

static void test_replace_env_argv(void) {
        log_info("/* %s */", __func__);

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

        r = replace_env_argv((char**) line, (char**) env);
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

static void test_env_clean(void) {
        log_info("/* %s */", __func__);

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

static void test_env_name_is_valid(void) {
        log_info("/* %s */", __func__);

        assert_se(env_name_is_valid("test"));

        assert_se(!env_name_is_valid(NULL));
        assert_se(!env_name_is_valid(""));
        assert_se(!env_name_is_valid("xxx\a"));
        assert_se(!env_name_is_valid("xxx\007b"));
        assert_se(!env_name_is_valid("\007\009"));
        assert_se(!env_name_is_valid("5_starting_with_a_number_is_wrong"));
        assert_se(!env_name_is_valid("#¤%&?_only_numbers_letters_and_underscore_allowed"));
}

static void test_env_value_is_valid(void) {
        log_info("/* %s */", __func__);

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

static void test_env_assignment_is_valid(void) {
        log_info("/* %s */", __func__);

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

static void test_putenv_dup(void) {
        log_info("/* %s */", __func__);

        assert_se(putenv_dup("A=a1", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a1", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a2", false) == 0);
        assert_se(streq_ptr(getenv("A"), "a1"));
        assert_se(putenv_dup("A=a2", true) == 0);
        assert_se(streq_ptr(getenv("A"), "a2"));
}

static void test_setenv_systemd_exec_pid(void) {
        _cleanup_free_ char *saved = NULL;
        const char *e;
        pid_t p;

        log_info("/* %s */", __func__);

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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_strv_env_delete();
        test_strv_env_get();
        test_strv_env_pairs_get();
        test_strv_env_unset();
        test_strv_env_merge();
        test_strv_env_replace_strdup();
        test_strv_env_assign();
        test_env_strv_get_n();
        test_replace_env(false);
        test_replace_env(true);
        test_replace_env2(false);
        test_replace_env2(true);
        test_replace_env_argv();
        test_env_clean();
        test_env_name_is_valid();
        test_env_value_is_valid();
        test_env_assignment_is_valid();
        test_putenv_dup();
        test_setenv_systemd_exec_pid();

        return 0;
}
