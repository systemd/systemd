/* SPDX-License-Identifier: LGPL-2.1+ */

#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
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

static void test_strv_env_set(void) {
        log_info("/* %s */", __func__);

        _cleanup_strv_free_ char **l = NULL, **r = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES");
        assert_se(l);

        r = strv_env_set(l, "WALDO=WALDO");
        assert_se(r);

        assert_se(streq(r[0], "PIEP"));
        assert_se(streq(r[1], "SCHLUMPF=SMURFF"));
        assert_se(streq(r[2], "NANANANA=YES"));
        assert_se(streq(r[3], "WALDO=WALDO"));
        assert_se(strv_length(r) == 4);
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
        _cleanup_free_ char *t = NULL, *s = NULL, *q = NULL, *r = NULL, *p = NULL, *x = NULL;
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
                                                "BASH_FUNC_foo%%=() {  echo foo\n}");
        assert_se(e);
        assert_se(!strv_env_is_valid(e));
        assert_se(strv_env_clean(e) == e);
        assert_se(strv_env_is_valid(e));

        assert_se(streq(e[0], "FOOBAR=WALDO"));
        assert_se(streq(e[1], "X="));
        assert_se(streq(e[2], "F=F"));
        assert_se(streq(e[3], "0000=000"));
        assert_se(streq(e[4], "abcd=äöüß"));
        assert_se(streq(e[5], "xyz=xyz\n"));
        assert_se(streq(e[6], "another=final one"));
        assert_se(streq(e[7], "BASH_FUNC_foo%%=() {  echo foo\n}"));
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
        assert_se( env_name_is_valid("5_starting_with_a_number_is_unexpected_but_valid"));
        assert_se(!env_name_is_valid("#¤%&?_only_numbers_letters_and_underscore_allowed"));
        assert_se( env_name_is_valid("BASH_FUNC_foo%%"));
        assert_se(!env_name_is_valid("with spaces%%"));
        assert_se(!env_name_is_valid("with\nnewline%%"));
}

static void test_env_value_is_valid(void) {
        log_info("/* %s */", __func__);

        assert_se(env_value_is_valid(""));
        assert_se(env_value_is_valid("głąb kapuściany"));
        assert_se(env_value_is_valid("printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
        assert_se(env_value_is_valid("tab\tcharacter"));
        assert_se(env_value_is_valid("new\nline"));
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
        /* Names with dots and dashes makes those variables inaccessible as bash variables (as the syntax
         * simply does not allow such variable names, see http://tldp.org/LDP/abs/html/gotchas.html). They
         * are still valid variables according to POSIX though. */
        assert_se( env_assignment_is_valid("a.b="));
        assert_se( env_assignment_is_valid("a-b="));
        /* Those are not ASCII, so not valid according to POSIX (though zsh does allow unicode variable
         * names…). */
        assert_se(!env_assignment_is_valid("\007=głąb kapuściany"));
        assert_se(!env_assignment_is_valid("c\009=\007\009\011"));
        assert_se(!env_assignment_is_valid("głąb=printf \"\x1b]0;<mock-chroot>\x07<mock-chroot>\""));
}

int main(int argc, char *argv[]) {
        test_strv_env_delete();
        test_strv_env_get();
        test_strv_env_unset();
        test_strv_env_set();
        test_strv_env_merge();
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

        return 0;
}
