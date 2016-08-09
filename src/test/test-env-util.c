/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2016 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "env-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static void test_strv_env_delete(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", NULL);
        assert_se(a);

        b = strv_new("PIEP", "FOO", NULL);
        assert_se(b);

        c = strv_new("SCHLUMPF", NULL);
        assert_se(c);

        d = strv_env_delete(a, 2, b, c);
        assert_se(d);

        assert_se(streq(d[0], "WALDO=WALDO"));
        assert_se(streq(d[1], "WALDO="));
        assert_se(strv_length(d) == 2);
}

static void test_strv_env_get(void) {
        _cleanup_strv_free_ char **l = NULL;

        l = strv_new("ONE_OR_TWO=1", "THREE=3", "ONE_OR_TWO=2", "FOUR=4", NULL);
        assert_se(l);

        assert_se(streq(strv_env_get(l, "ONE_OR_TWO"), "2"));
        assert_se(streq(strv_env_get(l, "THREE"), "3"));
        assert_se(streq(strv_env_get(l, "FOUR"), "4"));
}

static void test_strv_env_unset(void) {
        _cleanup_strv_free_ char **l = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);
        assert_se(l);

        assert_se(strv_env_unset(l, "SCHLUMPF") == l);

        assert_se(streq(l[0], "PIEP"));
        assert_se(streq(l[1], "NANANANA=YES"));
        assert_se(strv_length(l) == 2);
}

static void test_strv_env_set(void) {
        _cleanup_strv_free_ char **l = NULL, **r = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);
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
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **r = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", NULL);
        assert_se(a);

        b = strv_new("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);
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

static void test_replace_env_arg(void) {
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
        assert_se(streq(r[11], "BAR BAR"));
        assert_se(streq(r[12], "BAR BAR"));
        assert_se(streq(r[13], "waldo"));
        assert_se(streq(r[14], ""));
        assert_se(streq(r[15], "|waldo|}"));
        assert_se(streq(r[16], "|waldo{|"));
        assert_se(strv_length(r) == 17);
}

static void test_env_clean(void) {
        _cleanup_strv_free_ char **e;

        e = strv_new("FOOBAR=WALDO",
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
                     NULL);
        assert_se(e);
        assert_se(!strv_env_is_valid(e));
        assert_se(strv_env_clean(e) == e);
        assert_se(strv_env_is_valid(e));

        assert_se(streq(e[0], "FOOBAR=WALDO"));
        assert_se(streq(e[1], "X="));
        assert_se(streq(e[2], "F=F"));
        assert_se(streq(e[3], "abcd=äöüß"));
        assert_se(streq(e[4], "another=final one"));
        assert_se(e[5] == NULL);
}

static void test_env_name_is_valid(void) {
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
        assert_se(env_value_is_valid(""));
        assert_se(env_value_is_valid("głąb kapuściany"));
        assert_se(env_value_is_valid("printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));
}

static void test_env_assignment_is_valid(void) {
        assert_se(env_assignment_is_valid("a="));
        assert_se(env_assignment_is_valid("b=głąb kapuściany"));
        assert_se(env_assignment_is_valid("c=\\007\\009\\011"));
        assert_se(env_assignment_is_valid("e=printf \"\\x1b]0;<mock-chroot>\\x07<mock-chroot>\""));

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

int main(int argc, char *argv[]) {
        test_strv_env_delete();
        test_strv_env_get();
        test_strv_env_unset();
        test_strv_env_set();
        test_strv_env_merge();
        test_replace_env_arg();
        test_env_clean();
        test_env_name_is_valid();
        test_env_value_is_valid();
        test_env_assignment_is_valid();

        return 0;
}
