/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <unistd.h>
#include <string.h>

#include "util.h"
#include "strv.h"

static void test_strv_env_delete(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **c = NULL, **d = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", NULL);
        b = strv_new("PIEP", "FOO", NULL);
        c = strv_new("SCHLUMPF", NULL);

        d = strv_env_delete(a, 2, b, c);

        assert(streq(d[0], "WALDO=WALDO"));
        assert(streq(d[1], "WALDO="));
        assert(strv_length(d) == 2);
}

static void test_strv_env_unset(void) {
        _cleanup_strv_free_ char **l = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);

        strv_env_unset(l, "SCHLUMPF");

        assert(streq(l[0], "PIEP"));
        assert(streq(l[1], "NANANANA=YES"));
        assert(strv_length(l) == 2);
}

static void test_strv_env_set(void) {
        _cleanup_strv_free_ char **l = NULL, **r = NULL;

        l = strv_new("PIEP", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);

        r = strv_env_set(l, "WALDO=WALDO");

        assert(streq(r[0], "PIEP"));
        assert(streq(r[1], "SCHLUMPF=SMURFF"));
        assert(streq(r[2], "NANANANA=YES"));
        assert(streq(r[3], "WALDO=WALDO"));
        assert(strv_length(r) == 4);
}

static void test_strv_env_merge(void) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL, **r = NULL;

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", NULL);
        b = strv_new("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);

        r = strv_env_merge(2, a, b);
        assert(streq(r[0], "FOO="));
        assert(streq(r[1], "WALDO="));
        assert(streq(r[2], "PIEP"));
        assert(streq(r[3], "SCHLUMPF=SMURFF"));
        assert(streq(r[4], "PIEP="));
        assert(streq(r[5], "NANANANA=YES"));
        assert(strv_length(r) == 6);

        strv_env_clean(r);
        assert(streq(r[0], "PIEP"));
        assert(streq(r[1], "SCHLUMPF=SMURFF"));
        assert(streq(r[2], "NANANANA=YES"));
        assert(strv_length(r) == 3);
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
                NULL
        };
        _cleanup_strv_free_ char **r = NULL;

        r = replace_env_argv((char**) line, (char**) env);
        assert(streq(r[0], "FOO$FOO"));
        assert(streq(r[1], "FOO$FOOFOO"));
        assert(streq(r[2], "FOOBAR BAR$FOO"));
        assert(streq(r[3], "FOOBAR BAR"));
        assert(streq(r[4], "BAR BAR"));
        assert(streq(r[5], "BAR"));
        assert(streq(r[6], "BAR"));
        assert(streq(r[7], "BAR BARwaldo"));
        assert(streq(r[8], "${FOO"));
        assert(strv_length(r) == 9);
}

static void test_one_normalize(const char *input, const char *output)
{
        _cleanup_free_ char *t;

        t = normalize_env_assignment(input);
        assert(streq(t, output));
}

static void test_normalize_env_assignment(void) {
        test_one_normalize("foo=bar", "foo=bar");
        test_one_normalize("=bar", "=bar");
        test_one_normalize("foo=", "foo=");
        test_one_normalize("=", "=");
        test_one_normalize("", "");
        test_one_normalize("a=\"waldo\"", "a=waldo");
        test_one_normalize("a=\"waldo", "a=\"waldo");
        test_one_normalize("a=waldo\"", "a=waldo\"");
        test_one_normalize("a=\'", "a='");
        test_one_normalize("a=\'\'", "a=");
        test_one_normalize(" xyz  ", "xyz");
        test_one_normalize(" xyz = bar  ", "xyz=bar");
        test_one_normalize(" xyz = 'bar ' ", "xyz=bar ");
        test_one_normalize(" ' xyz' = 'bar ' ", "' xyz'=bar ");
}

int main(int argc, char *argv[]) {
        test_strv_env_delete();
        test_strv_env_unset();
        test_strv_env_set();
        test_strv_env_merge();
        test_replace_env_arg();
        test_normalize_env_assignment();

        return 0;
}
