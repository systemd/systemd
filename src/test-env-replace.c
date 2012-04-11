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
#include "log.h"
#include "strv.h"

int main(int argc, char *argv[]) {

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

        char **i, **r, *t, **a, **b;
        const char nulstr[] = "fuck\0fuck2\0fuck3\0\0fuck5\0\0xxx";

        a = strv_parse_nulstr(nulstr, sizeof(nulstr)-1);

        STRV_FOREACH(i, a)
                printf("nulstr--%s\n", *i);

        strv_free(a);

        r = replace_env_argv((char**) line, (char**) env);

        STRV_FOREACH(i, r)
                printf("%s\n", *i);

        strv_free(r);

        t = normalize_env_assignment("foo=bar");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("=bar");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("foo=");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("=");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("a=\"waldo\"");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("a=\"waldo");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("a=waldo\"");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("a=\'");
        printf("%s\n", t);
        free(t);

        t = normalize_env_assignment("a=\'\'");
        printf("%s\n", t);
        free(t);

        a = strv_new("FOO=BAR", "WALDO=WALDO", "WALDO=", "PIEP", "SCHLUMPF=SMURF", NULL);
        b = strv_new("FOO=KKK", "FOO=", "PIEP=", "SCHLUMPF=SMURFF", "NANANANA=YES", NULL);

        r = strv_env_merge(2, a, b);
        strv_free(a);
        strv_free(b);

        STRV_FOREACH(i, r)
                printf("%s\n", *i);

        printf("CLEANED UP:\n");

        r = strv_env_clean(r);

        STRV_FOREACH(i, r)
                printf("%s\n", *i);

        strv_free(r);

        return 0;
}
