/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

#include <stdio.h>

#include "string-util.h"
#include "terminal-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        char *p;

        assert_se(p = strdup("\tFoobar\tbar\twaldo\t"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        fprintf(stdout, "<%s>\n", p);
        assert_se(streq(p, "        Foobar        bar        waldo        "));
        free(p);

        assert_se(p = strdup(ANSI_HIGHLIGHT "Hello" ANSI_NORMAL ANSI_HIGHLIGHT_RED " world!" ANSI_NORMAL));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        fprintf(stdout, "<%s>\n", p);
        assert_se(streq(p, "Hello world!"));
        free(p);

        assert_se(p = strdup("\x1B[\x1B[\t\x1B[" ANSI_HIGHLIGHT "\x1B[" "Hello" ANSI_NORMAL ANSI_HIGHLIGHT_RED " world!" ANSI_NORMAL));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        assert_se(streq(p, "\x1B[\x1B[        \x1B[\x1B[Hello world!"));
        free(p);

        assert_se(p = strdup("\x1B[waldo"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        assert_se(streq(p, "\x1B[waldo"));
        free(p);

        return 0;
}
