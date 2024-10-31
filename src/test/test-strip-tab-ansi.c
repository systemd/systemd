/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"

TEST(strip_tab_ansi) {
        _cleanup_free_ char *urlified = NULL, *q = NULL, *qq = NULL;
        char *p, *z;

        assert_se(p = strdup("\tFoobar\tbar\twaldo\t"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        fprintf(stdout, "<%s>\n", p);
        ASSERT_STREQ(p, "        Foobar        bar        waldo        ");
        free(p);

        assert_se(p = strdup(ANSI_HIGHLIGHT "Hello" ANSI_NORMAL ANSI_HIGHLIGHT_RED " world!" ANSI_NORMAL));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        fprintf(stdout, "<%s>\n", p);
        ASSERT_STREQ(p, "Hello world!");
        free(p);

        assert_se(p = strdup("\x1B[\x1B[\t\x1B[" ANSI_HIGHLIGHT "\x1B[" "Hello" ANSI_NORMAL ANSI_HIGHLIGHT_RED " world!" ANSI_NORMAL));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "\x1B[\x1B[        \x1B[\x1B[Hello world!");
        free(p);

        assert_se(p = strdup("\x1B[waldo"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "\x1B[waldo");
        free(p);

        assert_se(p = strdup("\r\rwaldo"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "\r\rwaldo");
        free(p);

        assert_se(p = strdup("waldo\r\r"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "waldo");
        free(p);

        assert_se(p = strdup("waldo\r\r\n\r\n"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "waldo\n\n");
        free(p);

        assert_se(terminal_urlify_path("/etc/fstab", "i am a fabulous link", &urlified) >= 0);
        assert_se(p = strjoin("something ", urlified, " something-else"));
        assert_se(q = strdup(p));
        printf("<%s>\n", p);
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        printf("<%s>\n", p);
        ASSERT_STREQ(p, "something i am a fabulous link something-else");
        p = mfree(p);

        /* Truncate the formatted string in the middle of an ANSI sequence (in which case we shouldn't touch the
         * incomplete sequence) */
        z = strstr(q, "fstab");
        if (z) {
                *z = 0;
                assert_se(qq = strdup(q));
                assert_se(strip_tab_ansi(&q, NULL, NULL));
                ASSERT_STREQ(q, qq);
        }

        /* Test that both kinds of ST are recognized after OSC */
        assert_se(p = strdup("before" ANSI_OSC "inside1" ANSI_ST
                             "between1" ANSI_OSC "inside2\a"
                             "between2" ANSI_OSC "inside3\x1b\x5c"
                             "after"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "beforebetween1between2after");
        free(p);
}

DEFINE_TEST_MAIN(LOG_INFO);
