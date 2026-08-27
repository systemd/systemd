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

        /* Aborted sequences and complete ones are dropped (note that "\x1B[H" below is
         * a complete CSI sequence, hence "Hello" loses its first character) */
        assert_se(p = strdup("\x1B[\x1B[\t\x1B[" ANSI_HIGHLIGHT "\x1B[" "Hello" ANSI_NORMAL ANSI_HIGHLIGHT_RED " world!" ANSI_NORMAL));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "        ello world!");
        free(p);

        /* "\x1B[w" is a complete CSI sequence, too */
        assert_se(p = strdup("\x1B[waldo"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "aldo");
        free(p);

        /* Non-SGR CSI sequences are dropped as well */
        assert_se(p = strdup("foo\x1B[2Jbar\x1B[?25lbaz"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "foobarbaz");
        free(p);

        /* A carriage return followed by a (dropped) sequence is not trailing, and hence kept … */
        assert_se(p = strdup("y\r\x1B[m"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "y\r");
        free(p);

        /* … also if an aborted sequence was encountered earlier */
        assert_se(p = strdup("\x1BZy\r\x1B[m"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "Zy\r");
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

        /* Truncate the formatted string in the middle of an ANSI sequence */
        z = strstr(q, "fstab");
        if (z) {
                *z = 0;
                _cleanup_free_ char *d = ASSERT_PTR(strdup(z+5));

                assert_se(strip_tab_ansi(&q, NULL, NULL));
                assert_se(strip_tab_ansi(&d, NULL, NULL));

                ASSERT_STREQ(q, "something ");
                ASSERT_STREQ(d, "\\i am a fabulous link something-else");
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
