/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"

TEST(strip_tab_ansi) {
        _cleanup_free_ char *urlified = NULL, *q = NULL;
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

        /* Two-character Fe sequences (7-bit C1 controls, such as RI) are dropped as a whole: the final
         * character must not leak through as text */
        assert_se(p = strdup("a\x1BMb\x1B" "Ec\x1B\\d"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "abcd");
        free(p);

        /* A carriage return followed by a (dropped) sequence is not trailing, and hence kept … */
        assert_se(p = strdup("y\r\x1B[m"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "y\r");
        free(p);

        /* … also if a (dropped) two-character Fe sequence was encountered earlier … */
        assert_se(p = strdup("\x1BZy\r\x1B[m"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "y\r");
        free(p);

        /* … or an aborted sequence (the aborting character is replayed as text) */
        assert_se(p = strdup("\x1B\ny\r\x1B[m"));
        assert_se(strip_tab_ansi(&p, NULL, NULL));
        ASSERT_STREQ(p, "\ny\r");
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
                /* NB: d starts with the tail of the truncated ST, i.e. a stray "ESC \", which is a complete
                 * Fe sequence, and hence dropped in its entirety */
                ASSERT_STREQ(d, "i am a fabulous link something-else");
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

TEST(strip_tab_ansi_highlight) {
        /* The highlight offsets (as used by "journalctl --grep" to mark the matched range) refer to the
         * input, and must be moved along with it: TAB expansion pushes them forward, dropped sequences pull
         * them back. */

        const char *in = "\tfoo" ANSI_HIGHLIGHT "bar" ANSI_NORMAL "\tbaz" ANSI_HIGHLIGHT_RED "qux";
        const char *out = "        foobar        bazqux";
        size_t bar = strlen("\tfoo" ANSI_HIGHLIGHT),
               qux = strlen("\tfoo" ANSI_HIGHLIGHT "bar" ANSI_NORMAL "\tbaz" ANSI_HIGHLIGHT_RED);

        /* A range following a TAB and a dropped sequence, ending right where another sequence starts */
        _cleanup_free_ char *p = ASSERT_PTR(strdup(in));
        size_t highlight[2] = { bar, bar + 3 };
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, out);
        ASSERT_EQ(highlight[0], 11U);
        ASSERT_EQ(highlight[1], 14U);
        ASSERT_EQ(memcmp(p + highlight[0], "bar", 3), 0);

        /* A range past two TABs and three dropped sequences */
        p = mfree(p);
        p = ASSERT_PTR(strdup(in));
        highlight[0] = qux;
        highlight[1] = qux + 3;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, out);
        ASSERT_EQ(highlight[0], 25U);
        ASSERT_EQ(highlight[1], 28U);
        ASSERT_EQ(memcmp(p + highlight[0], "qux", 3), 0);

        /* A range that starts inside a dropped sequence collapses onto its beginning */
        p = mfree(p);
        p = ASSERT_PTR(strdup(in));
        highlight[0] = bar - 2;
        highlight[1] = bar + 3;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, out);
        ASSERT_EQ(highlight[0], 11U);
        ASSERT_EQ(highlight[1], 14U);

        /* A range spanning TABs and sequences: both ends move independently */
        p = mfree(p);
        p = ASSERT_PTR(strdup(in));
        highlight[0] = 1; /* "foo" */
        highlight[1] = qux + 3;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, out);
        ASSERT_EQ(highlight[0], 8U);
        ASSERT_EQ(highlight[1], 28U);

        /* An aborted (and hence dropped) sequence before a TAB: only the ESC is dropped, the aborting
         * character is replayed as text */
        p = mfree(p);
        p = ASSERT_PTR(strdup("\x1B\x01\tab"));
        highlight[0] = 3;
        highlight[1] = 5;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, "\x01        ab");
        ASSERT_EQ(highlight[0], 9U);
        ASSERT_EQ(highlight[1], 11U);

        /* A dropped two-character Fe sequence before a TAB */
        p = mfree(p);
        p = ASSERT_PTR(strdup("\x1BZ\tab"));
        highlight[0] = 3;
        highlight[1] = 5;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, "        ab");
        ASSERT_EQ(highlight[0], 8U);
        ASSERT_EQ(highlight[1], 10U);

        /* A truncated sequence at the very end is dropped, too: a range reaching into it is clamped to the
         * end of the output, rather than pointing past it */
        p = mfree(p);
        p = ASSERT_PTR(strdup("ab\x1B[31"));
        highlight[0] = 1;
        highlight[1] = 5;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, "ab");
        ASSERT_EQ(highlight[0], 1U);
        ASSERT_EQ(highlight[1], 2U);

        /* Nothing to shift: a range before all of it stays put */
        p = mfree(p);
        p = ASSERT_PTR(strdup("ab\t" ANSI_HIGHLIGHT "c"));
        highlight[0] = 0;
        highlight[1] = 2;
        ASSERT_NOT_NULL(strip_tab_ansi(&p, NULL, highlight));
        ASSERT_STREQ(p, "ab        c");
        ASSERT_EQ(highlight[0], 0U);
        ASSERT_EQ(highlight[1], 2U);
}

DEFINE_TEST_MAIN(LOG_INFO);
