/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-seq.h"
#include "escape.h"
#include "tests.h"

static void feed_string(AnsiSeqParser *p, const char *s, const char *expected_events) {
        size_t e = 0;
        int r;

        _cleanup_free_ char *escaped = ASSERT_PTR(cescape(s));

        log_info("looking at: %s", escaped);

        /* NB: an aborted character is fed twice and hence produces two events, i.e. the expected event
         * string may be longer than the input string */

        for (size_t i = 0; s[i]; i++)
                for (;;) {
                        r = ansi_seq_parser_feed(p, s[i]);
                        ASSERT_OK(r);

                        AnsiSeqEvent expected;

                        switch (expected_events[e++]) {
                        case 't':
                                expected = ANSI_SEQ_EVENT_TEXT;
                                break;
                        case 's':
                                expected = ANSI_SEQ_EVENT_SEQUENCE;
                                break;
                        case 'e':
                                expected = ANSI_SEQ_EVENT_END;
                                break;
                                break;
                        case 'a':
                                expected = ANSI_SEQ_EVENT_ABORT;
                                break;
                        default:
                                assert_not_reached();
                        }

                        ASSERT_EQ(r, (int) expected);

                        if (r != ANSI_SEQ_EVENT_ABORT) /* aborted characters must be fed again */
                                break;
                }

        ASSERT_EQ(expected_events[e], '\0');
}

TEST(ansi_seq_parser) {
        _cleanup_(ansi_seq_parser_done) AnsiSeqParser p = { .capture = true };

        /* Regular text */
        feed_string(&p, "hello\n\r", "ttttttt");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* A CSI color sequence */
        feed_string(&p, "\x1B[0;31m", "sssssse");
        ASSERT_EQ(p.introducer, '[');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "0;31m");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* A two-character escape sequence */
        feed_string(&p, "\x1B" "c", "se");
        ASSERT_EQ(p.introducer, 'c');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* A CSI sequence with DEC private parameters */
        feed_string(&p, "\x1B[?25l", "ssssse");
        ASSERT_EQ(p.introducer, '[');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "?25l");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* An nF escape sequence */
        feed_string(&p, "\x1B(B", "sse");
        ASSERT_EQ(p.introducer, '(');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "B");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* An nF escape sequence with a 0x2F intermediate byte */
        feed_string(&p, "\x1B#/0", "ssse");
        ASSERT_EQ(p.introducer, '#');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "/0");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* An OSC sequence terminated by BEL */
        feed_string(&p, "\x1B]0;title\a", "ssssssssse");
        ASSERT_EQ(p.introducer, ']');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "0;title");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* An OSC sequence terminated by ST, interleaved feeding */
        feed_string(&p, "\x1B]28", "ssss");
        feed_string(&p, "11;width=80;height=24\x1B\\", "sssssssssssssssssssssse");
        ASSERT_EQ(p.introducer, ']');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "2811;width=80;height=24");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* A DCS sequence: tracked, payload captured with 'P' introducer */
        feed_string(&p, "\x1BPxyz\x1B\\", "sssssse");
        ASSERT_EQ(p.introducer, 'P');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "xyz");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* An aborted OSC sequence: the \n is replayed as text */
        feed_string(&p, "\x1B]123\n", "sssssat");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));

        /* An overlong string sequence */
        feed_string(&p, "\x1B]", "ss");
        for (size_t i = 0; i < ANSI_SEQ_STRING_MAX; i++)
                ASSERT_EQ(ansi_seq_parser_feed(&p, 'x'), ANSI_SEQ_EVENT_SEQUENCE);
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'x'), ANSI_SEQ_EVENT_ABORT);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));

        /* Capturing works again afterwards */
        feed_string(&p, "\x1B]foo\a", "ssssse");
        ASSERT_EQ(p.introducer, ']');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "foo");
}

DEFINE_TEST_MAIN(LOG_INFO);
