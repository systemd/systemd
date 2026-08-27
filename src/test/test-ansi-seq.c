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

        /* The other string sequence introducers: SOS, PM, APC */
        feed_string(&p, "\x1BXsos\x1B\\", "sssssse");
        ASSERT_EQ(p.introducer, 'X');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "sos");

        feed_string(&p, "\x1B^pm\a", "sssse");
        ASSERT_EQ(p.introducer, '^');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "pm");

        feed_string(&p, "\x1B_apc\a", "ssssse");
        ASSERT_EQ(p.introducer, '_');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "apc");

        /* A two-character Fp escape sequence (DECSC) */
        feed_string(&p, "\x1B" "7", "se");
        ASSERT_EQ(p.introducer, '7');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* Two-character Fe escape sequences, i.e. 7-bit encoded C1 controls (RI, NEL, a stray ST) */
        feed_string(&p, "\x1BM", "se");
        ASSERT_EQ(p.introducer, 'M');
        ASSERT_STREQ(ansi_seq_parser_string(&p), "");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        feed_string(&p, "\x1B" "E", "se");
        ASSERT_EQ(p.introducer, 'E');
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        feed_string(&p, "\x1B\\", "se");
        ASSERT_EQ(p.introducer, '\\');
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* ESC followed by something that cannot start a sequence: aborted, the character is replayed */
        feed_string(&p, "\x1B\n", "sat");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));

        /* An ESC inside a string sequence that is not followed by '\' (i.e. not ST): aborted, the
         * character following the ESC is replayed */
        feed_string(&p, "\x1B]foo\x1B" "x", "ssssssat");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));

        /* An overlong CSI sequence: aborted, even at its final byte */
        feed_string(&p, "\x1B[", "ss");
        for (size_t i = 0; i < ANSI_SEQ_STRING_MAX; i++)
                ASSERT_EQ(ansi_seq_parser_feed(&p, ';'), ANSI_SEQ_EVENT_SEQUENCE);
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'm'), ANSI_SEQ_EVENT_ABORT);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'm'), ANSI_SEQ_EVENT_TEXT);

        /* Ditto for an overlong nF sequence */
        feed_string(&p, "\x1B(", "ss");
        for (size_t i = 0; i < ANSI_SEQ_STRING_MAX; i++)
                ASSERT_EQ(ansi_seq_parser_feed(&p, ' '), ANSI_SEQ_EVENT_SEQUENCE);
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'B'), ANSI_SEQ_EVENT_ABORT);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'B'), ANSI_SEQ_EVENT_TEXT);

        /* And an overlong CSI sequence that continues past the limit with a non-final byte */
        feed_string(&p, "\x1B[", "ss");
        for (size_t i = 0; i < ANSI_SEQ_STRING_MAX; i++)
                ASSERT_EQ(ansi_seq_parser_feed(&p, '1'), ANSI_SEQ_EVENT_SEQUENCE);
        ASSERT_EQ(ansi_seq_parser_feed(&p, '1'), ANSI_SEQ_EVENT_ABORT);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_EQ(ansi_seq_parser_feed(&p, '1'), ANSI_SEQ_EVENT_TEXT);
}

static void feed_string_harder(AnsiSeqParser *p, const char *s, const char *expected_events) {
        size_t e = 0;

        _cleanup_free_ char *escaped = ASSERT_PTR(cescape(s));

        log_info("looking at (harder): %s", escaped);

        /* Unlike feed_string() this never sees abort events, as ansi_seq_parser_feed_harder() swallows
         * them, hence the expected event string has exactly one event per input character */

        for (size_t i = 0; s[i]; i++) {
                int r = ansi_seq_parser_feed_harder(p, s[i]);
                ASSERT_OK(r);
                ASSERT_NE(r, (int) ANSI_SEQ_EVENT_ABORT);

                switch (expected_events[e++]) {
                case 't':
                        ASSERT_EQ(r, (int) ANSI_SEQ_EVENT_TEXT);
                        break;
                case 's':
                        ASSERT_EQ(r, (int) ANSI_SEQ_EVENT_SEQUENCE);
                        break;
                case 'e':
                        ASSERT_EQ(r, (int) ANSI_SEQ_EVENT_END);
                        break;
                default:
                        assert_not_reached();
                }
        }

        ASSERT_EQ(expected_events[e], '\0');
}

TEST(ansi_seq_parser_feed_harder) {
        _cleanup_(ansi_seq_parser_done) AnsiSeqParser p = { .capture = true };

        /* Complete sequences work as with ansi_seq_parser_feed() */
        feed_string_harder(&p, "a\x1B[1mb", "tssset");
        ASSERT_STREQ(ansi_seq_parser_string(&p), "1m");

        /* An aborted OSC sequence: the aborting character is resubmitted internally and comes out as text */
        feed_string_harder(&p, "\x1B]123\nx", "ssssstt");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(ansi_seq_parser_string(&p));

        /* An aborted CSI sequence whose aborting character (ESC) starts a new sequence */
        feed_string_harder(&p, "\x1B[1\x1B[m", "ssssse");
        ASSERT_STREQ(ansi_seq_parser_string(&p), "m");
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        /* ESC ESC: the first ESC is dropped, the second one starts a sequence */
        feed_string_harder(&p, "\x1B\x1B[m", "ssse");
        ASSERT_STREQ(ansi_seq_parser_string(&p), "m");
}

TEST(ansi_seq_parser_no_capture) {
        _cleanup_(ansi_seq_parser_done) AnsiSeqParser p = {}; /* capture off */

        /* Boundaries are still tracked, but no payload is ever made available */
        feed_string(&p, "\x1B]0;title\a", "ssssssssse");
        ASSERT_EQ(p.introducer, ']');
        ASSERT_NULL(ansi_seq_parser_string(&p));
        ASSERT_NULL(p.string);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);

        feed_string(&p, "\x1B[0;31m", "sssssse");
        ASSERT_EQ(p.introducer, '[');
        ASSERT_NULL(ansi_seq_parser_string(&p));
        ASSERT_NULL(p.string);

        /* The length limit applies regardless */
        feed_string(&p, "\x1B]", "ss");
        for (size_t i = 0; i < ANSI_SEQ_STRING_MAX; i++)
                ASSERT_EQ(ansi_seq_parser_feed(&p, 'x'), ANSI_SEQ_EVENT_SEQUENCE);
        ASSERT_EQ(ansi_seq_parser_feed(&p, 'x'), ANSI_SEQ_EVENT_ABORT);
        ASSERT_EQ(p.state, ANSI_SEQ_STATE_GROUND);
        ASSERT_NULL(p.string);
}

DEFINE_TEST_MAIN(LOG_INFO);
