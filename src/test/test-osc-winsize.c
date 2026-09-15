/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-seq.h"
#include "osc-winsize.h"
#include "tests.h"

TEST(osc_winsize_parse) {
        OscWinsize ws;

        /* Not OSC 2811 */
        ASSERT_EQ(osc_winsize_parse("0;some title", &ws), 0);
        ASSERT_EQ(osc_winsize_parse("28110;foo", &ws), 0);
        ASSERT_EQ(osc_winsize_parse("281", &ws), 0);

        /* A subscribe sequence */
        ASSERT_EQ(osc_winsize_parse("2811;?;columns=80;lines=24", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE);
        ASSERT_EQ(ws.columns, 80U);
        ASSERT_EQ(ws.lines, 24U);

        /* Field order is undefined */
        ASSERT_EQ(osc_winsize_parse("2811;?;lines=24;columns=80", &ws), 1);
        ASSERT_EQ(ws.columns, 80U);
        ASSERT_EQ(ws.lines, 24U);

        /* The cancel sequence */
        ASSERT_EQ(osc_winsize_parse("2811;?", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_CANCEL);

        /* A report sequence */
        ASSERT_EQ(osc_winsize_parse("2811;columns=120;lines=40", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 120U);
        ASSERT_EQ(ws.lines, 40U);

        /* Unknown fields are ignored, missing/unparsable fields are treated as 0 */
        ASSERT_EQ(osc_winsize_parse("2811;?;pixelcolumns=1024;lines=abc", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE); /* fields were present, just not understood, hence not a cancel */
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 0U);

        /* Out of range values are unparsable, hence 0 */
        ASSERT_EQ(osc_winsize_parse("2811;columns=65536;lines=65535", &ws), 1);
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 65535U);

        /* A '?' that is not the first field is just an unknown field */
        ASSERT_EQ(osc_winsize_parse("2811;columns=80;?", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);

        /* The '?' marker must be a field of its own */
        ASSERT_EQ(osc_winsize_parse("2811;?columns=80", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 0U);

        /* Boundary cases: the bare number, with or without a trailing separator, is a report of 0x0 */
        ASSERT_EQ(osc_winsize_parse("2811", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 0U);

        ASSERT_EQ(osc_winsize_parse("2811;", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 0U);

        /* A trailing empty field after the marker counts as a field, hence this is a subscription (with
         * unknown dimensions), not a cancellation */
        ASSERT_EQ(osc_winsize_parse("2811;?;", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE);
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 0U);

        /* Duplicate fields: the last one wins */
        ASSERT_EQ(osc_winsize_parse("2811;columns=1;columns=2;lines=3;lines=4", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 2U);
        ASSERT_EQ(ws.lines, 4U);

        /* Empty and negative values are unparsable, hence 0 */
        ASSERT_EQ(osc_winsize_parse("2811;columns=;lines=-1", &ws), 1);
        ASSERT_EQ(ws.columns, 0U);
        ASSERT_EQ(ws.lines, 0U);
}

static void round_trip(const char *seq, OscWinsize *ret) {
        assert(seq);
        assert(ret);

        /* Feeds the sequence through the ANSI sequence parser, the way the consumers of these sequences
         * (ptyfwd, ptybroker) do, and parses the captured payload back. This verifies that what
         * osc_winsize_format() generates and what osc_winsize_parse() expects agree on the boundaries
         * of the payload, i.e. on which part the parser hands over and which it swallows. */

        _cleanup_(ansi_seq_parser_done) AnsiSeqParser parser = { .capture = true };

        for (const char *c = seq; *c; c++) {
                int event = ansi_seq_parser_feed(&parser, *c);
                ASSERT_OK(event);

                /* The sequence ends exactly with the last character, and there's no text before it */
                ASSERT_EQ(event, c[1] == 0 ? ANSI_SEQ_EVENT_END : ANSI_SEQ_EVENT_SEQUENCE);
        }

        ASSERT_EQ(parser.introducer, ']'); /* It's an OSC sequence */

        const char *payload = ASSERT_PTR(ansi_seq_parser_string(&parser));
        ASSERT_EQ(osc_winsize_parse(payload, ret), 1);
}

TEST(osc_winsize_format) {
        _cleanup_free_ char *seq = NULL;
        OscWinsize ws;

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_SUBSCRIBE, 80, 24, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;?;columns=80;lines=24\x1B\\");
        round_trip(seq, &ws);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE);
        ASSERT_EQ(ws.columns, 80U);
        ASSERT_EQ(ws.lines, 24U);
        seq = mfree(seq);

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_CANCEL, 0, 0, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;?\x1B\\");
        round_trip(seq, &ws);
        ASSERT_EQ(ws.type, OSC_WINSIZE_CANCEL);
        seq = mfree(seq);

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_REPORT, 120, 40, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;columns=120;lines=40\x1B\\");
        round_trip(seq, &ws);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.columns, 120U);
        ASSERT_EQ(ws.lines, 40U);
}

DEFINE_TEST_MAIN(LOG_INFO);
