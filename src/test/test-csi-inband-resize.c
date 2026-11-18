/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-seq.h"
#include "csi-inband-resize.h"
#include "tests.h"

static void test_request_one(const char *csi, int expected_r, InbandResizeRequest expected_request, const char *expected_remaining) {
        _cleanup_free_ char *remaining = NULL;
        InbandResizeRequest request;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_request(csi, &request, &remaining), expected_r);
        if (expected_r <= 0)
                return;

        ASSERT_EQ(request, expected_request);
        ASSERT_STREQ(remaining, expected_remaining);
}

TEST(inband_resize_parse_request) {
        /* Not ours */
        test_request_one("", 0, 0, NULL);
        test_request_one("?", 0, 0, NULL);
        test_request_one("2048h", 0, 0, NULL);          /* not a DEC private mode */
        test_request_one("?2049h", 0, 0, NULL);
        test_request_one("?20480h", 0, 0, NULL);
        test_request_one("?204h", 0, 0, NULL);
        test_request_one("?1049;25l", 0, 0, NULL);
        test_request_one("?2048m", 0, 0, NULL);
        test_request_one("?2048 h", 0, 0, NULL);        /* intermediate byte */
        test_request_one("?2048:1h", 0, 0, NULL);
        test_request_one("?2048;2048$p", 0, 0, NULL);   /* DECRQM covers a single mode only */
        test_request_one("?2048p", 0, 0, NULL);
        test_request_one("?2048;2$y", 0, 0, NULL);      /* a DECRPM reply, not a request */

        /* Only our mode */
        test_request_one("?2048h", 1, INBAND_RESIZE_ENABLE, NULL);
        test_request_one("?2048l", 1, INBAND_RESIZE_DISABLE, NULL);
        test_request_one("?02048h", 1, INBAND_RESIZE_ENABLE, NULL);
        test_request_one("?2048;2048h", 1, INBAND_RESIZE_ENABLE, NULL);
        test_request_one("?2048$p", 1, INBAND_RESIZE_QUERY, NULL);

        /* Mixed with other modes, which must be kept in order */
        test_request_one("?1049;2048h", 1, INBAND_RESIZE_ENABLE, "?1049h");
        test_request_one("?2048;1049l", 1, INBAND_RESIZE_DISABLE, "?1049l");
        test_request_one("?25;2048;1049h", 1, INBAND_RESIZE_ENABLE, "?25;1049h");
        test_request_one("?;2048;h", 1, INBAND_RESIZE_ENABLE, "?;h");
}

static void test_report_one(const char *csi, int expected_r, unsigned lines, unsigned columns, unsigned height_pixels, unsigned width_pixels) {
        InbandResizeReport report;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_report(csi, &report), expected_r);
        if (expected_r <= 0)
                return;

        ASSERT_EQ(report.lines, lines);
        ASSERT_EQ(report.columns, columns);
        ASSERT_EQ(report.height_pixels, height_pixels);
        ASSERT_EQ(report.width_pixels, width_pixels);
}

TEST(inband_resize_parse_report) {
        /* Not ours */
        test_report_one("", 0, 0, 0, 0, 0);
        test_report_one("t", 0, 0, 0, 0, 0);
        test_report_one("8;24;80t", 0, 0, 0, 0, 0);        /* XTWINOPS text area size report in characters */
        test_report_one("4;240;1600t", 0, 0, 0, 0, 0);
        test_report_one("480;24;80t", 0, 0, 0, 0, 0);
        test_report_one("?48;24;80;0;0t", 0, 0, 0, 0, 0);
        test_report_one("48;24;80;0;0 t", 0, 0, 0, 0, 0);
        test_report_one("48;24;80;0;0m", 0, 0, 0, 0, 0);

        /* Regular reports */
        test_report_one("48;24;80;240;1600t", 1, 24, 80, 240, 1600);
        test_report_one("48;48;80;480;1600t", 1, 48, 80, 480, 1600);
        test_report_one("48;24;80;0;0t", 1, 24, 80, 0, 0);

        /* Missing, empty or unparsable fields are treated as 0, extra fields are ignored */
        test_report_one("48t", 1, 0, 0, 0, 0);
        test_report_one("48;24;80t", 1, 24, 80, 0, 0);
        test_report_one("48;;80;;t", 1, 0, 80, 0, 0);
        test_report_one("48;65536;65535;0;0t", 1, 0, 65535, 0, 0);
        test_report_one("48;24;80;240;1600;7;8t", 1, 24, 80, 240, 1600);

        /* Sub-parameters are ignored */
        test_report_one("48:1;24:2:3;80:;240;1600:9t", 1, 24, 80, 240, 1600);
}

static void round_trip(const char *seq, InbandResizeReport *ret) {
        assert(seq);
        assert(ret);

        /* Feeds the sequence through the ANSI sequence parser, the way ptybrokerd does, and parses the
         * captured payload back. This verifies that what inband_resize_format_report() generates and what
         * inband_resize_parse_report() expects agree on the boundaries of the payload, i.e. on which part
         * the parser hands over and which it swallows. */

        _cleanup_(ansi_seq_parser_done) AnsiSeqParser parser = { .capture = true };

        for (const char *c = seq; *c; c++) {
                int event = ansi_seq_parser_feed(&parser, *c);
                ASSERT_OK(event);

                /* The sequence ends exactly with the last character, and there's no text before it */
                ASSERT_EQ(event, c[1] == 0 ? ANSI_SEQ_EVENT_END : ANSI_SEQ_EVENT_SEQUENCE);
        }

        ASSERT_EQ(parser.introducer, '['); /* It's a CSI sequence */

        const char *payload = ASSERT_PTR(ansi_seq_parser_string(&parser));
        ASSERT_EQ(inband_resize_parse_report(payload, ret), 1);
}

TEST(inband_resize_format_report) {
        _cleanup_free_ char *seq = NULL;
        InbandResizeReport report;

        ASSERT_OK(inband_resize_format_report(
                                  &(const InbandResizeReport) {
                                          .lines = 24,
                                          .columns = 80,
                                          .height_pixels = 240,
                                          .width_pixels = 1600,
                                  },
                                  &seq));
        ASSERT_STREQ(seq, "\x1B[48;24;80;240;1600t");
        round_trip(seq, &report);
        ASSERT_EQ(report.lines, 24U);
        ASSERT_EQ(report.columns, 80U);
        ASSERT_EQ(report.height_pixels, 240U);
        ASSERT_EQ(report.width_pixels, 1600U);
        seq = mfree(seq);

        ASSERT_OK(inband_resize_format_report(&(const InbandResizeReport) { .lines = 65535, .columns = 1 }, &seq));
        ASSERT_STREQ(seq, "\x1B[48;65535;1;0;0t");
        round_trip(seq, &report);
        ASSERT_EQ(report.lines, 65535U);
        ASSERT_EQ(report.columns, 1U);
        ASSERT_EQ(report.height_pixels, 0U);
        ASSERT_EQ(report.width_pixels, 0U);
}

TEST(inband_resize_format_mode_report) {
        _cleanup_free_ char *seq = NULL;

        ASSERT_OK(inband_resize_format_mode_report(/* enabled= */ true, &seq));
        ASSERT_STREQ(seq, "\x1B[?2048;1$y");
        seq = mfree(seq);

        ASSERT_OK(inband_resize_format_mode_report(/* enabled= */ false, &seq));
        ASSERT_STREQ(seq, "\x1B[?2048;2$y");

        /* The enable/disable sequences we generate are recognized by our own parser */
        _cleanup_free_ char *remaining = NULL;
        InbandResizeRequest request;
        ASSERT_EQ(inband_resize_parse_request(&ANSI_INBAND_RESIZE_ENABLE[2], &request, &remaining), 1);
        ASSERT_EQ(request, INBAND_RESIZE_ENABLE);
        ASSERT_NULL(remaining);
        ASSERT_EQ(inband_resize_parse_request(&ANSI_INBAND_RESIZE_DISABLE[2], &request, &remaining), 1);
        ASSERT_EQ(request, INBAND_RESIZE_DISABLE);
        ASSERT_NULL(remaining);
}

DEFINE_TEST_MAIN(LOG_INFO);
