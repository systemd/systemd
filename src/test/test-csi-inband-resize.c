/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ansi-seq.h"
#include "csi-inband-resize.h"
#include "tests.h"

static void test_request_ignored(const char *csi) {
        _cleanup_free_ char *remaining = NULL;
        InbandResizeRequest request;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_request(csi, &request, &remaining), 0);
}

static void test_request_mixed(const char *csi, InbandResizeRequest expected_request, const char *expected_remaining) {
        _cleanup_free_ char *remaining = NULL;
        InbandResizeRequest request;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_request(csi, &request, &remaining), 1);
        ASSERT_EQ(request, expected_request);
        ASSERT_STREQ(remaining, expected_remaining);
}

static void test_request_one(const char *csi, InbandResizeRequest expected_request) {
        test_request_mixed(csi, expected_request, /* expected_remaining= */ NULL);
}

TEST(inband_resize_parse_request) {
        /* Not ours */
        test_request_ignored("");
        test_request_ignored("?");
        test_request_ignored("2048h");          /* not a DEC private mode */
        test_request_ignored("?2049h");
        test_request_ignored("?20480h");
        test_request_ignored("?204h");
        test_request_ignored("?1049;25l");
        test_request_ignored("?2048m");
        test_request_ignored("?2048 h");        /* intermediate byte */
        test_request_ignored("?2048:1h");
        test_request_ignored("?2048;2048$p");   /* DECRQM covers a single mode only */
        test_request_ignored("?2048p");
        test_request_ignored("?2048;2$y");      /* a DECRPM reply, not a request */

        /* Only our mode */
        test_request_one("?2048h", INBAND_RESIZE_ENABLE);
        test_request_one("?2048l", INBAND_RESIZE_DISABLE);
        test_request_one("?02048h", INBAND_RESIZE_ENABLE);
        test_request_one("?2048;2048h", INBAND_RESIZE_ENABLE);
        test_request_one("?2048$p", INBAND_RESIZE_QUERY);

        /* Mixed with other modes, which must be kept in order */
        test_request_mixed("?1049;2048h", INBAND_RESIZE_ENABLE, "?1049h");
        test_request_mixed("?2048;1049l", INBAND_RESIZE_DISABLE, "?1049l");
        test_request_mixed("?25;2048;1049h", INBAND_RESIZE_ENABLE, "?25;1049h");
        test_request_mixed("?;2048;h", INBAND_RESIZE_ENABLE, "?;h");
}

#define REPORT(l, c, h, w)                              \
        ((InbandResizeReport) {                         \
                .lines = (l),                           \
                .columns = (c),                         \
                .height_pixels = (h),                   \
                .width_pixels = (w),                    \
        })

static void test_report_ignored(const char *csi) {
        InbandResizeReport report;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_report(csi, &report), 0);
}

static void test_report_one(const char *csi, InbandResizeReport expected) {
        InbandResizeReport report;

        log_debug("/* %s(%s) */", __func__, csi);

        ASSERT_EQ(inband_resize_parse_report(csi, &report), 1);
        ASSERT_EQ(report.lines, expected.lines);
        ASSERT_EQ(report.columns, expected.columns);
        ASSERT_EQ(report.height_pixels, expected.height_pixels);
        ASSERT_EQ(report.width_pixels, expected.width_pixels);
}

TEST(inband_resize_parse_report) {
        /* Not ours */
        test_report_ignored("");
        test_report_ignored("t");
        test_report_ignored("8;24;80t");        /* XTWINOPS text area size report in characters */
        test_report_ignored("4;240;1600t");
        test_report_ignored("480;24;80t");
        test_report_ignored("?48;24;80;0;0t");
        test_report_ignored("48;24;80;0;0 t");
        test_report_ignored("48;24;80;0;0m");

        /* Regular reports */
        test_report_one("48;24;80;240;1600t", REPORT(24, 80, 240, 1600));
        test_report_one("48;48;80;480;1600t", REPORT(48, 80, 480, 1600));
        test_report_one("48;24;80;0;0t", REPORT(24, 80, 0, 0));

        /* Missing, empty or unparsable fields are treated as 0, extra fields are ignored */
        test_report_one("48t", REPORT(0, 0, 0, 0));
        test_report_one("48;24;80t", REPORT(24, 80, 0, 0));
        test_report_one("48;;80;;t", REPORT(0, 80, 0, 0));
        test_report_one("48;65536;65535;0;0t", REPORT(0, 65535, 0, 0));
        test_report_one("48;24;80;240;1600;7;8t", REPORT(24, 80, 240, 1600));

        /* Sub-parameters are ignored */
        test_report_one("48:1;24:2:3;80:;240;1600:9t", REPORT(24, 80, 240, 1600));
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

        ASSERT_OK(inband_resize_format_mode_report(INBAND_RESIZE_MODE_SET, &seq));
        ASSERT_STREQ(seq, "\x1B[?2048;1$y");
        seq = mfree(seq);

        ASSERT_OK(inband_resize_format_mode_report(INBAND_RESIZE_MODE_RESET, &seq));
        ASSERT_STREQ(seq, "\x1B[?2048;2$y");
        seq = mfree(seq);

        ASSERT_OK(inband_resize_format_mode_report(INBAND_RESIZE_MODE_PERMANENTLY_RESET, &seq));
        ASSERT_STREQ(seq, "\x1B[?2048;4$y");

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
