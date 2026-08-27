/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "osc-winsize.h"
#include "tests.h"

TEST(osc_winsize_parse) {
        OscWinsize ws;

        /* Not OSC 2811 */
        ASSERT_EQ(osc_winsize_parse("0;some title", &ws), 0);
        ASSERT_EQ(osc_winsize_parse("28110;foo", &ws), 0);
        ASSERT_EQ(osc_winsize_parse("281", &ws), 0);

        /* A subscribe sequence */
        ASSERT_EQ(osc_winsize_parse("2811;?;width=80;height=24", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE);
        ASSERT_EQ(ws.width, 80U);
        ASSERT_EQ(ws.height, 24U);

        /* Field order is undefined */
        ASSERT_EQ(osc_winsize_parse("2811;?;height=24;width=80", &ws), 1);
        ASSERT_EQ(ws.width, 80U);
        ASSERT_EQ(ws.height, 24U);

        /* The cancel sequence */
        ASSERT_EQ(osc_winsize_parse("2811;?", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_CANCEL);

        /* A report sequence */
        ASSERT_EQ(osc_winsize_parse("2811;width=120;height=40", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.width, 120U);
        ASSERT_EQ(ws.height, 40U);

        /* Unknown fields are ignored, missing/unparsable fields are treated as 0 */
        ASSERT_EQ(osc_winsize_parse("2811;?;pixelwidth=1024;height=abc", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_SUBSCRIBE); /* fields were present, just not understood, hence not a cancel */
        ASSERT_EQ(ws.width, 0U);
        ASSERT_EQ(ws.height, 0U);

        /* Out of range values are unparsable, hence 0 */
        ASSERT_EQ(osc_winsize_parse("2811;width=65536;height=65535", &ws), 1);
        ASSERT_EQ(ws.width, 0U);
        ASSERT_EQ(ws.height, 65535U);

        /* A '?' that is not the first field is just an unknown field */
        ASSERT_EQ(osc_winsize_parse("2811;width=80;?", &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
}

TEST(osc_winsize_format) {
        _cleanup_free_ char *seq = NULL;

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_SUBSCRIBE, 80, 24, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;?;width=80;height=24\x1B\\");
        seq = mfree(seq);

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_CANCEL, 0, 0, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;?\x1B\\");
        seq = mfree(seq);

        ASSERT_OK(osc_winsize_format(OSC_WINSIZE_REPORT, 120, 40, &seq));
        ASSERT_STREQ(seq, "\x1B]2811;width=120;height=40\x1B\\");

        /* Round trip: strip OSC and ST, then parse the payload back */
        OscWinsize ws;
        _cleanup_free_ char *payload = strndup(seq + 2, strlen(seq + 2) - 2);
        ASSERT_NOT_NULL(payload);
        ASSERT_EQ(osc_winsize_parse(payload, &ws), 1);
        ASSERT_EQ(ws.type, OSC_WINSIZE_REPORT);
        ASSERT_EQ(ws.width, 120U);
        ASSERT_EQ(ws.height, 40U);
}

DEFINE_TEST_MAIN(LOG_INFO);
