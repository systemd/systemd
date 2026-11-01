/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "sd-json.h"

#include "parse-argument.h"
#include "path-util.h"
#include "stdio-util.h"
#include "tests.h"

TEST(parse_json_argument) {
        sd_json_format_flags_t flags = SD_JSON_FORMAT_PRETTY;

        ASSERT_OK_EQ(parse_json_argument("help", &flags), 0);
        ASSERT_EQ(flags, SD_JSON_FORMAT_PRETTY);

        ASSERT_OK_EQ(parse_json_argument("off", &flags), 1);
        ASSERT_EQ(flags, SD_JSON_FORMAT_OFF);
}

TEST(parse_path_argument) {
        _cleanup_free_ char *path = NULL, *file = NULL;

        ASSERT_OK_ZERO(parse_path_argument("help", /* suppress_root= */ false, &path));
        ASSERT_OK(path_extract_filename(path, &file));
        ASSERT_STREQ(file, "help");

        ASSERT_OK_ZERO(parse_path_argument("/", /* suppress_root= */ false, &path));
        ASSERT_STREQ(path, "/");

        ASSERT_OK_ZERO(parse_path_argument("/", /* suppress_root= */ true, &path));
        ASSERT_NULL(path);
}

TEST(parse_signal_argument) {
        int  signal = -1;

        ASSERT_OK_EQ(parse_signal_argument("help", &signal), 0);
        ASSERT_EQ(signal, -1);

        ASSERT_OK_EQ(parse_signal_argument("list", &signal), 0);
        ASSERT_EQ(signal, -1);

        ASSERT_OK_EQ(parse_signal_argument("SIGABRT", &signal), 1);
        ASSERT_EQ(signal, SIGABRT);

        ASSERT_OK_EQ(parse_signal_argument("ABRT", &signal), 1);
        ASSERT_EQ(signal, SIGABRT);

        char buf[DECIMAL_STR_MAX(int)];
        xsprintf(buf, "%d", SIGABRT);
        ASSERT_OK_EQ(parse_signal_argument(buf, &signal), 1);
        ASSERT_EQ(signal, SIGABRT);
}

TEST(parse_background_argument) {
        _cleanup_free_ char *arg_bg_good = NULL;

        /* Should accept empty string */
        ASSERT_OK(parse_background_argument("", &arg_bg_good));
        ASSERT_STREQ(arg_bg_good, "");

        /* Should accept ANSI color codes in palette, 8-bit, or 24-bit format */
        ASSERT_OK(parse_background_argument("42", &arg_bg_good));
        ASSERT_STREQ(arg_bg_good, "42");

        ASSERT_OK(parse_background_argument("48;5;219", &arg_bg_good));
        ASSERT_STREQ(arg_bg_good, "48;5;219");

        ASSERT_OK(parse_background_argument("48;2;3;141;59", &arg_bg_good));
        ASSERT_STREQ(arg_bg_good, "48;2;3;141;59");

        _cleanup_free_ char *arg_bg_bad = NULL;

        /* Should reject various invalid arguments */
        ASSERT_FAIL(parse_background_argument("42;", &arg_bg_bad));
        ASSERT_NULL(arg_bg_bad);

        ASSERT_FAIL(parse_background_argument(";42", &arg_bg_bad));
        ASSERT_NULL(arg_bg_bad);

        ASSERT_FAIL(parse_background_argument("4;;2", &arg_bg_bad));
        ASSERT_NULL(arg_bg_bad);

        ASSERT_FAIL(parse_background_argument("4a2", &arg_bg_bad));
        ASSERT_NULL(arg_bg_bad);
}

DEFINE_TEST_MAIN(LOG_INFO);
