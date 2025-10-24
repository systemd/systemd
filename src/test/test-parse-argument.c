/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "sd-json.h"

#include "parse-argument.h"
#include "path-util.h"
#include "stdio-util.h"
#include "tests.h"

TEST(parse_json_argument) {
        sd_json_format_flags_t flags = SD_JSON_FORMAT_PRETTY;

        assert_se(parse_json_argument("help", &flags) == 0);
        assert_se(flags == SD_JSON_FORMAT_PRETTY);

        assert_se(parse_json_argument("off", &flags) == 1);
        assert_se(flags == SD_JSON_FORMAT_OFF);
}

TEST(parse_path_argument) {
        _cleanup_free_ char *path = NULL, *file = NULL;

        assert_se(parse_path_argument("help", false, &path) == 0);
        ASSERT_OK(path_extract_filename(path, &file));
        ASSERT_STREQ(file, "help");

        assert_se(parse_path_argument("/", false, &path) == 0);
        ASSERT_STREQ(path, "/");

        assert_se(parse_path_argument("/", true, &path) == 0);
        ASSERT_NULL(path);
}

TEST(parse_signal_argument) {
        int  signal = -1;

        assert_se(parse_signal_argument("help", &signal) == 0);
        assert_se(signal == -1);

        assert_se(parse_signal_argument("list", &signal) == 0);
        assert_se(signal == -1);

        assert_se(parse_signal_argument("SIGABRT", &signal) == 1);
        assert_se(signal == SIGABRT);

        assert_se(parse_signal_argument("ABRT", &signal) == 1);
        assert_se(signal == SIGABRT);

        char buf[DECIMAL_STR_MAX(int)];
        xsprintf(buf, "%d", SIGABRT);
        assert_se(parse_signal_argument(buf, &signal) == 1);
        assert_se(signal == SIGABRT);
}

TEST(parse_background_argument) {
        _cleanup_free_ char *arg_bg_good = NULL;

        /* Should accept empty string */
        assert_se(parse_background_argument("", &arg_bg_good) >= 0);
        ASSERT_STREQ(arg_bg_good, "");

        /* Should accept ANSI color codes in palette, 8-bit, or 24-bit format */
        assert_se(parse_background_argument("42", &arg_bg_good) >= 0);
        ASSERT_STREQ(arg_bg_good, "42");

        assert_se(parse_background_argument("48;5;219", &arg_bg_good) >= 0);
        ASSERT_STREQ(arg_bg_good, "48;5;219");

        assert_se(parse_background_argument("48;2;3;141;59", &arg_bg_good) >= 0);
        ASSERT_STREQ(arg_bg_good, "48;2;3;141;59");

        _cleanup_free_ char *arg_bg_bad = NULL;

        /* Should reject various invalid arguments */
        assert_se(parse_background_argument("42;", &arg_bg_bad) < 0);
        ASSERT_NULL(arg_bg_bad);

        assert_se(parse_background_argument(";42", &arg_bg_bad) < 0);
        ASSERT_NULL(arg_bg_bad);

        assert_se(parse_background_argument("4;;2", &arg_bg_bad) < 0);
        ASSERT_NULL(arg_bg_bad);

        assert_se(parse_background_argument("4a2", &arg_bg_bad) < 0);
        ASSERT_NULL(arg_bg_bad);
}

DEFINE_TEST_MAIN(LOG_INFO);
