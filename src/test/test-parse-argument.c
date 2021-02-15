/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-argument.h"
#include "stdio-util.h"
#include "tests.h"

static void test_parse_json_argument(void) {
        log_info("/* %s */", __func__);

        JsonFormatFlags flags = JSON_FORMAT_PRETTY;

        assert_se(parse_json_argument("help", &flags) == 0);
        assert_se(flags == JSON_FORMAT_PRETTY);

        assert_se(parse_json_argument("off", &flags) == 1);
        assert_se(flags == JSON_FORMAT_OFF);
}

static void test_parse_path_argument(void) {
        log_info("/* %s */", __func__);

        _cleanup_free_ char *path = NULL;

        assert_se(parse_path_argument("help", false, &path) == 0);
        assert_se(streq(basename(path), "help"));

        assert_se(parse_path_argument("/", false, &path) == 0);
        assert_se(streq(path, "/"));

        assert_se(parse_path_argument("/", true, &path) == 0);
        assert_se(path == NULL);
}

static void test_parse_signal_argument(void) {
        log_info("/* %s */", __func__);

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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        test_parse_json_argument();
        test_parse_path_argument();
        test_parse_signal_argument();
}
