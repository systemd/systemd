/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mountpoint-util.h"
#include "path-util.h"
#include "signal-util.h"
#include "strv.h"
#include "tests.h"
#include "udev-event.h"
#include "udev-spawn.h"

#define BUF_SIZE 1024

static void test_event_spawn_core(bool with_pidfd, const char *cmd, char *result_buf, size_t buf_size) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_(udev_event_unrefp) UdevEvent *event = NULL;

        ASSERT_OK_ERRNO(setenv("SYSTEMD_PIDFD", yes_no(with_pidfd), 1));

        ASSERT_OK(sd_device_new_from_syspath(&dev, "/sys/class/net/lo"));
        ASSERT_NOT_NULL(event = udev_event_new(dev, NULL, EVENT_TEST_SPAWN));
        ASSERT_OK_ZERO(udev_event_spawn(event, false, cmd, result_buf, buf_size, NULL));

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_PIDFD"));
}

static void test_event_spawn_cat(bool with_pidfd, size_t buf_size) {
        _cleanup_strv_free_ char **lines = NULL;
        _cleanup_free_ char *cmd = NULL;
        char result_buf[BUF_SIZE];

        log_debug("/* %s(%s) */", __func__, yes_no(with_pidfd));

        ASSERT_OK(find_executable("cat", &cmd));
        ASSERT_NOT_NULL(strextend_with_separator(&cmd, " ", "/sys/class/net/lo/uevent"));

        test_event_spawn_core(with_pidfd, cmd, result_buf,
                              buf_size >= BUF_SIZE ? BUF_SIZE : buf_size);

        ASSERT_NOT_NULL(lines = strv_split_newlines(result_buf));
        strv_print(lines);

        if (buf_size >= BUF_SIZE) {
                ASSERT_TRUE(strv_contains(lines, "INTERFACE=lo"));
                ASSERT_TRUE(strv_contains(lines, "IFINDEX=1"));
        }
}

static void test_event_spawn_self(const char *self, const char *arg, bool with_pidfd) {
        _cleanup_strv_free_ char **lines = NULL;
        _cleanup_free_ char *cmd = NULL;
        char result_buf[BUF_SIZE];

        log_debug("/* %s(%s, %s) */", __func__, arg, yes_no(with_pidfd));

        /* 'self' may contain spaces, hence needs to be quoted. */
        ASSERT_NOT_NULL(cmd = strjoin("'", self, "' ", arg));

        test_event_spawn_core(with_pidfd, cmd, result_buf, BUF_SIZE);

        ASSERT_NOT_NULL(lines = strv_split_newlines(result_buf));
        strv_print(lines);

        ASSERT_TRUE(strv_contains(lines, "aaa"));
        ASSERT_TRUE(strv_contains(lines, "bbb"));
}

static void test1(void) {
        fprintf(stdout, "aaa\nbbb");
        fprintf(stderr, "ccc\nddd");
}

static void test2(void) {
        char buf[16384];

        fprintf(stdout, "aaa\nbbb");

        memset(buf, 'a', sizeof(buf) - 1);
        char_array_0(buf);
        fputs(buf, stderr);
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *self = NULL;

        if (path_is_mount_point("/sys") <= 0)
                return log_tests_skipped("/sys is not mounted");

        if (argc > 1) {
                if (streq(argv[1], "test1"))
                        test1();
                else if (streq(argv[1], "test2"))
                        test2();
                else
                        assert_not_reached();

                return 0;
        }

        test_setup_logging(LOG_DEBUG);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);

        test_event_spawn_cat(true, SIZE_MAX);
        test_event_spawn_cat(false, SIZE_MAX);
        test_event_spawn_cat(true, 5);
        test_event_spawn_cat(false, 5);

        assert_se(path_make_absolute_cwd(argv[0], &self) >= 0);
        path_simplify(self);

        test_event_spawn_self(self, "test1", true);
        test_event_spawn_self(self, "test1", false);

        test_event_spawn_self(self, "test2", true);
        test_event_spawn_self(self, "test2", false);

        return 0;
}
