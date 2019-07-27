/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/socket.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "namespace.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

static void test_tmpdir(const char *id, const char *A, const char *B) {
        _cleanup_free_ char *a, *b;
        struct stat x, y;
        char *c, *d;

        assert_se(setup_tmp_dirs(id, &a, &b) == 0);
        assert_se(startswith(a, A));
        assert_se(startswith(b, B));

        assert_se(stat(a, &x) >= 0);
        assert_se(stat(b, &y) >= 0);

        assert_se(S_ISDIR(x.st_mode));
        assert_se(S_ISDIR(y.st_mode));

        assert_se((x.st_mode & 01777) == 0700);
        assert_se((y.st_mode & 01777) == 0700);

        c = strjoina(a, "/tmp");
        d = strjoina(b, "/tmp");

        assert_se(stat(c, &x) >= 0);
        assert_se(stat(d, &y) >= 0);

        assert_se(S_ISDIR(x.st_mode));
        assert_se(S_ISDIR(y.st_mode));

        assert_se((x.st_mode & 01777) == 01777);
        assert_se((y.st_mode & 01777) == 01777);

        assert_se(rmdir(c) >= 0);
        assert_se(rmdir(d) >= 0);

        assert_se(rmdir(a) >= 0);
        assert_se(rmdir(b) >= 0);
}

static int test_netns(void) {
        _cleanup_close_pair_ int s[2] = { -1, -1 };
        pid_t pid1, pid2, pid3;
        int r, n = 0;
        siginfo_t si;

        if (geteuid() > 0)
                return log_tests_skipped("not root");

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM, 0, s) >= 0);

        pid1 = fork();
        assert_se(pid1 >= 0);

        if (pid1 == 0) {
                r = setup_netns(s);
                assert_se(r >= 0);
                _exit(r);
        }

        pid2 = fork();
        assert_se(pid2 >= 0);

        if (pid2 == 0) {
                r = setup_netns(s);
                assert_se(r >= 0);
                exit(r);
        }

        pid3 = fork();
        assert_se(pid3 >= 0);

        if (pid3 == 0) {
                r = setup_netns(s);
                assert_se(r >= 0);
                exit(r);
        }

        r = wait_for_terminate(pid1, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        n += si.si_status;

        r = wait_for_terminate(pid2, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        n += si.si_status;

        r = wait_for_terminate(pid3, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        n += si.si_status;

        assert_se(n == 1);
        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        sd_id128_t bid;
        char boot_id[SD_ID128_STRING_MAX];
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *zz = NULL;

        test_setup_logging(LOG_INFO);

        if (!have_namespaces()) {
                log_tests_skipped("Don't have namespace support");
                return EXIT_TEST_SKIP;
        }

        assert_se(sd_id128_get_boot(&bid) >= 0);
        sd_id128_to_string(bid, boot_id);

        x = strjoin("/tmp/systemd-private-", boot_id, "-abcd.service-");
        y = strjoin("/var/tmp/systemd-private-", boot_id, "-abcd.service-");
        assert_se(x && y);

        test_tmpdir("abcd.service", x, y);

        z = strjoin("/tmp/systemd-private-", boot_id, "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-");
        zz = strjoin("/var/tmp/systemd-private-", boot_id, "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-");

        assert_se(z && zz);

        test_tmpdir("sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device", z, zz);

        return test_netns();
}
