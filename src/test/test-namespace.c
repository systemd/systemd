/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "namespace.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"
#include "user-util.h"
#include "virt.h"

TEST(namespace_cleanup_tmpdir) {
        {
                _cleanup_(namespace_cleanup_tmpdirp) char *dir;
                assert_se(dir = strdup(RUN_SYSTEMD_EMPTY));
        }

        {
                _cleanup_(namespace_cleanup_tmpdirp) char *dir;
                assert_se(dir = strdup("/tmp/systemd-test-namespace.XXXXXX"));
                assert_se(mkdtemp(dir));
        }
}

static void test_tmpdir_one(const char *id, const char *A, const char *B) {
        _cleanup_free_ char *a, *b;
        struct stat x, y;
        char *c, *d;

        assert_se(setup_tmp_dirs(id, &a, &b) == 0);

        assert_se(stat(a, &x) >= 0);
        assert_se(stat(b, &y) >= 0);

        assert_se(S_ISDIR(x.st_mode));
        assert_se(S_ISDIR(y.st_mode));

        if (!streq(a, RUN_SYSTEMD_EMPTY)) {
                assert_se(startswith(a, A));
                assert_se((x.st_mode & 01777) == 0700);
                c = strjoina(a, "/tmp");
                assert_se(stat(c, &x) >= 0);
                assert_se(S_ISDIR(x.st_mode));
                assert_se(FLAGS_SET(x.st_mode, 01777));
                assert_se(rmdir(c) >= 0);
                assert_se(rmdir(a) >= 0);
        }

        if (!streq(b, RUN_SYSTEMD_EMPTY)) {
                assert_se(startswith(b, B));
                assert_se((y.st_mode & 01777) == 0700);
                d = strjoina(b, "/tmp");
                assert_se(stat(d, &y) >= 0);
                assert_se(S_ISDIR(y.st_mode));
                assert_se(FLAGS_SET(y.st_mode, 01777));
                assert_se(rmdir(d) >= 0);
                assert_se(rmdir(b) >= 0);
        }
}

TEST(tmpdir) {
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *zz = NULL;
        sd_id128_t bid;

        assert_se(sd_id128_get_boot(&bid) >= 0);

        x = strjoin("/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-abcd.service-");
        y = strjoin("/var/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-abcd.service-");
        assert_se(x && y);

        test_tmpdir_one("abcd.service", x, y);

        z = strjoin("/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-");
        zz = strjoin("/var/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-");

        assert_se(z && zz);

        test_tmpdir_one("sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device", z, zz);
}

static void test_shareable_ns(unsigned long nsflag) {
        _cleanup_close_pair_ int s[2] = EBADF_PAIR;
        bool permission_denied = false;
        pid_t pid1, pid2, pid3;
        int r, n = 0;
        siginfo_t si;

        if (geteuid() > 0) {
                (void) log_tests_skipped("not root");
                return;
        }

        assert_se(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, s) >= 0);

        pid1 = fork();
        assert_se(pid1 >= 0);

        if (pid1 == 0) {
                r = setup_shareable_ns(s, nsflag);
                assert_se(r >= 0 || ERRNO_IS_NEG_PRIVILEGE(r));
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        pid2 = fork();
        assert_se(pid2 >= 0);

        if (pid2 == 0) {
                r = setup_shareable_ns(s, nsflag);
                assert_se(r >= 0 || ERRNO_IS_NEG_PRIVILEGE(r));
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        pid3 = fork();
        assert_se(pid3 >= 0);

        if (pid3 == 0) {
                r = setup_shareable_ns(s, nsflag);
                assert_se(r >= 0 || ERRNO_IS_NEG_PRIVILEGE(r));
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        r = wait_for_terminate(pid1, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        r = wait_for_terminate(pid2, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        r = wait_for_terminate(pid3, &si);
        assert_se(r >= 0);
        assert_se(si.si_code == CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        /* LSMs can cause setup_shareable_ns() to fail with permission denied, do not fail the test in that
         * case (e.g.: LXC with AppArmor on kernel < v6.2). */
        if (permission_denied)
                return (void) log_tests_skipped("insufficient privileges");

        assert_se(n == 1);
}

TEST(netns) {
        test_shareable_ns(CLONE_NEWNET);
}

TEST(ipcns) {
        test_shareable_ns(CLONE_NEWIPC);
}

TEST(protect_kernel_logs) {
        static const NamespaceParameters p = {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
                .protect_kernel_logs = true,
        };
        pid_t pid;
        int r;

        if (geteuid() > 0) {
                (void) log_tests_skipped("not root");
                return;
        }

        /* In a container we likely don't have access to /dev/kmsg */
        if (detect_container() > 0) {
                (void) log_tests_skipped("in container");
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                _cleanup_close_ int fd = -EBADF;

                fd = open("/dev/kmsg", O_RDONLY | O_CLOEXEC);
                assert_se(fd > 0);

                r = setup_namespace(&p, NULL);
                assert_se(r == 0);

                assert_se(setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY) >= 0);
                assert_se(open("/dev/kmsg", O_RDONLY | O_CLOEXEC) < 0);
                assert_se(errno == EACCES);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("ns-kernellogs", pid, WAIT_LOG) == EXIT_SUCCESS);
}

TEST(idmapping_supported) {
        assert_se(is_idmapping_supported("/run") >= 0);
        assert_se(is_idmapping_supported("/var/lib") >= 0);
        assert_se(is_idmapping_supported("/var/cache") >= 0);
        assert_se(is_idmapping_supported("/var/log") >= 0);
        assert_se(is_idmapping_supported("/etc") >= 0);
}

TEST(namespace_is_init) {
        int r;

        for (NamespaceType t = 0; t < _NAMESPACE_TYPE_MAX; t++) {
                r = namespace_is_init(t);
                if (r == -EBADR)
                        log_info_errno(r, "In root namespace of type '%s': don't know", namespace_info[t].proc_name);
                else {
                        ASSERT_OK(r);
                        log_info("In root namespace of type '%s': %s", namespace_info[t].proc_name, yes_no(r));
                }
        }
}

static int intro(void) {
        if (!have_namespaces())
                return log_tests_skipped("Don't have namespace support or lacking privileges");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
