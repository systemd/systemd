/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "namespace.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"
#include "uid-range.h"
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

TEST(fd_is_namespace) {
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK_ZERO(fd_is_namespace(STDIN_FILENO, NAMESPACE_NET));
        ASSERT_OK_ZERO(fd_is_namespace(STDOUT_FILENO, NAMESPACE_NET));
        ASSERT_OK_ZERO(fd_is_namespace(STDERR_FILENO, NAMESPACE_NET));

        fd = namespace_open_by_type(NAMESPACE_MOUNT);
        if (IN_SET(fd, -ENOSYS, -ENOPKG)) {
                log_notice("Path %s not found, skipping test", "/proc/self/ns/mnt");
                return;
        }
        ASSERT_OK(fd);
        ASSERT_OK_POSITIVE(fd_is_namespace(fd, NAMESPACE_MOUNT));
        ASSERT_OK_ZERO(fd_is_namespace(fd, NAMESPACE_NET));
        fd = safe_close(fd);

        ASSERT_OK(fd = namespace_open_by_type(NAMESPACE_IPC));
        ASSERT_OK_POSITIVE(fd_is_namespace(fd, NAMESPACE_IPC));
        fd = safe_close(fd);

        ASSERT_OK(fd = namespace_open_by_type(NAMESPACE_NET));
        ASSERT_OK_POSITIVE(fd_is_namespace(fd, NAMESPACE_NET));
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

TEST(userns_get_base_uid) {
        _cleanup_close_ int fd = -EBADF;

        fd = userns_acquire("0 1 1", "0 2 1");
        if (ERRNO_IS_NEG_NOT_SUPPORTED(fd))
                return (void) log_tests_skipped("userns is not supported");
        if (ERRNO_IS_NEG_PRIVILEGE(fd))
                return (void) log_tests_skipped("lacking userns privileges");

        uid_t base_uid, base_gid;
        ASSERT_OK(userns_get_base_uid(fd, &base_uid, &base_gid));
        ASSERT_EQ(base_uid, 1U);
        ASSERT_EQ(base_gid, 2U);

        ASSERT_ERROR(userns_get_base_uid(fd, &base_uid, NULL), EUCLEAN);

        fd = safe_close(fd);

        fd = userns_acquire_empty();
        ASSERT_OK(fd);

        ASSERT_ERROR(userns_get_base_uid(fd, &base_uid, &base_gid), ENOMSG);
}

TEST(process_is_owned_by_uid) {
        int r;

        /* Test our own PID */
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        ASSERT_OK(pidref_set_self(&pid));
        ASSERT_OK_POSITIVE(process_is_owned_by_uid(&pid, getuid()));
        pidref_done(&pid);

        if (getuid() != 0)
                return (void) log_tests_skipped("lacking userns privileges");

        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        ASSERT_OK(uid_range_load_userns(/* path= */ NULL, UID_RANGE_USERNS_INSIDE, &range));
        if (!uid_range_contains(range, 1))
                return (void) log_tests_skipped("UID 1 not included in userns UID delegation, skipping test");

        /* Test a child that runs as uid 1 */
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));

        r = pidref_safe_fork("(child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL, &pid);
        ASSERT_OK(r);
        if (r == 0) {
                p[0] = safe_close(p[0]);
                ASSERT_OK(fully_set_uid_gid(1, 1, NULL, 0));
                ASSERT_OK_EQ_ERRNO(write(p[1], &(const char[]) { 'x' }, 1), 1);
                p[1] = safe_close(p[1]);
                freeze();
        }

        p[1] = safe_close(p[1]);
        char x = 0;
        ASSERT_OK_EQ_ERRNO(read(p[0], &x, 1), 1);
        ASSERT_EQ(x, 'x');
        p[0] = safe_close(p[0]);

        ASSERT_OK_ZERO(process_is_owned_by_uid(&pid, getuid()));

        ASSERT_OK(pidref_kill(&pid, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&pid, /* ret= */ NULL));

        /* Test a child that runs in a userns as uid 1, but the userns is owned by us */
        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));

        _cleanup_close_pair_ int pp[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pp, O_CLOEXEC));

        r = pidref_safe_fork("(child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_NEW_USERNS, &pid);
        ASSERT_OK(r);
        if (r == 0) {
                p[0] = safe_close(p[0]);
                pp[1] = safe_close(pp[1]);

                x = 0;
                ASSERT_OK_EQ_ERRNO(read(pp[0], &x, 1), 1);
                ASSERT_EQ(x, 'x');
                pp[0] = safe_close(pp[0]);

                ASSERT_OK(reset_uid_gid());

                ASSERT_OK_EQ_ERRNO(write(p[1], &(const char[]) { 'x' }, 1), 1);
                p[1] = safe_close(p[1]);
                freeze();
        }

        p[1] = safe_close(p[1]);
        pp[0] = safe_close(pp[0]);

        ASSERT_OK(write_string_file(procfs_file_alloca(pid.pid, "uid_map"), "0 1 1\n", 0));
        ASSERT_OK(write_string_file(procfs_file_alloca(pid.pid, "setgroups"), "deny", 0));
        ASSERT_OK(write_string_file(procfs_file_alloca(pid.pid, "gid_map"), "0 1 1\n", 0));

        ASSERT_OK_EQ_ERRNO(write(pp[1], &(const char[]) { 'x' }, 1), 1);
        pp[1] = safe_close(pp[1]);

        x = 0;
        ASSERT_OK_EQ_ERRNO(read(p[0], &x, 1), 1);
        ASSERT_EQ(x, 'x');
        p[0] = safe_close(p[0]);

        ASSERT_OK_POSITIVE(process_is_owned_by_uid(&pid, getuid()));

        ASSERT_OK(pidref_kill(&pid, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&pid, /* ret= */ NULL));
}

TEST(namespace_get_leader) {
        int r;

        _cleanup_(pidref_done) PidRef original = PIDREF_NULL;
        ASSERT_OK(pidref_set_self(&original));

        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        r = pidref_safe_fork("(child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_NEW_MOUNTNS|FORK_WAIT|FORK_LOG, &pid);
        ASSERT_OK(r);
        if (r == 0) {

                _cleanup_(pidref_done) PidRef pid2 = PIDREF_NULL;
                r = pidref_safe_fork("(child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_WAIT|FORK_LOG, &pid2);
                ASSERT_OK(r);

                if (r == 0) {
                        log_info("PID hierarchy: " PID_FMT " ← " PID_FMT " ← " PID_FMT, original.pid, pid.pid, pid2.pid);

                        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
                        ASSERT_OK(pidref_set_self(&self));
                        ASSERT_TRUE(pidref_equal(&self, &pid2));

                        _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;
                        ASSERT_OK(pidref_set_parent(&parent));
                        ASSERT_TRUE(pidref_equal(&parent, &pid));
                        ASSERT_TRUE(!pidref_equal(&self, &pid));
                        ASSERT_TRUE(!pidref_equal(&self, &parent));

                        _cleanup_(pidref_done) PidRef grandparent = PIDREF_NULL;
                        ASSERT_OK(pidref_get_ppid_as_pidref(&parent, &grandparent));
                        ASSERT_TRUE(pidref_equal(&grandparent, &original));
                        ASSERT_TRUE(!pidref_equal(&grandparent, &self));
                        ASSERT_TRUE(!pidref_equal(&grandparent, &pid));
                        ASSERT_TRUE(!pidref_equal(&grandparent, &pid2));
                        ASSERT_TRUE(!pidref_equal(&grandparent, &parent));

                        _cleanup_(pidref_done) PidRef leader = PIDREF_NULL;
                        ASSERT_OK(namespace_get_leader(&self, NAMESPACE_MOUNT, &leader));
                        ASSERT_TRUE(pidref_equal(&parent, &leader));
                        ASSERT_TRUE(pidref_equal(&pid, &leader));
                        ASSERT_TRUE(!pidref_equal(&self, &leader));
                        ASSERT_TRUE(!pidref_equal(&pid2, &leader));
                        ASSERT_TRUE(!pidref_equal(&original, &leader));
                        ASSERT_TRUE(!pidref_equal(&grandparent, &leader));
                }
        }
}

static int intro(void) {
        if (!have_namespaces())
                return log_tests_skipped("Don't have namespace support or lacking privileges");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
