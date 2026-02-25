/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "libmount-util.h"
#include "namespace-util.h"
#include "namespace.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-range.h"
#include "user-util.h"
#include "virt.h"

TEST(namespace_cleanup_tmpdir) {
        {
                _cleanup_(namespace_cleanup_tmpdirp) char *dir = NULL;
                ASSERT_NOT_NULL(dir = strdup(RUN_SYSTEMD_EMPTY));
        }

        {
                _cleanup_(namespace_cleanup_tmpdirp) char *dir = NULL;
                ASSERT_OK(mkdtemp_malloc("/tmp/systemd-test-namespace.XXXXXX", &dir));
        }
}

static void test_tmpdir_one(const char *id, const char *A, const char *B) {
        _cleanup_free_ char *a, *b;
        struct stat x, y;
        char *c, *d;

        ASSERT_OK(setup_tmp_dir_one(id, "/tmp", &a));
        ASSERT_OK(setup_tmp_dir_one(id, "/var/tmp", &b));

        ASSERT_OK_ERRNO(stat(a, &x));
        ASSERT_OK_ERRNO(stat(b, &y));

        ASSERT_TRUE(S_ISDIR(x.st_mode));
        ASSERT_TRUE(S_ISDIR(y.st_mode));

        if (!streq(a, RUN_SYSTEMD_EMPTY)) {
                ASSERT_TRUE(startswith(a, A));
                ASSERT_EQ((x.st_mode & 01777), 0700U);
                ASSERT_NOT_NULL(c = strjoina(a, "/tmp"));
                ASSERT_OK_ERRNO(stat(c, &x));
                ASSERT_TRUE(S_ISDIR(x.st_mode));
                ASSERT_TRUE(FLAGS_SET(x.st_mode, 01777));
                ASSERT_OK_ERRNO(rmdir(c));
                ASSERT_OK_ERRNO(rmdir(a));
        }

        if (!streq(b, RUN_SYSTEMD_EMPTY)) {
                ASSERT_TRUE(startswith(b, B));
                ASSERT_EQ((y.st_mode & 01777), 0700U);
                ASSERT_NOT_NULL(d = strjoina(b, "/tmp"));
                ASSERT_OK_ERRNO(stat(d, &y));
                ASSERT_TRUE(S_ISDIR(y.st_mode));
                ASSERT_TRUE(FLAGS_SET(y.st_mode, 01777));
                ASSERT_OK_ERRNO(rmdir(d));
                ASSERT_OK_ERRNO(rmdir(b));
        }
}

TEST(tmpdir) {
        _cleanup_free_ char *x = NULL, *y = NULL, *z = NULL, *zz = NULL;
        sd_id128_t bid;

        ASSERT_OK(sd_id128_get_boot(&bid));

        ASSERT_NOT_NULL(x = strjoin("/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-abcd.service-"));
        ASSERT_NOT_NULL(y = strjoin("/var/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-abcd.service-"));

        test_tmpdir_one("abcd.service", x, y);

        ASSERT_NOT_NULL(z = strjoin("/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-"));
        ASSERT_NOT_NULL(zz = strjoin("/var/tmp/systemd-private-", SD_ID128_TO_STRING(bid), "-sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device-"));

        test_tmpdir_one("sys-devices-pci0000:00-0000:00:1a.0-usb3-3\\x2d1-3\\x2d1:1.0-bluetooth-hci0.device", z, zz);
}

static void test_shareable_ns(unsigned long nsflag) {
        _cleanup_close_pair_ int s[2] = EBADF_PAIR;
        bool permission_denied = false;
        _cleanup_(pidref_done) PidRef pidref1 = PIDREF_NULL, pidref2 = PIDREF_NULL, pidref3 = PIDREF_NULL;
        int r, n = 0;
        siginfo_t si;

        if (geteuid() > 0) {
                (void) log_tests_skipped("not root");
                return;
        }

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, s));

        r = ASSERT_OK(pidref_safe_fork("(share-ns-1)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref1));

        if (r == 0) {
                r = setup_shareable_ns(s, nsflag);
                if (!ERRNO_IS_PRIVILEGE(r))
                        ASSERT_OK(r);
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        r = ASSERT_OK(pidref_safe_fork("(share-ns-2)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref2));

        if (r == 0) {
                r = setup_shareable_ns(s, nsflag);
                if (!ERRNO_IS_PRIVILEGE(r))
                        ASSERT_OK(r);
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        r = ASSERT_OK(pidref_safe_fork("(share-ns-3)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &pidref3));

        if (r == 0) {
                r = setup_shareable_ns(s, nsflag);
                if (!ERRNO_IS_PRIVILEGE(r))
                        ASSERT_OK(r);
                _exit(r >= 0 ? r : EX_NOPERM);
        }

        ASSERT_OK(pidref_wait_for_terminate(&pidref1, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        ASSERT_OK(pidref_wait_for_terminate(&pidref2, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        ASSERT_OK(pidref_wait_for_terminate(&pidref3, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        if (si.si_status == EX_NOPERM)
                permission_denied = true;
        else
                n += si.si_status;

        /* LSMs can cause setup_shareable_ns() to fail with permission denied, do not fail the test in that
         * case (e.g.: LXC with AppArmor on kernel < v6.2). */
        if (permission_denied)
                return (void) log_tests_skipped("insufficient privileges");

        ASSERT_EQ(n, 1);
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

        r = dlopen_libmount();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                (void) log_tests_skipped("libmount support not compiled in");
                return;
        }
        ASSERT_OK(r);

        r = ASSERT_OK(pidref_safe_fork("(protect)", FORK_WAIT|FORK_LOG|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));

        if (r == 0) {
                _cleanup_close_ int fd = -EBADF;

                ASSERT_OK_ERRNO(fd = open("/dev/kmsg", O_RDONLY | O_CLOEXEC));

                ASSERT_OK_ZERO(setup_namespace(&p, NULL));

                ASSERT_OK_ERRNO(setresuid(UID_NOBODY, UID_NOBODY, UID_NOBODY));
                ASSERT_ERROR_ERRNO(open("/dev/kmsg", O_RDONLY | O_CLOEXEC), EACCES);

                _exit(EXIT_SUCCESS);
        }
}

TEST(idmapping_supported) {
        ASSERT_OK(is_idmapping_supported("/run"));
        ASSERT_OK(is_idmapping_supported("/var/lib"));
        ASSERT_OK(is_idmapping_supported("/var/cache"));
        ASSERT_OK(is_idmapping_supported("/var/log"));
        ASSERT_OK(is_idmapping_supported("/etc"));
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

        fd = userns_acquire("0 1 1", "0 2 1", /* setgroups_deny= */ true);
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

                /* After successfully changing id/gid DEATHSIG is reset, so it has to be set again */
                ASSERT_OK_ERRNO(prctl(PR_SET_PDEATHSIG, SIGKILL));

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
        ASSERT_OK(pidref_wait_for_terminate(&pid, NULL));

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

                /* After successfully changing id/gid DEATHSIG is reset, so it has to be set again */
                ASSERT_OK_ERRNO(prctl(PR_SET_PDEATHSIG, SIGKILL));

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
        ASSERT_OK(pidref_wait_for_terminate(&pid, NULL));
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

                        _exit(EXIT_SUCCESS);
                }

                _exit(EXIT_SUCCESS);
        }
}

TEST(detach_mount_namespace_harder) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        char x = 0;
        int r;

        ASSERT_OK_ERRNO(pipe2(p, O_CLOEXEC));

        ASSERT_OK(r = pidref_safe_fork("(child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));
        if (r == 0) {
                p[0] = safe_close(p[0]);

                ASSERT_OK(detach_mount_namespace_harder(0, 0));

                ASSERT_OK_EQ_ERRNO(write(p[1], &(const char[]) { 'x' }, 1), 1);
                freeze();
        }

        p[1] = safe_close(p[1]);
        ASSERT_OK_EQ_ERRNO(read(p[0], &x, 1), 1);
        ASSERT_EQ(x, 'x');

        ASSERT_OK_POSITIVE(pidref_in_same_namespace(NULL, &pid, NAMESPACE_USER));
        ASSERT_OK_ZERO(pidref_in_same_namespace(NULL, &pid, NAMESPACE_MOUNT));
}

static int intro(void) {
        if (!have_namespaces())
                return log_tests_skipped("Don't have namespace support or lacking privileges");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
