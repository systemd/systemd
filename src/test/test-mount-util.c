/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static void test_mount_option_mangle(void) {
        char *opts = NULL;
        unsigned long f;

        assert_se(mount_option_mangle(NULL, MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("", MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec,mode=755", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(streq(opts, "mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,foo,hogehoge,nodev,mode=755", 0, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "foo,hogehoge,mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,noexec,relatime,net_cls,net_prio", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME));
        assert_se(streq(opts, "net_cls,net_prio"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,relatime,size=1630748k,mode=700,uid=1000,gid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,mode=700,uid=1000,gid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("size=1630748k,rw,gid=1000,,,nodev,relatime,,mode=700,nosuid,uid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,gid=1000,mode=700,uid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,exec,size=8143984k,nr_inodes=2035996,mode=755", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "size=8143984k,nr_inodes=2035996,mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,,,dmask=0022", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == MS_RELATIME);
        assert_se(streq(opts, "fmask=0022,dmask=0022"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,dmask=0022,\"hogehoge", MS_RDONLY, &f, &opts) < 0);
}

static void test_bind_remount_recursive(void) {
        const char *p;

        if (geteuid() != 0) {
                (void) log_tests_skipped("not running as root");
                return;
        }

        FOREACH_STRING(p, "/usr", "/sys", "/") {
                pid_t pid;

                pid = fork();
                assert_se(pid >= 0);

                if (pid == 0) {
                        /* child */
                        assert_se(detach_mount_namespace() >= 0);
                        assert_se(bind_remount_recursive(p, MS_RDONLY, MS_RDONLY, STRV_MAKE("/sys/kernel")) >= 0);
                        _exit(EXIT_SUCCESS);
                }

                assert_se(wait_for_terminate_and_check("test-remount-rec", pid, WAIT_LOG) == EXIT_SUCCESS);
        }
}

static void test_bind_remount_one(void) {
        pid_t pid;

        if (geteuid() != 0) {
                (void) log_tests_skipped("not running as root");
                return;
        }

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* child */

                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                assert_se(detach_mount_namespace() >= 0);

                assert_se(fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo) >= 0);

                assert_se(bind_remount_one_with_mountinfo("/run", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);
                assert_se(bind_remount_one_with_mountinfo("/proc/idontexist", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -ENOENT);
                assert_se(bind_remount_one_with_mountinfo("/proc/self", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) == -EINVAL);
                assert_se(bind_remount_one_with_mountinfo("/", MS_RDONLY, MS_RDONLY, proc_self_mountinfo) >= 0);

                _exit(EXIT_SUCCESS);
        }

        assert_se(wait_for_terminate_and_check("test-remount-one", pid, WAIT_LOG) == EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_mount_option_mangle();
        test_bind_remount_recursive();
        test_bind_remount_one();

        return 0;
}
