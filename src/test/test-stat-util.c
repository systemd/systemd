/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-list.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(null_or_empty_path) {
        assert_se(null_or_empty_path("/dev/null") == 1);
        assert_se(null_or_empty_path("/dev/tty") == 1);  /* We assume that any character device is "empty", bleh. */
        assert_se(null_or_empty_path("../../../../../../../../../../../../../../../../../../../../dev/null") == 1);
        assert_se(null_or_empty_path("/proc/self/exe") == 0);
        assert_se(null_or_empty_path("/nosuchfileordir") == -ENOENT);
}

TEST(null_or_empty_path_with_root) {
        assert_se(null_or_empty_path_with_root("/dev/null", NULL) == 1);
        assert_se(null_or_empty_path_with_root("/dev/null", "/") == 1);
        assert_se(null_or_empty_path_with_root("/dev/null", "/.././../") == 1);
        assert_se(null_or_empty_path_with_root("/dev/null", "/.././..") == 1);
        assert_se(null_or_empty_path_with_root("../../../../../../../../../../../../../../../../../../../../dev/null", NULL) == 1);
        assert_se(null_or_empty_path_with_root("../../../../../../../../../../../../../../../../../../../../dev/null", "/") == 1);
        assert_se(null_or_empty_path_with_root("/proc/self/exe", NULL) == 0);
        assert_se(null_or_empty_path_with_root("/proc/self/exe", "/") == 0);
        assert_se(null_or_empty_path_with_root("/nosuchfileordir", NULL) == -ENOENT);
        assert_se(null_or_empty_path_with_root("/nosuchfileordir", "/.././../") == -ENOENT);
        assert_se(null_or_empty_path_with_root("/nosuchfileordir", "/.././..") == -ENOENT);
        assert_se(null_or_empty_path_with_root("/foobar/barbar/dev/null", "/foobar/barbar") == 1);
        assert_se(null_or_empty_path_with_root("/foobar/barbar/dev/null", "/foobar/barbar/") == 1);
}

TEST(inode_same) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-files_same.XXXXXX";
        _cleanup_(unlink_tempfilep) char name_alias[] = "/tmp/test-files_same.alias";

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_alias) >= 0);

        assert_se(inode_same(name, name, 0));
        assert_se(inode_same(name, name, AT_SYMLINK_NOFOLLOW));
        assert_se(inode_same(name, name_alias, 0));
        assert_se(!inode_same(name, name_alias, AT_SYMLINK_NOFOLLOW));
}

TEST(is_symlink) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-is_symlink.XXXXXX";
        _cleanup_(unlink_tempfilep) char name_link[] = "/tmp/test-is_symlink.link";
        _cleanup_close_ int fd = -EBADF;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_link) >= 0);

        assert_se(is_symlink(name) == 0);
        assert_se(is_symlink(name_link) == 1);
        assert_se(is_symlink("/a/file/which/does/not/exist/i/guess") < 0);
}

TEST(path_is_fs_type) {
        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0) {
                assert_se(path_is_fs_type("/run", TMPFS_MAGIC) > 0);
                assert_se(path_is_fs_type("/run", BTRFS_SUPER_MAGIC) == 0);
        }
        if (path_is_mount_point("/proc", NULL, AT_SYMLINK_FOLLOW) > 0) {
                assert_se(path_is_fs_type("/proc", PROC_SUPER_MAGIC) > 0);
                assert_se(path_is_fs_type("/proc", BTRFS_SUPER_MAGIC) == 0);
        }
        assert_se(path_is_fs_type("/i-dont-exist", BTRFS_SUPER_MAGIC) == -ENOENT);
}

TEST(path_is_temporary_fs) {
        int r;

        FOREACH_STRING(s, "/", "/run", "/sys", "/sys/", "/proc", "/i-dont-exist", "/var", "/var/lib") {
                r = path_is_temporary_fs(s);

                log_info_errno(r, "path_is_temporary_fs(\"%s\"): %d, %s",
                               s, r, r < 0 ? errno_to_name(r) : yes_no(r));
        }

        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0)
                assert_se(path_is_temporary_fs("/run") > 0);
        assert_se(path_is_temporary_fs("/proc") == 0);
        assert_se(path_is_temporary_fs("/i-dont-exist") == -ENOENT);
}

TEST(path_is_read_only_fs) {
        int r;

        FOREACH_STRING(s, "/", "/run", "/sys", "/sys/", "/proc", "/i-dont-exist", "/var", "/var/lib") {
                r = path_is_read_only_fs(s);

                log_info_errno(r, "path_is_read_only_fs(\"%s\"): %d, %s",
                               s, r, r < 0 ? errno_to_name(r) : yes_no(r));
        }

        if (path_is_mount_point("/sys", NULL, AT_SYMLINK_FOLLOW) > 0)
                assert_se(IN_SET(path_is_read_only_fs("/sys"), 0, 1));

        assert_se(path_is_read_only_fs("/proc") == 0);
        assert_se(path_is_read_only_fs("/i-dont-exist") == -ENOENT);
}

TEST(fd_is_ns) {
        _cleanup_close_ int fd = -EBADF;

        assert_se(fd_is_ns(STDIN_FILENO, CLONE_NEWNET) == 0);
        assert_se(fd_is_ns(STDERR_FILENO, CLONE_NEWNET) == 0);
        assert_se(fd_is_ns(STDOUT_FILENO, CLONE_NEWNET) == 0);

        fd = open("/proc/self/ns/mnt", O_CLOEXEC|O_RDONLY);
        if (fd < 0) {
                assert_se(errno == ENOENT);
                log_notice("Path %s not found, skipping test", "/proc/self/ns/mnt");
                return;
        }
        assert_se(fd >= 0);
        assert_se(IN_SET(fd_is_ns(fd, CLONE_NEWNET), 0, -EUCLEAN));
        fd = safe_close(fd);

        assert_se((fd = open("/proc/self/ns/ipc", O_CLOEXEC|O_RDONLY)) >= 0);
        assert_se(IN_SET(fd_is_ns(fd, CLONE_NEWIPC), 1, -EUCLEAN));
        fd = safe_close(fd);

        assert_se((fd = open("/proc/self/ns/net", O_CLOEXEC|O_RDONLY)) >= 0);
        assert_se(IN_SET(fd_is_ns(fd, CLONE_NEWNET), 1, -EUCLEAN));
}

TEST(dir_is_empty) {
        _cleanup_(rm_rf_physical_and_freep) char *empty_dir = NULL;
        _cleanup_free_ char *j = NULL, *jj = NULL, *jjj = NULL;

        assert_se(dir_is_empty_at(AT_FDCWD, "/proc", /* ignore_hidden_or_backup= */ true) == 0);
        assert_se(dir_is_empty_at(AT_FDCWD, "/icertainlydontexistdoi", /* ignore_hidden_or_backup= */ true) == -ENOENT);

        assert_se(mkdtemp_malloc("/tmp/emptyXXXXXX", &empty_dir) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) > 0);

        j = path_join(empty_dir, "zzz");
        assert_se(j);
        assert_se(touch(j) >= 0);

        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) == 0);

        jj = path_join(empty_dir, "ppp");
        assert_se(jj);
        assert_se(touch(jj) >= 0);

        jjj = path_join(empty_dir, ".qqq");
        assert_se(jjj);
        assert_se(touch(jjj) >= 0);

        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) == 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ false) == 0);
        assert_se(unlink(j) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) == 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ false) == 0);
        assert_se(unlink(jj) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) > 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ false) == 0);
        assert_se(unlink(jjj) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ true) > 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir, /* ignore_hidden_or_backup= */ false) > 0);
}

TEST(inode_type_from_string) {
        static const mode_t types[] = {
                S_IFREG,
                S_IFDIR,
                S_IFLNK,
                S_IFCHR,
                S_IFBLK,
                S_IFIFO,
                S_IFSOCK,
        };

        FOREACH_ARRAY(m, types, ELEMENTSOF(types))
                assert_se(inode_type_from_string(inode_type_to_string(*m)) == *m);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
