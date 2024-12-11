/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sched.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-list.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "missing_mount.h"
#include "mount-util.h"
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
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_alias) >= 0);

        assert_se(inode_same(name, name, 0) > 0);
        assert_se(inode_same(name, name, AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(inode_same(name, name_alias, 0) > 0);
        assert_se(inode_same(name, name_alias, AT_SYMLINK_NOFOLLOW) == 0);

        assert_se(inode_same("/proc", "/proc", 0));
        assert_se(inode_same("/proc", "/proc", AT_SYMLINK_NOFOLLOW));

        _cleanup_close_ int fd1 = open("/dev/null", O_CLOEXEC|O_RDONLY),
                fd2 = open("/dev/null", O_CLOEXEC|O_RDONLY);

        assert_se(fd1 >= 0);
        assert_se(fd2 >= 0);

        assert_se(inode_same_at(fd1, NULL, fd2, NULL, AT_EMPTY_PATH) > 0);
        assert_se(inode_same_at(fd2, NULL, fd1, NULL, AT_EMPTY_PATH) > 0);
        assert_se(inode_same_at(fd1, NULL, fd2, NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(inode_same_at(fd2, NULL, fd1, NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) > 0);
        assert_se(inode_same_at(fd1, NULL, fd1, NULL, AT_EMPTY_PATH) > 0);
        assert_se(inode_same_at(fd2, NULL, fd2, NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) > 0);

        safe_close(fd2);
        fd2 = open("/dev/urandom", O_CLOEXEC|O_RDONLY);
        assert_se(fd2 >= 0);

        assert_se(inode_same_at(fd1, NULL, fd2, NULL, AT_EMPTY_PATH) == 0);
        assert_se(inode_same_at(fd2, NULL, fd1, NULL, AT_EMPTY_PATH) == 0);
        assert_se(inode_same_at(fd1, NULL, fd2, NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) == 0);
        assert_se(inode_same_at(fd2, NULL, fd1, NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) == 0);

        assert_se(inode_same_at(AT_FDCWD, NULL, AT_FDCWD, NULL, AT_EMPTY_PATH) > 0);
        assert_se(inode_same_at(AT_FDCWD, NULL, fd1, NULL, AT_EMPTY_PATH) == 0);
        assert_se(inode_same_at(fd1, NULL, AT_FDCWD, NULL, AT_EMPTY_PATH) == 0);

        _cleanup_(umount_and_unlink_and_freep) char *p = NULL;

        assert_se(tempfn_random_child(NULL, NULL, &p) >= 0);
        assert_se(touch(p) >= 0);

        r = mount_nofollow_verbose(LOG_ERR, name, p, NULL, MS_BIND, NULL);
        if (r < 0)
                assert_se(ERRNO_IS_NEG_PRIVILEGE(r));
        else {
                assert_se(inode_same(name, p, 0) > 0);
                assert_se(inode_same(name, p, AT_SYMLINK_NOFOLLOW) > 0);
        }
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
        if (path_is_mount_point_full("/run", NULL, AT_SYMLINK_FOLLOW) > 0) {
                assert_se(path_is_fs_type("/run", TMPFS_MAGIC) > 0);
                assert_se(path_is_fs_type("/run", BTRFS_SUPER_MAGIC) == 0);
        }
        if (path_is_mount_point_full("/proc", NULL, AT_SYMLINK_FOLLOW) > 0) {
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
        if (path_is_mount_point_full("/run", NULL, AT_SYMLINK_FOLLOW) > 0)
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

        if (path_is_mount_point_full("/sys", NULL, AT_SYMLINK_FOLLOW) > 0)
                assert_se(IN_SET(path_is_read_only_fs("/sys"), 0, 1));

        assert_se(path_is_read_only_fs("/proc") == 0);
        assert_se(path_is_read_only_fs("/i-dont-exist") == -ENOENT);
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

        FOREACH_ELEMENT(m, types)
                assert_se(inode_type_from_string(inode_type_to_string(*m)) == *m);
}

TEST(anonymous_inode) {
        _cleanup_close_ int fd = -EBADF;

        fd = eventfd(0, EFD_CLOEXEC);
        assert_se(fd >= 0);

        /* Verify that we handle anonymous inodes correctly, i.e. those which have no file type */

        struct stat st;
        ASSERT_OK_ERRNO(fstat(fd, &st));
        assert_se((st.st_mode & S_IFMT) == 0);

        assert_se(!inode_type_to_string(st.st_mode));
}

TEST(fd_verify_linked) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL;

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);

        assert_se(p = path_join(t, "hoge"));
        assert_se(touch(p) >= 0);

        fd = open(p, O_CLOEXEC | O_PATH);
        assert_se(fd >= 0);

        assert_se(fd_verify_linked(fd) >= 0);
        assert_se(unlinkat(tfd, "hoge", 0) >= 0);
        assert_se(fd_verify_linked(fd) == -EIDRM);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
