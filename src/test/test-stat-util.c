/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing.h"
#include "mountpoint-util.h"
#include "stat-util.h"

static void test_files_same(void) {
        _cleanup_close_ int fd = -1;
        char name[] = "/tmp/test-files_same.XXXXXX";
        char name_alias[] = "/tmp/test-files_same.alias";

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_alias) >= 0);

        assert_se(files_same(name, name, 0));
        assert_se(files_same(name, name, AT_SYMLINK_NOFOLLOW));
        assert_se(files_same(name, name_alias, 0));
        assert_se(!files_same(name, name_alias, AT_SYMLINK_NOFOLLOW));

        unlink(name);
        unlink(name_alias);
}

static void test_is_symlink(void) {
        char name[] = "/tmp/test-is_symlink.XXXXXX";
        char name_link[] = "/tmp/test-is_symlink.link";
        _cleanup_close_ int fd = -1;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(symlink(name, name_link) >= 0);

        assert_se(is_symlink(name) == 0);
        assert_se(is_symlink(name_link) == 1);
        assert_se(is_symlink("/a/file/which/does/not/exist/i/guess") < 0);

        unlink(name);
        unlink(name_link);
}

static void test_path_is_fs_type(void) {
        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0) {
                assert_se(path_is_fs_type("/run", TMPFS_MAGIC) > 0);
                assert_se(path_is_fs_type("/run", BTRFS_SUPER_MAGIC) == 0);
        }
        assert_se(path_is_fs_type("/proc", PROC_SUPER_MAGIC) > 0);
        assert_se(path_is_fs_type("/proc", BTRFS_SUPER_MAGIC) == 0);
        assert_se(path_is_fs_type("/proc", BTRFS_SUPER_MAGIC) == 0);
        assert_se(path_is_fs_type("/i-dont-exist", BTRFS_SUPER_MAGIC) == -ENOENT);
}

static void test_path_is_temporary_fs(void) {
        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0)
                assert_se(path_is_temporary_fs("/run") > 0);
        assert_se(path_is_temporary_fs("/proc") == 0);
        assert_se(path_is_temporary_fs("/i-dont-exist") == -ENOENT);
}

static void test_fd_is_network_ns(void) {
        _cleanup_close_ int fd = -1;
        assert_se(fd_is_network_ns(STDIN_FILENO) == 0);
        assert_se(fd_is_network_ns(STDERR_FILENO) == 0);
        assert_se(fd_is_network_ns(STDOUT_FILENO) == 0);

        assert_se((fd = open("/proc/self/ns/mnt", O_CLOEXEC|O_RDONLY)) >= 0);
        assert_se(IN_SET(fd_is_network_ns(fd), 0, -EUCLEAN));
        fd = safe_close(fd);

        assert_se((fd = open("/proc/self/ns/net", O_CLOEXEC|O_RDONLY)) >= 0);
        assert_se(IN_SET(fd_is_network_ns(fd), 1, -EUCLEAN));
}

int main(int argc, char *argv[]) {
        test_files_same();
        test_is_symlink();
        test_path_is_fs_type();
        test_path_is_temporary_fs();
        test_fd_is_network_ns();

        return 0;
}
