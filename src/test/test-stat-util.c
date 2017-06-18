/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "missing.h"
#include "mount-util.h"
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

static void test_path_is_os_tree(void) {
        assert_se(path_is_os_tree("/") > 0);
        assert_se(path_is_os_tree("/etc") == 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

static void test_path_check_fstype(void) {
        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0) {
                assert_se(path_check_fstype("/run", TMPFS_MAGIC) > 0);
                assert_se(path_check_fstype("/run", BTRFS_SUPER_MAGIC) == 0);
        }
        assert_se(path_check_fstype("/proc", PROC_SUPER_MAGIC) > 0);
        assert_se(path_check_fstype("/proc", BTRFS_SUPER_MAGIC) == 0);
        assert_se(path_check_fstype("/proc", BTRFS_SUPER_MAGIC) == 0);
        assert_se(path_check_fstype("/i-dont-exist", BTRFS_SUPER_MAGIC) == -ENOENT);
}

static void test_path_is_temporary_fs(void) {
        /* run might not be a mount point in build chroots */
        if (path_is_mount_point("/run", NULL, AT_SYMLINK_FOLLOW) > 0)
                assert_se(path_is_temporary_fs("/run") > 0);
        assert_se(path_is_temporary_fs("/proc") == 0);
        assert_se(path_is_temporary_fs("/i-dont-exist") == -ENOENT);
}

int main(int argc, char *argv[]) {
        test_files_same();
        test_is_symlink();
        test_path_is_os_tree();
        test_path_check_fstype();
        test_path_is_temporary_fs();

        return 0;
}
