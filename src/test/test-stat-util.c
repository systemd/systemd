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

TEST(files_same) {
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

TEST(is_symlink) {
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
        const char *s;
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
        const char *s;
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
        _cleanup_close_ int fd = -1;

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

TEST(device_major_minor_valid) {
        /* on glibc dev_t is 64bit, even though in the kernel it is only 32bit */
        assert_cc(sizeof(dev_t) == sizeof(uint64_t));

        assert_se(DEVICE_MAJOR_VALID(0U));
        assert_se(DEVICE_MINOR_VALID(0U));

        assert_se(DEVICE_MAJOR_VALID(1U));
        assert_se(DEVICE_MINOR_VALID(1U));

        assert_se(!DEVICE_MAJOR_VALID(-1U));
        assert_se(!DEVICE_MINOR_VALID(-1U));

        assert_se(DEVICE_MAJOR_VALID(1U << 10));
        assert_se(DEVICE_MINOR_VALID(1U << 10));

        assert_se(DEVICE_MAJOR_VALID((1U << 12) - 1));
        assert_se(DEVICE_MINOR_VALID((1U << 20) - 1));

        assert_se(!DEVICE_MAJOR_VALID((1U << 12)));
        assert_se(!DEVICE_MINOR_VALID((1U << 20)));

        assert_se(!DEVICE_MAJOR_VALID(1U << 25));
        assert_se(!DEVICE_MINOR_VALID(1U << 25));

        assert_se(!DEVICE_MAJOR_VALID(UINT32_MAX));
        assert_se(!DEVICE_MINOR_VALID(UINT32_MAX));

        assert_se(!DEVICE_MAJOR_VALID(UINT64_MAX));
        assert_se(!DEVICE_MINOR_VALID(UINT64_MAX));

        assert_se(DEVICE_MAJOR_VALID(major(0)));
        assert_se(DEVICE_MINOR_VALID(minor(0)));
}

static void test_device_path_make_canonical_one(const char *path) {
        _cleanup_free_ char *resolved = NULL, *raw = NULL;
        struct stat st;
        dev_t devno;
        mode_t mode;
        int r;

        log_debug("> %s", path);

        if (stat(path, &st) < 0) {
                assert_se(errno == ENOENT);
                log_notice("Path %s not found, skipping test", path);
                return;
        }

        r = device_path_make_canonical(st.st_mode, st.st_rdev, &resolved);
        if (r == -ENOENT) {
                /* maybe /dev/char/x:y and /dev/block/x:y are missing in this test environment, because we
                 * run in a container or so? */
                log_notice("Device %s cannot be resolved, skipping test", path);
                return;
        }

        assert_se(r >= 0);
        assert_se(path_equal(path, resolved));

        assert_se(device_path_make_major_minor(st.st_mode, st.st_rdev, &raw) >= 0);
        assert_se(device_path_parse_major_minor(raw, &mode, &devno) >= 0);

        assert_se(st.st_rdev == devno);
        assert_se((st.st_mode & S_IFMT) == (mode & S_IFMT));
}

TEST(device_path_make_canonical) {
        test_device_path_make_canonical_one("/dev/null");
        test_device_path_make_canonical_one("/dev/zero");
        test_device_path_make_canonical_one("/dev/full");
        test_device_path_make_canonical_one("/dev/random");
        test_device_path_make_canonical_one("/dev/urandom");
        test_device_path_make_canonical_one("/dev/tty");

        if (is_device_node("/run/systemd/inaccessible/blk") > 0) {
                test_device_path_make_canonical_one("/run/systemd/inaccessible/chr");
                test_device_path_make_canonical_one("/run/systemd/inaccessible/blk");
        }
}

TEST(dir_is_empty) {
        _cleanup_(rm_rf_physical_and_freep) char *empty_dir = NULL;
        _cleanup_free_ char *j = NULL, *jj = NULL;

        assert_se(dir_is_empty_at(AT_FDCWD, "/proc") == 0);
        assert_se(dir_is_empty_at(AT_FDCWD, "/icertainlydontexistdoi") == -ENOENT);

        assert_se(mkdtemp_malloc("/tmp/emptyXXXXXX", &empty_dir) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir) > 0);

        j = path_join(empty_dir, "zzz");
        assert_se(j);
        assert_se(touch(j) >= 0);

        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir) == 0);

        jj = path_join(empty_dir, "ppp");
        assert_se(jj);
        assert_se(touch(jj) >= 0);

        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir) == 0);
        assert_se(unlink(j) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir) == 0);
        assert_se(unlink(jj) >= 0);
        assert_se(dir_is_empty_at(AT_FDCWD, empty_dir) > 0);
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
