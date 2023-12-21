/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "constants.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_mount_propagation_flag_one(const char *name, int ret, unsigned long expected) {
        unsigned long flags;

        log_info("/* %s(%s) */", __func__, strnull(name));

        assert_se(mount_propagation_flag_from_string(name, &flags) == ret);

        if (ret >= 0) {
                const char *c;

                assert_se(flags == expected);

                c = mount_propagation_flag_to_string(flags);
                if (isempty(name))
                        assert_se(isempty(c));
                else
                        assert_se(streq(c, name));
        }
}

TEST(mount_propagation_flag) {
        test_mount_propagation_flag_one("shared", 0, MS_SHARED);
        test_mount_propagation_flag_one("slave", 0, MS_SLAVE);
        test_mount_propagation_flag_one("private", 0, MS_PRIVATE);
        test_mount_propagation_flag_one(NULL, 0, 0);
        test_mount_propagation_flag_one("", 0, 0);
        test_mount_propagation_flag_one("xxxx", -EINVAL, 0);
        test_mount_propagation_flag_one(" ", -EINVAL, 0);
}

TEST(mnt_id) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_hashmap_free_free_ Hashmap *h = NULL;
        char *p;
        void *k;
        int r;

        assert_se(f = fopen("/proc/self/mountinfo", "re"));
        assert_se(h = hashmap_new(&trivial_hash_ops));

        for (;;) {
                _cleanup_free_ char *line = NULL, *path = NULL;
                int mnt_id;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r == 0)
                        break;
                assert_se(r > 0);

                assert_se(sscanf(line, "%i %*s %*s %*s %ms", &mnt_id, &path) == 2);
#if HAS_FEATURE_MEMORY_SANITIZER
                /* We don't know the length of the string, so we need to unpoison it one char at a time */
                for (const char *c = path; ;c++) {
                        msan_unpoison(c, 1);
                        if (!*c)
                                break;
                }
#endif
                log_debug("mountinfo: %s → %i", path, mnt_id);

                assert_se(hashmap_put(h, INT_TO_PTR(mnt_id), path) >= 0);
                path = NULL;
        }

        HASHMAP_FOREACH_KEY(p, k, h) {
                int mnt_id = PTR_TO_INT(k), mnt_id2;
                const char *q;

                r = path_get_mnt_id(p, &mnt_id2);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get the mnt id of %s: %m", p);
                        continue;
                }

                if (mnt_id == mnt_id2) {
                        log_debug("mnt ids of %s is %i.", p, mnt_id);
                        continue;
                } else
                        log_debug("mnt ids of %s are %i (from /proc/self/mountinfo), %i (from path_get_mnt_id()).", p, mnt_id, mnt_id2);

                /* The ids don't match? This can easily happen e.g. running with "unshare --mount-proc".
                 * See #11505. */
                assert_se(q = hashmap_get(h, INT_TO_PTR(mnt_id2)));

                assert_se((r = path_is_mount_point(p, NULL, 0)) >= 0);
                if (r == 0) {
                        /* If the path is not a mount point anymore, then it must be a sub directory of
                         * the path corresponds to mnt_id2. */
                        log_debug("The path %s for mnt id %i is not a mount point.", p, mnt_id2);
                        assert_se(!isempty(path_startswith(p, q)));
                } else {
                        /* If the path is still a mount point, then it must be equivalent to the path
                         * corresponds to mnt_id2 */
                        log_debug("There are multiple mounts on the same path %s.", p);
                        assert_se(path_equal(p, q));
                }
        }
}

TEST(path_is_mount_point) {
        int fd;
        char tmp_dir[] = "/tmp/test-path-is-mount-point-XXXXXX";
        _cleanup_free_ char *file1 = NULL, *file2 = NULL, *link1 = NULL, *link2 = NULL;
        _cleanup_free_ char *dir1 = NULL, *dir1file = NULL, *dirlink1 = NULL, *dirlink1file = NULL;
        _cleanup_free_ char *dir2 = NULL, *dir2file = NULL;

        assert_se(path_is_mount_point("/", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/", NULL, 0) > 0);
        assert_se(path_is_mount_point("//", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("//", NULL, 0) > 0);

        assert_se(path_is_mount_point("/proc", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/proc", NULL, 0) > 0);
        assert_se(path_is_mount_point("/proc/", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/proc/", NULL, 0) > 0);

        assert_se(path_is_mount_point("/proc/1", NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point("/proc/1", NULL, 0) == 0);
        assert_se(path_is_mount_point("/proc/1/", NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point("/proc/1/", NULL, 0) == 0);

        /* we'll create a hierarchy of different kinds of dir/file/link
         * layouts:
         *
         * <tmp>/file1, <tmp>/file2
         * <tmp>/link1 -> file1, <tmp>/link2 -> file2
         * <tmp>/dir1/
         * <tmp>/dir1/file
         * <tmp>/dirlink1 -> dir1
         * <tmp>/dirlink1file -> dirlink1/file
         * <tmp>/dir2/
         * <tmp>/dir2/file
         */

        /* file mountpoints */
        assert_se(mkdtemp(tmp_dir) != NULL);
        file1 = path_join(tmp_dir, "file1");
        assert_se(file1);
        file2 = path_join(tmp_dir, "file2");
        assert_se(file2);
        fd = open(file1, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);
        fd = open(file2, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);
        link1 = path_join(tmp_dir, "link1");
        assert_se(link1);
        assert_se(symlink("file1", link1) == 0);
        link2 = path_join(tmp_dir, "link2");
        assert_se(link1);
        assert_se(symlink("file2", link2) == 0);

        assert_se(path_is_mount_point(file1, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(file1, NULL, 0) == 0);
        assert_se(path_is_mount_point(link1, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(link1, NULL, 0) == 0);

        /* directory mountpoints */
        dir1 = path_join(tmp_dir, "dir1");
        assert_se(dir1);
        assert_se(mkdir(dir1, 0755) == 0);
        dirlink1 = path_join(tmp_dir, "dirlink1");
        assert_se(dirlink1);
        assert_se(symlink("dir1", dirlink1) == 0);
        dirlink1file = path_join(tmp_dir, "dirlink1file");
        assert_se(dirlink1file);
        assert_se(symlink("dirlink1/file", dirlink1file) == 0);
        dir2 = path_join(tmp_dir, "dir2");
        assert_se(dir2);
        assert_se(mkdir(dir2, 0755) == 0);

        assert_se(path_is_mount_point(dir1, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dir1, NULL, 0) == 0);
        assert_se(path_is_mount_point(dirlink1, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dirlink1, NULL, 0) == 0);

        /* file in subdirectory mountpoints */
        dir1file = path_join(dir1, "file");
        assert_se(dir1file);
        fd = open(dir1file, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
        assert_se(fd > 0);
        close(fd);

        assert_se(path_is_mount_point(dir1file, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dir1file, NULL, 0) == 0);
        assert_se(path_is_mount_point(dirlink1file, NULL, AT_SYMLINK_FOLLOW) == 0);
        assert_se(path_is_mount_point(dirlink1file, NULL, 0) == 0);

        /* these tests will only work as root */
        if (mount(file1, file2, NULL, MS_BIND, NULL) >= 0) {
                int rf, rt, rdf, rdt, rlf, rlt, rl1f, rl1t;
                const char *file2d;

                /* files */
                /* capture results in vars, to avoid dangling mounts on failure */
                log_info("%s: %s", __func__, file2);
                rf = path_is_mount_point(file2, NULL, 0);
                rt = path_is_mount_point(file2, NULL, AT_SYMLINK_FOLLOW);

                file2d = strjoina(file2, "/");
                log_info("%s: %s", __func__, file2d);
                rdf = path_is_mount_point(file2d, NULL, 0);
                rdt = path_is_mount_point(file2d, NULL, AT_SYMLINK_FOLLOW);

                log_info("%s: %s", __func__, link2);
                rlf = path_is_mount_point(link2, NULL, 0);
                rlt = path_is_mount_point(link2, NULL, AT_SYMLINK_FOLLOW);

                assert_se(umount(file2) == 0);

                assert_se(rf == 1);
                assert_se(rt == 1);
                assert_se(rdf == -ENOTDIR);
                assert_se(rdt == -ENOTDIR);
                assert_se(rlf == 0);
                assert_se(rlt == 1);

                /* dirs */
                dir2file = path_join(dir2, "file");
                assert_se(dir2file);
                fd = open(dir2file, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0664);
                assert_se(fd > 0);
                close(fd);

                assert_se(mount(dir2, dir1, NULL, MS_BIND, NULL) >= 0);

                log_info("%s: %s", __func__, dir1);
                rf = path_is_mount_point(dir1, NULL, 0);
                rt = path_is_mount_point(dir1, NULL, AT_SYMLINK_FOLLOW);
                log_info("%s: %s", __func__, dirlink1);
                rlf = path_is_mount_point(dirlink1, NULL, 0);
                rlt = path_is_mount_point(dirlink1, NULL, AT_SYMLINK_FOLLOW);
                log_info("%s: %s", __func__, dirlink1file);
                /* its parent is a mount point, but not /file itself */
                rl1f = path_is_mount_point(dirlink1file, NULL, 0);
                rl1t = path_is_mount_point(dirlink1file, NULL, AT_SYMLINK_FOLLOW);

                assert_se(umount(dir1) == 0);

                assert_se(rf == 1);
                assert_se(rt == 1);
                assert_se(rlf == 0);
                assert_se(rlt == 1);
                assert_se(rl1f == 0);
                assert_se(rl1t == 0);

        } else
                log_info("Skipping bind mount file test");

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

TEST(fd_is_mount_point) {
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = open("/", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY);
        assert_se(fd >= 0);

        /* Not allowed, since "/" is a path, not a plain filename */
        assert_se(fd_is_mount_point(fd, "/", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, ".", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "./", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "..", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "../", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "/proc", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "/proc/", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "proc/sys", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "proc/sys/", 0) == -EINVAL);

        /* This one definitely is a mount point */
        assert_se(fd_is_mount_point(fd, "proc", 0) > 0);
        assert_se(fd_is_mount_point(fd, "proc/", 0) > 0);

        safe_close(fd);
        fd = open("/tmp", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY);
        assert_se(fd >= 0);

        assert_se(mkdtemp_malloc("/tmp/not-mounted-XXXXXX", &tmpdir) >= 0);
        assert_se(fd_is_mount_point(fd, basename(tmpdir), 0) == 0);
        assert_se(fd_is_mount_point(fd, strjoina(basename(tmpdir), "/"), 0) == 0);

        safe_close(fd);
        fd = open("/proc", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOCTTY);
        assert_se(fd >= 0);

        assert_se(fd_is_mount_point(fd, NULL, 0) > 0);
        assert_se(fd_is_mount_point(fd, "", 0) == -EINVAL);
        assert_se(fd_is_mount_point(fd, "version", 0) == 0);

        safe_close(fd);
        fd = open("/proc/version", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);

        r = fd_is_mount_point(fd, NULL, 0);
        assert_se(IN_SET(r, 0, -ENOTDIR)); /* on old kernels we can't determine if regular files are mount points if we have no directory fd */
        assert_se(fd_is_mount_point(fd, "", 0) == -EINVAL);
}

TEST(ms_nosymfollow_supported) {
        log_info("MS_NOSYMFOLLOW supported: %s", yes_no(ms_nosymfollow_supported()));
}

TEST(mount_option_supported) {
        int r;

        r = mount_option_supported("tmpfs", "size", "64M");
        log_info("tmpfs supports size=64M: %s (%i)", r < 0 ? "don't know" : yes_no(r), r);
        assert_se(r > 0 || r == -EAGAIN || (r < 0 && ERRNO_IS_PRIVILEGE(r)));

        r = mount_option_supported("ext4", "discard", NULL);
        log_info("ext4 supports discard: %s (%i)", r < 0 ? "don't know" : yes_no(r), r);
        assert_se(r > 0 || r == -EAGAIN || (r < 0 && ERRNO_IS_PRIVILEGE(r)));

        r = mount_option_supported("tmpfs", "idontexist", "64M");
        log_info("tmpfs supports idontexist: %s (%i)", r < 0 ? "don't know" : yes_no(r), r);
        assert_se(r == 0 || r == -EAGAIN || (r < 0 && ERRNO_IS_PRIVILEGE(r)));

        r = mount_option_supported("tmpfs", "ialsodontexist", NULL);
        log_info("tmpfs supports ialsodontexist: %s (%i)", r < 0 ? "don't know" : yes_no(r), r);
        assert_se(r == 0 || r == -EAGAIN || (r < 0 && ERRNO_IS_PRIVILEGE(r)));

        r = mount_option_supported("proc", "hidepid", "1");
        log_info("proc supports hidepid=1: %s (%i)", r < 0 ? "don't know" : yes_no(r), r);
        assert_se(r >= 0 || r == -EAGAIN || (r < 0 && ERRNO_IS_PRIVILEGE(r)));
}

TEST(fstype_can_discard) {
        assert_se(fstype_can_discard("ext4"));
        assert_se(!fstype_can_discard("squashfs"));
        assert_se(!fstype_can_discard("iso9660"));
}

TEST(fstype_can_norecovery) {
        assert_se(fstype_can_norecovery("ext4"));
        assert_se(!fstype_can_norecovery("vfat"));
        assert_se(!fstype_can_norecovery("tmpfs"));
}

TEST(fstype_can_umask) {
        assert_se(fstype_can_umask("vfat"));
        assert_se(!fstype_can_umask("tmpfs"));
}

TEST(path_get_mnt_id_at_null) {
        _cleanup_close_ int root_fd = -EBADF, run_fd = -EBADF;
        int id1, id2;

        assert_se(path_get_mnt_id_at(AT_FDCWD, "/run/", &id1) >= 0);
        assert_se(id1 > 0);

        assert_se(path_get_mnt_id_at(AT_FDCWD, "/run", &id2) >= 0);
        assert_se(id1 == id2);
        id2 = -1;

        root_fd = open("/", O_DIRECTORY|O_CLOEXEC);
        assert_se(root_fd >= 0);

        assert_se(path_get_mnt_id_at(root_fd, "/run/", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        assert_se(path_get_mnt_id_at(root_fd, "/run", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        assert_se(path_get_mnt_id_at(root_fd, "run", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        assert_se(path_get_mnt_id_at(root_fd, "run/", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        run_fd = openat(root_fd, "run", O_DIRECTORY|O_CLOEXEC);
        assert_se(run_fd >= 0);

        id2 = -1;
        assert_se(path_get_mnt_id_at(run_fd, "", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        assert_se(path_get_mnt_id_at(run_fd, NULL, &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;

        assert_se(path_get_mnt_id_at(run_fd, ".", &id2) >= 0);
        assert_se(id1 = id2);
        id2 = -1;
}

static int intro(void) {
        /* let's move into our own mount namespace with all propagation from the host turned off, so
         * that /proc/self/mountinfo is static and constant for the whole time our test runs. */

        if (unshare(CLONE_NEWNS) < 0) {
                if (!ERRNO_IS_PRIVILEGE(errno))
                        return log_error_errno(errno, "Failed to detach mount namespace: %m");

                log_notice("Lacking privilege to create separate mount namespace, proceeding in originating mount namespace.");
        } else
                assert_se(mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) >= 0);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
