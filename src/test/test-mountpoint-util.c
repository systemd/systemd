/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"

static void test_mount_propagation_flags(const char *name, int ret, unsigned long expected) {
        long unsigned flags;

        log_info("/* %s(%s) */", __func__, name);

        assert_se(mount_propagation_flags_from_string(name, &flags) == ret);

        if (ret >= 0) {
                const char *c;

                assert_se(flags == expected);

                c = mount_propagation_flags_to_string(flags);
                if (isempty(name))
                        assert_se(isempty(c));
                else
                        assert_se(streq(c, name));
        }
}

static void test_mnt_id(void) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_hashmap_free_free_ Hashmap *h = NULL;
        Iterator i;
        char *p;
        void *k;
        int r;

        log_info("/* %s */", __func__);

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

        HASHMAP_FOREACH_KEY(p, k, h, i) {
                int mnt_id = PTR_TO_INT(k), mnt_id2;

                r = path_get_mnt_id(p, &mnt_id2);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get the mnt id of %s: %m\n", p);
                        continue;
                }

                log_debug("mnt ids of %s are %i, %i\n", p, mnt_id, mnt_id2);

                if (mnt_id == mnt_id2)
                        continue;

                /* The ids don't match? If so, then there are two mounts on the same path, let's check if
                 * that's really the case */
                char *t = hashmap_get(h, INT_TO_PTR(mnt_id2));
                log_debug("the other path for mnt id %i is %s\n", mnt_id2, t);
                assert_se(path_equal(p, t));
        }
}

static void test_path_is_mount_point(void) {
        int fd;
        char tmp_dir[] = "/tmp/test-path-is-mount-point-XXXXXX";
        _cleanup_free_ char *file1 = NULL, *file2 = NULL, *link1 = NULL, *link2 = NULL;
        _cleanup_free_ char *dir1 = NULL, *dir1file = NULL, *dirlink1 = NULL, *dirlink1file = NULL;
        _cleanup_free_ char *dir2 = NULL, *dir2file = NULL;

        log_info("/* %s */", __func__);

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

        assert_se(path_is_mount_point("/sys", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/sys", NULL, 0) > 0);
        assert_se(path_is_mount_point("/sys/", NULL, AT_SYMLINK_FOLLOW) > 0);
        assert_se(path_is_mount_point("/sys/", NULL, 0) > 0);

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
                printf("Skipping bind mount file test: %m\n");

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_mount_propagation_flags("shared", 0, MS_SHARED);
        test_mount_propagation_flags("slave", 0, MS_SLAVE);
        test_mount_propagation_flags("private", 0, MS_PRIVATE);
        test_mount_propagation_flags(NULL, 0, 0);
        test_mount_propagation_flags("", 0, 0);
        test_mount_propagation_flags("xxxx", -EINVAL, 0);
        test_mount_propagation_flags(" ", -EINVAL, 0);

        test_mnt_id();
        test_path_is_mount_point();

        return 0;
}
