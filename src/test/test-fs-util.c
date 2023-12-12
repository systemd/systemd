/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <unistd.h>

#include "alloc-util.h"
#include "copy.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "virt.h"

static const char *arg_test_dir = NULL;

TEST(readlink_and_make_absolute) {
        const char *tempdir, *name, *name2, *name_alias;
        _cleanup_free_ char *r1 = NULL, *r2 = NULL, *pwd = NULL;

        tempdir = strjoina(arg_test_dir ?: "/tmp", "/test-readlink_and_make_absolute");
        name = strjoina(tempdir, "/original");
        name2 = "test-readlink_and_make_absolute/original";
        name_alias = strjoina(arg_test_dir ?: "/tmp", "/test-readlink_and_make_absolute-alias");

        assert_se(mkdir_safe(tempdir, 0755, getuid(), getgid(), MKDIR_WARN_MODE) >= 0);
        assert_se(touch(name) >= 0);

        if (symlink(name, name_alias) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
        } else {
                assert_se(readlink_and_make_absolute(name_alias, &r1) >= 0);
                assert_se(streq(r1, name));
                assert_se(unlink(name_alias) >= 0);

                assert_se(safe_getcwd(&pwd) >= 0);

                assert_se(chdir(tempdir) >= 0);
                assert_se(symlink(name2, name_alias) >= 0);
                assert_se(readlink_and_make_absolute(name_alias, &r2) >= 0);
                assert_se(streq(r2, name));
                assert_se(unlink(name_alias) >= 0);

                assert_se(chdir(pwd) >= 0);
        }

        assert_se(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

TEST(get_files_in_directory) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        assert_se(get_files_in_directory(arg_test_dir ?: "/tmp", &l) >= 0);
        assert_se(get_files_in_directory(".", &t) >= 0);
        assert_se(get_files_in_directory(".", NULL) >= 0);
}

TEST(var_tmp) {
        _cleanup_free_ char *tmpdir_backup = NULL, *temp_backup = NULL, *tmp_backup = NULL;
        const char *tmp_dir = NULL, *t;

        t = getenv("TMPDIR");
        if (t) {
                tmpdir_backup = strdup(t);
                assert_se(tmpdir_backup);
        }

        t = getenv("TEMP");
        if (t) {
                temp_backup = strdup(t);
                assert_se(temp_backup);
        }

        t = getenv("TMP");
        if (t) {
                tmp_backup = strdup(t);
                assert_se(tmp_backup);
        }

        assert_se(unsetenv("TMPDIR") >= 0);
        assert_se(unsetenv("TEMP") >= 0);
        assert_se(unsetenv("TMP") >= 0);

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/var/tmp"));

        assert_se(setenv("TMPDIR", "/tmp", true) >= 0);
        assert_se(streq(getenv("TMPDIR"), "/tmp"));

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/tmp"));

        assert_se(setenv("TMPDIR", "/88_does_not_exist_88", true) >= 0);
        assert_se(streq(getenv("TMPDIR"), "/88_does_not_exist_88"));

        assert_se(var_tmp_dir(&tmp_dir) >= 0);
        assert_se(streq(tmp_dir, "/var/tmp"));

        if (tmpdir_backup)  {
                assert_se(setenv("TMPDIR", tmpdir_backup, true) >= 0);
                assert_se(streq(getenv("TMPDIR"), tmpdir_backup));
        }

        if (temp_backup)  {
                assert_se(setenv("TEMP", temp_backup, true) >= 0);
                assert_se(streq(getenv("TEMP"), temp_backup));
        }

        if (tmp_backup)  {
                assert_se(setenv("TMP", tmp_backup, true) >= 0);
                assert_se(streq(getenv("TMP"), tmp_backup));
        }
}

TEST(dot_or_dot_dot) {
        assert_se(!dot_or_dot_dot(NULL));
        assert_se(!dot_or_dot_dot(""));
        assert_se(!dot_or_dot_dot("xxx"));
        assert_se(dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot(".."));
        assert_se(!dot_or_dot_dot(".foo"));
        assert_se(!dot_or_dot_dot("..foo"));
}

TEST(access_fd) {
        _cleanup_(rmdir_and_freep) char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *a;

        a = strjoina(arg_test_dir ?: "/tmp", "/access-fd.XXXXXX");
        assert_se(mkdtemp_malloc(a, &p) >= 0);

        fd = open(p, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        assert_se(fd >= 0);

        assert_se(access_fd(fd, R_OK) >= 0);
        assert_se(access_fd(fd, F_OK) >= 0);
        assert_se(access_fd(fd, W_OK) >= 0);

        assert_se(fchmod(fd, 0000) >= 0);

        assert_se(access_fd(fd, F_OK) >= 0);

        if (geteuid() == 0) {
                assert_se(access_fd(fd, R_OK) >= 0);
                assert_se(access_fd(fd, W_OK) >= 0);
        } else {
                assert_se(access_fd(fd, R_OK) == -EACCES);
                assert_se(access_fd(fd, W_OK) == -EACCES);
        }
}

TEST(touch_file) {
        uid_t test_uid, test_gid;
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        struct stat st;
        const char *a;
        usec_t test_mtime;
        int r;

        test_uid = geteuid() == 0 ? 65534 : getuid();
        test_gid = geteuid() == 0 ? 65534 : getgid();

        test_mtime = usec_sub_unsigned(now(CLOCK_REALTIME), USEC_PER_WEEK);

        a = strjoina(arg_test_dir ?: "/dev/shm", "/touch-file-XXXXXX");
        assert_se(mkdtemp_malloc(a, &p) >= 0);

        a = strjoina(p, "/regular");
        r = touch_file(a, false, test_mtime, test_uid, test_gid, 0640);
        if (r < 0) {
                assert_se(IN_SET(r, -EINVAL, -ENOSYS, -ENOTTY, -EPERM));
                log_tests_skipped_errno(errno, "touch_file() not possible");
                return;
        }

        assert_se(lstat(a, &st) >= 0);
        assert_se(st.st_uid == test_uid);
        assert_se(st.st_gid == test_gid);
        assert_se(S_ISREG(st.st_mode));
        assert_se((st.st_mode & 0777) == 0640);
        assert_se(timespec_load(&st.st_mtim) == test_mtime);

        a = strjoina(p, "/dir");
        assert_se(mkdir(a, 0775) >= 0);
        assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
        assert_se(lstat(a, &st) >= 0);
        assert_se(st.st_uid == test_uid);
        assert_se(st.st_gid == test_gid);
        assert_se(S_ISDIR(st.st_mode));
        assert_se((st.st_mode & 0777) == 0640);
        assert_se(timespec_load(&st.st_mtim) == test_mtime);

        a = strjoina(p, "/fifo");
        assert_se(mkfifo(a, 0775) >= 0);
        assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
        assert_se(lstat(a, &st) >= 0);
        assert_se(st.st_uid == test_uid);
        assert_se(st.st_gid == test_gid);
        assert_se(S_ISFIFO(st.st_mode));
        assert_se((st.st_mode & 0777) == 0640);
        assert_se(timespec_load(&st.st_mtim) == test_mtime);

        a = strjoina(p, "/sock");
        assert_se(mknod(a, 0775 | S_IFSOCK, 0) >= 0);
        assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
        assert_se(lstat(a, &st) >= 0);
        assert_se(st.st_uid == test_uid);
        assert_se(st.st_gid == test_gid);
        assert_se(S_ISSOCK(st.st_mode));
        assert_se((st.st_mode & 0777) == 0640);
        assert_se(timespec_load(&st.st_mtim) == test_mtime);

        if (geteuid() == 0) {
                a = strjoina(p, "/bdev");
                r = mknod(a, 0775 | S_IFBLK, makedev(0, 0));
                if (r < 0 && errno == EPERM && detect_container() > 0) {
                        log_notice("Running in unprivileged container? Skipping remaining tests in %s", __func__);
                        return;
                }
                assert_se(r >= 0);
                assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
                assert_se(lstat(a, &st) >= 0);
                assert_se(st.st_uid == test_uid);
                assert_se(st.st_gid == test_gid);
                assert_se(S_ISBLK(st.st_mode));
                assert_se((st.st_mode & 0777) == 0640);
                assert_se(timespec_load(&st.st_mtim) == test_mtime);

                a = strjoina(p, "/cdev");
                assert_se(mknod(a, 0775 | S_IFCHR, makedev(0, 0)) >= 0);
                assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
                assert_se(lstat(a, &st) >= 0);
                assert_se(st.st_uid == test_uid);
                assert_se(st.st_gid == test_gid);
                assert_se(S_ISCHR(st.st_mode));
                assert_se((st.st_mode & 0777) == 0640);
                assert_se(timespec_load(&st.st_mtim) == test_mtime);
        }

        a = strjoina(p, "/lnk");
        assert_se(symlink("target", a) >= 0);
        assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
        assert_se(lstat(a, &st) >= 0);
        assert_se(st.st_uid == test_uid);
        assert_se(st.st_gid == test_gid);
        assert_se(S_ISLNK(st.st_mode));
        assert_se(timespec_load(&st.st_mtim) == test_mtime);
}

TEST(unlinkat_deallocate) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        assert_se(tempfn_random_child(arg_test_dir, "unlink-deallocation", &p) >= 0);

        fd = open(p, O_WRONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0600);
        assert_se(fd >= 0);

        assert_se(write(fd, "hallo\n", 6) == 6);

        assert_se(fstat(fd, &st) >= 0);
        assert_se(st.st_size == 6);
        assert_se(st.st_blocks > 0);
        assert_se(st.st_nlink == 1);

        assert_se(unlinkat_deallocate(AT_FDCWD, p, UNLINK_ERASE) >= 0);

        assert_se(fstat(fd, &st) >= 0);
        assert_se(IN_SET(st.st_size, 0, 6)); /* depending on whether hole punching worked the size will be 6
                                                (it worked) or 0 (we had to resort to truncation) */
        assert_se(st.st_blocks == 0);
        assert_se(st.st_nlink == 0);
}

TEST(fsync_directory_of_file) {
        _cleanup_close_ int fd = -EBADF;

        fd = open_tmpfile_unlinkable(arg_test_dir, O_RDWR);
        assert_se(fd >= 0);

        assert_se(fsync_directory_of_file(fd) >= 0);
}

TEST(rename_noreplace) {
        static const char* const table[] = {
                "/reg",
                "/dir",
                "/fifo",
                "/socket",
                "/symlink",
                NULL
        };

        _cleanup_(rm_rf_physical_and_freep) char *z = NULL;
        const char *j = NULL;

        if (arg_test_dir)
                j = strjoina(arg_test_dir, "/testXXXXXX");
        assert_se(mkdtemp_malloc(j, &z) >= 0);

        j = strjoina(z, table[0]);
        assert_se(touch(j) >= 0);

        j = strjoina(z, table[1]);
        assert_se(mkdir(j, 0777) >= 0);

        j = strjoina(z, table[2]);
        (void) mkfifo(j, 0777);

        j = strjoina(z, table[3]);
        (void) mknod(j, S_IFSOCK | 0777, 0);

        j = strjoina(z, table[4]);
        (void) symlink("foobar", j);

        STRV_FOREACH(a, table) {
                _cleanup_free_ char *x = NULL, *y = NULL;

                x = strjoin(z, *a);
                assert_se(x);

                if (access(x, F_OK) < 0) {
                        assert_se(errno == ENOENT);
                        continue;
                }

                STRV_FOREACH(b, table) {
                        _cleanup_free_ char *w = NULL;

                        w = strjoin(z, *b);
                        assert_se(w);

                        if (access(w, F_OK) < 0) {
                                assert_se(errno == ENOENT);
                                continue;
                        }

                        assert_se(rename_noreplace(AT_FDCWD, x, AT_FDCWD, w) == -EEXIST);
                }

                y = strjoin(z, "/somethingelse");
                assert_se(y);

                assert_se(rename_noreplace(AT_FDCWD, x, AT_FDCWD, y) >= 0);
                assert_se(rename_noreplace(AT_FDCWD, y, AT_FDCWD, x) >= 0);
        }
}

TEST(chmod_and_chown) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        struct stat st;
        const char *p;

        if (geteuid() != 0)
                return;

        BLOCK_WITH_UMASK(0000);

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);

        p = strjoina(d, "/reg");
        assert_se(mknod(p, S_IFREG | 0123, 0) >= 0);

        assert_se(chmod_and_chown(p, S_IFREG | 0321, 1, 2) >= 0);
        assert_se(chmod_and_chown(p, S_IFDIR | 0555, 3, 4) == -EINVAL);

        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISREG(st.st_mode));
        assert_se((st.st_mode & 07777) == 0321);

        p = strjoina(d, "/dir");
        assert_se(mkdir(p, 0123) >= 0);

        assert_se(chmod_and_chown(p, S_IFDIR | 0321, 1, 2) >= 0);
        assert_se(chmod_and_chown(p, S_IFREG | 0555, 3, 4) == -EINVAL);

        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se((st.st_mode & 07777) == 0321);

        p = strjoina(d, "/lnk");
        assert_se(symlink("idontexist", p) >= 0);

        assert_se(chmod_and_chown(p, S_IFLNK | 0321, 1, 2) >= 0);
        assert_se(chmod_and_chown(p, S_IFREG | 0555, 3, 4) == -EINVAL);
        assert_se(chmod_and_chown(p, S_IFDIR | 0555, 3, 4) == -EINVAL);

        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
}

static void create_binary_file(const char *p, const void *data, size_t l) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(p, O_CREAT|O_WRONLY|O_EXCL|O_CLOEXEC, 0600);
        assert_se(fd >= 0);
        assert_se(write(fd, data, l) == (ssize_t) l);
}

TEST(conservative_rename) {
        _cleanup_(unlink_and_freep) char *p = NULL;
        _cleanup_free_ char *q = NULL;
        size_t l = 16*1024 + random_u64() % (32 * 1024); /* some randomly sized buffer 16k…48k */
        uint8_t buffer[l+1];

        random_bytes(buffer, l);

        assert_se(tempfn_random_child(NULL, NULL, &p) >= 0);
        create_binary_file(p, buffer, l);

        assert_se(tempfn_random_child(NULL, NULL, &q) >= 0);

        /* Check that the hardlinked "copy" is detected */
        assert_se(link(p, q) >= 0);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) == 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Check that a manual copy is detected */
        assert_se(copy_file(p, q, 0, MODE_INVALID, COPY_REFLINK) >= 0);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) == 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Check that a manual new writeout is also detected */
        create_binary_file(q, buffer, l);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) == 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Check that a minimally changed version is detected */
        buffer[47] = ~buffer[47];
        create_binary_file(q, buffer, l);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) > 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Check that this really is new updated version */
        create_binary_file(q, buffer, l);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) == 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Make sure we detect extended files */
        buffer[l++] = 47;
        create_binary_file(q, buffer, l);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) > 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);

        /* Make sure we detect truncated files */
        l--;
        create_binary_file(q, buffer, l);
        assert_se(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p) > 0);
        assert_se(access(q, F_OK) < 0 && errno == ENOENT);
}

static void test_rmdir_parents_one(
                const char *prefix,
                const char *path,
                const char *stop,
                int expected,
                const char *test_exist,
                const char *test_nonexist_subdir) {

        const char *p, *s;

        log_debug("/* %s(%s, %s) */", __func__, path, stop);

        p = strjoina(prefix, path);
        s = strjoina(prefix, stop);

        if (expected >= 0)
                assert_se(mkdir_parents(p, 0700) >= 0);

        assert_se(rmdir_parents(p, s) == expected);

        if (expected >= 0) {
                const char *e, *f;

                e = strjoina(prefix, test_exist);
                f = strjoina(e, test_nonexist_subdir);

                assert_se(access(e, F_OK) >= 0);
                assert_se(access(f, F_OK) < 0);
        }
}

TEST(rmdir_parents) {
        char *temp;

        temp = strjoina(arg_test_dir ?: "/tmp", "/test-rmdir.XXXXXX");
        assert_se(mkdtemp(temp));

        test_rmdir_parents_one(temp, "/aaa/../hoge/foo", "/hoge/foo", -EINVAL, NULL, NULL);
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc", "/hoge/../aaa", -EINVAL, NULL, NULL);

        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb/ccc/ddd", 0, "/aaa/bbb/ccc/ddd", "/eee");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb/ccc", 0, "/aaa/bbb/ccc", "/ddd");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb", 0, "/aaa/bbb", "/ccc");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa", 0, "/aaa", "/bbb");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/", 0, "/", "/aaa");

        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/hoge/foo", 0, "/aaa", "/bbb");
        test_rmdir_parents_one(temp, "/aaa////bbb/.//ccc//ddd/eee///./.", "///././aaa/.", 0, "/aaa", "/bbb");

        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_parse_cifs_service_one(const char *f, const char *h, const char *s, const char *d, int ret) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL;

        assert_se(parse_cifs_service(f, &a, &b, &c) == ret);
        assert_se(streq_ptr(a, h));
        assert_se(streq_ptr(b, s));
        assert_se(streq_ptr(c, d));
}

TEST(parse_cifs_service) {
        test_parse_cifs_service_one("//foo/bar/baz", "foo", "bar", "baz", 0);
        test_parse_cifs_service_one("\\\\foo\\bar\\baz", "foo", "bar", "baz", 0);
        test_parse_cifs_service_one("//foo/bar", "foo", "bar", NULL, 0);
        test_parse_cifs_service_one("\\\\foo\\bar", "foo", "bar", NULL, 0);
        test_parse_cifs_service_one("//foo/bar/baz/uuu", "foo", "bar", "baz/uuu", 0);
        test_parse_cifs_service_one("\\\\foo\\bar\\baz\\uuu", "foo", "bar", "baz/uuu", 0);

        test_parse_cifs_service_one(NULL, NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("abc", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("abc/cde/efg", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("//foo/bar/baz/..", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("//foo///", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("//foo/.", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("//foo/a/.", NULL, NULL, NULL, -EINVAL);
        test_parse_cifs_service_one("//./a", NULL, NULL, NULL, -EINVAL);
}

TEST(open_mkdir_at) {
        _cleanup_close_ int fd = -EBADF, subdir_fd = -EBADF, subsubdir_fd = -EBADF;
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        struct stat sta, stb;

        assert_se(open_mkdir_at(AT_FDCWD, "/", O_EXCL|O_CLOEXEC, 0) == -EEXIST);
        assert_se(open_mkdir_at(AT_FDCWD, ".", O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        fd = open_mkdir_at(AT_FDCWD, "/", O_CLOEXEC, 0);
        assert_se(fd >= 0);
        assert_se(stat("/", &sta) >= 0);
        assert_se(fstat(fd, &stb) >= 0);
        assert_se(stat_inode_same(&sta, &stb));
        fd = safe_close(fd);

        fd = open_mkdir_at(AT_FDCWD, ".", O_CLOEXEC, 0);
        assert_se(stat(".", &sta) >= 0);
        assert_se(fstat(fd, &stb) >= 0);
        assert_se(stat_inode_same(&sta, &stb));
        fd = safe_close(fd);

        assert_se(open_mkdir_at(AT_FDCWD, "/proc", O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        fd = open_mkdir_at(AT_FDCWD, "/proc", O_CLOEXEC, 0);
        assert_se(fd >= 0);
        fd = safe_close(fd);

        assert_se(open_mkdir_at(AT_FDCWD, "/bin/sh", O_EXCL|O_CLOEXEC, 0) == -EEXIST);
        assert_se(open_mkdir_at(AT_FDCWD, "/bin/sh", O_CLOEXEC, 0) == -EEXIST);

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        assert_se(open_mkdir_at(AT_FDCWD, t, O_EXCL|O_CLOEXEC, 0) == -EEXIST);
        assert_se(open_mkdir_at(AT_FDCWD, t, O_PATH|O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        fd = open_mkdir_at(AT_FDCWD, t, O_CLOEXEC, 0000);
        assert_se(fd >= 0);
        fd = safe_close(fd);

        fd = open_mkdir_at(AT_FDCWD, t, O_PATH|O_CLOEXEC, 0000);
        assert_se(fd >= 0);

        subdir_fd = open_mkdir_at(fd, "xxx", O_PATH|O_EXCL|O_CLOEXEC, 0700);
        assert_se(subdir_fd >= 0);

        assert_se(open_mkdir_at(fd, "xxx", O_PATH|O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        subsubdir_fd = open_mkdir_at(subdir_fd, "yyy", O_EXCL|O_CLOEXEC, 0700);
        assert_se(subsubdir_fd >= 0);
        subsubdir_fd = safe_close(subsubdir_fd);

        assert_se(open_mkdir_at(subdir_fd, "yyy", O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        assert_se(open_mkdir_at(fd, "xxx/yyy", O_EXCL|O_CLOEXEC, 0) == -EEXIST);

        subsubdir_fd = open_mkdir_at(fd, "xxx/yyy", O_CLOEXEC, 0700);
        assert_se(subsubdir_fd >= 0);
}

TEST(openat_report_new) {
        _cleanup_free_ char *j = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_close_ int fd = -EBADF;
        bool b;

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);

        j = path_join(d, "test");
        assert_se(j);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(b);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(!b);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(!b);

        assert_se(unlink(j) >= 0);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(b);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(!b);

        assert_se(unlink(j) >= 0);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, NULL);
        assert_se(fd >= 0);
        fd = safe_close(fd);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(!b);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(!b);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT|O_EXCL, 0666, &b);
        assert_se(fd == -EEXIST);

        assert_se(unlink(j) >= 0);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR, 0666, &b);
        assert_se(fd == -ENOENT);

        fd = openat_report_new(AT_FDCWD, j, O_RDWR|O_CREAT|O_EXCL, 0666, &b);
        assert_se(fd >= 0);
        fd = safe_close(fd);
        assert_se(b);
}

TEST(xopenat) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF, fd2 = -EBADF;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        /* Test that xopenat() creates directories if O_DIRECTORY is specified. */

        assert_se((fd = xopenat(tfd, "abc", O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, 0, 0755)) >= 0);
        assert_se((fd_verify_directory(fd) >= 0));
        fd = safe_close(fd);

        assert_se(xopenat(tfd, "abc", O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, 0, 0755) == -EEXIST);

        assert_se((fd = xopenat(tfd, "abc", O_DIRECTORY|O_CREAT|O_CLOEXEC, 0, 0755)) >= 0);
        assert_se((fd_verify_directory(fd) >= 0));
        fd = safe_close(fd);

        /* Test that xopenat() creates regular files if O_DIRECTORY is not specified. */

        assert_se((fd = xopenat(tfd, "def", O_CREAT|O_EXCL|O_CLOEXEC, 0, 0644)) >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        fd = safe_close(fd);

        /* Test that we can reopen an existing fd with xopenat() by specifying an empty path. */

        assert_se((fd = xopenat(tfd, "def", O_PATH|O_CLOEXEC, 0, 0)) >= 0);
        assert_se((fd2 = xopenat(fd, "", O_RDWR|O_CLOEXEC, 0, 0644)) >= 0);
}

TEST(xopenat_lock) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        siginfo_t si;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        /* Test that we can acquire an exclusive lock on a directory in one process, remove the directory,
         * and close the file descriptor and still properly create the directory and acquire the lock in
         * another process.  */

        fd = xopenat_lock(tfd, "abc", O_CREAT|O_DIRECTORY|O_CLOEXEC, 0, 0755, LOCK_BSD, LOCK_EX);
        assert_se(fd >= 0);
        assert_se(faccessat(tfd, "abc", F_OK, 0) >= 0);
        assert_se(fd_verify_directory(fd) >= 0);
        assert_se(xopenat_lock(tfd, "abc", O_DIRECTORY|O_CLOEXEC, 0, 0755, LOCK_BSD, LOCK_EX|LOCK_NB) == -EAGAIN);

        pid_t pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                safe_close(fd);

                fd = xopenat_lock(tfd, "abc", O_CREAT|O_DIRECTORY|O_CLOEXEC, 0, 0755, LOCK_BSD, LOCK_EX);
                assert_se(fd >= 0);
                assert_se(faccessat(tfd, "abc", F_OK, 0) >= 0);
                assert_se(fd_verify_directory(fd) >= 0);
                assert_se(xopenat_lock(tfd, "abc", O_DIRECTORY|O_CLOEXEC, 0, 0755, LOCK_BSD, LOCK_EX|LOCK_NB) == -EAGAIN);

                _exit(EXIT_SUCCESS);
        }

        /* We need to give the child process some time to get past the xopenat() call in xopenat_lock() and
         * block in the call to lock_generic() waiting for the lock to become free. We can't modify
         * xopenat_lock() to signal an eventfd to let us know when that has happened, so we just sleep for a
         * little and assume that's enough time for the child process to get along far enough. It doesn't
         * matter if it doesn't get far enough, in that case we just won't trigger the fallback logic in
         * xopenat_lock(), but the test will still succeed. */
        assert_se(usleep_safe(20 * USEC_PER_MSEC) >= 0);

        assert_se(unlinkat(tfd, "abc", AT_REMOVEDIR) >= 0);
        fd = safe_close(fd);

        assert_se(wait_for_terminate(pid, &si) >= 0);
        assert_se(si.si_code == CLD_EXITED);

        assert_se(xopenat_lock(tfd, "abc", 0, 0, 0755, LOCK_POSIX, LOCK_EX) == -EBADF);
        assert_se(xopenat_lock(tfd, "def", O_DIRECTORY, 0, 0755, LOCK_POSIX, LOCK_EX) == -EBADF);
}

TEST(linkat_replace) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        _cleanup_close_ int fd1 = openat(tfd, "foo", O_CREAT|O_RDWR|O_CLOEXEC, 0600);
        assert_se(fd1 >= 0);

        assert_se(linkat_replace(tfd, "foo", tfd, "bar") >= 0);
        assert_se(linkat_replace(tfd, "foo", tfd, "bar") >= 0);

        _cleanup_close_ int fd1_check = openat(tfd, "bar", O_RDWR|O_CLOEXEC);
        assert_se(fd1_check >= 0);

        assert_se(inode_same_at(fd1, NULL, fd1_check, NULL, AT_EMPTY_PATH) > 0);

        _cleanup_close_ int fd2 = openat(tfd, "baz", O_CREAT|O_RDWR|O_CLOEXEC, 0600);
        assert_se(fd2 >= 0);

        assert_se(inode_same_at(fd1, NULL, fd2, NULL, AT_EMPTY_PATH) == 0);

        assert_se(linkat_replace(tfd, "foo", tfd, "baz") >= 0);

        _cleanup_close_ int fd2_check = openat(tfd, "baz", O_RDWR|O_CLOEXEC);

        assert_se(inode_same_at(fd2, NULL, fd2_check, NULL, AT_EMPTY_PATH) == 0);
        assert_se(inode_same_at(fd1, NULL, fd2_check, NULL, AT_EMPTY_PATH) > 0);
}

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
