/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "capability-util.h"
#include "copy.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "virt.h"

static const char *arg_test_dir = NULL;

TEST(readlink_and_make_absolute) {
        const char *tempdir, *name, *name2, *name_alias;
        _cleanup_free_ char *r1 = NULL, *r2 = NULL, *pwd = NULL;

        tempdir = strjoina(arg_test_dir ?: "/tmp", "/test-readlink_and_make_absolute");
        name = strjoina(tempdir, "/original");
        name2 = "test-readlink_and_make_absolute/original";
        name_alias = strjoina(arg_test_dir ?: "/tmp", "/test-readlink_and_make_absolute-alias");

        ASSERT_OK(mkdir_safe(tempdir, 0755, getuid(), getgid(), MKDIR_WARN_MODE));
        ASSERT_OK(touch(name));

        if (symlink(name, name_alias) < 0) {
                ASSERT_TRUE(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
        } else {
                ASSERT_OK(readlink_and_make_absolute(name_alias, &r1));
                ASSERT_STREQ(r1, name);
                ASSERT_OK_ERRNO(unlink(name_alias));

                ASSERT_OK(safe_getcwd(&pwd));

                ASSERT_OK_ERRNO(chdir(tempdir));
                ASSERT_OK_ERRNO(symlink(name2, name_alias));
                ASSERT_OK(readlink_and_make_absolute(name_alias, &r2));
                ASSERT_STREQ(r2, name);
                ASSERT_OK_ERRNO(unlink(name_alias));

                ASSERT_OK_ERRNO(chdir(pwd));
        }

        ASSERT_OK(rm_rf(tempdir, REMOVE_ROOT|REMOVE_PHYSICAL));
}

TEST(get_files_in_directory) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        ASSERT_OK(get_files_in_directory(arg_test_dir ?: "/tmp", &l));
        ASSERT_OK(get_files_in_directory(".", &t));
        ASSERT_OK(get_files_in_directory(".", /* list= */ NULL));
}

TEST(var_tmp) {
        _cleanup_free_ char *tmpdir_backup = NULL, *temp_backup = NULL, *tmp_backup = NULL;
        const char *tmp_dir = NULL, *t;

        t = getenv("TMPDIR");
        if (t)
                tmpdir_backup = ASSERT_NOT_NULL(strdup(t));

        t = getenv("TEMP");
        if (t)
                temp_backup = ASSERT_NOT_NULL(strdup(t));

        t = getenv("TMP");
        if (t)
                tmp_backup = ASSERT_NOT_NULL(strdup(t));

        ASSERT_OK_ERRNO(unsetenv("TMPDIR"));
        ASSERT_OK_ERRNO(unsetenv("TEMP"));
        ASSERT_OK_ERRNO(unsetenv("TMP"));

        ASSERT_OK(var_tmp_dir(&tmp_dir));
        ASSERT_STREQ(tmp_dir, "/var/tmp");

        ASSERT_OK_ERRNO(setenv("TMPDIR", "/tmp", true));
        ASSERT_STREQ(getenv("TMPDIR"), "/tmp");

        ASSERT_OK(var_tmp_dir(&tmp_dir));
        ASSERT_STREQ(tmp_dir, "/tmp");

        ASSERT_OK_ERRNO(setenv("TMPDIR", "/88_does_not_exist_88", true));
        ASSERT_STREQ(getenv("TMPDIR"), "/88_does_not_exist_88");

        ASSERT_OK(var_tmp_dir(&tmp_dir));
        ASSERT_STREQ(tmp_dir, "/var/tmp");

        if (tmpdir_backup)  {
                ASSERT_OK_ERRNO(setenv("TMPDIR", tmpdir_backup, true));
                ASSERT_STREQ(getenv("TMPDIR"), tmpdir_backup);
        }

        if (temp_backup)  {
                ASSERT_OK_ERRNO(setenv("TEMP", temp_backup, true));
                ASSERT_STREQ(getenv("TEMP"), temp_backup);
        }

        if (tmp_backup)  {
                ASSERT_OK_ERRNO(setenv("TMP", tmp_backup, true));
                ASSERT_STREQ(getenv("TMP"), tmp_backup);
        }
}

TEST(dot_or_dot_dot) {
        ASSERT_FALSE(dot_or_dot_dot(/* path= */ NULL));
        ASSERT_FALSE(dot_or_dot_dot(""));
        ASSERT_FALSE(dot_or_dot_dot("xxx"));
        ASSERT_TRUE(dot_or_dot_dot("."));
        ASSERT_TRUE(dot_or_dot_dot(".."));
        ASSERT_FALSE(dot_or_dot_dot(".foo"));
        ASSERT_FALSE(dot_or_dot_dot("..foo"));
}

TEST(access_fd) {
        _cleanup_(rmdir_and_freep) char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *a;

        a = strjoina(arg_test_dir ?: "/tmp", "/access-fd.XXXXXX");
        ASSERT_OK(mkdtemp_malloc(a, &p));

        fd = ASSERT_OK_ERRNO(open(p, O_RDONLY|O_DIRECTORY|O_CLOEXEC));

        ASSERT_OK(access_fd(fd, R_OK));
        ASSERT_OK(access_fd(fd, F_OK));
        ASSERT_OK(access_fd(fd, W_OK));

        ASSERT_OK_ERRNO(fchmod(fd, 0000));

        ASSERT_OK(access_fd(fd, F_OK));

        if (geteuid() == 0) {
                ASSERT_OK(access_fd(fd, R_OK));
                ASSERT_OK(access_fd(fd, W_OK));
        } else {
                ASSERT_ERROR(access_fd(fd, R_OK), EACCES);
                ASSERT_ERROR(access_fd(fd, W_OK), EACCES);
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
        ASSERT_OK(mkdtemp_malloc(a, &p));

        a = strjoina(p, "/regular");
        r = touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640);
        if (r < 0) {
                ASSERT_TRUE(IN_SET(r, -EINVAL, -ENOSYS, -ENOTTY, -EPERM));
                return (void) log_tests_skipped_errno(errno, "touch_file() not possible");
        }

        ASSERT_OK_ERRNO(lstat(a, &st));
        ASSERT_EQ(st.st_uid, test_uid);
        ASSERT_EQ(st.st_gid, test_gid);
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ(st.st_mode & 0777, 0640U);
        ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);

        a = strjoina(p, "/dir");
        ASSERT_OK_ERRNO(mkdir(a, 0775));
        ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
        ASSERT_OK_ERRNO(lstat(a, &st));
        ASSERT_EQ(st.st_uid, test_uid);
        ASSERT_EQ(st.st_gid, test_gid);
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ(st.st_mode & 0777, 0640U);
        ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);

        a = strjoina(p, "/fifo");
        ASSERT_OK_ERRNO(mkfifo(a, 0775));
        ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
        ASSERT_OK_ERRNO(lstat(a, &st));
        ASSERT_EQ(st.st_uid, test_uid);
        ASSERT_EQ(st.st_gid, test_gid);
        ASSERT_TRUE(S_ISFIFO(st.st_mode));
        ASSERT_EQ(st.st_mode & 0777, 0640U);
        ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);

        a = strjoina(p, "/sock");
        ASSERT_OK_ERRNO(mknod(a, 0775 | S_IFSOCK, 0));
        ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
        ASSERT_OK_ERRNO(lstat(a, &st));
        ASSERT_EQ(st.st_uid, test_uid);
        ASSERT_EQ(st.st_gid, test_gid);
        ASSERT_TRUE(S_ISSOCK(st.st_mode));
        ASSERT_EQ(st.st_mode & 0777, 0640U);
        ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);

        if (geteuid() == 0) {
                a = strjoina(p, "/bdev");
                r = RET_NERRNO(mknod(a, 0775 | S_IFBLK, makedev(0, 0)));
                if (r == -EPERM && detect_container() > 0) {
                        log_notice("Running in unprivileged container? Skipping remaining tests in %s", __func__);
                        return;
                }
                ASSERT_OK(r);
                ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
                ASSERT_OK_ERRNO(lstat(a, &st));
                ASSERT_EQ(st.st_uid, test_uid);
                ASSERT_EQ(st.st_gid, test_gid);
                ASSERT_TRUE(S_ISBLK(st.st_mode));
                ASSERT_EQ(st.st_mode & 0777, 0640U);
                ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);

                a = strjoina(p, "/cdev");
                ASSERT_OK_ERRNO(mknod(a, 0775 | S_IFCHR, makedev(0, 0)));
                ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
                ASSERT_OK_ERRNO(lstat(a, &st));
                ASSERT_EQ(st.st_uid, test_uid);
                ASSERT_EQ(st.st_gid, test_gid);
                ASSERT_TRUE(S_ISCHR(st.st_mode));
                ASSERT_EQ(st.st_mode & 0777, 0640U);
                ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);
        }

        a = strjoina(p, "/lnk");
        ASSERT_OK_ERRNO(symlink("target", a));
        ASSERT_OK(touch_file(a, /* parents= */ false, test_mtime, test_uid, test_gid, 0640));
        ASSERT_OK_ERRNO(lstat(a, &st));
        ASSERT_EQ(st.st_uid, test_uid);
        ASSERT_EQ(st.st_gid, test_gid);
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        ASSERT_EQ(timespec_load(&st.st_mtim), test_mtime);
}

TEST(unlinkat_deallocate) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct stat st;

        ASSERT_OK(tempfn_random_child(arg_test_dir, "unlink-deallocation", &p));

        fd = ASSERT_OK_ERRNO(open(p, O_WRONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0600));

        ASSERT_OK_EQ_ERRNO(write(fd, "hallo\n", 6), 6);

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ(st.st_size, 6);
        ASSERT_GT(st.st_blocks, 0);
        ASSERT_EQ(st.st_nlink, 1U);

        ASSERT_OK(unlinkat_deallocate(AT_FDCWD, p, UNLINK_ERASE));

        ASSERT_OK_ERRNO(fstat(fd, &st));
        /* depending on whether hole punching worked the size will be 6 (it worked) or 0 (we had to resort to
         * truncation) */
        ASSERT_TRUE(IN_SET(st.st_size, 0, 6));
        ASSERT_EQ(st.st_blocks, 0);
        ASSERT_EQ(st.st_nlink, 0U);
}

TEST(fsync_directory_of_file) {
        _cleanup_close_ int fd = -EBADF;

        fd = ASSERT_OK(open_tmpfile_unlinkable(arg_test_dir, O_RDWR));

        ASSERT_OK(fsync_directory_of_file(fd));
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
        ASSERT_OK(mkdtemp_malloc(j, &z));

        j = strjoina(z, table[0]);
        ASSERT_OK(touch(j));

        j = strjoina(z, table[1]);
        ASSERT_OK_ERRNO(mkdir(j, 0777));

        j = strjoina(z, table[2]);
        (void) mkfifo(j, 0777);

        j = strjoina(z, table[3]);
        (void) mknod(j, S_IFSOCK | 0777, 0);

        j = strjoina(z, table[4]);
        (void) symlink("foobar", j);

        STRV_FOREACH(a, table) {
                _cleanup_free_ char *x = NULL, *y = NULL;

                x = ASSERT_NOT_NULL(strjoin(z, *a));

                if (access(x, F_OK) < 0) {
                        ASSERT_EQ(errno, ENOENT);
                        continue;
                }

                STRV_FOREACH(b, table) {
                        _cleanup_free_ char *w = NULL;

                        w = ASSERT_NOT_NULL(strjoin(z, *b));

                        if (access(w, F_OK) < 0) {
                                ASSERT_EQ(errno, ENOENT);
                                continue;
                        }

                        ASSERT_ERROR(rename_noreplace(AT_FDCWD, x, AT_FDCWD, w), EEXIST);
                }

                y = ASSERT_NOT_NULL(strjoin(z, "/somethingelse"));

                ASSERT_OK(rename_noreplace(AT_FDCWD, x, AT_FDCWD, y));
                ASSERT_OK(rename_noreplace(AT_FDCWD, y, AT_FDCWD, x));
        }
}

TEST(chmod_and_chown) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        struct stat st;
        const char *p;

        if (geteuid() != 0 || userns_has_single_user())
                return (void) log_tests_skipped("not running as root or in userns with single user");

        BLOCK_WITH_UMASK(0000);

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &d));

        p = strjoina(d, "/reg");
        ASSERT_OK_ERRNO(mknod(p, S_IFREG | 0123, 0));

        ASSERT_OK(chmod_and_chown(p, S_IFREG | 0321, 1, 2));
        ASSERT_ERROR(chmod_and_chown(p, S_IFDIR | 0555, 3, 4), EINVAL);

        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0321U);

        p = strjoina(d, "/dir");
        ASSERT_OK_ERRNO(mkdir(p, 0123));

        ASSERT_OK(chmod_and_chown(p, S_IFDIR | 0321, 1, 2));
        ASSERT_ERROR(chmod_and_chown(p, S_IFREG | 0555, 3, 4), EINVAL);

        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0321U);

        p = strjoina(d, "/lnk");
        ASSERT_OK_ERRNO(symlink("idontexist", p));

        ASSERT_OK(chmod_and_chown(p, S_IFLNK | 0321, 1, 2));
        ASSERT_ERROR(chmod_and_chown(p, S_IFREG | 0555, 3, 4), EINVAL);
        ASSERT_ERROR(chmod_and_chown(p, S_IFDIR | 0555, 3, 4), EINVAL);

        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
}

static void create_binary_file(const char *p, const void *data, size_t l) {
        _cleanup_close_ int fd = -EBADF;

        fd = ASSERT_OK_ERRNO(open(p, O_CREAT|O_WRONLY|O_EXCL|O_CLOEXEC, 0600));
        ASSERT_OK_EQ_ERRNO(write(fd, data, l), (ssize_t) l);
}

TEST(conservative_rename) {
        _cleanup_(unlink_and_freep) char *p = NULL;
        _cleanup_free_ char *q = NULL;
        size_t l = 16*1024 + random_u64() % (32 * 1024); /* some randomly sized buffer 16k…48k */
        uint8_t buffer[l+1];

        random_bytes(buffer, l);

        ASSERT_OK(tempfn_random_child(NULL, /* extra= */ NULL, &p));
        create_binary_file(p, buffer, l);

        ASSERT_OK(tempfn_random_child(NULL, /* extra= */ NULL, &q));

        /* Check that the hardlinked "copy" is detected */
        ASSERT_OK_ERRNO(link(p, q));
        ASSERT_OK_EQ(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p), 0);
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Check that a manual copy is detected */
        ASSERT_OK(copy_file(p, q, /* open_flags= */ 0, MODE_INVALID, /* copy_flags= */ 0));
        ASSERT_OK_EQ(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p), 0);
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Check that a manual new writeout is also detected */
        create_binary_file(q, buffer, l);
        ASSERT_OK_EQ(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p), 0);
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Check that a minimally changed version is detected */
        buffer[47] = ~buffer[47];
        create_binary_file(q, buffer, l);
        ASSERT_OK_POSITIVE(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p));
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Check that this really is new updated version */
        create_binary_file(q, buffer, l);
        ASSERT_OK_EQ(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p), 0);
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Make sure we detect extended files */
        buffer[l++] = 47;
        create_binary_file(q, buffer, l);
        ASSERT_OK_POSITIVE(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p));
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);

        /* Make sure we detect truncated files */
        l--;
        create_binary_file(q, buffer, l);
        ASSERT_OK_POSITIVE(conservative_renameat(AT_FDCWD, q, AT_FDCWD, p));
        ASSERT_ERROR_ERRNO(access(q, F_OK), ENOENT);
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
                ASSERT_OK(mkdir_parents(p, 0700));

        ASSERT_EQ(rmdir_parents(p, s), expected);

        if (expected >= 0) {
                const char *e, *f;

                e = strjoina(prefix, test_exist);
                f = strjoina(e, test_nonexist_subdir);

                ASSERT_OK_ERRNO(access(e, F_OK));
                ASSERT_ERROR_ERRNO(access(f, F_OK), ENOENT);
        }
}

TEST(rmdir_parents) {
        char *temp;

        temp = strjoina(arg_test_dir ?: "/tmp", "/test-rmdir.XXXXXX");
        ASSERT_NOT_NULL(mkdtemp(temp));

        test_rmdir_parents_one(temp, "/aaa/../hoge/foo", "/hoge/foo", -EINVAL, /* test_exist= */ NULL, /* test_nonexist_subdir= */ NULL);
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc", "/hoge/../aaa", -EINVAL, /* test_exist= */ NULL, /* test_nonexist_subdir= */ NULL);

        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb/ccc/ddd", /* expected= */ 0, "/aaa/bbb/ccc/ddd", "/eee");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb/ccc", /* expected= */ 0, "/aaa/bbb/ccc", "/ddd");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/bbb", /* expected= */ 0, "/aaa/bbb", "/ccc");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa", /* expected= */ 0, "/aaa", "/bbb");
        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/", /* expected= */ 0, "/", "/aaa");

        test_rmdir_parents_one(temp, "/aaa/bbb/ccc/ddd/eee", "/aaa/hoge/foo", /* expected= */ 0, "/aaa", "/bbb");
        test_rmdir_parents_one(temp, "/aaa////bbb/.//ccc//ddd/eee///./.", "///././aaa/.", /* expected= */ 0, "/aaa", "/bbb");

        ASSERT_OK(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL));
}

static void test_parse_cifs_service_one(const char *f, const char *h, const char *s, const char *d, int ret) {
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL;

        ASSERT_EQ(parse_cifs_service(f, &a, &b, &c), ret);
        ASSERT_STREQ(a, h);
        ASSERT_STREQ(b, s);
        ASSERT_STREQ(c, d);
}

TEST(parse_cifs_service) {
        test_parse_cifs_service_one("//foo/bar/baz", "foo", "bar", "baz", /* ret= */ 0);
        test_parse_cifs_service_one("\\\\foo\\bar\\baz", "foo", "bar", "baz", /* ret= */ 0);
        test_parse_cifs_service_one("//foo/bar", "foo", "bar", NULL, /* ret= */ 0);
        test_parse_cifs_service_one("\\\\foo\\bar", "foo", "bar", NULL, /* ret= */ 0);
        test_parse_cifs_service_one("//foo/bar/baz/uuu", "foo", "bar", "baz/uuu", /* ret= */ 0);
        test_parse_cifs_service_one("\\\\foo\\bar\\baz\\uuu", "foo", "bar", "baz/uuu", /* ret= */ 0);

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

        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, "/", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);
        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, ".", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        fd = ASSERT_OK(open_mkdir_at(AT_FDCWD, "/", O_CLOEXEC, /* mode= */ 0));
        ASSERT_OK_ERRNO(stat("/", &sta));
        ASSERT_OK_ERRNO(fstat(fd, &stb));
        ASSERT_TRUE(stat_inode_same(&sta, &stb));
        fd = safe_close(fd);

        fd = open_mkdir_at(AT_FDCWD, ".", O_CLOEXEC, /* mode= */ 0);
        ASSERT_OK_ERRNO(stat(".", &sta));
        ASSERT_OK_ERRNO(fstat(fd, &stb));
        ASSERT_TRUE(stat_inode_same(&sta, &stb));
        fd = safe_close(fd);

        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, "/proc", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        fd = ASSERT_OK(open_mkdir_at(AT_FDCWD, "/proc", O_CLOEXEC, /* mode= */ 0));
        fd = safe_close(fd);

        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, "/bin/sh", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);
        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, "/bin/sh", O_CLOEXEC, /* mode= */ 0), EEXIST);

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, t, O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);
        ASSERT_ERROR(open_mkdir_at(AT_FDCWD, t, O_PATH|O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        fd = ASSERT_OK(open_mkdir_at(AT_FDCWD, t, O_CLOEXEC, 0000));
        fd = safe_close(fd);

        fd = ASSERT_OK(open_mkdir_at(AT_FDCWD, t, O_PATH|O_CLOEXEC, 0000));

        subdir_fd = ASSERT_OK(open_mkdir_at(fd, "xxx", O_PATH|O_EXCL|O_CLOEXEC, 0700));

        ASSERT_ERROR(open_mkdir_at(fd, "xxx", O_PATH|O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        subsubdir_fd = ASSERT_OK(open_mkdir_at(subdir_fd, "yyy", O_EXCL|O_CLOEXEC, 0700));
        subsubdir_fd = safe_close(subsubdir_fd);

        ASSERT_ERROR(open_mkdir_at(subdir_fd, "yyy", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        ASSERT_ERROR(open_mkdir_at(fd, "xxx/yyy", O_EXCL|O_CLOEXEC, /* mode= */ 0), EEXIST);

        subsubdir_fd = ASSERT_OK(open_mkdir_at(fd, "xxx/yyy", O_CLOEXEC, 0700));
}

TEST(openat_report_new) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        bool b;

        ASSERT_OK(tfd = mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_TRUE(b);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);

        ASSERT_OK_ERRNO(unlinkat(tfd, "test", 0));

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_TRUE(b);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);

        ASSERT_OK_ERRNO(unlinkat(tfd, "test", 0));

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, /* ret_newly_created= */ NULL);
        ASSERT_OK(fd);
        fd = safe_close(fd);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);

        fd = openat_report_new(tfd, "test", O_RDWR, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT|O_EXCL, 0666, &b);
        ASSERT_ERROR(fd, EEXIST);

        ASSERT_OK_ERRNO(unlinkat(tfd, "test", 0));

        fd = openat_report_new(tfd, "test", O_RDWR, 0666, &b);
        ASSERT_ERROR(fd, ENOENT);

        fd = openat_report_new(tfd, "test", O_RDWR|O_CREAT|O_EXCL, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_TRUE(b);

        ASSERT_OK_ERRNO(symlinkat("target", tfd, "link"));
        fd = openat_report_new(tfd, "link", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_ERROR(fd, EEXIST);

        fd = openat_report_new(tfd, "target", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_TRUE(b);

        fd = openat_report_new(tfd, "link", O_RDWR|O_CREAT, 0666, &b);
        ASSERT_OK(fd);
        fd = safe_close(fd);
        ASSERT_FALSE(b);
}

TEST(xopenat_full) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF, fd2 = -EBADF;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        /* Test that xopenat_full() creates directories if O_DIRECTORY is specified. */

        fd = ASSERT_OK(xopenat_full(tfd, "abc", O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, /* xopen_flags= */ 0, 0755));
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);

        ASSERT_ERROR(xopenat_full(tfd, "abc", O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, /* xopen_flags= */ 0, 0755), EEXIST);

        fd = ASSERT_OK(xopenat_full(tfd, "abc", O_DIRECTORY|O_CREAT|O_CLOEXEC, /* xopen_flags= */ 0, 0755));
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);

        /* Test that xopenat_full() creates regular files if O_DIRECTORY is not specified. */

        fd = ASSERT_OK(xopenat_full(tfd, "def", O_CREAT|O_EXCL|O_CLOEXEC, /* xopen_flags= */ 0, 0644));
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);

        /* Test that we can reopen an existing fd with xopenat_full() by specifying an empty path. */

        fd = ASSERT_OK(xopenat_full(tfd, "def", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
        fd2 = ASSERT_OK(xopenat_full(fd, "", O_RDWR|O_CLOEXEC, /* xopen_flags= */ 0, 0644));
}

TEST(xopenat_regular) {

        _cleanup_close_ int fd = -EBADF;

        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/dev/null", O_RDWR|O_CLOEXEC, XO_REGULAR, /* mode= */ 0), EBADFD);
        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/proc", O_RDONLY|O_CLOEXEC, XO_REGULAR, /* mode= */ 0), EISDIR);
        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/proc/self", O_RDONLY|O_CLOEXEC, XO_REGULAR, /* mode= */ 0), EISDIR);
        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/proc/self", O_RDONLY|O_CLOEXEC|O_NOFOLLOW, XO_REGULAR, /* mode= */ 0), ELOOP);

        fd = ASSERT_OK(xopenat_full(AT_FDCWD, "/proc/mounts", O_RDONLY|O_CLOEXEC, XO_REGULAR,
                                    /* mode= */ 0));
        fd = safe_close(fd);

        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/proc/mounts", O_RDONLY|O_CLOEXEC|O_NOFOLLOW, XO_REGULAR, /* mode= */ 0), ELOOP);

        fd = ASSERT_OK(xopenat_full(AT_FDCWD, "/proc/mounts", O_RDONLY|O_CLOEXEC|O_PATH, XO_REGULAR,
                                    /* mode= */ 0));
        fd = safe_close(fd);

        fd = ASSERT_OK(xopenat_full(AT_FDCWD, "/tmp/xopenat-regular-test", O_RDWR|O_CLOEXEC|O_CREAT,
                                    XO_REGULAR, 0600));
        fd = safe_close(fd);

        ASSERT_ERROR(xopenat_full(AT_FDCWD, "/tmp/xopenat-regular-test", O_RDWR|O_CLOEXEC|O_CREAT|O_EXCL, XO_REGULAR, 0600), EEXIST);

        ASSERT_OK_ERRNO(unlink("/tmp/xopenat-regular-test"));
}

TEST(xopenat_socket) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;

        ASSERT_OK(tfd = mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        /* Create a Unix domain socket via bind(). */
        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        ASSERT_OK(fd);

        const char *sockpath = strjoina(t, "/test.sock");
        union sockaddr_union sa = { .un.sun_family = AF_UNIX };
        strncpy(sa.un.sun_path, sockpath, sizeof(sa.un.sun_path) - 1);
        ASSERT_OK_ERRNO(bind(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sockpath) + 1));
        fd = safe_close(fd);

        /* XO_SOCKET requires O_PATH. */
        fd = xopenat_full(tfd, "test.sock", O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0);
        ASSERT_OK(fd);
        fd = safe_close(fd);

        /* Reopen via empty path should also work. */
        fd = ASSERT_OK(xopenat_full(tfd, "test.sock", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
        _cleanup_close_ int fd2 = xopenat_full(fd, /* path= */ NULL, O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0);
        ASSERT_OK(fd2);
        fd = safe_close(fd);

        /* Non-socket inodes must be rejected. */
        ASSERT_OK_ERRNO(mkdirat(tfd, "dir", 0755));
        ASSERT_ERROR(xopenat_full(tfd, "dir", O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0), EISDIR);

        fd = ASSERT_OK_ERRNO(openat(tfd, "reg", O_CREAT|O_CLOEXEC, 0600));
        fd = safe_close(fd);
        ASSERT_ERROR(xopenat_full(tfd, "reg", O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0), ENOTSOCK);

        /* Reopen via empty path of a non-socket fd must also be rejected. */
        fd = ASSERT_OK(xopenat_full(tfd, "reg", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
        ASSERT_ERROR(xopenat_full(fd, /* path= */ NULL, O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0), ENOTSOCK);
        fd = safe_close(fd);

        fd = ASSERT_OK(xopenat_full(tfd, "dir", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
        ASSERT_ERROR(xopenat_full(fd, /* path= */ NULL, O_PATH|O_CLOEXEC, XO_SOCKET, /* mode= */ 0), EISDIR);
        fd = safe_close(fd);
}

TEST(xopenat_trigger_automount) {
        _cleanup_close_ int fd = -EBADF;

        /* We can't easily set up an autofs mount in a test, but we can verify that
         * XO_TRIGGER_AUTOMOUNT works on a regular path and produces the same inode as a
         * plain O_PATH open. */
        fd = xopenat_full(AT_FDCWD, "/usr", O_PATH|O_CLOEXEC|O_DIRECTORY, XO_TRIGGER_AUTOMOUNT, /* mode= */ 0);
        ASSERT_OK(fd);

        _cleanup_close_ int fd2 = xopenat_full(AT_FDCWD, "/usr", O_PATH|O_CLOEXEC|O_DIRECTORY, /* xopen_flags= */ 0, /* mode= */ 0);
        ASSERT_OK(fd2);
        ASSERT_OK_POSITIVE(fd_inode_same(fd, fd2));
}

TEST(xopenat_auto_rw_ro) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        int fl;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        /* Regular writable file: XO_AUTO_RW_RO should end up in O_RDWR. */

        fd = ASSERT_OK(xopenat_full(tfd, "rw", O_CREAT|O_EXCL|O_CLOEXEC, XO_AUTO_RW_RO, 0644));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_EQ(fl & O_ACCMODE, O_RDWR);
        fd = safe_close(fd);

        /* Same thing, but with XO_REGULAR set too. */

        fd = ASSERT_OK(xopenat_full(tfd, "rw2", O_CREAT|O_EXCL|O_CLOEXEC, XO_AUTO_RW_RO|XO_REGULAR, 0644));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_EQ(fl & O_ACCMODE, O_RDWR);
        fd = safe_close(fd);

        /* Reopen via empty path on an O_PATH fd must also end up in O_RDWR. */

        _cleanup_close_ int path_fd = ASSERT_OK(xopenat_full(tfd, "rw", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
        fd = ASSERT_OK(xopenat_full(path_fd, "", O_CLOEXEC, XO_AUTO_RW_RO, /* mode= */ 0));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_EQ(fl & O_ACCMODE, O_RDWR);
        fd = safe_close(fd);

        /* Directories can only be opened read-only: XO_AUTO_RW_RO with O_DIRECTORY must fall back to O_RDONLY. */

        fd = ASSERT_OK(xopenat_full(tfd, "subdir", O_DIRECTORY|O_CREAT|O_CLOEXEC, XO_AUTO_RW_RO, 0755));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_EQ(fl & O_ACCMODE, O_RDONLY);
        fd = safe_close(fd);

        /* Same for opening an existing directory. */

        fd = ASSERT_OK(xopenat_full(tfd, "subdir", O_DIRECTORY|O_CLOEXEC, XO_AUTO_RW_RO, /* mode= */ 0));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
        ASSERT_EQ(fl & O_ACCMODE, O_RDONLY);
        fd = safe_close(fd);

        /* Fallback when the inode is not writable: create a file as read-only mode and verify that
         * XO_AUTO_RW_RO falls back to O_RDONLY. Root bypasses mode bits via CAP_DAC_OVERRIDE, so skip
         * this when running as root, or as a user with CAP_DAC_OVERRIDE. */

        if (have_effective_cap(CAP_DAC_OVERRIDE) <= 0) {
                fd = ASSERT_OK_ERRNO(openat(tfd, "ro", O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0444));
                fd = safe_close(fd);
                ASSERT_OK_ERRNO(fchmodat(tfd, "ro", 0444, 0));

                /* Plain case: no XO_REGULAR. */
                fd = ASSERT_OK(xopenat_full(tfd, "ro", O_CLOEXEC, XO_AUTO_RW_RO, /* mode= */ 0));
                ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
                ASSERT_EQ(fl & O_ACCMODE, O_RDONLY);
                fd = safe_close(fd);

                /* With XO_REGULAR (exercises the pin-via-O_PATH + reopen path). */
                fd = ASSERT_OK(xopenat_full(tfd, "ro", O_CLOEXEC, XO_AUTO_RW_RO|XO_REGULAR, /* mode= */ 0));
                ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
                ASSERT_EQ(fl & O_ACCMODE, O_RDONLY);
                fd = safe_close(fd);

                /* Also exercise the empty-path/fd-reopen branch. */
                _cleanup_close_ int ro_path_fd = ASSERT_OK(xopenat_full(tfd, "ro", O_PATH|O_CLOEXEC, /* xopen_flags= */ 0, /* mode= */ 0));
                fd = ASSERT_OK(xopenat_full(ro_path_fd, "", O_CLOEXEC, XO_AUTO_RW_RO, /* mode= */ 0));
                ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFL));
                ASSERT_EQ(fl & O_ACCMODE, O_RDONLY);
                fd = safe_close(fd);
        }
}

TEST(xopenat_lock_full) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        siginfo_t si;
        int r;

        ASSERT_OK((tfd = mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t)));

        /* Test that we can acquire an exclusive lock on a directory in one process, remove the directory,
         * and close the file descriptor and still properly create the directory and acquire the lock in
         * another process.  */

        fd = ASSERT_OK(xopenat_lock_full(tfd, "abc", O_CREAT|O_DIRECTORY|O_CLOEXEC, /* xopen_flags= */ 0, 0755, LOCK_BSD, LOCK_EX));
        ASSERT_OK_ERRNO(faccessat(tfd, "abc", F_OK, 0));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_ERROR(xopenat_lock_full(tfd, "abc", O_DIRECTORY|O_CLOEXEC, /* xopen_flags= */ 0, 0755, LOCK_BSD, LOCK_EX|LOCK_NB), EAGAIN);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = ASSERT_OK(pidref_safe_fork("(lock)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref));

        if (r == 0) {
                safe_close(fd);

                fd = ASSERT_OK(xopenat_lock_full(tfd, "abc", O_CREAT|O_DIRECTORY|O_CLOEXEC, /* xopen_flags= */ 0, 0755, LOCK_BSD, LOCK_EX));
                ASSERT_OK_ERRNO(faccessat(tfd, "abc", F_OK, 0));
                ASSERT_OK(fd_verify_directory(fd));
                ASSERT_ERROR(xopenat_lock_full(tfd, "abc", O_DIRECTORY|O_CLOEXEC, /* xopen_flags= */ 0, 0755, LOCK_BSD, LOCK_EX|LOCK_NB), EAGAIN);

                _exit(EXIT_SUCCESS);
        }

        /* We need to give the child process some time to get past the xopenat() call in xopenat_lock_full()
         * and block in the call to lock_generic() waiting for the lock to become free. We can't modify
         * xopenat_lock_full() to signal an eventfd to let us know when that has happened, so we just sleep
         * for a little and assume that's enough time for the child process to get along far enough. It
         * doesn't matter if it doesn't get far enough, in that case we just won't trigger the fallback logic
         * in xopenat_lock_full(), but the test will still succeed. */
        ASSERT_OK(usleep_safe(20 * USEC_PER_MSEC));

        ASSERT_OK(unlinkat(tfd, "abc", AT_REMOVEDIR));
        fd = safe_close(fd);

        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);

        ASSERT_ERROR(xopenat_lock_full(tfd, "abc", /* open_flags= */ 0, /* xopen_flags= */ 0, 0755, LOCK_POSIX, LOCK_EX), EBADF);
        ASSERT_ERROR(xopenat_lock_full(tfd, "def", O_DIRECTORY, /* xopen_flags= */ 0, 0755, LOCK_POSIX, LOCK_EX), EBADF);
}

TEST(linkat_replace) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        _cleanup_close_ int fd1 = ASSERT_OK_ERRNO(openat(tfd, "foo", O_CREAT|O_RDWR|O_CLOEXEC, 0600));

        ASSERT_OK(linkat_replace(tfd, "foo", tfd, "bar"));
        ASSERT_OK(linkat_replace(tfd, "foo", tfd, "bar"));

        _cleanup_close_ int fd1_check = ASSERT_OK_ERRNO(openat(tfd, "bar", O_RDWR|O_CLOEXEC));

        ASSERT_OK_POSITIVE(inode_same_at(fd1, /* filea= */ NULL, fd1_check, /* fileb= */ NULL,
                                         AT_EMPTY_PATH));

        _cleanup_close_ int fd2 = ASSERT_OK_ERRNO(openat(tfd, "baz", O_CREAT|O_RDWR|O_CLOEXEC, 0600));

        ASSERT_OK_EQ(inode_same_at(fd1, /* filea= */ NULL, fd2, /* fileb= */ NULL, AT_EMPTY_PATH), 0);

        ASSERT_OK(linkat_replace(tfd, "foo", tfd, "baz"));

        _cleanup_close_ int fd2_check = openat(tfd, "baz", O_RDWR|O_CLOEXEC);

        ASSERT_OK_EQ(inode_same_at(fd2, /* filea= */ NULL, fd2_check, /* fileb= */ NULL, AT_EMPTY_PATH), 0);
        ASSERT_OK_POSITIVE(inode_same_at(fd1, /* filea= */ NULL, fd2_check, /* fileb= */ NULL,
                                         AT_EMPTY_PATH));
}

TEST(readlinkat_malloc) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL, *q = NULL;
        const char *expect = "hgoehogefoobar";

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, O_PATH, &t));

        ASSERT_OK_ERRNO(symlinkat(expect, tfd, "linkname"));

        ASSERT_OK(readlinkat_malloc(tfd, "linkname", &p));
        ASSERT_STREQ(p, expect);
        p = mfree(p);

        fd = ASSERT_OK_ERRNO(openat(tfd, "linkname", O_PATH | O_NOFOLLOW | O_CLOEXEC));
        ASSERT_OK(readlinkat_malloc(fd, NULL, &p));
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        ASSERT_OK(readlinkat_malloc(fd, "", &p));
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        fd = safe_close(fd);

        ASSERT_NOT_NULL(q = path_join(t, "linkname"));
        ASSERT_OK(readlinkat_malloc(AT_FDCWD, q, &p));
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        ASSERT_OK(readlinkat_malloc(INT_MAX, q, &p));
        ASSERT_STREQ(p, expect);
        p = mfree(p);
        q = mfree(q);
}

TEST(xat_fdroot) {
        _cleanup_free_ char *p = NULL;
        ASSERT_OK(fd_get_path(XAT_FDROOT, &p));
        ASSERT_STREQ(p, "/");

        _cleanup_close_ int fd = -EBADF;
        fd = fd_reopen(XAT_FDROOT, O_CLOEXEC);
        ASSERT_OK(fd);

        ASSERT_OK_POSITIVE(path_is_root_at(XAT_FDROOT, /* path= */ NULL));
        ASSERT_OK_POSITIVE(path_is_root_at(XAT_FDROOT, "."));
        ASSERT_OK_POSITIVE(path_is_root_at(XAT_FDROOT, "/"));

        ASSERT_OK_POSITIVE(path_is_root_at(fd, /* path= */ NULL));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "."));
        ASSERT_OK_POSITIVE(path_is_root_at(fd, "/"));

        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, fd));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(XAT_FDROOT, XAT_FDROOT));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, XAT_FDROOT));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(XAT_FDROOT, fd));

        ASSERT_OK_POSITIVE(dir_fd_is_root(XAT_FDROOT));
        ASSERT_OK_POSITIVE(dir_fd_is_root(fd));

        ASSERT_OK_POSITIVE(dir_fd_is_root_or_cwd(XAT_FDROOT));
        ASSERT_OK_POSITIVE(dir_fd_is_root_or_cwd(AT_FDCWD));
        ASSERT_OK_POSITIVE(dir_fd_is_root_or_cwd(fd));

        ASSERT_OK(access_fd(XAT_FDROOT, F_OK));
        ASSERT_OK(access_fd(fd, F_OK));

        fd = safe_close(fd);
        fd = xopenat(XAT_FDROOT, ".", O_RDONLY);
        ASSERT_OK(fd);

        fd = safe_close(fd);
        fd = xopenat(XAT_FDROOT, "/", O_RDONLY);
        ASSERT_OK(fd);

        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK(fd_verify_directory(XAT_FDROOT));

        ASSERT_OK(fd_verify_linked(fd));
        ASSERT_OK(fd_verify_linked(XAT_FDROOT));

        int a = fd_is_read_only_fs(fd);
        ASSERT_OK(a);
        int b = fd_is_read_only_fs(XAT_FDROOT);
        ASSERT_OK(b);
        ASSERT_EQ(a, b);

        a = fd_is_temporary_fs(fd);
        ASSERT_OK(a);
        b = fd_is_temporary_fs(XAT_FDROOT);
        ASSERT_OK(b);
        ASSERT_EQ(a, b);
}

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
