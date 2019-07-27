/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

static const char *arg_test_dir = NULL;

static void test_chase_symlinks(void) {
        _cleanup_free_ char *result = NULL;
        char *temp;
        const char *top, *p, *pslash, *q, *qslash;
        struct stat st;
        int r, pfd;

        log_info("/* %s */", __func__);

        temp = strjoina(arg_test_dir ?: "/tmp", "/test-chase.XXXXXX");
        assert_se(mkdtemp(temp));

        top = strjoina(temp, "/top");
        assert_se(mkdir(top, 0700) >= 0);

        p = strjoina(top, "/dot");
        if (symlink(".", p) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
                goto cleanup;
        };

        p = strjoina(top, "/dotdot");
        assert_se(symlink("..", p) >= 0);

        p = strjoina(top, "/dotdota");
        assert_se(symlink("../a", p) >= 0);

        p = strjoina(temp, "/a");
        assert_se(symlink("b", p) >= 0);

        p = strjoina(temp, "/b");
        assert_se(symlink("/usr", p) >= 0);

        p = strjoina(temp, "/start");
        assert_se(symlink("top/dot/dotdota", p) >= 0);

        /* Paths that use symlinks underneath the "root" */

        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        result = mfree(result);

        pslash = strjoina(p, "/");
        r = chase_symlinks(pslash, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr/"));
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(pslash, temp, 0, &result);
        assert_se(r == -ENOENT);

        q = strjoina(temp, "/usr");

        r = chase_symlinks(p, temp, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        qslash = strjoina(q, "/");

        r = chase_symlinks(pslash, temp, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        assert_se(mkdir(q, 0700) >= 0);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        r = chase_symlinks(pslash, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        p = strjoina(temp, "/slash");
        assert_se(symlink("/", p) >= 0);

        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, temp));
        result = mfree(result);

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        assert_se(symlink("../../..", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, temp));
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        assert_se(symlink("../../../usr", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        assert_se(symlink("../../../../usr", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        assert_se(symlink("///usr///", p) >= 0);

        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        /* Paths underneath the "root" with different UIDs while using CHASE_SAFE */

        if (geteuid() == 0) {
                p = strjoina(temp, "/user");
                assert_se(mkdir(p, 0755) >= 0);
                assert_se(chown(p, UID_NOBODY, GID_NOBODY) >= 0);

                q = strjoina(temp, "/user/root");
                assert_se(mkdir(q, 0755) >= 0);

                p = strjoina(q, "/link");
                assert_se(symlink("/", p) >= 0);

                /* Fail when user-owned directories contain root-owned subdirectories. */
                r = chase_symlinks(p, temp, CHASE_SAFE, &result);
                assert_se(r == -ENOLINK);
                result = mfree(result);

                /* Allow this when the user-owned directories are all in the "root". */
                r = chase_symlinks(p, q, CHASE_SAFE, &result);
                assert_se(r > 0);
                result = mfree(result);
        }

        /* Paths using . */

        r = chase_symlinks("/etc/./.././", NULL, 0, &result);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase_symlinks("/etc/./.././", "/etc", 0, &result);
        assert_se(r > 0 && path_equal(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../etc", NULL, 0, &result);
        assert_se(r > 0);
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../test-chase.fsldajfl", NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result);
        assert_se(r > 0);
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase_symlinks("/etc/machine-id/foo", NULL, 0, &result);
        assert_se(r == -ENOTDIR);
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        assert_se(symlink("recursive-symlink", p) >= 0);
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result);
        assert_se(r == -ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        assert_se(symlink(q, p) >= 0);
        p = strjoina(temp, "/target/idontexist");
        r = chase_symlinks(p, NULL, 0, &result);
        assert_se(r == -ENOENT);

        if (geteuid() == 0) {
                p = strjoina(temp, "/priv1");
                assert_se(mkdir(p, 0755) >= 0);

                q = strjoina(p, "/priv2");
                assert_se(mkdir(q, 0755) >= 0);

                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(q, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(p, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);

                assert_se(chown(q, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) == -ENOLINK);

                assert_se(rmdir(q) >= 0);
                assert_se(symlink("/etc/passwd", q) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) == -ENOLINK);

                assert_se(chown(p, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL) >= 0);
        }

        p = strjoina(temp, "/machine-id-test");
        assert_se(symlink("/usr/../etc/./machine-id", p) >= 0);

        pfd = chase_symlinks(p, NULL, CHASE_OPEN, NULL);
        if (pfd != -ENOENT) {
                _cleanup_close_ int fd = -1;
                sd_id128_t a, b;

                assert_se(pfd >= 0);

                fd = fd_reopen(pfd, O_RDONLY|O_CLOEXEC);
                assert_se(fd >= 0);
                safe_close(pfd);

                assert_se(id128_read_fd(fd, ID128_PLAIN, &a) >= 0);
                assert_se(sd_id128_get_machine(&b) >= 0);
                assert_se(sd_id128_equal(a, b));
        }

        /* Test CHASE_NOFOLLOW */

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/symlink");
        assert_se(symlink(p, q) >= 0);
        pfd = chase_symlinks(q, NULL, CHASE_OPEN|CHASE_NOFOLLOW, &result);
        assert_se(pfd > 0);
        assert_se(path_equal(result, q));
        assert_se(fstat(pfd, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);

        /* s1 -> s2 -> nonexistent */
        q = strjoina(temp, "/s1");
        assert_se(symlink("s2", q) >= 0);
        p = strjoina(temp, "/s2");
        assert_se(symlink("nonexistent", p) >= 0);
        pfd = chase_symlinks(q, NULL, CHASE_OPEN|CHASE_NOFOLLOW, &result);
        assert_se(pfd > 0);
        assert_se(path_equal(result, q));
        assert_se(fstat(pfd, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);

        /* Test CHASE_ONE */

        p = strjoina(temp, "/start");
        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dot/dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        p = strjoina(temp, "/top/./dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        p = strjoina(temp, "/top/../a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        p = strjoina(temp, "/a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        p = strjoina(temp, "/b");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result);
        assert_se(r == 0);
        assert_se(streq("/usr", result));
        result = mfree(result);

        r = chase_symlinks("/usr", NULL, CHASE_STEP, &result);
        assert_se(r > 0);
        assert_se(streq("/usr", result));
        result = mfree(result);

 cleanup:
        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

static void test_unlink_noerrno(void) {
        char *name;
        int fd;

        log_info("/* %s */", __func__);

        name = strjoina(arg_test_dir ?: "/tmp", "/test-close_nointr.XXXXXX");
        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);

        {
                PROTECT_ERRNO;
                errno = 42;
                assert_se(unlink_noerrno(name) >= 0);
                assert_se(errno == 42);
                assert_se(unlink_noerrno(name) < 0);
                assert_se(errno == 42);
        }
}

static void test_readlink_and_make_absolute(void) {
        const char *tempdir, *name, *name2, *name_alias;
        _cleanup_free_ char *r1 = NULL, *r2 = NULL, *pwd = NULL;

        log_info("/* %s */", __func__);

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

static void test_get_files_in_directory(void) {
        _cleanup_strv_free_ char **l = NULL, **t = NULL;

        assert_se(get_files_in_directory(arg_test_dir ?: "/tmp", &l) >= 0);
        assert_se(get_files_in_directory(".", &t) >= 0);
        assert_se(get_files_in_directory(".", NULL) >= 0);
}

static void test_var_tmp(void) {
        _cleanup_free_ char *tmpdir_backup = NULL, *temp_backup = NULL, *tmp_backup = NULL;
        const char *tmp_dir = NULL, *t;

        log_info("/* %s */", __func__);

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

static void test_dot_or_dot_dot(void) {
        log_info("/* %s */", __func__);

        assert_se(!dot_or_dot_dot(NULL));
        assert_se(!dot_or_dot_dot(""));
        assert_se(!dot_or_dot_dot("xxx"));
        assert_se(dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot(".."));
        assert_se(!dot_or_dot_dot(".foo"));
        assert_se(!dot_or_dot_dot("..foo"));
}

static void test_access_fd(void) {
        _cleanup_(rmdir_and_freep) char *p = NULL;
        _cleanup_close_ int fd = -1;
        const char *a;

        log_info("/* %s */", __func__);

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

static void test_touch_file(void) {
        uid_t test_uid, test_gid;
        _cleanup_(rm_rf_physical_and_freep) char *p = NULL;
        struct stat st;
        const char *a;
        usec_t test_mtime;
        int r;

        log_info("/* %s */", __func__);

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
                a = strjoina(p, "/cdev");
                r = mknod(a, 0775 | S_IFCHR, makedev(0, 0));
                if (r < 0 && errno == EPERM && detect_container() > 0) {
                        log_notice("Running in unprivileged container? Skipping remaining tests in %s", __func__);
                        return;
                }
                assert_se(r >= 0);
                assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
                assert_se(lstat(a, &st) >= 0);
                assert_se(st.st_uid == test_uid);
                assert_se(st.st_gid == test_gid);
                assert_se(S_ISCHR(st.st_mode));
                assert_se((st.st_mode & 0777) == 0640);
                assert_se(timespec_load(&st.st_mtim) == test_mtime);

                a = strjoina(p, "/bdev");
                assert_se(mknod(a, 0775 | S_IFBLK, makedev(0, 0)) >= 0);
                assert_se(touch_file(a, false, test_mtime, test_uid, test_gid, 0640) >= 0);
                assert_se(lstat(a, &st) >= 0);
                assert_se(st.st_uid == test_uid);
                assert_se(st.st_gid == test_gid);
                assert_se(S_ISBLK(st.st_mode));
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

static void test_unlinkat_deallocate(void) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;

        log_info("/* %s */", __func__);

        assert_se(tempfn_random_child(arg_test_dir, "unlink-deallocation", &p) >= 0);

        fd = open(p, O_WRONLY|O_CLOEXEC|O_CREAT|O_EXCL, 0600);
        assert_se(fd >= 0);

        assert_se(write(fd, "hallo\n", 6) == 6);

        assert_se(fstat(fd, &st) >= 0);
        assert_se(st.st_size == 6);
        assert_se(st.st_blocks > 0);
        assert_se(st.st_nlink == 1);

        assert_se(unlinkat_deallocate(AT_FDCWD, p, 0) >= 0);

        assert_se(fstat(fd, &st) >= 0);
        assert_se(IN_SET(st.st_size, 0, 6)); /* depending on whether hole punching worked the size will be 6
                                                (it worked) or 0 (we had to resort to truncation) */
        assert_se(st.st_blocks == 0);
        assert_se(st.st_nlink == 0);
}

static void test_fsync_directory_of_file(void) {
        _cleanup_close_ int fd = -1;

        log_info("/* %s */", __func__);

        fd = open_tmpfile_unlinkable(arg_test_dir, O_RDWR);
        assert_se(fd >= 0);

        assert_se(fsync_directory_of_file(fd) >= 0);
}

static void test_rename_noreplace(void) {
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
        char **a, **b;

        log_info("/* %s */", __func__);

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

        STRV_FOREACH(a, (char**) table) {
                _cleanup_free_ char *x = NULL, *y = NULL;

                x = strjoin(z, *a);
                assert_se(x);

                if (access(x, F_OK) < 0) {
                        assert_se(errno == ENOENT);
                        continue;
                }

                STRV_FOREACH(b, (char**) table) {
                        _cleanup_free_ char *w = NULL;

                        w = strjoin(w, *b);
                        assert_se(w);

                        if (access(w, F_OK) < 0) {
                                assert_se(errno == ENOENT);
                                continue;
                        }

                        assert_se(rename_noreplace(AT_FDCWD, w, AT_FDCWD, y) == -EEXIST);
                }

                y = strjoin(z, "/somethingelse");
                assert_se(y);

                assert_se(rename_noreplace(AT_FDCWD, x, AT_FDCWD, y) >= 0);
                assert_se(rename_noreplace(AT_FDCWD, y, AT_FDCWD, x) >= 0);
        }
}

static void test_chmod_and_chown(void) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _unused_ _cleanup_umask_ mode_t u = umask(0000);
        struct stat st;
        const char *p;

        if (geteuid() != 0)
                return;

        log_info("/* %s */", __func__);

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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_INFO);

        arg_test_dir = argv[1];

        test_chase_symlinks();
        test_unlink_noerrno();
        test_readlink_and_make_absolute();
        test_get_files_in_directory();
        test_var_tmp();
        test_dot_or_dot_dot();
        test_access_fd();
        test_touch_file();
        test_unlinkat_deallocate();
        test_fsync_directory_of_file();
        test_rename_noreplace();
        test_chmod_and_chown();

        return 0;
}
