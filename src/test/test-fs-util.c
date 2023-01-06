/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "id128-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
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

TEST(chase_symlinks) {
        _cleanup_free_ char *result = NULL, *pwd = NULL;
        _cleanup_close_ int pfd = -EBADF;
        char *temp;
        const char *top, *p, *pslash, *q, *qslash;
        struct stat st;
        int r;

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

        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        result = mfree(result);

        pslash = strjoina(p, "/");
        r = chase_symlinks(pslash, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr/"));
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase_symlinks(pslash, temp, 0, &result, NULL);
        assert_se(r == -ENOENT);

        q = strjoina(temp, "/usr");

        r = chase_symlinks(p, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        qslash = strjoina(q, "/");

        r = chase_symlinks(pslash, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        assert_se(mkdir(q, 0700) >= 0);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        r = chase_symlinks(pslash, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        p = strjoina(temp, "/slash");
        assert_se(symlink("/", p) >= 0);

        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, temp));
        result = mfree(result);

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        assert_se(symlink("../../..", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, temp));
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        assert_se(symlink("../../../usr", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        assert_se(symlink("../../../../usr", p) >= 0);

        r = chase_symlinks(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        assert_se(symlink("///usr///", p) >= 0);

        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        assert_se(streq(result, "/usr")); /* we guarantee that we drop redundant slashes */
        result = mfree(result);

        r = chase_symlinks(p, temp, 0, &result, NULL);
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
                r = chase_symlinks(p, temp, CHASE_SAFE, &result, NULL);
                assert_se(r == -ENOLINK);
                result = mfree(result);

                /* Allow this when the user-owned directories are all in the "root". */
                r = chase_symlinks(p, q, CHASE_SAFE, &result, NULL);
                assert_se(r > 0);
                result = mfree(result);
        }

        /* Paths using . */

        r = chase_symlinks("/etc/./.././", NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase_symlinks("/etc/./.././", "/etc", 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../etc", NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../test-chase.fsldajfl", NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result, NULL);
        assert_se(r > 0);
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase_symlinks("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase_symlinks("/etc/machine-id/foo", NULL, 0, &result, NULL);
        assert_se(IN_SET(r, -ENOTDIR, -ENOENT));
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        assert_se(symlink("recursive-symlink", p) >= 0);
        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r == -ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        /* Relative paths */

        assert_se(safe_getcwd(&pwd) >= 0);

        assert_se(chdir(temp) >= 0);

        p = "this/is/a/relative/path";
        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);

        p = strjoina(temp, "/", p);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = "this/is/a/relative/path";
        r = chase_symlinks(p, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);

        p = strjoina(temp, "/", p);
        assert_se(path_equal(result, p));
        result = mfree(result);

        assert_se(chdir(pwd) >= 0);

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase_symlinks(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == -ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        assert_se(symlink(q, p) >= 0);
        p = strjoina(temp, "/target/idontexist");
        r = chase_symlinks(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        if (geteuid() == 0) {
                p = strjoina(temp, "/priv1");
                assert_se(mkdir(p, 0755) >= 0);

                q = strjoina(p, "/priv2");
                assert_se(mkdir(q, 0755) >= 0);

                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(q, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(p, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(q, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                assert_se(rmdir(q) >= 0);
                assert_se(symlink("/etc/passwd", q) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                assert_se(chown(p, 0, 0) >= 0);
                assert_se(chase_symlinks(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);
        }

        p = strjoina(temp, "/machine-id-test");
        assert_se(symlink("/usr/../etc/./machine-id", p) >= 0);

        r = chase_symlinks(p, NULL, 0, NULL, &pfd);
        if (r != -ENOENT && sd_id128_get_machine(NULL) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                sd_id128_t a, b;

                assert_se(pfd >= 0);

                fd = fd_reopen(pfd, O_RDONLY|O_CLOEXEC);
                assert_se(fd >= 0);
                safe_close(pfd);

                assert_se(id128_read_fd(fd, ID128_FORMAT_PLAIN, &a) >= 0);
                assert_se(sd_id128_get_machine(&b) >= 0);
                assert_se(sd_id128_equal(a, b));
        }

        assert_se(lstat(p, &st) >= 0);
        r = chase_symlinks_and_unlink(p, NULL, 0, 0,  &result);
        assert_se(path_equal(result, p));
        result = mfree(result);
        assert_se(r == 0);
        assert_se(lstat(p, &st) == -1 && errno == ENOENT);

        /* Test CHASE_NOFOLLOW */

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/symlink");
        assert_se(symlink(p, q) >= 0);
        r = chase_symlinks(q, NULL, CHASE_NOFOLLOW, &result, &pfd);
        assert_se(r >= 0);
        assert_se(pfd >= 0);
        assert_se(path_equal(result, q));
        assert_se(fstat(pfd, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* s1 -> s2 -> nonexistent */
        q = strjoina(temp, "/s1");
        assert_se(symlink("s2", q) >= 0);
        p = strjoina(temp, "/s2");
        assert_se(symlink("nonexistent", p) >= 0);
        r = chase_symlinks(q, NULL, CHASE_NOFOLLOW, &result, &pfd);
        assert_se(r >= 0);
        assert_se(pfd >= 0);
        assert_se(path_equal(result, q));
        assert_se(fstat(pfd, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* Test CHASE_STEP */

        p = strjoina(temp, "/start");
        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dot/dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/../a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/b");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase_symlinks(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        assert_se(streq("/usr", result));
        result = mfree(result);

        r = chase_symlinks("/usr", NULL, CHASE_STEP, &result, NULL);
        assert_se(r > 0);
        assert_se(streq("/usr", result));
        result = mfree(result);

        /* Make sure that symlinks in the "root" path are not resolved, but those below are */
        p = strjoina("/etc/..", temp, "/self");
        assert_se(symlink(".", p) >= 0);
        q = strjoina(p, "/top/dot/dotdota");
        r = chase_symlinks(q, p, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(path_startswith(result, p), "usr"));
        result = mfree(result);

        /* Test CHASE_PROHIBIT_SYMLINKS */

        assert_se(chase_symlinks("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase_symlinks("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);
        assert_se(chase_symlinks("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase_symlinks("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);
        assert_se(chase_symlinks("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase_symlinks("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);

 cleanup:
        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

TEST(chase_symlinks_at) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *result = NULL;
        const char *p;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        /* Test that AT_FDCWD with CHASE_AT_RESOLVE_IN_ROOT resolves against / and not the current working
         * directory. */

        assert_se(symlinkat("/usr", tfd, "abc") >= 0);

        p = strjoina(t, "/abc");
        assert_se(chase_symlinks_at(AT_FDCWD, p, CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        /* Test that absolute path or not are the same when resolving relative to a directory file
         * descriptor and that we always get a relative path back. */

        assert_se(fd = openat(tfd, "def", O_CREAT|O_CLOEXEC, 0700) >= 0);
        fd = safe_close(fd);
        assert_se(symlinkat("/def", tfd, "qed") >= 0);
        assert_se(chase_symlinks_at(tfd, "qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "def"));
        result = mfree(result);
        assert_se(chase_symlinks_at(tfd, "/qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "def"));
        result = mfree(result);

        /* Valid directory file descriptor without CHASE_AT_RESOLVE_IN_ROOT should resolve symlinks against
         * host's root. */
        assert_se(chase_symlinks_at(tfd, "/qed", 0, &result, NULL) == -ENOENT);
}

TEST(unlink_noerrno) {
        char *name;
        int fd;

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
        assert_se(copy_file(p, q, 0, MODE_INVALID, 0, 0, COPY_REFLINK) >= 0);
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

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
