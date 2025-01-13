/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static const char *arg_test_dir = NULL;

static void test_chase_extract_filename_one(const char *path, const char *root, const char *expected) {
        _cleanup_free_ char *ret1 = NULL, *ret2 = NULL, *fname = NULL;

        log_debug("/* %s(path=%s, root=%s) */", __func__, path, strnull(root));

        assert_se(chase(path, root, CHASE_EXTRACT_FILENAME, &ret1, NULL) > 0);
        ASSERT_STREQ(ret1, expected);

        assert_se(chase(path, root, 0, &ret2, NULL) > 0);
        ASSERT_OK(chase_extract_filename(ret2, root, &fname));
        ASSERT_STREQ(fname, expected);
}

TEST(chase) {
        _cleanup_free_ char *result = NULL, *pwd = NULL;
        _cleanup_close_ int pfd = -EBADF;
        char *temp;
        const char *top, *p, *pslash, *q, *qslash;
        struct stat st;
        int r;

        temp = strjoina(arg_test_dir ?: "/tmp", "/test-chase.XXXXXX");
        assert_se(mkdtemp(temp));

        top = strjoina(temp, "/top");
        ASSERT_OK(mkdir(top, 0700));

        p = strjoina(top, "/dot");
        if (symlink(".", p) < 0) {
                assert_se(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
                goto cleanup;
        };

        p = strjoina(top, "/dotdot");
        ASSERT_OK(symlink("..", p));

        p = strjoina(top, "/dotdota");
        ASSERT_OK(symlink("../a", p));

        p = strjoina(temp, "/a");
        ASSERT_OK(symlink("b", p));

        p = strjoina(temp, "/b");
        ASSERT_OK(symlink("/usr", p));

        p = strjoina(temp, "/start");
        ASSERT_OK(symlink("top/dot/dotdota", p));

        /* Paths that use symlinks underneath the "root" */

        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        result = mfree(result);

        r = chase(p, "/.//../../../", 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        result = mfree(result);

        pslash = strjoina(p, "/");
        r = chase(pslash, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr/"));
        result = mfree(result);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase(pslash, temp, 0, &result, NULL);
        assert_se(r == -ENOENT);

        q = strjoina(temp, "/usr");

        r = chase(p, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        qslash = strjoina(q, "/");

        r = chase(pslash, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        ASSERT_OK(mkdir(q, 0700));

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        r = chase(pslash, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, qslash));
        result = mfree(result);

        p = strjoina(temp, "/slash");
        assert_se(symlink("/", p) >= 0);

        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, temp));
        result = mfree(result);

        /* Tests for CHASE_EXTRACT_FILENAME and chase_extract_filename() */

        p = strjoina(temp, "/start");
        pslash = strjoina(p, "/");
        test_chase_extract_filename_one(p, NULL, "usr");
        test_chase_extract_filename_one(pslash, NULL, "usr");
        test_chase_extract_filename_one(p, temp, "usr");
        test_chase_extract_filename_one(pslash, temp, "usr");

        p = strjoina(temp, "/slash");
        test_chase_extract_filename_one(p, NULL, ".");
        test_chase_extract_filename_one(p, temp, ".");

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        ASSERT_OK(symlink("../../..", p));

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, temp));
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        ASSERT_OK(symlink("../../../usr", p));

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        ASSERT_OK(symlink("../../../../usr", p));

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        ASSERT_OK(symlink("///usr///", p));

        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        ASSERT_STREQ(result, "/usr"); /* we guarantee that we drop redundant slashes */
        result = mfree(result);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, q));
        result = mfree(result);

        /* Paths underneath the "root" with different UIDs while using CHASE_SAFE */

        if (geteuid() == 0 && !userns_has_single_user()) {
                p = strjoina(temp, "/user");
                ASSERT_OK(mkdir(p, 0755));
                ASSERT_OK(chown(p, UID_NOBODY, GID_NOBODY));

                q = strjoina(temp, "/user/root");
                ASSERT_OK(mkdir(q, 0755));

                p = strjoina(q, "/link");
                ASSERT_OK(symlink("/", p));

                /* Fail when user-owned directories contain root-owned subdirectories. */
                r = chase(p, temp, CHASE_SAFE, &result, NULL);
                assert_se(r == -ENOLINK);
                result = mfree(result);

                /* Allow this when the user-owned directories are all in the "root". */
                r = chase(p, q, CHASE_SAFE, &result, NULL);
                assert_se(r > 0);
                result = mfree(result);
        }

        /* Paths using . */

        r = chase("/etc/./.././", NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/"));
        result = mfree(result);

        r = chase("/etc/./.././", "/etc", 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, "/etc"));
        result = mfree(result);

        r = chase("/../.././//../../etc", NULL, 0, &result, NULL);
        assert_se(r > 0);
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        r = chase("/../.././//../../test-chase.fsldajfl", NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        r = chase("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result, NULL);
        assert_se(r > 0);
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        r = chase("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        r = chase("/.path/with/dot", temp, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL);
        ASSERT_OK(r);
        q = strjoina(temp, "/.path/with/dot");
        ASSERT_STREQ(result, q);
        result = mfree(result);

        r = chase("/etc/machine-id/foo", NULL, 0, &result, NULL);
        assert_se(IN_SET(r, -ENOTDIR, -ENOENT));
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        ASSERT_OK(symlink("recursive-symlink", p));
        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r == -ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);

        /* Relative paths */

        ASSERT_OK(safe_getcwd(&pwd));

        ASSERT_OK(chdir(temp));

        p = "this/is/a/relative/path";
        r = chase(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);

        p = strjoina(temp, "/", p);
        assert_se(path_equal(result, p));
        result = mfree(result);

        p = "this/is/a/relative/path";
        r = chase(p, temp, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);

        p = strjoina(temp, "/", p);
        assert_se(path_equal(result, p));
        result = mfree(result);

        assert_se(chdir(pwd) >= 0);

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        r = chase(p, NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == -ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        assert_se(symlink(q, p) >= 0);
        p = strjoina(temp, "/target/idontexist");
        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r == -ENOENT);

        if (geteuid() == 0 && !userns_has_single_user()) {
                p = strjoina(temp, "/priv1");
                ASSERT_OK(mkdir(p, 0755));

                q = strjoina(p, "/priv2");
                ASSERT_OK(mkdir(q, 0755));

                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                ASSERT_OK(chown(q, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                ASSERT_OK(chown(p, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                assert_se(chown(q, 0, 0) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                ASSERT_OK(rmdir(q));
                ASSERT_OK(symlink("/etc/passwd", q));
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                assert_se(chown(p, 0, 0) >= 0);
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));
        }

        p = strjoina(temp, "/machine-id-test");
        ASSERT_OK(symlink("/usr/../etc/./machine-id", p));

        r = chase(p, NULL, 0, NULL, &pfd);
        if (r != -ENOENT && sd_id128_get_machine(NULL) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                sd_id128_t a, b;

                ASSERT_OK(pfd);

                fd = fd_reopen(pfd, O_RDONLY|O_CLOEXEC);
                ASSERT_OK(fd);
                safe_close(pfd);

                ASSERT_OK(id128_read_fd(fd, ID128_FORMAT_PLAIN, &a));
                ASSERT_OK(sd_id128_get_machine(&b));
                assert_se(sd_id128_equal(a, b));
        }

        assert_se(lstat(p, &st) >= 0);
        r = chase_and_unlink(p, NULL, 0, 0, &result);
        assert_se(r == 0);
        assert_se(path_equal(result, p));
        result = mfree(result);
        assert_se(lstat(p, &st) == -1 && errno == ENOENT);

        /* Test CHASE_NOFOLLOW */

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/symlink");
        assert_se(symlink(p, q) >= 0);
        r = chase(q, NULL, CHASE_NOFOLLOW, &result, &pfd);
        ASSERT_OK(r);
        ASSERT_OK(pfd);
        assert_se(path_equal(result, q));
        ASSERT_OK(fstat(pfd, &st));
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* s1 -> s2 -> nonexistent */
        q = strjoina(temp, "/s1");
        ASSERT_OK(symlink("s2", q));
        p = strjoina(temp, "/s2");
        ASSERT_OK(symlink("nonexistent", p));
        r = chase(q, NULL, CHASE_NOFOLLOW, &result, &pfd);
        ASSERT_OK(r);
        ASSERT_OK(pfd);
        assert_se(path_equal(result, q));
        ASSERT_OK(fstat(pfd, &st));
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* Test CHASE_STEP */

        p = strjoina(temp, "/start");
        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dot/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/../a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/b");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        ASSERT_STREQ("/usr", result);
        result = mfree(result);

        r = chase("/usr", NULL, CHASE_STEP, &result, NULL);
        assert_se(r > 0);
        ASSERT_STREQ("/usr", result);
        result = mfree(result);

        /* Make sure that symlinks in the "root" path are not resolved, but those below are */
        p = strjoina("/etc/..", temp, "/self");
        assert_se(symlink(".", p) >= 0);
        q = strjoina(p, "/top/dot/dotdota");
        r = chase(q, p, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(path_startswith(result, p), "usr"));
        result = mfree(result);

        /* Test CHASE_PROHIBIT_SYMLINKS */

        assert_se(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);
        assert_se(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);
        assert_se(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL) == -EREMCHG);
        assert_se(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL) == -EREMCHG);

 cleanup:
        ASSERT_OK(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL));
}

TEST(chaseat) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *result = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        const char *p;

        ASSERT_OK((tfd = mkdtemp_open(NULL, 0, &t)));

        /* Test that AT_FDCWD with CHASE_AT_RESOLVE_IN_ROOT resolves against / and not the current working
         * directory. */

        ASSERT_OK(symlinkat("/usr", tfd, "abc"));

        p = strjoina(t, "/abc");
        ASSERT_OK(chaseat(AT_FDCWD, p, CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* If the file descriptor points to the root directory, the result will be absolute. */

        fd = open("/", O_CLOEXEC | O_DIRECTORY | O_PATH);
        ASSERT_OK(fd);

        ASSERT_OK(chaseat(fd, p, 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK(chaseat(fd, p, CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        fd = safe_close(fd);

        /* If the file descriptor does not point to the root directory, the result will be relative
         * unless the result is outside of the specified file descriptor. */

        ASSERT_OK(chaseat(tfd, "abc", 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "/abc", 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        assert_se(chaseat(tfd, "abc", CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL) == -ENOENT);
        assert_se(chaseat(tfd, "/abc", CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL) == -ENOENT);

        ASSERT_OK(chaseat(tfd, "abc", CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "/abc", CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        /* Test that absolute path or not are the same when resolving relative to a directory file
         * descriptor and that we always get a relative path back. */

        ASSERT_OK(fd = openat(tfd, "def", O_CREAT|O_CLOEXEC, 0700));
        fd = safe_close(fd);
        ASSERT_OK(symlinkat("/def", tfd, "qed"));
        ASSERT_OK(chaseat(tfd, "qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);
        ASSERT_OK(chaseat(tfd, "/qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);

        /* Valid directory file descriptor without CHASE_AT_RESOLVE_IN_ROOT should resolve symlinks against
         * host's root. */
        assert_se(chaseat(tfd, "/qed", 0, NULL, NULL) == -ENOENT);

        /* Test CHASE_PARENT */

        ASSERT_OK((fd = open_mkdir_at(tfd, "chase", O_CLOEXEC, 0755)));
        ASSERT_OK(symlinkat("/def", fd, "parent"));
        fd = safe_close(fd);

        /* Make sure that when we chase a symlink parent directory, that we chase the parent directory of the
         * symlink target and not the symlink itself. But if we add CHASE_NOFOLLOW, we get the parent
         * directory of the symlink itself. */

        ASSERT_OK(chaseat(tfd, "chase/parent", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, &fd));
        ASSERT_OK(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_NOFOLLOW, &result, &fd));
        ASSERT_OK(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "chase/parent");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "chase", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, &fd));
        ASSERT_OK(faccessat(fd, "chase", F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "/", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        assert_se(chaseat(tfd, ".", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test CHASE_MKDIR_0755 */

        ASSERT_OK(chaseat(tfd, "m/k/d/i/r", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL));
        ASSERT_OK(faccessat(tfd, "m/k/d/i", F_OK, 0));
        assert_se(RET_NERRNO(faccessat(tfd, "m/k/d/i/r", F_OK, 0)) == -ENOENT);
        ASSERT_STREQ(result, "m/k/d/i/r");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "m/../q", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL));
        ASSERT_OK(faccessat(tfd, "m", F_OK, 0));
        assert_se(RET_NERRNO(faccessat(tfd, "q", F_OK, 0)) == -ENOENT);
        ASSERT_STREQ(result, "q");
        result = mfree(result);

        assert_se(chaseat(tfd, "i/../p", CHASE_MKDIR_0755|CHASE_NONEXISTENT, NULL, NULL) == -ENOENT);

        /* Test CHASE_EXTRACT_FILENAME */

        ASSERT_OK(chaseat(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, &result, &fd));
        ASSERT_OK(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "chase", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, &fd));
        ASSERT_OK(faccessat(fd, result, F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, "/", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, ".", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, NULL, CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test chase_and_openat() */

        fd = chase_and_openat(tfd, "o/p/e/n/f/i/l/e", CHASE_MKDIR_0755, O_CREAT|O_EXCL|O_CLOEXEC, NULL);
        ASSERT_OK(fd);
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);

        fd = chase_and_openat(tfd, "o/p/e/n/d/i/r", CHASE_MKDIR_0755, O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, NULL);
        ASSERT_OK(fd);
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);

        fd = chase_and_openat(tfd, NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result);
        ASSERT_OK(fd);
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        /* Test chase_and_openatdir() */

        ASSERT_OK(chase_and_opendirat(tfd, "o/p/e/n/d/i", 0, &result, &dir));
        FOREACH_DIRENT(de, dir, assert_not_reached())
                ASSERT_STREQ(de->d_name, "r");
        ASSERT_STREQ(result, "o/p/e/n/d/i");
        result = mfree(result);

        /* Test chase_and_statat() */

        ASSERT_OK(chase_and_statat(tfd, "o/p", 0, &result, &st));
        ASSERT_OK(stat_verify_directory(&st));
        ASSERT_STREQ(result, "o/p");
        result = mfree(result);

        /* Test chase_and_accessat() */

        ASSERT_OK(chase_and_accessat(tfd, "o/p/e", 0, F_OK, &result));
        ASSERT_STREQ(result, "o/p/e");
        result = mfree(result);

        /* Test chase_and_fopenat_unlocked() */

        ASSERT_OK(chase_and_fopenat_unlocked(tfd, "o/p/e/n/f/i/l/e", 0, "re", &result, &f));
        assert_se(fread(&(char[1]) {}, 1, 1, f) == 0);
        assert_se(feof(f));
        f = safe_fclose(f);
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_unlinkat() */

        ASSERT_OK(chase_and_unlinkat(tfd, "o/p/e/n/f/i/l/e", 0, 0, &result));
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_open_parent_at() */

        ASSERT_OK((fd = chase_and_open_parent_at(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_NOFOLLOW, &result)));
        ASSERT_OK(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK((fd = chase_and_open_parent_at(tfd, "chase", CHASE_AT_RESOLVE_IN_ROOT, &result)));
        ASSERT_OK(faccessat(fd, result, F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK((fd = chase_and_open_parent_at(tfd, "/", CHASE_AT_RESOLVE_IN_ROOT, &result)));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK((fd = chase_and_open_parent_at(tfd, ".", CHASE_AT_RESOLVE_IN_ROOT, &result)));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);
}

TEST(chaseat_prefix_root) {
        _cleanup_free_ char *cwd = NULL, *ret = NULL, *expected = NULL;

        ASSERT_OK(safe_getcwd(&cwd));

        ASSERT_OK(chaseat_prefix_root("/hoge", NULL, &ret));
        ASSERT_STREQ(ret, "/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_prefix_root("/hoge", "a/b/c", &ret));
        ASSERT_STREQ(ret, "/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_prefix_root("hoge", "/a/b//./c///", &ret));
        ASSERT_STREQ(ret, "/a/b/c/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_prefix_root("hoge", "a/b//./c///", &ret));
        assert_se(expected = path_join(cwd, "a/b/c/hoge"));
        ASSERT_STREQ(ret, expected);

        ret = mfree(ret);
        expected = mfree(expected);

        ASSERT_OK(chaseat_prefix_root("./hoge/aaa/../././b", "/a/b//./c///", &ret));
        ASSERT_STREQ(ret, "/a/b/c/hoge/aaa/../././b");

        ret = mfree(ret);

        assert_se(chaseat_prefix_root("./hoge/aaa/../././b", "a/b//./c///", &ret) >= 0);
        assert_se(expected = path_join(cwd, "a/b/c/hoge/aaa/../././b"));
        ASSERT_STREQ(ret, expected);
}

TEST(trailing_dot_dot) {
        _cleanup_free_ char *path = NULL, *fdpath = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(chase("/usr/..", NULL, CHASE_PARENT, &path, &fd));
        assert_se(path_equal(path, "/"));
        ASSERT_OK(fd_get_path(fd, &fdpath));
        assert_se(path_equal(fdpath, "/"));

        path = mfree(path);
        fdpath = mfree(fdpath);
        fd = safe_close(fd);

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc(NULL, &t));
        _cleanup_free_ char *sub = ASSERT_PTR(path_join(t, "a/b/c/d"));
        ASSERT_OK(mkdir_p(sub, 0700));
        _cleanup_free_ char *suffixed = ASSERT_PTR(path_join(sub, ".."));
        ASSERT_OK(chase(suffixed, NULL, CHASE_PARENT, &path, &fd));
        _cleanup_free_ char *expected1 = ASSERT_PTR(path_join(t, "a/b/c"));
        _cleanup_free_ char *expected2 = ASSERT_PTR(path_join(t, "a/b"));

        assert_se(path_equal(path, expected1));
        ASSERT_OK(fd_get_path(fd, &fdpath));
        assert_se(path_equal(fdpath, expected2));
}

TEST(use_chase_as_mkdir_p) {
        _cleanup_free_ char *p = NULL;
        ASSERT_OK_ERRNO(asprintf(&p, "/tmp/chasemkdir%" PRIu64 "/a/b/c", random_u64()));

        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(chase(p, NULL, CHASE_PREFIX_ROOT|CHASE_MKDIR_0755, NULL, &fd));

        ASSERT_OK_EQ(inode_same_at(AT_FDCWD, p, fd, NULL, AT_EMPTY_PATH), 1);

        _cleanup_close_ int fd2 = -EBADF;
        ASSERT_OK(chase(p, p, CHASE_PREFIX_ROOT|CHASE_MKDIR_0755, NULL, &fd2));

        _cleanup_free_ char *pp = ASSERT_PTR(path_join(p, p));

        ASSERT_OK_EQ(inode_same_at(AT_FDCWD, pp, fd2, NULL, AT_EMPTY_PATH), 1);

        _cleanup_free_ char *f = NULL;
        ASSERT_OK(path_extract_directory(p, &f));

        _cleanup_free_ char *ff = NULL;
        ASSERT_OK(path_extract_directory(f, &ff));

        _cleanup_free_ char *fff = NULL;
        ASSERT_OK(path_extract_directory(ff, &fff));

        ASSERT_OK(rm_rf(fff, REMOVE_PHYSICAL));
}

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
