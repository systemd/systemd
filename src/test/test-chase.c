/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "id128-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

static const char *arg_test_dir = NULL;

static void test_chase_extract_filename_one(const char *path, const char *root, const char *expected) {
        _cleanup_free_ char *ret1 = NULL, *ret2 = NULL, *fname = NULL;

        log_debug("/* %s(path=%s, root=%s) */", __func__, path, strnull(root));

        ASSERT_OK_POSITIVE(chase(path, root, CHASE_EXTRACT_FILENAME, &ret1, NULL));
        ASSERT_STREQ(ret1, expected);

        ASSERT_OK_POSITIVE(chase(path, root, 0, &ret2, NULL));
        ASSERT_OK(chase_extract_filename(ret2, root, &fname));
        ASSERT_STREQ(fname, expected);
}

TEST(chase) {
        _cleanup_free_ char *result = NULL, *pwd = NULL;
        _cleanup_close_ int pfd = -EBADF;
        char *temp;
        const char *top, *p, *pslash, *q, *qslash;
        struct stat st;

        temp = strjoina(arg_test_dir ?: "/tmp", "/test-chase.XXXXXX");
        ASSERT_NOT_NULL(mkdtemp(temp));

        top = strjoina(temp, "/top");
        ASSERT_OK(mkdir(top, 0700));

        p = strjoina(top, "/dot");
        if (symlink(".", p) < 0) {
                ASSERT_TRUE(IN_SET(errno, EINVAL, ENOSYS, ENOTTY, EPERM));
                log_tests_skipped_errno(errno, "symlink() not possible");
                goto cleanup;
        };

        p = strjoina(top, "/dotdot");
        ASSERT_OK_ERRNO(symlink("..", p));

        p = strjoina(top, "/dotdota");
        ASSERT_OK_ERRNO(symlink("../a", p));

        p = strjoina(temp, "/a");
        ASSERT_OK_ERRNO(symlink("b", p));

        p = strjoina(temp, "/b");
        ASSERT_OK_ERRNO(symlink("/usr", p));

        p = strjoina(temp, "/start");
        ASSERT_OK_ERRNO(symlink("top/dot/dotdota", p));

        /* Paths that use symlinks underneath the "root" */

        ASSERT_OK_POSITIVE(chase(p, NULL, 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, "/.//../../../", 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/usr");
        result = mfree(result);

        pslash = strjoina(p, "/");
        ASSERT_OK_POSITIVE(chase(pslash, NULL, 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/usr/");
        result = mfree(result);

        ASSERT_ERROR(chase(p, temp, 0, &result, NULL), ENOENT);
        ASSERT_ERROR(chase(pslash, temp, 0, &result, NULL), ENOENT);

        q = strjoina(temp, "/usr");

        ASSERT_OK_ZERO(chase(p, temp, CHASE_NONEXISTENT, &result, NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        qslash = strjoina(q, "/");

        ASSERT_OK_ZERO(chase(pslash, temp, CHASE_NONEXISTENT, &result, NULL));
        ASSERT_PATH_EQ(result, qslash);
        result = mfree(result);

        ASSERT_OK_ERRNO(mkdir(q, 0700));

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(pslash, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, qslash);
        result = mfree(result);

        p = strjoina(temp, "/slash");
        ASSERT_OK_ERRNO(symlink("/", p));

        ASSERT_OK_POSITIVE(chase(p, NULL, 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, temp);
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
        ASSERT_OK_ERRNO(symlink("../../..", p));

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, temp);
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        ASSERT_OK_ERRNO(symlink("../../../usr", p));

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        ASSERT_OK_ERRNO(symlink("../../../../usr", p));

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        ASSERT_OK_ERRNO(symlink("///usr///", p));

        ASSERT_OK_POSITIVE(chase(p, NULL, 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/usr");
        ASSERT_STREQ(result, "/usr"); /* we guarantee that we drop redundant slashes */
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, temp, 0, &result, NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        /* Paths underneath the "root" with different UIDs while using CHASE_SAFE */

        if (geteuid() == 0 && !userns_has_single_user()) {
                p = strjoina(temp, "/user");
                ASSERT_OK_ERRNO(mkdir(p, 0755));
                ASSERT_OK_ERRNO(chown(p, UID_NOBODY, GID_NOBODY));

                q = strjoina(temp, "/user/root");
                ASSERT_OK_ERRNO(mkdir(q, 0755));

                p = strjoina(q, "/link");
                ASSERT_OK_ERRNO(symlink("/", p));

                /* Fail when user-owned directories contain root-owned subdirectories. */
                ASSERT_ERROR(chase(p, temp, CHASE_SAFE, &result, NULL), ENOLINK);
                result = mfree(result);

                /* Allow this when the user-owned directories are all in the "root". */
                ASSERT_OK_POSITIVE(chase(p, q, CHASE_SAFE, &result, NULL));
                result = mfree(result);
        }

        /* Paths using . */

        ASSERT_OK_POSITIVE(chase("/etc/./.././", NULL, 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/etc/./.././", "/etc", 0, &result, NULL));
        ASSERT_PATH_EQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/../.././//../../etc", NULL, 0, &result, NULL));
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_ZERO(chase("/../.././//../../test-chase.fsldajfl", NULL, CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result, NULL));
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_ZERO(chase("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        ASSERT_OK(chase("/.path/with/dot", temp, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL));
        q = strjoina(temp, "/.path/with/dot");
        ASSERT_STREQ(result, q);
        result = mfree(result);

        ASSERT_TRUE(IN_SET(chase("/etc/machine-id/foo", NULL, 0, &result, NULL), -ENOTDIR, -ENOENT));
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        ASSERT_OK_ERRNO(symlink("recursive-symlink", p));
        ASSERT_ERROR(chase(p, NULL, 0, &result, NULL), ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        ASSERT_ERROR(chase(p, NULL, 0, &result, NULL), ENOENT);
        ASSERT_OK_ZERO(chase(p, NULL, CHASE_NONEXISTENT, &result, NULL));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        ASSERT_ERROR(chase(p, NULL, 0, &result, NULL), ENOENT);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_NONEXISTENT, &result, NULL));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        /* Relative paths */

        ASSERT_OK(safe_getcwd(&pwd));

        ASSERT_OK_ERRNO(chdir(temp));

        p = "this/is/a/relative/path";
        ASSERT_OK_ZERO(chase(p, NULL, CHASE_NONEXISTENT, &result, NULL));

        p = strjoina(temp, "/", p);
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        p = "this/is/a/relative/path";
        ASSERT_OK_ZERO(chase(p, temp, CHASE_NONEXISTENT, &result, NULL));

        p = strjoina(temp, "/", p);
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        ASSERT_OK_ERRNO(chdir(pwd));

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        ASSERT_ERROR(chase(p, NULL, 0, &result, NULL), ENOENT);

        ASSERT_ERROR(chase(p, NULL, CHASE_NONEXISTENT, &result, NULL), ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        ASSERT_OK_ERRNO(symlink(q, p));
        p = strjoina(temp, "/target/idontexist");
        ASSERT_ERROR(chase(p, NULL, 0, &result, NULL), ENOENT);

        if (geteuid() == 0 && !userns_has_single_user()) {
                p = strjoina(temp, "/priv1");
                ASSERT_OK_ERRNO(mkdir(p, 0755));

                q = strjoina(p, "/priv2");
                ASSERT_OK_ERRNO(mkdir(q, 0755));

                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                ASSERT_OK_ERRNO(chown(q, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                ASSERT_OK(chown(p, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));

                ASSERT_OK_ERRNO(chown(q, 0, 0));
                ASSERT_ERROR(chase(q, NULL, CHASE_SAFE, NULL, NULL), ENOLINK);

                ASSERT_OK_ERRNO(rmdir(q));
                ASSERT_OK_ERRNO(symlink("/etc/passwd", q));
                ASSERT_ERROR(chase(q, NULL, CHASE_SAFE, NULL, NULL), ENOLINK);

                ASSERT_OK_ERRNO(chown(p, 0, 0));
                ASSERT_OK(chase(q, NULL, CHASE_SAFE, NULL, NULL));
        }

        p = strjoina(temp, "/machine-id-test");
        ASSERT_OK_ERRNO(symlink("/usr/../etc/./machine-id", p));

        if (chase(p, NULL, 0, NULL, &pfd) != -ENOENT && sd_id128_get_machine(NULL) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                sd_id128_t a, b;

                ASSERT_OK(pfd);

                fd = fd_reopen(pfd, O_RDONLY|O_CLOEXEC);
                ASSERT_OK(fd);
                safe_close(pfd);

                ASSERT_OK(id128_read_fd(fd, ID128_FORMAT_PLAIN, &a));
                ASSERT_OK(sd_id128_get_machine(&b));
                ASSERT_TRUE(sd_id128_equal(a, b));
        }

        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_OK_ZERO(chase_and_unlink(p, NULL, 0, 0, &result));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);
        ASSERT_ERROR_ERRNO(lstat(p, &st), ENOENT);

        /* Test CHASE_NOFOLLOW */

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/symlink");
        ASSERT_OK_ERRNO(symlink(p, q));
        ASSERT_OK(chase(q, NULL, CHASE_NOFOLLOW, &result, &pfd));
        ASSERT_PATH_EQ(result, q);
        ASSERT_OK_ERRNO(fstat(pfd, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* s1 -> s2 -> nonexistent */
        q = strjoina(temp, "/s1");
        ASSERT_OK_ERRNO(symlink("s2", q));
        p = strjoina(temp, "/s2");
        ASSERT_OK_ERRNO(symlink("nonexistent", p));
        ASSERT_OK(chase(q, NULL, CHASE_NOFOLLOW, &result, &pfd));
        ASSERT_PATH_EQ(result, q);
        ASSERT_OK_ERRNO(fstat(pfd, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* Test CHASE_STEP */

        p = strjoina(temp, "/start");
        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        p = strjoina(temp, "/top/dot/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        p = strjoina(temp, "/top/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        p = strjoina(temp, "/top/../a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        p = strjoina(temp, "/a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        p = strjoina(temp, "/b");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, NULL, CHASE_STEP, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/usr", NULL, CHASE_STEP, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* Make sure that symlinks in the "root" path are not resolved, but those below are */
        p = strjoina("/etc/..", temp, "/self");
        ASSERT_OK_ERRNO(symlink(".", p));
        q = strjoina(p, "/top/dot/dotdota");
        ASSERT_OK_POSITIVE(chase(q, p, 0, &result, NULL));
        ASSERT_PATH_EQ(path_startswith(result, p), "usr");
        result = mfree(result);

        /* Test CHASE_PROHIBIT_SYMLINKS */

        ASSERT_ERROR(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL), ELOOP);
        ASSERT_ERROR(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL), ELOOP);
        ASSERT_ERROR(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, NULL, NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, NULL, NULL), ELOOP);

 cleanup:
        ASSERT_OK(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL));
}

TEST(chase_and_open) {
        _cleanup_free_ char *result = NULL;
        _cleanup_close_ int fd = -EBADF;

        /* Test chase_and_open() with various CHASE_PARENT / CHASE_EXTRACT_FILENAME combinations. */

        /* No CHASE_PARENT, no CHASE_EXTRACT_FILENAME, with ret_path — opens the target, returns full path. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", NULL, 0, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "/usr/lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT with ret_path — opens parent dir, returns full path including final component. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", NULL, CHASE_PARENT, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "lib", F_OK, 0));
        ASSERT_STREQ(result, "/usr/lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME — opens parent dir, returns just the filename. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "lib", F_OK, 0));
        ASSERT_STREQ(result, "lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME only — opens the target itself, returns just the filename. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", NULL, CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME on a regular file (regression test for a bug where chase_and_open()
         * reopened the parent directory instead of the target file). */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", NULL, CHASE_EXTRACT_FILENAME, O_PATH|O_CLOEXEC, &result));
        ASSERT_STREQ(result, "os-release");
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT through a symlink — symlink is followed, parent of the target is opened. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", NULL, CHASE_PARENT, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_NOT_NULL(result);
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW through a symlink — symlink is NOT followed, parent of the
         * symlink is opened. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", NULL, CHASE_PARENT|CHASE_NOFOLLOW, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "os-release", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "/etc/os-release");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME through a symlink — parent of the symlink
         * is opened, returns just the symlink name. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", NULL, CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "os-release", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "os-release");
        fd = safe_close(fd);
        result = mfree(result);

        /* When the resolved path equals the root directory itself, the filename should be "." — not
         * the basename of the root directory. This is the edge case that chase_extract_filename()
         * handles by stripping the root prefix before extracting, which plain path_extract_filename()
         * would get wrong. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = ASSERT_OK(mkdtemp_open(NULL, 0, &tmpdir));
        /* Create a symlink to "/" — when chased under tmpdir as root, it resolves to tmpdir itself. */
        ASSERT_OK_ERRNO(symlinkat("/", tfd, "to_root"));

        _cleanup_free_ char *link_path = ASSERT_NOT_NULL(path_join(tmpdir, "to_root"));
        fd = ASSERT_OK(chase_and_open(link_path, tmpdir, 0, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_PATH_EQ(result, tmpdir);
        fd = safe_close(fd);
        result = mfree(result);
}

TEST(chaseat) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF, fd2 = -EBADF;
        _cleanup_free_ char *result = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        const char *p;

        ASSERT_OK(tfd = mkdtemp_open(NULL, 0, &t));

        /* Test that AT_FDCWD resolves against / and not the current working
         * directory. */

        ASSERT_OK_ERRNO(symlinkat("/usr", tfd, "abc"));

        p = strjoina(t, "/abc");
        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, p, 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* If the file descriptor points to the root directory, the result will be absolute. */

        fd = open("/", O_CLOEXEC | O_DIRECTORY | O_PATH);
        ASSERT_OK(fd);

        ASSERT_OK(chaseat(XAT_FDROOT, fd, p, 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* (XAT_FDROOT, fd-of-/, relative): fd points to "/" which is the host root, so root_fd is
         * normalized to XAT_FDROOT internally. A relative path resolves from "/". Result is absolute. */
        ASSERT_OK(chaseat(XAT_FDROOT, fd, "usr", 0, &result, &fd2));
        ASSERT_STREQ(result, "/usr");
        ASSERT_TRUE(inode_same_at(fd2, NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        result = mfree(result);
        fd2 = safe_close(fd2);

        /* Same without ret_path to exercise the shortcut. */
        ASSERT_OK(chaseat(XAT_FDROOT, fd, "usr", 0, NULL, &fd2));
        ASSERT_TRUE(inode_same_at(fd2, NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd2 = safe_close(fd2);

        ASSERT_OK(chaseat(fd, fd, p, 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        fd = safe_close(fd);

        /* Same but with XAT_FDROOT */
        _cleanup_close_ int found_fd1 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, 0, &result, &found_fd1));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        _cleanup_close_ int found_fd2 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, 0, &result, &found_fd2));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);
        assert(fd_inode_same(found_fd1, found_fd2) > 0);

        /* Do the same XAT_FDROOT tests again, this time without querying the path, so that the open_tree()
         * shortcut can work */
        _cleanup_close_ int found_fd3 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, 0, NULL, &found_fd3));
        assert(fd_inode_same(found_fd1, found_fd3) > 0);
        assert(fd_inode_same(found_fd2, found_fd3) > 0);

        _cleanup_close_ int found_fd4 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, 0, NULL, &found_fd4));
        assert(fd_inode_same(found_fd1, found_fd4) > 0);
        assert(fd_inode_same(found_fd2, found_fd4) > 0);
        assert(fd_inode_same(found_fd3, found_fd4) > 0);

        found_fd1 = safe_close(found_fd1);
        found_fd2 = safe_close(found_fd2);
        found_fd3 = safe_close(found_fd3);
        found_fd4 = safe_close(found_fd4);

        /* (XAT_FDROOT, XAT_FDROOT, relative): relative path from host root. XAT_FDROOT as dir_fd
         * redirects to root_fd which is also XAT_FDROOT (/), so "usr" resolves to /usr. Result is
         * absolute because root_fd == XAT_FDROOT. */
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, "usr", 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* Same without ret_path so the shortcut can fire. */
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, "usr", 0, NULL, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd = safe_close(fd);

        /* (XAT_FDROOT, AT_FDCWD, relative): relative path from current working directory. */
        _cleanup_free_ char *cwd_saved = NULL;
        ASSERT_OK(safe_getcwd(&cwd_saved));

        ASSERT_OK_ERRNO(chdir(t));

        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "abc", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "/usr");
        fd = safe_close(fd);
        result = mfree(result);

        /* Same without ret_path to exercise the shortcut. */
        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "abc", 0, NULL, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd = safe_close(fd);

        /* A plain file (no symlink indirection) should also work. */
        fd = ASSERT_OK_ERRNO(openat(tfd, "cwd_test", O_CREAT|O_CLOEXEC, 0600));
        fd = safe_close(fd);

        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "cwd_test", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, tfd, "cwd_test", AT_EMPTY_PATH));
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK_ERRNO(chdir(cwd_saved));

        /* If the file descriptor does not point to the root directory, the result will be relative
         * unless the result is outside of the specified file descriptor. */

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "abc", 0, &result, NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_ERROR(chaseat(tfd, tfd, "abc", 0, NULL, NULL), ENOENT);
        ASSERT_ERROR(chaseat(tfd, tfd, "/abc", 0, NULL, NULL), ENOENT);

        ASSERT_OK(chaseat(tfd, tfd, "abc", CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "/abc", CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        /* Test that absolute path or not are the same when resolving relative to a directory file
         * descriptor and that we always get a relative path back. */

        fd = ASSERT_OK_ERRNO(openat(tfd, "def", O_CREAT|O_CLOEXEC, 0700));
        fd = safe_close(fd);
        ASSERT_OK_ERRNO(symlinkat("/def", tfd, "qed"));
        ASSERT_OK(chaseat(tfd, tfd, "qed", 0, &result, NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);
        ASSERT_OK(chaseat(tfd, tfd, "/qed", 0, &result, NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);

        /* Valid directory file descriptor should resolve symlinks against
         * host's root. */
        ASSERT_ERROR(chaseat(XAT_FDROOT, tfd, "/qed", 0, NULL, NULL), ENOENT);

        /* Test CHASE_PARENT */

        fd = ASSERT_OK(open_mkdir_at(tfd, "chase", O_CLOEXEC, 0755));
        ASSERT_OK_ERRNO(symlinkat("/def", fd, "parent"));
        fd = safe_close(fd);

        /* Make sure that when we chase a symlink parent directory, that we chase the parent directory of the
         * symlink target and not the symlink itself. But if we add CHASE_NOFOLLOW, we get the parent
         * directory of the symlink itself. */

        ASSERT_OK(chaseat(tfd, tfd, "chase/parent", CHASE_PARENT, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "chase/parent");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "chase", CHASE_PARENT, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(fd, "chase", F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "/", CHASE_PARENT, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, ".", CHASE_PARENT, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test CHASE_MKDIR_0755 */

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "m/k/d/i/r", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL));
        ASSERT_OK_ERRNO(faccessat(tfd, "m/k/d/i", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "m/k/d/i/r", F_OK, 0)), ENOENT);
        ASSERT_STREQ(result, "m/k/d/i/r");
        result = mfree(result);

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "m/../q", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL));
        ASSERT_OK_ERRNO(faccessat(tfd, "m", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "q", F_OK, 0)), ENOENT);
        ASSERT_STREQ(result, "q");
        result = mfree(result);

        ASSERT_ERROR(chaseat(XAT_FDROOT, tfd, "i/../p", CHASE_MKDIR_0755|CHASE_NONEXISTENT, NULL, NULL), ENOENT);

        /* Test CHASE_MKDIR_0755|CHASE_PARENT — creates intermediate dirs but not the final component */

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "mkp/a/r/e/n/t/file", CHASE_MKDIR_0755|CHASE_PARENT, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(tfd, "mkp/a/r/e/n/t", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "mkp/a/r/e/n/t/file", F_OK, 0)), ENOENT);
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);
        ASSERT_STREQ(result, "mkp/a/r/e/n/t/file");
        result = mfree(result);

        /* Test CHASE_EXTRACT_FILENAME */

        ASSERT_OK(chaseat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "chase", CHASE_PARENT|CHASE_EXTRACT_FILENAME, &result, &fd));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "/", CHASE_PARENT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, ".", CHASE_PARENT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test chase_and_openat() */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", CHASE_MKDIR_0755, O_CREAT|O_EXCL|O_CLOEXEC, NULL));
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_MKDIR_0755, O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, NULL));
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        /* Test chase_and_openat() with CHASE_MKDIR_0755|CHASE_PARENT — opens parent dir */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "mkopen/p/a/r/file.txt", CHASE_MKDIR_0755|CHASE_PARENT, O_RDONLY|O_CLOEXEC, NULL));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK(faccessat(tfd, "mkopen/p/a/r", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "mkopen/p/a/r/file.txt", F_OK, 0)), ENOENT);
        fd = safe_close(fd);

        /* Test chase_and_openat() with CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY + O_CREAT — creates and opens target dir */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "mkopen/d/i/r/target", CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, O_CREAT|O_RDONLY|O_CLOEXEC, NULL));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK(faccessat(tfd, "mkopen/d/i/r/target", F_OK, 0));
        fd = safe_close(fd);

        /* Test chase_and_openat() with various CHASE_PARENT / CHASE_EXTRACT_FILENAME combinations */

        /* No CHASE_PARENT, no CHASE_EXTRACT_FILENAME, with ret_path — opens the target, returns full path. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", 0, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "o/p/e/n/d/i/r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT with ret_path — opens parent dir, returns full path including final component. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_PARENT, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "r", F_OK, 0));
        ASSERT_STREQ(result, "o/p/e/n/d/i/r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME with a real multi-component path — opens parent dir,
         * returns just the filename. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "r", F_OK, 0));
        ASSERT_STREQ(result, "r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME only (without CHASE_PARENT) — opens the target itself, returns just
         * the filename. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT through a symlink — the symlink is followed, parent of the target is opened.
         * "chase/parent" where parent→/def: resolves to /def, parent is the root dir. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME through a symlink — parent of the target is opened,
         * returns just the target filename. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW through a symlink — the symlink is NOT followed, parent of the
         * symlink is opened. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "chase/parent");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME through a symlink — parent of the symlink
         * is opened, returns just the symlink name. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY|O_CLOEXEC, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        /* Test chase_and_openatdir() */

        ASSERT_OK(chase_and_opendirat(XAT_FDROOT, tfd, "o/p/e/n/d/i", 0, &result, &dir));
        FOREACH_DIRENT(de, dir, assert_not_reached())
                ASSERT_STREQ(de->d_name, "r");
        ASSERT_STREQ(result, "o/p/e/n/d/i");
        result = mfree(result);

        /* Test chase_and_statat() */

        ASSERT_OK(chase_and_statat(XAT_FDROOT, tfd, "o/p", 0, &result, &st));
        ASSERT_OK(stat_verify_directory(&st));
        ASSERT_STREQ(result, "o/p");
        result = mfree(result);

        /* Test chase_and_accessat() */

        ASSERT_OK(chase_and_accessat(XAT_FDROOT, tfd, "o/p/e", 0, F_OK, &result));
        ASSERT_STREQ(result, "o/p/e");
        result = mfree(result);

        /* Test chase_and_fopenat_unlocked() */

        ASSERT_OK(chase_and_fopenat_unlocked(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", 0, "re", &result, &f));
        ASSERT_EQ(fread(&(char[1]) {}, 1, 1, f), 0u);
        ASSERT_TRUE(feof(f));
        f = safe_fclose(f);
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_unlinkat() */

        ASSERT_OK(chase_and_unlinkat(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", 0, 0, &result));
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_open_parent_at() */

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "chase/parent", CHASE_NOFOLLOW, &result));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "chase", 0, &result));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "/", 0, &result));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, ".", 0, &result));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);
}

TEST(chaseat_separate_root_and_dir) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, sub_fd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *result = NULL;

        /* Exercise chaseat() with root_fd != dir_fd. The root marks the chroot boundary (symlinks may
         * not escape it, absolute symlinks resolve to it), while dir_fd is the starting directory for
         * relative paths. */

        root_fd = ASSERT_OK(mkdtemp_open(NULL, 0, &t));

        /* Create a file at the root and a subdirectory containing another file. */
        ASSERT_OK_ERRNO(mkdirat(root_fd, "sub", 0755));
        sub_fd = ASSERT_OK_ERRNO(openat(root_fd, "sub", O_CLOEXEC|O_DIRECTORY|O_PATH));

        fd = ASSERT_OK_ERRNO(openat(root_fd, "outside", O_CREAT|O_CLOEXEC, 0600));
        fd = safe_close(fd);

        fd = ASSERT_OK_ERRNO(openat(sub_fd, "inside", O_CREAT|O_CLOEXEC, 0600));
        fd = safe_close(fd);

        /* Relative lookup from sub_fd under root_fd finds sub's own files. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "inside", 0, &result, NULL));
        ASSERT_STREQ(result, "inside");
        result = mfree(result);

        /* Absolute path with dir_fd=sub_fd and root_fd set: path is relative to root_fd so "/inside" finds
         * nothing. */
        ASSERT_ERROR(chaseat(root_fd, sub_fd, "/inside", 0, &result, NULL), ENOENT);
        ASSERT_OK_ZERO(chaseat(root_fd, sub_fd, "/inside", CHASE_NONEXISTENT, &result, NULL));
        result = mfree(result);

        /* "../outside" from sub_fd goes up one level (within root), finds root's file. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "../outside", 0, &result, NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* "../../../outside" cannot escape above root_fd — clamped. Still resolves to root's file. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "../../../outside", 0, &result, NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* Absolute symlink inside sub pointing at "/outside" — with root_fd set, /outside resolves to
         * root_fd/outside, not the host's /outside. */
        ASSERT_OK_ERRNO(symlinkat("/outside", sub_fd, "escape_abs"));
        ASSERT_OK(chaseat(root_fd, sub_fd, "escape_abs", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "/outside");
        result = mfree(result);
        fd = safe_close(fd);

        /* Relative symlink trying to escape via many ".." — also clamped to root. */
        ASSERT_OK_ERRNO(symlinkat("../../../../../outside", sub_fd, "escape_rel"));
        ASSERT_OK(chaseat(root_fd, sub_fd, "escape_rel", 0, &result, NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* Symlink pointing to an absolute host path that does NOT exist under our root must fail, not
         * leak to the host. /etc almost always exists on the host; under our tmp root it doesn't. */
        ASSERT_OK_ERRNO(symlinkat("/etc", sub_fd, "escape_host"));
        ASSERT_ERROR(chaseat(root_fd, sub_fd, "escape_host/hosts", 0, NULL, NULL), ENOENT);

        /* Chasing just ".." from root_fd itself stays at root. */
        ASSERT_OK(chaseat(root_fd, root_fd, "..", 0, &result, NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, relative): XAT_FDROOT as dir_fd redirects to root_fd, so relative
         * paths start at root_fd. Result is relative because root_fd is a non-host-root fd and
         * dir_fd (after redirection) equals root_fd. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "sub/inside", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, sub_fd, "inside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "sub/inside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, absolute): same as relative — absolute paths also resolve from
         * root_fd. Leading slash is stripped. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "/sub/inside", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, sub_fd, "inside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "sub/inside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, absolute) resolving to root: "/outside" lives directly under
         * root_fd. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "/outside", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "outside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT) with an absolute symlink: the symlink target "/outside" resolves
         * relative to root_fd, not the host root. Since dir_fd == root_fd (XAT_FDROOT was redirected),
         * the result stays relative. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "sub/escape_abs", 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "outside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT) with non-existent path. */
        ASSERT_OK_ZERO(chaseat(root_fd, XAT_FDROOT, "/nonexistent", CHASE_NONEXISTENT, &result, NULL));
        ASSERT_STREQ(result, "nonexistent");
        result = mfree(result);
        ASSERT_ERROR(chaseat(root_fd, XAT_FDROOT, "/nonexistent", 0, NULL, NULL), ENOENT);
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
        expected = ASSERT_NOT_NULL(path_join(cwd, "a/b/c/hoge"));
        ASSERT_STREQ(ret, expected);

        ret = mfree(ret);
        expected = mfree(expected);

        ASSERT_OK(chaseat_prefix_root("./hoge/aaa/../././b", "/a/b//./c///", &ret));
        ASSERT_STREQ(ret, "/a/b/c/hoge/aaa/../././b");

        ret = mfree(ret);

        ASSERT_OK(chaseat_prefix_root("./hoge/aaa/../././b", "a/b//./c///", &ret));
        expected = ASSERT_NOT_NULL(path_join(cwd, "a/b/c/hoge/aaa/../././b"));
        ASSERT_STREQ(ret, expected);
}

TEST(trailing_dot_dot) {
        _cleanup_free_ char *path = NULL, *fdpath = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(chase("/usr/..", NULL, CHASE_PARENT, &path, &fd));
        ASSERT_PATH_EQ(path, "/");
        ASSERT_OK(fd_get_path(fd, &fdpath));
        ASSERT_PATH_EQ(fdpath, "/");

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

        ASSERT_PATH_EQ(path, expected1);
        ASSERT_OK(fd_get_path(fd, &fdpath));
        ASSERT_PATH_EQ(fdpath, expected2);
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
