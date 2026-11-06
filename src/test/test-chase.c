/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "argv-util.h"
#include "capability-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "id128-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"

static const char *arg_test_dir = NULL;

static void test_chase_split_prefix_filename_one(const char *path, const char *root, const char *expected) {
        /* A path in the chase fixture may resolve through a symlink or to its root. Extracting the
         * filename from the resolved path must match CHASE_EXTRACT_FILENAME_HARDER. */
        _cleanup_free_ char *ret1 = NULL, *ret2 = NULL, *fname = NULL;

        log_debug("/* %s(path=%s, root=%s) */", __func__, path, strnull(root));

        ASSERT_OK_POSITIVE(chase(path, root, CHASE_EXTRACT_FILENAME_HARDER, &ret1, /* ret_fd= */ NULL));
        ASSERT_STREQ(ret1, expected);

        ASSERT_OK_POSITIVE(chase(path, root, /* flags= */ 0, &ret2, /* ret_fd= */ NULL));
        ASSERT_OK(chase_split_prefix_filename(ret2, root, /* ret_dir= */ NULL, &fname));
        ASSERT_STREQ(fname, expected);
}

TEST(chase_split_prefix_filename) {
        /* Relative and absolute chase results must split into the directory path and filename used
         * with CHASE_PARENT's fd. A result ending in ".." must retain that directory path and use "."
         * as the filename. A temporary root prefix must remain in the returned directory path. */
        static const struct {
                const char *path;
                const char *dir;
                const char *filename;
                int result;
        } cases[] = {
                { "sub/file",   "sub",   "file", 0           },
                { "file",       ".",     "file", 0           },
                { "./file",     ".",     "file", 0           },
                { "/sub/file",  "/sub",  "file", 0           },
                { "../file",    "..",    "file", 0           },
                { "..file",     ".",     "..file", 0         },
                { ".",          ".",     ".",    0           },
                { "./",         ".",     ".",    0           },
                { "..",         "..",    ".",    0           },
                { "../..",      "../..", ".",    0           },
                { "/",          "/",     ".",    0           },
                { "sub/file/",  "sub",   "file", O_DIRECTORY },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_free_ char *dir = NULL, *filename = NULL;

                ASSERT_EQ(chase_split_prefix_filename(c->path, /* root= */ NULL, &dir, &filename), c->result);
                ASSERT_PATH_EQ(dir, c->dir);
                ASSERT_STREQ(filename, c->filename);

                /* Callers may request the directory path or filename independently. */
                dir = mfree(dir);
                filename = mfree(filename);
                ASSERT_EQ(chase_split_prefix_filename(c->path, /* root= */ NULL, &dir, /* ret_filename= */ NULL), c->result);
                ASSERT_PATH_EQ(dir, c->dir);
                ASSERT_EQ(chase_split_prefix_filename(c->path, /* root= */ NULL, /* ret_dir= */ NULL, &filename), c->result);
                ASSERT_STREQ(filename, c->filename);
        }

        /* A resolved path includes its root prefix, including when the result is the root itself. */
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_free_ char *dir = NULL, *filename = NULL;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &root));
        ASSERT_OK(chase_split_prefix_filename(strjoina(root, "/file"), root, &dir, &filename));
        ASSERT_PATH_EQ(dir, root);
        ASSERT_STREQ(filename, "file");

        dir = mfree(dir);
        filename = mfree(filename);
        ASSERT_OK(chase_split_prefix_filename(root, root, &dir, &filename));
        ASSERT_PATH_EQ(dir, root);
        ASSERT_STREQ(filename, ".");

        /* Invalid input and paths outside the supplied root must leave the outputs unchanged. */
        ASSERT_ERROR(chase_split_prefix_filename("", /* root= */ NULL, &dir, &filename), EINVAL);
        ASSERT_ERROR(chase_split_prefix_filename(strjoina(root, "-other/file"), root, &dir, &filename), EINVAL);
        ASSERT_ERROR(chase_split_prefix_filename("file", root, &dir, &filename), EINVAL);
        ASSERT_PATH_EQ(dir, root);
        ASSERT_STREQ(filename, ".");
}

TEST(chase_and_unlink_root) {
        /* A temporary root contains an empty directory with the root's basename. Removing the root
         * must fail without removing that child. Relative ancestor lookup must reject removal too. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, sub_fd = -EBADF;
        struct stat st;

        root_fd = ASSERT_OK(mkdtemp_open("/var/tmp/test-chase.XXXXXX", /* flags= */ 0, &t));
        const char *name = last_path_component(t);
        ASSERT_OK_ERRNO(mkdirat(root_fd, name, 0700));
        ASSERT_OK_ERRNO(mkdirat(root_fd, "sub", 0700));
        sub_fd = ASSERT_OK(xopenat(root_fd, "sub", O_PATH|O_DIRECTORY));

        /* The path wrapper must recognize the configured root before extracting its filename. */
        ASSERT_ERROR(chase_and_unlink(t, t, /* chase_flags= */ 0, AT_REMOVEDIR, /* ret_path= */ NULL), EINVAL);
        ASSERT_ERROR(chase_and_unlink("/", t, CHASE_PREFIX_ROOT, AT_REMOVEDIR, /* ret_path= */ NULL), EINVAL);
        ASSERT_OK_ERRNO(fstatat(root_fd, name, &st, AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(S_ISDIR(st.st_mode));

        /* Root and ancestor results have no filename to remove relative to the returned fd. */
        FOREACH_STRING(path, "/", ".", "")
                ASSERT_ERROR(chase_and_unlinkat(root_fd, root_fd, path, CHASE_EMPTY_PATH, AT_REMOVEDIR, /* ret_path= */ NULL), EINVAL);
        ASSERT_ERROR(chase_and_unlinkat(root_fd, sub_fd, "..", /* chase_flags= */ 0, AT_REMOVEDIR, /* ret_path= */ NULL), EINVAL);
        ASSERT_OK_ERRNO(fstatat(root_fd, name, &st, AT_SYMLINK_NOFOLLOW));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
}

TEST(chase) {
        /* A temporary directory contains symlinks to relative paths, absolute paths, and the root.
         * Path and fd results must match the chase flags and stay within a configured root. */
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

        ASSERT_OK_POSITIVE(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, "/.//../../../", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/usr");
        result = mfree(result);

        pslash = strjoina(p, "/");
        ASSERT_OK_POSITIVE(chase(pslash, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/usr/");
        result = mfree(result);

        ASSERT_ERROR(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);
        ASSERT_ERROR(chase(pslash, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);

        q = strjoina(temp, "/usr");

        ASSERT_OK_ZERO(chase(p, temp, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        qslash = strjoina(q, "/");

        ASSERT_OK_ZERO(chase(pslash, temp, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, qslash);
        result = mfree(result);

        ASSERT_OK_ERRNO(mkdir(q, 0700));

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(pslash, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, qslash);
        result = mfree(result);

        p = strjoina(temp, "/slash");
        ASSERT_OK_ERRNO(symlink("/", p));

        ASSERT_OK_POSITIVE(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, temp);
        result = mfree(result);

        /* Filename extraction must match CHASE_EXTRACT_FILENAME for paths through symlinks. */

        p = strjoina(temp, "/start");
        pslash = strjoina(p, "/");
        test_chase_split_prefix_filename_one(p, /* root= */ NULL, "usr");
        test_chase_split_prefix_filename_one(pslash, /* root= */ NULL, "usr");
        test_chase_split_prefix_filename_one(p, temp, "usr");
        test_chase_split_prefix_filename_one(pslash, temp, "usr");

        p = strjoina(temp, "/slash");
        test_chase_split_prefix_filename_one(p, /* root= */ NULL, ".");
        test_chase_split_prefix_filename_one(p, temp, ".");

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        ASSERT_OK_ERRNO(symlink("../../..", p));

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, temp);
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        ASSERT_OK_ERRNO(symlink("../../../usr", p));

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        ASSERT_OK_ERRNO(symlink("../../../../usr", p));

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, q);
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        ASSERT_OK_ERRNO(symlink("///usr///", p));

        ASSERT_OK_POSITIVE(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/usr");
        ASSERT_STREQ(result, "/usr"); /* we guarantee that we drop redundant slashes */
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase(p, temp, /* flags= */ 0, &result, /* ret_fd= */ NULL));
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
                ASSERT_ERROR(chase(p, temp, CHASE_SAFE, &result, /* ret_fd= */ NULL), ENOLINK);
                result = mfree(result);

                /* Allow this when the user-owned directories are all in the "root". */
                ASSERT_OK_POSITIVE(chase(p, q, CHASE_SAFE, &result, /* ret_fd= */ NULL));
                result = mfree(result);
        }

        /* Paths using . */

        ASSERT_OK_POSITIVE(chase("/etc/./.././", /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/etc/./.././", "/etc", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/../.././//../../etc", /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_ZERO(chase("/../.././//../../test-chase.fsldajfl", /* root= */ NULL, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/etc");
        result = mfree(result);

        ASSERT_OK_ZERO(chase("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/test-chase.fsldajfl");
        result = mfree(result);

        ASSERT_OK(chase("/.path/with/dot", temp, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        q = strjoina(temp, "/.path/with/dot");
        ASSERT_STREQ(result, q);
        result = mfree(result);

        ASSERT_TRUE(IN_SET(chase("/etc/machine-id/foo", /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), -ENOTDIR, -ENOENT));
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        ASSERT_OK_ERRNO(symlink("recursive-symlink", p));
        ASSERT_ERROR(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), ELOOP);

        /* Path which doesn't exist */

        p = strjoina(temp, "/idontexist");
        ASSERT_ERROR(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);
        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        p = strjoina(temp, "/idontexist/meneither");
        ASSERT_ERROR(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        /* Relative paths */

        ASSERT_OK(safe_getcwd(&pwd));

        ASSERT_OK_ERRNO(chdir(temp));

        p = "this/is/a/relative/path";
        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));

        p = strjoina(temp, "/", p);
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        p = "this/is/a/relative/path";
        ASSERT_OK_ZERO(chase(p, temp, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));

        p = strjoina(temp, "/", p);
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);

        ASSERT_OK_ERRNO(chdir(pwd));

        /* Path which doesn't exist, but contains weird stuff */

        p = strjoina(temp, "/idontexist/..");
        ASSERT_ERROR(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);

        ASSERT_ERROR(chase(p, /* root= */ NULL, CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL), ENOENT);

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/top");
        ASSERT_OK_ERRNO(symlink(q, p));
        p = strjoina(temp, "/target/idontexist");
        ASSERT_ERROR(chase(p, /* root= */ NULL, /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);

        if (geteuid() == 0 && !userns_has_single_user()) {
                p = strjoina(temp, "/priv1");
                ASSERT_OK_ERRNO(mkdir(p, 0755));

                q = strjoina(p, "/priv2");
                ASSERT_OK_ERRNO(mkdir(q, 0755));

                ASSERT_OK(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL));

                ASSERT_OK_ERRNO(chown(q, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL));

                ASSERT_OK(chown(p, UID_NOBODY, GID_NOBODY));
                ASSERT_OK(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL));

                ASSERT_OK_ERRNO(chown(q, 0, 0));
                ASSERT_ERROR(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);

                ASSERT_OK_ERRNO(rmdir(q));
                ASSERT_OK_ERRNO(symlink("/etc/passwd", q));
                ASSERT_ERROR(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);

                ASSERT_OK_ERRNO(chown(p, 0, 0));
                ASSERT_OK(chase(q, /* root= */ NULL, CHASE_SAFE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        }

        p = strjoina(temp, "/machine-id-test");
        ASSERT_OK_ERRNO(symlink("/usr/../etc/./machine-id", p));

        if (chase(p, /* root= */ NULL, /* flags= */ 0, /* ret_path= */ NULL, &pfd) != -ENOENT && sd_id128_get_machine(/* ret= */ NULL) >= 0) {
                _cleanup_close_ int fd = -EBADF;
                sd_id128_t a, b;

                ASSERT_OK(pfd);

                fd = fd_reopen(pfd, O_RDONLY);
                ASSERT_OK(fd);
                safe_close(pfd);

                ASSERT_OK(id128_read_fd(fd, ID128_FORMAT_PLAIN, &a));
                ASSERT_OK(sd_id128_get_machine(&b));
                ASSERT_TRUE(sd_id128_equal(a, b));
        }

        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_OK_ZERO(chase_and_unlink(p, /* root= */ NULL, /* chase_flags= */ 0, /* unlink_flags= */ 0, &result));
        ASSERT_PATH_EQ(result, p);
        result = mfree(result);
        ASSERT_ERROR_ERRNO(lstat(p, &st), ENOENT);

        /* Test CHASE_NOFOLLOW */

        p = strjoina(temp, "/target");
        q = strjoina(temp, "/symlink");
        ASSERT_OK_ERRNO(symlink(p, q));
        ASSERT_OK(chase(q, /* root= */ NULL, CHASE_NOFOLLOW, &result, &pfd));
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
        ASSERT_OK(chase(q, /* root= */ NULL, CHASE_NOFOLLOW, &result, &pfd));
        ASSERT_PATH_EQ(result, q);
        ASSERT_OK_ERRNO(fstat(pfd, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* Test CHASE_STEP */

        p = strjoina(temp, "/start");
        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        p = strjoina(temp, "/top/dot/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        p = strjoina(temp, "/top/dotdota");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        p = strjoina(temp, "/top/../a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        p = strjoina(temp, "/a");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        p = strjoina(temp, "/b");
        ASSERT_STREQ(p, result);
        result = mfree(result);

        ASSERT_OK_ZERO(chase(p, /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_OK_POSITIVE(chase("/usr", /* root= */ NULL, CHASE_STEP, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* Make sure that symlinks in the "root" path are not resolved, but those below are */
        p = strjoina("/etc/..", temp, "/self");
        ASSERT_OK_ERRNO(symlink(".", p));
        q = strjoina(p, "/top/dot/dotdota");
        ASSERT_OK_POSITIVE(chase(q, p, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_PATH_EQ(path_startswith(result, p), "usr");
        result = mfree(result);

        /* Test CHASE_PROHIBIT_SYMLINKS */

        ASSERT_ERROR(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
        ASSERT_ERROR(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
        ASSERT_ERROR(chase("top/dotdot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
        ASSERT_ERROR(chase("top/dot/dot", temp, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS|CHASE_WARN, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);

 cleanup:
        ASSERT_OK(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL));
}

TEST(chase_and_open) {
        /* Host paths and a symlink under a temporary root must open the target or its parent according
         * to CHASE_PARENT. CHASE_EXTRACT_FILENAME must change the returned path to the final filename. */
        _cleanup_free_ char *result = NULL;
        _cleanup_close_ int fd = -EBADF;

        /* No CHASE_PARENT, no CHASE_EXTRACT_FILENAME, with ret_path — opens the target, returns full path. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", /* root= */ NULL, /* chase_flags= */ 0, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "/usr/lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT with ret_path — opens parent dir, returns full path including final component. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", /* root= */ NULL, CHASE_PARENT, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "lib", F_OK, 0));
        ASSERT_STREQ(result, "/usr/lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* O_CREAT on the parent opened with CHASE_PARENT */
        ASSERT_ERROR(chase_and_open("/usr/lib", /* root= */ NULL, CHASE_PARENT, O_RDONLY|O_CREAT, /* ret_path= */ NULL), EISDIR);

        /* An empty path on the shortcut reopens the cwd and refuses O_CREAT, like the full chase */
        fd = ASSERT_OK(chase_and_open("", /* root= */ NULL, CHASE_EMPTY_PATH, O_RDONLY|O_DIRECTORY, /* ret_path= */ NULL));
        ASSERT_OK_POSITIVE(inode_same_at(AT_FDCWD, ".", fd, /* fileb= */ NULL, AT_EMPTY_PATH));
        fd = safe_close(fd);
        ASSERT_ERROR(chase_and_open("", /* root= */ NULL, CHASE_EMPTY_PATH, O_RDONLY|O_CREAT, /* ret_path= */ NULL), EISDIR);
        ASSERT_ERROR(chase_and_openat(XAT_FDROOT, AT_FDCWD, "", CHASE_EMPTY_PATH, O_RDONLY|O_CREAT, /* ret_path= */ NULL), EISDIR);
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, AT_FDCWD, "", CHASE_EMPTY_PATH, O_RDONLY|O_DIRECTORY, /* ret_path= */ NULL));
        ASSERT_OK_POSITIVE(inode_same_at(AT_FDCWD, ".", fd, /* fileb= */ NULL, AT_EMPTY_PATH));
        fd = safe_close(fd);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME — opens parent dir, returns just the filename. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", /* root= */ NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "lib", F_OK, 0));
        ASSERT_STREQ(result, "lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME only — opens the target itself, returns just the filename. */
        fd = ASSERT_OK(chase_and_open("/usr/lib", /* root= */ NULL, CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "lib");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME on a regular file (regression test for a bug where chase_and_open()
         * reopened the parent directory instead of the target file). */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", /* root= */ NULL, CHASE_EXTRACT_FILENAME, O_PATH, &result));
        ASSERT_STREQ(result, "os-release");
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT through a symlink — symlink is followed, parent of the target is opened. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", /* root= */ NULL, CHASE_PARENT, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_NOT_NULL(result);
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW through a symlink — symlink is NOT followed, parent of the
         * symlink is opened. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", /* root= */ NULL, CHASE_PARENT|CHASE_NOFOLLOW, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "os-release", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "/etc/os-release");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME through a symlink — parent of the symlink
         * is opened, returns just the symlink name. */
        fd = ASSERT_OK(chase_and_open("/etc/os-release", /* root= */ NULL, CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "os-release", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "os-release");
        fd = safe_close(fd);
        result = mfree(result);

        /* When the resolved path equals the root directory itself, the filename should be "." — not
         * the basename of the root directory. This is the edge case that chase_split_prefix_filename()
         * handles by stripping the root prefix before extracting, which plain path_extract_filename()
         * would get wrong. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_close_ int tfd = -EBADF;

        tfd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &tmpdir));
        /* Create a symlink to "/" — when chased under tmpdir as root, it resolves to tmpdir itself. */
        ASSERT_OK_ERRNO(symlinkat("/", tfd, "to_root"));

        _cleanup_free_ char *link_path = ASSERT_NOT_NULL(path_join(tmpdir, "to_root"));
        fd = ASSERT_OK(chase_and_open(link_path, tmpdir, /* chase_flags= */ 0, O_PATH|O_DIRECTORY, &result));
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

        ASSERT_OK(tfd = mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        /* Test that AT_FDCWD resolves against / and not the current working
         * directory. */

        ASSERT_OK_ERRNO(symlinkat("/usr", tfd, "abc"));

        p = strjoina(t, "/abc");
        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, p, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* If the file descriptor points to the root directory, the result will be absolute. */

        fd = xopenat(AT_FDCWD, "/", O_DIRECTORY | O_PATH);
        ASSERT_OK(fd);

        ASSERT_OK(chaseat(XAT_FDROOT, fd, p, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* (XAT_FDROOT, fd-of-/, relative): fd points to "/" which is the host root, so root_fd is
         * normalized to XAT_FDROOT internally. A relative path resolves from "/". Result is absolute. */
        ASSERT_OK(chaseat(XAT_FDROOT, fd, "usr", /* flags= */ 0, &result, &fd2));
        ASSERT_STREQ(result, "/usr");
        ASSERT_TRUE(inode_same_at(fd2, /* filea= */ NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        result = mfree(result);
        fd2 = safe_close(fd2);

        /* Same without ret_path to exercise the shortcut. */
        ASSERT_OK(chaseat(XAT_FDROOT, fd, "usr", /* flags= */ 0, /* ret_path= */ NULL, &fd2));
        ASSERT_TRUE(inode_same_at(fd2, /* filea= */ NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd2 = safe_close(fd2);

        ASSERT_OK(chaseat(fd, fd, p, /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        fd = safe_close(fd);

        /* Same but with XAT_FDROOT */
        _cleanup_close_ int found_fd1 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, /* flags= */ 0, &result, &found_fd1));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        _cleanup_close_ int found_fd2 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, /* flags= */ 0, &result, &found_fd2));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);
        assert(fd_inode_same(found_fd1, found_fd2) > 0);

        /* Do the same XAT_FDROOT tests again, this time without querying the path, so that the open_tree()
         * shortcut can work */
        _cleanup_close_ int found_fd3 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, /* flags= */ 0, /* ret_path= */ NULL, &found_fd3));
        assert(fd_inode_same(found_fd1, found_fd3) > 0);
        assert(fd_inode_same(found_fd2, found_fd3) > 0);

        _cleanup_close_ int found_fd4 = -EBADF;
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, p, /* flags= */ 0, /* ret_path= */ NULL, &found_fd4));
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
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, "usr", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        /* Same without ret_path so the shortcut can fire. */
        ASSERT_OK(chaseat(XAT_FDROOT, XAT_FDROOT, "usr", /* flags= */ 0, /* ret_path= */ NULL, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd = safe_close(fd);

        /* (XAT_FDROOT, AT_FDCWD, relative): relative path from current working directory. */
        _cleanup_free_ char *cwd_saved = NULL;
        ASSERT_OK(safe_getcwd(&cwd_saved));

        ASSERT_OK_ERRNO(chdir(t));

        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "abc", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "/usr");
        fd = safe_close(fd);
        result = mfree(result);

        /* Same without ret_path to exercise the shortcut. */
        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "abc", /* flags= */ 0, /* ret_path= */ NULL, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, AT_FDCWD, "/usr", AT_EMPTY_PATH));
        fd = safe_close(fd);

        /* A plain file (no symlink indirection) should also work. */
        fd = ASSERT_OK(xopenat_full(tfd, "cwd_test", O_CREAT, /* xopen_flags= */ 0, 0600));
        fd = safe_close(fd);

        ASSERT_OK(chaseat(XAT_FDROOT, AT_FDCWD, "cwd_test", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, tfd, "cwd_test", AT_EMPTY_PATH));
        fd = safe_close(fd);
        result = mfree(result);

        ASSERT_OK_ERRNO(chdir(cwd_saved));

        /* If the file descriptor does not point to the root directory, the result will be relative
         * unless the result is outside of the specified file descriptor. */

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "abc", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "/usr");
        result = mfree(result);

        ASSERT_ERROR(chaseat(tfd, tfd, "abc", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);
        ASSERT_ERROR(chaseat(tfd, tfd, "/abc", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);

        ASSERT_OK(chaseat(tfd, tfd, "abc", CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, "/abc", CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "usr");
        result = mfree(result);

        /* Test that absolute path or not are the same when resolving relative to a directory file
         * descriptor and that we always get a relative path back. */

        fd = ASSERT_OK(xopenat_full(tfd, "def", O_CREAT, /* xopen_flags= */ 0, 0700));
        fd = safe_close(fd);
        ASSERT_OK_ERRNO(symlinkat("/def", tfd, "qed"));
        ASSERT_OK(chaseat(tfd, tfd, "qed", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);
        ASSERT_OK(chaseat(tfd, tfd, "/qed", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "def");
        result = mfree(result);

        /* Valid directory file descriptor should resolve symlinks against
         * host's root. */
        ASSERT_ERROR(chaseat(XAT_FDROOT, tfd, "/qed", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);

        /* Test CHASE_PARENT */

        fd = ASSERT_OK(open_mkdir_at(tfd, "chase", /* flags= */ 0, 0755));
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

        ASSERT_OK(chaseat(tfd, tfd, "/", CHASE_PARENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, ".", CHASE_PARENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test CHASE_MKDIR_0755 */

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "m/k/d/i/r", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(faccessat(tfd, "m/k/d/i", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "m/k/d/i/r", F_OK, 0)), ENOENT);
        ASSERT_STREQ(result, "m/k/d/i/r");
        result = mfree(result);

        ASSERT_OK(chaseat(XAT_FDROOT, tfd, "m/../q", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(faccessat(tfd, "m", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "q", F_OK, 0)), ENOENT);
        ASSERT_STREQ(result, "q");
        result = mfree(result);

        ASSERT_ERROR(chaseat(XAT_FDROOT, tfd, "i/../p", CHASE_MKDIR_0755|CHASE_NONEXISTENT, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);

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

        ASSERT_OK(chaseat(tfd, tfd, "/", CHASE_PARENT|CHASE_EXTRACT_FILENAME_HARDER, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, ".", CHASE_PARENT|CHASE_EXTRACT_FILENAME_HARDER, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        ASSERT_OK(chaseat(tfd, tfd, /* path= */ NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME_HARDER|CHASE_EMPTY_PATH, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* Test chase_and_openat() */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", CHASE_MKDIR_0755, O_CREAT|O_EXCL, /* ret_path= */ NULL));
        ASSERT_OK(fd_verify_regular(fd));
        fd = safe_close(fd);

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_MKDIR_0755, O_DIRECTORY|O_CREAT|O_EXCL, /* ret_path= */ NULL));
        ASSERT_OK(fd_verify_directory(fd));
        fd = safe_close(fd);

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, /* path= */ NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME_HARDER|CHASE_EMPTY_PATH, O_PATH|O_DIRECTORY, &result));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        /* Test chase_and_openat() with CHASE_MKDIR_0755|CHASE_PARENT — opens parent dir */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "mkopen/p/a/r/file.txt", CHASE_MKDIR_0755|CHASE_PARENT, O_RDONLY, /* ret_path= */ NULL));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK(faccessat(tfd, "mkopen/p/a/r", F_OK, 0));
        ASSERT_ERROR(RET_NERRNO(faccessat(tfd, "mkopen/p/a/r/file.txt", F_OK, 0)), ENOENT);
        fd = safe_close(fd);

        /* Test chase_and_openat() with CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY + O_CREAT — creates and opens target dir */

        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "mkopen/d/i/r/target", CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY, O_CREAT|O_RDONLY, /* ret_path= */ NULL));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK(faccessat(tfd, "mkopen/d/i/r/target", F_OK, 0));
        fd = safe_close(fd);

        /* O_CREAT on the directory itself: the parent opened with CHASE_PARENT, or a symlink to the root */
        ASSERT_ERROR(chase_and_openat(tfd, tfd, "mkopen/d/i/r/target", CHASE_PARENT, O_CREAT|O_RDONLY, /* ret_path= */ NULL), EISDIR);
        ASSERT_OK_ERRNO(symlinkat("/", tfd, "mkopen/toroot"));
        ASSERT_ERROR(chase_and_openat(tfd, tfd, "mkopen/toroot", /* chase_flags= */ 0, O_CREAT|O_RDONLY, /* ret_path= */ NULL), EISDIR);
        ASSERT_ERROR(chase_and_openat(tfd, tfd, "mkopen/toroot", CHASE_PARENT, O_CREAT|O_RDONLY, /* ret_path= */ NULL), EISDIR);

        /* Test chase_and_openat() with various CHASE_PARENT / CHASE_EXTRACT_FILENAME combinations */

        /* No CHASE_PARENT, no CHASE_EXTRACT_FILENAME, with ret_path — opens the target, returns full path. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", /* chase_flags= */ 0, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "o/p/e/n/d/i/r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT with ret_path — opens parent dir, returns full path including final component. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_PARENT, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "r", F_OK, 0));
        ASSERT_STREQ(result, "o/p/e/n/d/i/r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME with a real multi-component path — opens parent dir,
         * returns just the filename. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "r", F_OK, 0));
        ASSERT_STREQ(result, "r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_EXTRACT_FILENAME only (without CHASE_PARENT) — opens the target itself, returns just
         * the filename. */
        fd = ASSERT_OK(chase_and_openat(XAT_FDROOT, tfd, "o/p/e/n/d/i/r", CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_STREQ(result, "r");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT through a symlink — the symlink is followed, parent of the target is opened.
         * "chase/parent" where parent→/def: resolves to /def, parent is the root dir. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_EXTRACT_FILENAME through a symlink — parent of the target is opened,
         * returns just the target filename. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "def", F_OK, 0));
        ASSERT_STREQ(result, "def");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW through a symlink — the symlink is NOT followed, parent of the
         * symlink is opened. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "chase/parent");
        fd = safe_close(fd);
        result = mfree(result);

        /* CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME through a symlink — parent of the symlink
         * is opened, returns just the symlink name. */
        fd = ASSERT_OK(chase_and_openat(tfd, tfd, "chase/parent", CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, O_PATH|O_DIRECTORY, &result));
        ASSERT_OK(fd_verify_directory(fd));
        ASSERT_OK_ERRNO(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        /* Test chase_and_openatdir() */

        ASSERT_OK(chase_and_opendirat(XAT_FDROOT, tfd, "o/p/e/n/d/i", /* chase_flags= */ 0, &result, &dir));
        FOREACH_DIRENT(de, dir, assert_not_reached())
                ASSERT_STREQ(de->d_name, "r");
        ASSERT_STREQ(result, "o/p/e/n/d/i");
        result = mfree(result);

        /* Test chase_and_statat() */

        ASSERT_OK(chase_and_statat(XAT_FDROOT, tfd, "o/p", /* chase_flags= */ 0, &result, &st));
        ASSERT_OK(stat_verify_directory(&st));
        ASSERT_STREQ(result, "o/p");
        result = mfree(result);

        /* Test chase_and_accessat() */

        ASSERT_OK(chase_and_accessat(XAT_FDROOT, tfd, "o/p/e", /* chase_flags= */ 0, F_OK, &result));
        ASSERT_STREQ(result, "o/p/e");
        result = mfree(result);

        /* Test chase_and_fopenat_unlocked() */

        ASSERT_OK(chase_and_fopenat_unlocked(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", /* chase_flags= */ 0, "re", &result, &f));
        ASSERT_EQ(fread(&(char[1]) {}, 1, 1, f), 0u);
        ASSERT_TRUE(feof(f));
        f = safe_fclose(f);
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_unlinkat() */

        ASSERT_OK(chase_and_unlinkat(XAT_FDROOT, tfd, "o/p/e/n/f/i/l/e", /* chase_flags= */ 0, /* unlink_flags= */ 0, &result));
        ASSERT_STREQ(result, "o/p/e/n/f/i/l/e");
        result = mfree(result);

        /* Test chase_and_open_parent_at() */

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "chase/parent", CHASE_NOFOLLOW, &result));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW));
        ASSERT_STREQ(result, "parent");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "chase", /* chase_flags= */ 0, &result));
        ASSERT_OK_ERRNO(faccessat(fd, result, F_OK, 0));
        ASSERT_STREQ(result, "chase");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, "/", CHASE_EXTRACT_FILENAME_HARDER, &result));
        ASSERT_STREQ(result, ".");
        fd = safe_close(fd);
        result = mfree(result);

        fd = ASSERT_OK(chase_and_open_parent_at(XAT_FDROOT, tfd, ".", CHASE_EXTRACT_FILENAME_HARDER, &result));
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

        root_fd = ASSERT_OK(mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));

        /* Create a file at the root and a subdirectory containing another file. */
        ASSERT_OK_ERRNO(mkdirat(root_fd, "sub", 0755));
        sub_fd = ASSERT_OK(xopenat(root_fd, "sub", O_DIRECTORY|O_PATH));

        fd = ASSERT_OK(xopenat_full(root_fd, "outside", O_CREAT, /* xopen_flags= */ 0, 0600));
        fd = safe_close(fd);

        fd = ASSERT_OK(xopenat_full(sub_fd, "inside", O_CREAT, /* xopen_flags= */ 0, 0600));
        fd = safe_close(fd);

        /* Relative lookup from sub_fd under root_fd finds sub's own files. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "inside", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "inside");
        result = mfree(result);

        /* Absolute path with dir_fd=sub_fd and root_fd set: path is relative to root_fd so "/inside" finds
         * nothing. */
        ASSERT_ERROR(chaseat(root_fd, sub_fd, "/inside", /* flags= */ 0, &result, /* ret_fd= */ NULL), ENOENT);
        ASSERT_OK_ZERO(chaseat(root_fd, sub_fd, "/inside", CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        result = mfree(result);

        /* "../outside" from sub_fd goes up one level (within root), finds root's file. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "../outside", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* "../../../outside" cannot escape above root_fd — clamped. Still resolves to root's file. */
        ASSERT_OK(chaseat(root_fd, sub_fd, "../../../outside", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* Absolute symlink inside sub pointing at "/outside" — with root_fd set, /outside resolves to
         * root_fd/outside, not the host's /outside. */
        ASSERT_OK_ERRNO(symlinkat("/outside", sub_fd, "escape_abs"));
        ASSERT_OK(chaseat(root_fd, sub_fd, "escape_abs", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "/outside");
        result = mfree(result);
        fd = safe_close(fd);

        /* Relative symlink trying to escape via many ".." — also clamped to root. */
        ASSERT_OK_ERRNO(symlinkat("../../../../../outside", sub_fd, "escape_rel"));
        ASSERT_OK(chaseat(root_fd, sub_fd, "escape_rel", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "../outside");
        result = mfree(result);

        /* Symlink pointing to an absolute host path that does NOT exist under our root must fail, not
         * leak to the host. /etc almost always exists on the host; under our tmp root it doesn't. */
        ASSERT_OK_ERRNO(symlinkat("/etc", sub_fd, "escape_host"));
        ASSERT_ERROR(chaseat(root_fd, sub_fd, "escape_host/hosts", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);

        /* Chasing just ".." from root_fd itself stays at root. */
        ASSERT_OK(chaseat(root_fd, root_fd, "..", /* flags= */ 0, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, ".");
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, relative): XAT_FDROOT as dir_fd redirects to root_fd, so relative
         * paths start at root_fd. Result is relative because root_fd is a non-host-root fd and
         * dir_fd (after redirection) equals root_fd. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "sub/inside", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, sub_fd, "inside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "sub/inside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, absolute): same as relative — absolute paths also resolve from
         * root_fd. Leading slash is stripped. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "/sub/inside", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, sub_fd, "inside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "sub/inside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT, absolute) resolving to root: "/outside" lives directly under
         * root_fd. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "/outside", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "outside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT) with an absolute symlink: the symlink target "/outside" resolves
         * relative to root_fd, not the host root. Since dir_fd == root_fd (XAT_FDROOT was redirected),
         * the result stays relative. */
        ASSERT_OK(chaseat(root_fd, XAT_FDROOT, "sub/escape_abs", /* flags= */ 0, &result, &fd));
        ASSERT_TRUE(inode_same_at(fd, /* filea= */ NULL, root_fd, "outside", AT_EMPTY_PATH));
        ASSERT_STREQ(result, "outside");
        fd = safe_close(fd);
        result = mfree(result);

        /* (real-fd, XAT_FDROOT) with non-existent path. */
        ASSERT_OK_ZERO(chaseat(root_fd, XAT_FDROOT, "/nonexistent", CHASE_NONEXISTENT, &result, /* ret_fd= */ NULL));
        ASSERT_STREQ(result, "nonexistent");
        result = mfree(result);
        ASSERT_ERROR(chaseat(root_fd, XAT_FDROOT, "/nonexistent", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOENT);
}

TEST(chaseat_make_absolute) {
        /* Absolute results must stay unchanged. Relative results must use an absolute or cwd-relative
         * base while preserving unresolved interior ".." components. */
        _cleanup_free_ char *cwd = NULL, *ret = NULL, *expected = NULL;

        ASSERT_OK(safe_getcwd(&cwd));

        ASSERT_OK(chaseat_make_absolute("/hoge", /* base= */ NULL, &ret));
        ASSERT_STREQ(ret, "/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_make_absolute("/hoge", "a/b/c", &ret));
        ASSERT_STREQ(ret, "/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_make_absolute("hoge", "/a/b//./c///", &ret));
        ASSERT_STREQ(ret, "/a/b/c/hoge");

        ret = mfree(ret);

        ASSERT_OK(chaseat_make_absolute("hoge", "a/b//./c///", &ret));
        expected = ASSERT_NOT_NULL(path_join(cwd, "a/b/c/hoge"));
        ASSERT_STREQ(ret, expected);

        ret = mfree(ret);
        expected = mfree(expected);

        ASSERT_OK(chaseat_make_absolute("./hoge/aaa/../././b", "/a/b//./c///", &ret));
        ASSERT_STREQ(ret, "/a/b/c/hoge/aaa/../././b");

        ret = mfree(ret);

        ASSERT_OK(chaseat_make_absolute("./hoge/aaa/../././b", "a/b//./c///", &ret));
        expected = ASSERT_NOT_NULL(path_join(cwd, "a/b/c/hoge/aaa/../././b"));
        ASSERT_STREQ(ret, expected);
}

TEST(chaseat_make_absolute_relative) {
        /* Relative results must become absolute without changing unresolved interior components or resolving
         * symlinks in the base. A "/" base must produce a single leading slash. Leading ".." components must
         * remove matching base components and stop at "/". */
        const struct {
                const char *path;
                const char *base;
                const char *expected;
        } cases[] = {
                { "file",          "/",    "/file" },
                { "./file",        "/",    "/file" },
                { "./file/./more", "/",    "/file/./more" },
                { "./",            "/",    "/" },
                { "./",            "/a/b", "/a/b/" },
                { ".",             "/",    "/" },
                { "..",            "/",    "/" },
                { "../file",       "/a/b", "/a/file" },
                { "../../file",    "/a/b", "/file" },
                { "../../../file", "/a/b", "/file" },
                { "../..",         "/a/b", "/" },
                { "../leaf/file",  "/a/b", "/a/leaf/file" },
                { "..file",        "/a/b", "/a/b/..file" },
        };

        FOREACH_ELEMENT(c, cases) {
                _cleanup_free_ char *path = NULL;
                ASSERT_OK(chaseat_make_absolute(c->path, c->base, &path));
                ASSERT_STREQ(path, c->expected);
        }

        /* A stored path inside another root can name an unrelated symlink in the host filesystem. */
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &tmpdir));
        _cleanup_free_ char *prefix = ASSERT_PTR(path_join(tmpdir, "root"));
        _cleanup_free_ char *expected = ASSERT_PTR(path_join(prefix, "file"));
        ASSERT_OK_ERRNO(symlink("/", prefix));

        _cleanup_free_ char *path = NULL;
        ASSERT_OK(chaseat_make_absolute("file", prefix, &path));
        ASSERT_STREQ(path, expected);
}

TEST(trailing_dot_dot) {
        _cleanup_free_ char *path = NULL, *fdpath = NULL;
        _cleanup_close_ int fd = -EBADF;

        ASSERT_OK(chase("/usr/..", /* root= */ NULL, CHASE_PARENT, &path, &fd));
        ASSERT_PATH_EQ(path, "/");
        ASSERT_OK(fd_get_path(fd, &fdpath));
        ASSERT_PATH_EQ(fdpath, "/");

        path = mfree(path);
        fdpath = mfree(fdpath);
        fd = safe_close(fd);

        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        _cleanup_free_ char *sub = ASSERT_PTR(path_join(t, "a/b/c/d"));
        ASSERT_OK(mkdir_p(sub, 0700));
        _cleanup_free_ char *suffixed = ASSERT_PTR(path_join(sub, ".."));
        ASSERT_OK(chase(suffixed, /* root= */ NULL, CHASE_PARENT, &path, &fd));
        _cleanup_free_ char *expected1 = ASSERT_PTR(path_join(t, "a/b/c"));
        _cleanup_free_ char *expected2 = ASSERT_PTR(path_join(t, "a/b"));

        ASSERT_PATH_EQ(path, expected1);
        ASSERT_OK(fd_get_path(fd, &fdpath));
        ASSERT_PATH_EQ(fdpath, expected2);
}

TEST(chase_extract_filename_strict) {
        /* A leaf directory below a temporary root has no filename for root, dot, or ancestor results.
         * Strict extraction must fail without changing outputs; HARDER must return "." for the same inode. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, leaf_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &t));
        root_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_PATH|O_DIRECTORY));
        ASSERT_OK_ERRNO(mkdirat(root_fd, "leaf", 0700));
        leaf_fd = ASSERT_OK(xopenat(root_fd, "leaf", O_PATH|O_DIRECTORY));

        FOREACH_STRING(path, "/", ".", "..") {
                _cleanup_free_ char *filename = NULL;
                _cleanup_close_ int fd = -EBADF;
                ChaseFlags flags;

                FOREACH_ARGUMENT(flags, CHASE_EXTRACT_FILENAME, CHASE_PARENT|CHASE_EXTRACT_FILENAME) {
                        ASSERT_ERROR(chaseat(root_fd, leaf_fd, path, flags, &filename, &fd),
                                     streq(path, "..") ? EINVAL : EADDRNOTAVAIL);
                        ASSERT_NULL(filename);
                        ASSERT_LT(fd, 0);
                }

                /* The tolerant variant identifies the resolved directory through its own fd. */
                ASSERT_OK_POSITIVE(chaseat(root_fd, leaf_fd, path, CHASE_EXTRACT_FILENAME_HARDER, &filename, &fd));
                ASSERT_STREQ(filename, ".");
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, streq(path, ".") ? leaf_fd : root_fd));
        }
}

TEST(open_trailing_dot_dot) {
        /* The walk starts at a leaf below a temporary root. Equivalent spellings of ".." must reopen
         * the leaf's parent with each path-output mode. Filename extraction must return "." with or
         * without CHASE_PARENT. Directory creation must fail for the result. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, sub_fd = -EBADF, leaf_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &t));
        root_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_PATH|O_DIRECTORY));
        ASSERT_OK_ERRNO(mkdirat(root_fd, "sub", 0700));
        sub_fd = ASSERT_OK(xopenat(root_fd, "sub", O_PATH|O_DIRECTORY));
        ASSERT_OK_ERRNO(mkdirat(sub_fd, "leaf", 0700));
        leaf_fd = ASSERT_OK(xopenat(sub_fd, "leaf", O_PATH|O_DIRECTORY));

        /* Filename extraction must also work when chaseat() opens the target directly. */
        _cleanup_free_ char *direct_filename = NULL;
        _cleanup_close_ int direct_fd = -EBADF;
        ASSERT_OK_POSITIVE(chaseat(root_fd, leaf_fd, "..", CHASE_EXTRACT_FILENAME_HARDER, &direct_filename, &direct_fd));
        ASSERT_STREQ(direct_filename, ".");
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(direct_fd, sub_fd));

        ChaseFlags flags;
        FOREACH_STRING(path, "..", "../leaf/..", ".././")
                FOREACH_ARGUMENT(flags, 0, CHASE_EXTRACT_FILENAME_HARDER, CHASE_TRAIL_SLASH) {
                        _cleanup_close_ int fd = -EBADF;

                        fd = ASSERT_OK(chase_and_openat(root_fd, leaf_fd, path, flags, O_PATH|O_DIRECTORY, /* ret_path= */ NULL));
                        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, sub_fd));
                        ASSERT_ERROR(chase_and_openat(root_fd, leaf_fd, path, flags, O_CREAT|O_DIRECTORY, /* ret_path= */ NULL), EISDIR);
                }

        /* Parent lookup must return a filename that opens the same resolved directory in its fd. */
        _cleanup_free_ char *filename = NULL;
        _cleanup_close_ int fd = ASSERT_OK(chase_and_open_parent_at(root_fd, leaf_fd, "..", CHASE_EXTRACT_FILENAME_HARDER, &filename));
        ASSERT_STREQ(filename, ".");
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, sub_fd));
}

TEST(chase_root_without_proc) {
        /* A child enters a temporary root without /proc. Root lookup must preserve the pinned inode
         * without directory search permission, including on kernels without O_EMPTYPATH. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF;
        int r;

        if (have_effective_cap(CAP_SYS_CHROOT) <= 0)
                return (void) log_tests_skipped("CAP_SYS_CHROOT is required");

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &t));
        ASSERT_OK(mkdir_p(strjoina(t, "/root"), 0755));
        root_fd = ASSERT_OK(xopenat(AT_FDCWD, strjoina(t, "/root"), O_PATH|O_DIRECTORY));

        /* The child changes its filesystem root so /proc is absent without changing the parent process. */
        r = ASSERT_OK(pidref_safe_fork("(chase-root)", FORK_WAIT|FORK_LOG|FORK_DEATHSIG_SIGKILL, /* ret= */ NULL));
        if (r > 0)
                return;

        ASSERT_OK_ERRNO(chroot(t));
        ASSERT_OK_ERRNO(chdir("/"));

        /* CHASE_PREFIX_ROOT must preserve root lookup through the open wrapper without /proc. */
        _cleanup_close_ int opened = ASSERT_OK(chase_and_open("/", "/root", CHASE_PREFIX_ROOT, O_PATH|O_DIRECTORY, /* ret_path= */ NULL));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(opened, root_fd));

        /* Dropping DAC overrides makes a "." lookup fail after removing directory search permission. */
        ASSERT_OK_ERRNO(chmod("/root", 0400));
        ASSERT_OK(drop_capability(CAP_DAC_OVERRIDE));
        ASSERT_OK(drop_capability(CAP_DAC_READ_SEARCH));
        ASSERT_ERROR(xopenat(root_fd, ".", O_PATH|O_DIRECTORY), EACCES);

        ChaseFlags flags;
        FOREACH_ARGUMENT(flags, 0, CHASE_PARENT, CHASE_EXTRACT_FILENAME_HARDER, CHASE_PARENT|CHASE_EXTRACT_FILENAME_HARDER) {
                _cleanup_free_ char *path = NULL;
                _cleanup_close_ int fd = -EBADF;

                ASSERT_OK_POSITIVE(chase("/root", "/root", flags, &path, &fd));
                ASSERT_STREQ(path, FLAGS_SET(flags, CHASE_EXTRACT_FILENAME) ? "." : "/root");
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, root_fd));
                ASSERT_TRUE(FLAGS_SET(ASSERT_OK_ERRNO(fcntl(fd, F_GETFD)), FD_CLOEXEC));

                /* Final O_PATH opens must not look up "." inside the unsearchable directory. */
                _cleanup_close_ int full = ASSERT_OK(chase_and_open("/", "/root", flags|CHASE_PREFIX_ROOT,
                                                                 O_PATH|O_DIRECTORY, /* ret_path= */ NULL));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(full, root_fd));
                _cleanup_close_ int relative = ASSERT_OK(chase_and_openat(root_fd, root_fd, "/", flags,
                                                                        O_PATH|O_DIRECTORY, /* ret_path= */ NULL));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(relative, root_fd));
        }

        /* An explicit empty lookup must also preserve the inode without searching the directory. */
        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(chaseat(root_fd, root_fd, "", CHASE_EMPTY_PATH, /* ret_path= */ NULL, &fd));
        ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, root_fd));
        _exit(EXIT_SUCCESS);
}

TEST(chase_empty_path) {
        /* A temporary root contains a file and an O_PATH symlink. Empty paths must require CHASE_EMPTY_PATH and preserve the inode
         * identity of their fds. Nonempty relative paths must reject the file and symlink as lookup
         * directories. Type checks must still apply to an empty-path lookup. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, file_fd = -EBADF, path_fd = -EBADF, link_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc("/var/tmp/test-chase.XXXXXX", &t));
        root_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_PATH|O_DIRECTORY));
        file_fd = ASSERT_OK(xopenat(root_fd, "file", O_CREAT|O_RDWR));
        path_fd = ASSERT_OK(xopenat(root_fd, "file", O_PATH));
        ASSERT_OK_ERRNO(symlinkat("file", root_fd, "link"));
        link_fd = ASSERT_OK(xopenat(root_fd, "link", O_PATH|O_NOFOLLOW));

        int start_fd;
        FOREACH_ARGUMENT(start_fd, file_fd, path_fd, link_fd) {
                _cleanup_close_ int fd = -EBADF, opened = -EBADF;
                _cleanup_free_ char *path = NULL;

                ASSERT_ERROR(chaseat(root_fd, start_fd, "", /* flags= */ 0, &path, &fd), ENOENT);
                ASSERT_NULL(path);
                ASSERT_LT(fd, 0);
                ASSERT_ERROR(chase_and_openat(root_fd, start_fd, "", /* chase_flags= */ 0,
                                             O_PATH, /* ret_path= */ NULL), ENOENT);
                ASSERT_OK(chaseat(root_fd, start_fd, "", CHASE_EMPTY_PATH, &path, &fd));
                ASSERT_STREQ(path, ".");
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(fd, start_fd));
                ASSERT_OK_POSITIVE(fd_is_opath(fd));
                ASSERT_TRUE(FLAGS_SET(ASSERT_OK_ERRNO(fcntl(fd, F_GETFD)), FD_CLOEXEC));
                ASSERT_OK(chaseat(root_fd, start_fd, "", CHASE_EMPTY_PATH, /* ret_path= */ NULL, /* ret_fd= */ NULL));
                opened = ASSERT_OK(chase_and_openat(root_fd, start_fd, "", CHASE_EMPTY_PATH, O_PATH, /* ret_path= */ NULL));
                ASSERT_OK_POSITIVE(fds_inode_and_mount_same(opened, start_fd));
                ASSERT_ERROR(chaseat(root_fd, start_fd, "child", /* flags= */ 0, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOTDIR);
                ASSERT_ERROR(chaseat(root_fd, start_fd, "", CHASE_PARENT|CHASE_EMPTY_PATH, /* ret_path= */ NULL, /* ret_fd= */ NULL),
                             start_fd == link_fd ? ELOOP : ENOTDIR);
        }

        /* Empty cwd lookups must honor the flag even when no result path is requested. */
        struct stat st, cwd_st;
        ASSERT_OK_ERRNO(stat(".", &cwd_st));
        ASSERT_ERROR(chase_and_statat(XAT_FDROOT, AT_FDCWD, "", /* chase_flags= */ 0,
                                     /* ret_path= */ NULL, &st), ENOENT);
        ASSERT_OK(chase_and_statat(XAT_FDROOT, AT_FDCWD, "", CHASE_EMPTY_PATH,
                                  /* ret_path= */ NULL, &st));
        ASSERT_TRUE(stat_inode_same(&st, &cwd_st));
        ASSERT_ERROR(chase_and_accessat(XAT_FDROOT, AT_FDCWD, "", /* chase_flags= */ 0,
                                       F_OK, /* ret_path= */ NULL), ENOENT);
        ASSERT_OK(chase_and_accessat(XAT_FDROOT, AT_FDCWD, "", CHASE_EMPTY_PATH,
                                    F_OK, /* ret_path= */ NULL));
        _cleanup_closedir_ DIR *d = NULL;
        ASSERT_ERROR(chase_and_opendirat(XAT_FDROOT, AT_FDCWD, "", /* chase_flags= */ 0,
                                        /* ret_path= */ NULL, &d), ENOENT);
        ASSERT_OK(chase_and_opendirat(XAT_FDROOT, AT_FDCWD, "", CHASE_EMPTY_PATH,
                                     /* ret_path= */ NULL, &d));

        /* Type verification must distinguish the file and symlink even when no name is looked up. */
        ASSERT_OK(chaseat(root_fd, file_fd, "", CHASE_MUST_BE_REGULAR|CHASE_EMPTY_PATH, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_ERROR(chaseat(root_fd, file_fd, "", CHASE_MUST_BE_DIRECTORY|CHASE_EMPTY_PATH, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOTDIR);
        ASSERT_ERROR(chaseat(root_fd, link_fd, "", CHASE_MUST_BE_REGULAR|CHASE_EMPTY_PATH, /* ret_path= */ NULL, /* ret_fd= */ NULL), ELOOP);
}

TEST(trailing_dot_dot_below_root) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int root_fd = -EBADF, a_fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        _cleanup_free_ char *sub = ASSERT_PTR(path_join(t, "a/b"));
        ASSERT_OK(mkdir_p(sub, 0700));
        root_fd = ASSERT_OK(xopenat(AT_FDCWD, t, O_PATH|O_DIRECTORY));
        a_fd = ASSERT_OK(xopenat(root_fd, "a", O_PATH|O_DIRECTORY));
        ASSERT_OK_ERRNO(symlinkat("..", root_fd, "a/up"));

        /* The parent of the root directory is the root directory itself. */
        FOREACH_STRING(p, "..", "a/..", "/a/..", "a/up") {
                _cleanup_free_ char *path = NULL;
                _cleanup_close_ int fd = -EBADF;

                log_debug("/* %s(%s) */", __func__, p);

                ASSERT_OK(chaseat(root_fd, root_fd, p, CHASE_PARENT, &path, &fd));
                ASSERT_STREQ(path, ".");
                ASSERT_OK_POSITIVE(fd_inode_same(fd, root_fd));
        }

        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(chaseat(root_fd, a_fd, "..", CHASE_PARENT, &path, &fd));
        ASSERT_STREQ(path, "..");
        ASSERT_OK_POSITIVE(fd_inode_same(fd, root_fd));

        /* A result of "." refers to dir_fd, so the fd refers to dir_fd as well. */
        path = mfree(path);
        fd = safe_close(fd);
        ASSERT_OK(chaseat(root_fd, a_fd, "b/..", CHASE_PARENT, &path, &fd));
        ASSERT_STREQ(path, ".");
        ASSERT_OK_POSITIVE(fd_inode_same(fd, a_fd));

        path = mfree(path);
        fd = safe_close(fd);
        ASSERT_OK(chaseat(root_fd, root_fd, "a/b/..", CHASE_PARENT, &path, &fd));
        ASSERT_STREQ(path, "a");
        ASSERT_OK_POSITIVE(fd_inode_same(fd, root_fd));
}

TEST(use_chase_as_mkdir_p) {
        _cleanup_free_ char *p = NULL;
        ASSERT_OK_ERRNO(asprintf(&p, "/tmp/chasemkdir%" PRIu64 "/a/b/c", random_u64()));

        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(chase(p, /* root= */ NULL, CHASE_PREFIX_ROOT|CHASE_MKDIR_0755, /* ret_path= */ NULL, &fd));

        ASSERT_OK_EQ(inode_same_at(AT_FDCWD, p, fd, /* fileb= */ NULL, AT_EMPTY_PATH), 1);

        _cleanup_close_ int fd2 = -EBADF;
        ASSERT_OK(chase(p, p, CHASE_PREFIX_ROOT|CHASE_MKDIR_0755, /* ret_path= */ NULL, &fd2));

        _cleanup_free_ char *pp = ASSERT_PTR(path_join(p, p));

        ASSERT_OK_EQ(inode_same_at(AT_FDCWD, pp, fd2, /* fileb= */ NULL, AT_EMPTY_PATH), 1);

        _cleanup_free_ char *f = NULL;
        ASSERT_OK(path_extract_directory(p, &f));

        _cleanup_free_ char *ff = NULL;
        ASSERT_OK(path_extract_directory(f, &ff));

        _cleanup_free_ char *fff = NULL;
        ASSERT_OK(path_extract_directory(ff, &fff));

        ASSERT_OK(rm_rf(fff, REMOVE_PHYSICAL));
}

TEST(chase_mode) {
        /* A temporary tree exercises CHASE_MAX_MODE on files, directories, symlinks, and parent traversal.
         * Unsafe mode bits must be rejected on every inode that the walk checks. */
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *a = NULL, *b = NULL, *c = NULL, *f = NULL, *l = NULL, *al = NULL;
        _cleanup_close_ int tfd = -EBADF, bfd = -EBADF, cfd = -EBADF, fd = -EBADF;

        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));
        ASSERT_OK_ERRNO(chmod(t, 0755));
        ASSERT_OK(tfd = xopenat(AT_FDCWD, t, O_PATH|O_DIRECTORY));

        ASSERT_NOT_NULL(a = path_join(t, "a"));
        ASSERT_NOT_NULL(b = path_join(t, "a/b"));
        ASSERT_NOT_NULL(c = path_join(t, "a/b/c"));
        ASSERT_NOT_NULL(f = path_join(t, "a/b/f"));
        ASSERT_NOT_NULL(l = path_join(t, "a/l"));

        WITH_UMASK(0022) {
                ASSERT_OK(mkdir_p(b, 0755));
                ASSERT_OK(write_string_file(f, "x", WRITE_STRING_FILE_CREATE));
                ASSERT_OK_ERRNO(symlink("b/f", l));
        }

        /* 0755 directories all the way down to a 0644 file pass, a symlink on the way is not checked */
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK(chaseat(tfd, tfd, "a/l", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK(chase("a/b/f", t, CHASE_PREFIX_ROOT|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK(fd = chase_and_openat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, O_RDONLY,
                                        /* ret_path= */ NULL));
        fd = safe_close(fd);

        /* A directory writable by others fails */
        ASSERT_OK_ERRNO(chmod(b, 0777));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_ERROR(chase_and_openat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, O_RDONLY, /* ret_path= */ NULL),
                     ENOLINK);
        ASSERT_OK_ERRNO(chmod(b, 0757));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);

        /* Group write, stricter modes and the special bits pass */
        ASSERT_OK_ERRNO(chmod(b, 0775));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(b, 0750));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(b, 0700));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(b, 02755));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(b, 01755));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(b, 0755));

        /* The final file may not exceed 0664, exec and special bits included */
        ASSERT_OK_ERRNO(chmod(f, 0666));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 0646));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 0755));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 04644));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 02644));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 01644));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(f, 0664));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(f, 0600));
        ASSERT_OK(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(f, 0644));

        /* A symlink as the final component is not checked when it is not followed */
        ASSERT_OK_ERRNO(chmod(f, 0666));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/l", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK(chaseat(tfd, tfd, "a/l", CHASE_NOFOLLOW|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(f, 0644));

        /* The starting directory is checked like any other, also when ".." leads back to it */
        ASSERT_OK_ERRNO(chmod(t, 0777));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_ERROR(chase("a/b/f", t, CHASE_PREFIX_ROOT|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_ERROR(chaseat(tfd, tfd, "a/../a/b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(t, 0755));

        /* And so is the parent walked through with ".." */
        ASSERT_OK(chaseat(tfd, tfd, "a/b/../b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(a, 0777));
        ASSERT_ERROR(chaseat(tfd, tfd, "a/b/../b/f", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(a, 0755));

        /* Directories created on the way are 0755 and pass */
        WITH_UMASK(0022)
                ASSERT_OK(chaseat(tfd, tfd, "n/m", CHASE_MKDIR_0755|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK(chaseat(tfd, tfd, "n/m", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));

        /* A normalized result ending in ".." returns the result itself with CHASE_PARENT. The directory
         * above the result is not part of the walk. */
        WITH_UMASK(0022)
                ASSERT_OK(mkdir_p(c, 0755));
        ASSERT_OK(bfd = xopenat(AT_FDCWD, b, O_PATH|O_DIRECTORY));
        ASSERT_OK(cfd = xopenat(AT_FDCWD, c, O_PATH|O_DIRECTORY));
        ASSERT_OK(chaseat(tfd, cfd, "..", CHASE_PARENT|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(a, 0777));
        ASSERT_OK(chaseat(tfd, cfd, "..", CHASE_PARENT|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_ERROR(chaseat(tfd, bfd, "..", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK(chaseat(tfd, bfd, "c/..", CHASE_PARENT|CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
        ASSERT_OK_ERRNO(chmod(a, 0755));

        /* The root is checked like the starting directory when ".." climbs into it, and not at all when the
         * walk never gets there */
        ASSERT_OK_ERRNO(chmod(t, 0777));
        ASSERT_ERROR(chaseat(tfd, bfd, "../..", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_ERROR(chaseat(tfd, bfd, "../../a/b/c", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK(chaseat(tfd, bfd, "c", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));

        /* An absolute symlink leads back to the root, which is checked then */
        ASSERT_NOT_NULL(al = path_join(t, "a/al"));
        ASSERT_OK_ERRNO(symlink("/a/b/c", al));
        ASSERT_ERROR(chaseat(tfd, bfd, "../al", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL), ENOLINK);
        ASSERT_OK_ERRNO(chmod(t, 0755));
        ASSERT_OK(chaseat(tfd, bfd, "../al", CHASE_MAX_MODE, /* ret_path= */ NULL, /* ret_fd= */ NULL));
}

TEST(chase_and_open_cloexec) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int fl;

        ASSERT_OK(tfd = mkdtemp_open(/* template= */ NULL, /* flags= */ 0, &t));
        ASSERT_OK_ERRNO(mkdirat(tfd, "dir", 0755));

        /* O_CLOEXEC is implied, whether requested or not, on the shortcut and on the full chase */
        ASSERT_OK(fd = chase_and_open(t, /* root= */ NULL, /* chase_flags= */ 0, O_DIRECTORY, /* ret_path= */ NULL));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFD));
        ASSERT_TRUE(FLAGS_SET(fl, FD_CLOEXEC));
        fd = safe_close(fd);

        ASSERT_OK(fd = chase_and_open(t, /* root= */ NULL, /* chase_flags= */ 0, O_DIRECTORY, &p));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFD));
        ASSERT_TRUE(FLAGS_SET(fl, FD_CLOEXEC));
        fd = safe_close(fd);

        ASSERT_OK(fd = chase_and_openat(tfd, tfd, "dir", /* chase_flags= */ 0, O_DIRECTORY, /* ret_path= */ NULL));
        ASSERT_OK_ERRNO(fl = fcntl(fd, F_GETFD));
        ASSERT_TRUE(FLAGS_SET(fl, FD_CLOEXEC));
}

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
