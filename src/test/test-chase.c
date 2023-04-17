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
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static const char *arg_test_dir = NULL;

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

        r = chase(p, NULL, 0, &result, NULL);
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

        assert_se(mkdir(q, 0700) >= 0);

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

        /* Paths that would "escape" outside of the "root" */

        p = strjoina(temp, "/6dots");
        assert_se(symlink("../../..", p) >= 0);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, temp));
        result = mfree(result);

        p = strjoina(temp, "/6dotsusr");
        assert_se(symlink("../../../usr", p) >= 0);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        p = strjoina(temp, "/top/8dotsusr");
        assert_se(symlink("../../../../usr", p) >= 0);

        r = chase(p, temp, 0, &result, NULL);
        assert_se(r > 0 && path_equal(result, q));
        result = mfree(result);

        /* Paths that contain repeated slashes */

        p = strjoina(temp, "/slashslash");
        assert_se(symlink("///usr///", p) >= 0);

        r = chase(p, NULL, 0, &result, NULL);
        assert_se(r > 0);
        assert_se(path_equal(result, "/usr"));
        assert_se(streq(result, "/usr")); /* we guarantee that we drop redundant slashes */
        result = mfree(result);

        r = chase(p, temp, 0, &result, NULL);
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
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase("/../.././//../../test-chase.fsldajfl", NULL, CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase("/../.././//../../etc", "/", CHASE_PREFIX_ROOT, &result, NULL);
        assert_se(r > 0);
        assert_se(streq(result, "/etc"));
        result = mfree(result);

        r = chase("/../.././//../../test-chase.fsldajfl", "/", CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &result, NULL);
        assert_se(r == 0);
        assert_se(streq(result, "/test-chase.fsldajfl"));
        result = mfree(result);

        r = chase("/etc/machine-id/foo", NULL, 0, &result, NULL);
        assert_se(IN_SET(r, -ENOTDIR, -ENOENT));
        result = mfree(result);

        /* Path that loops back to self */

        p = strjoina(temp, "/recursive-symlink");
        assert_se(symlink("recursive-symlink", p) >= 0);
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

        assert_se(safe_getcwd(&pwd) >= 0);

        assert_se(chdir(temp) >= 0);

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

        if (geteuid() == 0) {
                p = strjoina(temp, "/priv1");
                assert_se(mkdir(p, 0755) >= 0);

                q = strjoina(p, "/priv2");
                assert_se(mkdir(q, 0755) >= 0);

                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(q, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(p, UID_NOBODY, GID_NOBODY) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);

                assert_se(chown(q, 0, 0) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                assert_se(rmdir(q) >= 0);
                assert_se(symlink("/etc/passwd", q) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) == -ENOLINK);

                assert_se(chown(p, 0, 0) >= 0);
                assert_se(chase(q, NULL, CHASE_SAFE, NULL, NULL) >= 0);
        }

        p = strjoina(temp, "/machine-id-test");
        assert_se(symlink("/usr/../etc/./machine-id", p) >= 0);

        r = chase(p, NULL, 0, NULL, &pfd);
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
        r = chase(q, NULL, CHASE_NOFOLLOW, &result, &pfd);
        assert_se(r >= 0);
        assert_se(pfd >= 0);
        assert_se(path_equal(result, q));
        assert_se(fstat(pfd, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        result = mfree(result);
        pfd = safe_close(pfd);

        /* Test CHASE_STEP */

        p = strjoina(temp, "/start");
        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dot/dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/dotdota");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/top/../a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/a");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        p = strjoina(temp, "/b");
        assert_se(streq(p, result));
        result = mfree(result);

        r = chase(p, NULL, CHASE_STEP, &result, NULL);
        assert_se(r == 0);
        assert_se(streq("/usr", result));
        result = mfree(result);

        r = chase("/usr", NULL, CHASE_STEP, &result, NULL);
        assert_se(r > 0);
        assert_se(streq("/usr", result));
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
        assert_se(rm_rf(temp, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);
}

TEST(chaseat) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *result = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        struct stat st;
        const char *p;

        assert_se((tfd = mkdtemp_open(NULL, 0, &t)) >= 0);

        /* Test that AT_FDCWD with CHASE_AT_RESOLVE_IN_ROOT resolves against / and not the current working
         * directory. */

        assert_se(symlinkat("/usr", tfd, "abc") >= 0);

        p = strjoina(t, "/abc");
        assert_se(chaseat(AT_FDCWD, p, CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        /* If the file descriptor points to the root directory, the result will be absolute. */

        fd = open("/", O_CLOEXEC | O_DIRECTORY | O_PATH);
        assert_se(fd >= 0);

        assert_se(chaseat(fd, p, 0, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        assert_se(chaseat(fd, p, CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        fd = safe_close(fd);

        /* If the file descriptor does not point to the root directory, the result will be relative
         * unless the result is outside of the specified file descriptor. */

        assert_se(chaseat(tfd, "abc", 0, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        assert_se(chaseat(tfd, "/abc", 0, &result, NULL) >= 0);
        assert_se(streq(result, "/usr"));
        result = mfree(result);

        assert_se(chaseat(tfd, "abc", CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL) == -ENOENT);
        assert_se(chaseat(tfd, "/abc", CHASE_AT_RESOLVE_IN_ROOT, NULL, NULL) == -ENOENT);

        assert_se(chaseat(tfd, "abc", CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &result, NULL) >= 0);
        assert_se(streq(result, "usr"));
        result = mfree(result);

        assert_se(chaseat(tfd, "/abc", CHASE_AT_RESOLVE_IN_ROOT | CHASE_NONEXISTENT, &result, NULL) >= 0);
        assert_se(streq(result, "usr"));
        result = mfree(result);

        /* Test that absolute path or not are the same when resolving relative to a directory file
         * descriptor and that we always get a relative path back. */

        assert_se(fd = openat(tfd, "def", O_CREAT|O_CLOEXEC, 0700) >= 0);
        fd = safe_close(fd);
        assert_se(symlinkat("/def", tfd, "qed") >= 0);
        assert_se(chaseat(tfd, "qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "def"));
        result = mfree(result);
        assert_se(chaseat(tfd, "/qed", CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "def"));
        result = mfree(result);

        /* Valid directory file descriptor without CHASE_AT_RESOLVE_IN_ROOT should resolve symlinks against
         * host's root. */
        assert_se(chaseat(tfd, "/qed", 0, NULL, NULL) == -ENOENT);

        /* Test CHASE_PARENT */

        assert_se((fd = open_mkdir_at(tfd, "chase", O_CLOEXEC, 0755)) >= 0);
        assert_se(symlinkat("/def", fd, "parent") >= 0);
        fd = safe_close(fd);

        /* Make sure that when we chase a symlink parent directory, that we chase the parent directory of the
         * symlink target and not the symlink itself. But if we add CHASE_NOFOLLOW, we get the parent
         * directory of the symlink itself. */

        assert_se(chaseat(tfd, "chase/parent", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, &fd) >= 0);
        assert_se(faccessat(fd, "def", F_OK, 0) >= 0);
        assert_se(streq(result, "def"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se(chaseat(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_NOFOLLOW, &result, &fd) >= 0);
        assert_se(faccessat(fd, "parent", F_OK, AT_SYMLINK_NOFOLLOW) >= 0);
        assert_se(streq(result, "chase/parent"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se(chaseat(tfd, "chase", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, &fd) >= 0);
        assert_se(faccessat(fd, "chase", F_OK, 0) >= 0);
        assert_se(streq(result, "chase"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se(chaseat(tfd, "/", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "."));
        result = mfree(result);

        assert_se(chaseat(tfd, ".", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT, &result, NULL) >= 0);
        assert_se(streq(result, "."));
        result = mfree(result);

        /* Test CHASE_MKDIR_0755 */

        assert_se(chaseat(tfd, "m/k/d/i/r", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL) >= 0);
        assert_se(faccessat(tfd, "m/k/d/i", F_OK, 0) >= 0);
        assert_se(RET_NERRNO(faccessat(tfd, "m/k/d/i/r", F_OK, 0)) == -ENOENT);
        assert_se(streq(result, "m/k/d/i/r"));
        result = mfree(result);

        assert_se(chaseat(tfd, "m/../q", CHASE_MKDIR_0755|CHASE_NONEXISTENT, &result, NULL) >= 0);
        assert_se(faccessat(tfd, "m", F_OK, 0) >= 0);
        assert_se(RET_NERRNO(faccessat(tfd, "q", F_OK, 0)) == -ENOENT);
        assert_se(streq(result, "q"));
        result = mfree(result);

        assert_se(chaseat(tfd, "i/../p", CHASE_MKDIR_0755|CHASE_NONEXISTENT, NULL, NULL) == -ENOENT);

        /* Test CHASE_FILENAME */

        assert_se(chaseat(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_NOFOLLOW|CHASE_EXTRACT_FILENAME, &result, &fd) >= 0);
        assert_se(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW) >= 0);
        assert_se(streq(result, "parent"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se(chaseat(tfd, "chase", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, &fd) >= 0);
        assert_se(faccessat(fd, result, F_OK, 0) >= 0);
        assert_se(streq(result, "chase"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se(chaseat(tfd, "/", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, NULL) >= 0);
        assert_se(streq(result, "."));
        result = mfree(result);

        assert_se(chaseat(tfd, ".", CHASE_PARENT|CHASE_AT_RESOLVE_IN_ROOT|CHASE_EXTRACT_FILENAME, &result, NULL) >= 0);
        assert_se(streq(result, "."));
        result = mfree(result);

        /* Test chase_and_openat() */

        fd = chase_and_openat(tfd, "o/p/e/n/f/i/l/e", CHASE_MKDIR_0755, O_CREAT|O_EXCL|O_CLOEXEC, NULL);
        assert_se(fd >= 0);
        assert_se(fd_verify_regular(fd) >= 0);
        fd = safe_close(fd);

        fd = chase_and_openat(tfd, "o/p/e/n/d/i/r", CHASE_MKDIR_0755, O_DIRECTORY|O_CREAT|O_EXCL|O_CLOEXEC, NULL);
        assert_se(fd >= 0);
        assert_se(fd_verify_directory(fd) >= 0);
        fd = safe_close(fd);

        /* Test chase_and_openatdir() */

        assert_se(chase_and_opendirat(tfd, "o/p/e/n/d/i", 0, &result, &dir) >= 0);
        FOREACH_DIRENT(de, dir, assert_not_reached())
                assert_se(streq(de->d_name, "r"));
        assert_se(streq(result, "o/p/e/n/d/i"));
        result = mfree(result);

        /* Test chase_and_statat() */

        assert_se(chase_and_statat(tfd, "o/p", 0, &result, &st) >= 0);
        assert_se(stat_verify_directory(&st) >= 0);
        assert_se(streq(result, "o/p"));
        result = mfree(result);

        /* Test chase_and_accessat() */

        assert_se(chase_and_accessat(tfd, "o/p/e", 0, F_OK, &result) >= 0);
        assert_se(streq(result, "o/p/e"));
        result = mfree(result);

        /* Test chase_and_fopenat_unlocked() */

        assert_se(chase_and_fopenat_unlocked(tfd, "o/p/e/n/f/i/l/e", 0, "re", &result, &f) >= 0);
        assert_se(fread(&(char[1]) {}, 1, 1, f) == 0);
        assert_se(feof(f));
        f = safe_fclose(f);
        assert_se(streq(result, "o/p/e/n/f/i/l/e"));
        result = mfree(result);

        /* Test chase_and_unlinkat() */

        assert_se(chase_and_unlinkat(tfd, "o/p/e/n/f/i/l/e", 0, 0, &result) >= 0);
        assert_se(streq(result, "o/p/e/n/f/i/l/e"));
        result = mfree(result);

        /* Test chase_and_open_parent_at() */

        assert_se((fd = chase_and_open_parent_at(tfd, "chase/parent", CHASE_AT_RESOLVE_IN_ROOT|CHASE_NOFOLLOW, &result)) >= 0);
        assert_se(faccessat(fd, result, F_OK, AT_SYMLINK_NOFOLLOW) >= 0);
        assert_se(streq(result, "parent"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se((fd = chase_and_open_parent_at(tfd, "chase", CHASE_AT_RESOLVE_IN_ROOT, &result)) >= 0);
        assert_se(faccessat(fd, result, F_OK, 0) >= 0);
        assert_se(streq(result, "chase"));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se((fd = chase_and_open_parent_at(tfd, "/", CHASE_AT_RESOLVE_IN_ROOT, &result)) >= 0);
        assert_se(streq(result, "."));
        fd = safe_close(fd);
        result = mfree(result);

        assert_se((fd = chase_and_open_parent_at(tfd, ".", CHASE_AT_RESOLVE_IN_ROOT, &result)) >= 0);
        assert_se(streq(result, "."));
        fd = safe_close(fd);
        result = mfree(result);
}

static int intro(void) {
        arg_test_dir = saved_argv[1];
        return EXIT_SUCCESS;
}

TEST(chaseat_prefix_root) {
        _cleanup_free_ char *cwd = NULL, *ret = NULL, *expected = NULL;

        assert_se(safe_getcwd(&cwd) >= 0);

        assert_se(chaseat_prefix_root("/hoge", NULL, &ret) >= 0);
        assert_se(streq(ret, "/hoge"));

        ret = mfree(ret);

        assert_se(chaseat_prefix_root("/hoge", "a/b/c", &ret) >= 0);
        assert_se(streq(ret, "/hoge"));

        ret = mfree(ret);

        assert_se(chaseat_prefix_root("hoge", "/a/b//./c///", &ret) >= 0);
        assert_se(streq(ret, "/a/b/c/hoge"));

        ret = mfree(ret);

        assert_se(chaseat_prefix_root("hoge", "a/b//./c///", &ret) >= 0);
        assert_se(expected = path_join(cwd, "a/b/c/hoge"));
        assert_se(streq(ret, expected));

        ret = mfree(ret);
        expected = mfree(expected);

        assert_se(chaseat_prefix_root("./hoge/aaa/../././b", "/a/b//./c///", &ret) >= 0);
        assert_se(streq(ret, "/a/b/c/hoge/aaa/../././b"));

        ret = mfree(ret);

        assert_se(chaseat_prefix_root("./hoge/aaa/../././b", "a/b//./c///", &ret) >= 0);
        assert_se(expected = path_join(cwd, "a/b/c/hoge/aaa/../././b"));
        assert_se(streq(ret, expected));
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
