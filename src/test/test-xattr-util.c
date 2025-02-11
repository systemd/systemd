/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "nulstr-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "xattr-util.h"

TEST(getxattr_at_malloc) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_free_ char *value = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *x;
        int r;

        fd = mkdtemp_open("/var/tmp/test-xattrtestXXXXXX", O_RDONLY|O_NOCTTY, &t);
        assert_se(fd >= 0);
        x = strjoina(t, "/test");
        assert_se(touch(x) >= 0);

        r = setxattr(x, "user.foo", "bar", 3, 0);
        if (r < 0 && ERRNO_IS_NOT_SUPPORTED(errno))
                return (void) log_tests_skipped_errno(errno, "no xattrs supported on /var/tmp");
        assert_se(r >= 0);

        assert_se(getxattr_at_malloc(fd, "test", "user.foo", 0, &value) == 3);
        assert_se(memcmp(value, "bar", 3) == 0);
        value = mfree(value);

        assert_se(getxattr_at_malloc(AT_FDCWD, x, "user.foo", 0, &value) == 3);
        assert_se(memcmp(value, "bar", 3) == 0);
        value = mfree(value);

        safe_close(fd);
        fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOCTTY);
        assert_se(fd >= 0);
        r = getxattr_at_malloc(fd, "usr", "user.idontexist", 0, &value);
        assert_se(ERRNO_IS_NEG_XATTR_ABSENT(r));

        safe_close(fd);
        fd = open(x, O_PATH|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(getxattr_at_malloc(fd, NULL, "user.foo", 0, &value) == 3);
        ASSERT_STREQ(value, "bar");
}

TEST(getcrtime) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        usec_t usec, k;
        int r;

        fd = mkdtemp_open("/var/tmp/test-xattrtestXXXXXX", 0, &t);
        assert_se(fd >= 0);

        r = fd_getcrtime(fd, &usec);
        if (r < 0)
                log_debug_errno(r, "btime: %m");
        else
                log_debug("btime: %s", FORMAT_TIMESTAMP(usec));

        k = now(CLOCK_REALTIME);

        r = fd_setcrtime(fd, 1519126446UL * USEC_PER_SEC);
        if (!IN_SET(r, -EOPNOTSUPP, -ENOTTY)) {
                assert_se(fd_getcrtime(fd, &usec) >= 0);
                assert_se(k < 1519126446UL * USEC_PER_SEC ||
                          usec == 1519126446UL * USEC_PER_SEC);
        }
}

static void verify_xattr(int dfd, const char *expected) {
        _cleanup_free_ char *value = NULL;

        ASSERT_OK_EQ(getxattr_at_malloc(dfd, "test", "user.foo", 0, &value), (int) strlen(expected));
        ASSERT_STREQ(value, expected);
}

static void xattr_symlink_test_one(int fd, const char *path) {
        _cleanup_free_ char *value = NULL, *list = NULL;
        _cleanup_strv_free_ char **list_split = NULL;
        int r;

        ASSERT_ERROR(xsetxattr_full(fd, path, 0, "trusted.bar", "bogus", SIZE_MAX, XATTR_CREATE), EEXIST);

        ASSERT_OK(xsetxattr(fd, path, 0, "trusted.test", "schaffen"));
        ASSERT_OK_EQ(getxattr_at_malloc(fd, path, "trusted.test", 0, &value), (int) STRLEN("schaffen"));
        ASSERT_STREQ(value, "schaffen");

        r = listxattr_at_malloc(fd, path, 0, &list);
        ASSERT_OK(r);
        ASSERT_GE(r, (int) sizeof("trusted.test\0trusted.bar"));
        ASSERT_NOT_NULL(list_split = strv_parse_nulstr(list, r));
        ASSERT_TRUE(strv_contains(list_split, "trusted.bar"));
        ASSERT_TRUE(strv_contains(list_split, "trusted.test"));

        ASSERT_OK(xremovexattr(fd, path, 0, "trusted.test"));
        ASSERT_ERROR(getxattr_at_malloc(fd, path, "trusted.test", 0, &value), ENODATA);
}

TEST(xsetxattr) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int dfd = -EBADF, fd = -EBADF;
        const char *x;
        int r;

        dfd = mkdtemp_open("/var/tmp/test-xattrtestXXXXXX", O_PATH, &t);
        assert_se(dfd >= 0);
        x = strjoina(t, "/test");
        assert_se(touch(x) >= 0);

        /* by full path */
        r = xsetxattr(AT_FDCWD, x, 0, "user.foo", "fullpath");
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "no xattrs supported on /var/tmp");
        ASSERT_OK(r);
        verify_xattr(dfd, "fullpath");

        /* by dirfd */
        ASSERT_ERROR(xsetxattr_full(dfd, "test", 0, "user.foo", "dirfd", SIZE_MAX, XATTR_CREATE), EEXIST);
        verify_xattr(dfd, "fullpath");

        ASSERT_OK(xsetxattr_full(dfd, "test", 0, "user.foo", "dirfd", SIZE_MAX, XATTR_REPLACE));
        verify_xattr(dfd, "dirfd");

        /* by fd (O_PATH) */
        ASSERT_OK_ERRNO(fd = openat(dfd, "test", O_PATH|O_CLOEXEC));

        ASSERT_OK(xremovexattr(fd, "", 0, "user.foo"));

        ASSERT_OK(xsetxattr_full(fd, NULL, AT_EMPTY_PATH, "user.foo", "fd_opath", SIZE_MAX, XATTR_CREATE));
        verify_xattr(dfd, "fd_opath");

        ASSERT_OK(xsetxattr(fd, "", 0, "user.foo", "fd_opath_empty"));
        verify_xattr(dfd, "fd_opath_empty");

        fd = safe_close(fd);

        fd = openat(dfd, "test", O_RDONLY|O_CLOEXEC);

        ASSERT_OK(xsetxattr_full(fd, NULL, 0, "user.foo", "fd_regular", SIZE_MAX, XATTR_REPLACE));
        verify_xattr(dfd, "fd_regular");

        ASSERT_OK(xsetxattr(fd, "", 0, "user.foo", "fd_regular_empty"));
        verify_xattr(dfd, "fd_regular_empty");

        fd = safe_close(fd);

        /* user.* xattrs are not supported on symlinks. Use trusted.* which requires privilege. */
        ASSERT_OK_ERRNO(symlinkat("empty", dfd, "symlink"));
        ASSERT_OK_ERRNO(fd = openat(dfd, "symlink", O_NOFOLLOW|O_PATH|O_CLOEXEC));

        ASSERT_ERROR(xsetxattr(dfd, "symlink", AT_SYMLINK_FOLLOW, "trusted.test", "bogus"), ENOENT);

        r = xsetxattr_full(dfd, "symlink", 0, "trusted.bar", "baz", SIZE_MAX, XATTR_CREATE);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Unable to set trusted.* xattr");
        ASSERT_OK(r);

        xattr_symlink_test_one(dfd, "symlink");
        xattr_symlink_test_one(fd, NULL);
        xattr_symlink_test_one(fd, "");

        x = strjoina(t, "/symlink");
        xattr_symlink_test_one(AT_FDCWD, x);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
