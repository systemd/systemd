/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "fd-util.h"
#include "fdset.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(fdset_new_fill) {
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int fd = -EBADF, flags;

        log_close();
        log_set_open_when_needed(true);

        fd = ASSERT_OK_ERRNO(open("/dev/null", O_CLOEXEC|O_RDONLY));

        ASSERT_OK(fdset_new_fill(/* filter_cloexec= */ -1, &fdset));
        ASSERT_TRUE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_ERROR(fd_validate(fd), EBADF);

        fd = ASSERT_OK_ERRNO(open("/dev/null", O_CLOEXEC|O_RDONLY));

        ASSERT_OK(fdset_new_fill(/* filter_cloexec= */ 0, &fdset));
        ASSERT_FALSE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_OK(fd_validate(fd));

        ASSERT_OK(fdset_new_fill(/* filter_cloexec= */ 1, &fdset));
        ASSERT_TRUE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_ERROR(fd_validate(fd), EBADF);

        fd = ASSERT_OK_ERRNO(open("/dev/null", O_RDONLY));

        ASSERT_OK(fdset_new_fill(/* filter_cloexec= */ 1, &fdset));
        ASSERT_FALSE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_OK(fd_validate(fd));

        ASSERT_OK(fdset_new_fill(/* filter_cloexec= */ 0, &fdset));
        ASSERT_TRUE(fdset_contains(fdset, fd));
        flags = ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        ASSERT_TRUE(FLAGS_SET(flags, FD_CLOEXEC));
        fdset = fdset_free(fdset);
        ASSERT_ERROR(fd_validate(fd), EBADF);

        log_open();
}

TEST(fdset_put_dup) {
        _cleanup_close_ int fd = -EBADF;
        int copyfd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_put_dup.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());
        copyfd = fdset_put_dup(fdset, fd);
        ASSERT_OK(copyfd);
        ASSERT_NE(copyfd, fd);
        ASSERT_TRUE(fdset_contains(fdset, copyfd));
        ASSERT_FALSE(fdset_contains(fdset, fd));
}

TEST(fdset_cloexec) {
        int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int flags = -1;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_cloexec.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());
        ASSERT_OK_POSITIVE(fdset_put(fdset, fd));

        ASSERT_OK(fdset_cloexec(fdset, false));
        flags = ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        ASSERT_FALSE(flags & FD_CLOEXEC);

        ASSERT_OK(fdset_cloexec(fdset, true));
        flags = ASSERT_OK_ERRNO(fcntl(fd, F_GETFD));
        ASSERT_TRUE(flags & FD_CLOEXEC);
}

TEST(fdset_close_others) {
        int fd = -EBADF, copyfd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_close_others.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());
        copyfd = ASSERT_OK(fdset_put_dup(fdset, fd));

        /* fdset_close_others() will close any logging file descriptors as well, so close them beforehand
         * and reopen them again afterwards. */
        log_close();
        ASSERT_OK(fdset_close_others(fdset));

        ASSERT_ERROR(fd_validate(fd), EBADF);

        /* Open log again after checking that fd is invalid, since reopening the log might make fd a valid
         * file descriptor again. */
        (void) log_open();

        ASSERT_OK(fd_validate(copyfd));
}

TEST(fdset_remove) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_remove.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_remove(fdset, fd));
        ASSERT_FALSE(fdset_contains(fdset, fd));

        ASSERT_OK(fd_validate(fd));
}

TEST(fdset_iterate) {
        int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_iterate.XXXXXX";
        int c = 0;
        int a;

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_put(fdset, fd));

        FDSET_FOREACH(a, fdset) {
                c++;
                ASSERT_EQ(a, fd);
        }
        ASSERT_EQ(c, 1);
}

TEST(fdset_isempty) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_isempty.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());

        ASSERT_TRUE(fdset_isempty(fdset));
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_FALSE(fdset_isempty(fdset));
}

TEST(fdset_steal_first) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_steal_first.XXXXXX";

        fd = ASSERT_OK(mkostemp_safe(name));

        fdset = ASSERT_NOT_NULL(fdset_new());

        ASSERT_FAIL(fdset_steal_first(fdset));
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK_EQ(fdset_steal_first(fdset), fd);
        ASSERT_FAIL(fdset_steal_first(fdset));
        ASSERT_OK(fdset_put(fdset, fd));
}

TEST(fdset_new_array) {
        int fds[] = {10, 11, 12, 13};
        _cleanup_fdset_free_ FDSet *fdset = NULL;

        ASSERT_OK(fdset_new_array(&fdset, fds, 4));
        ASSERT_EQ(fdset_size(fdset), 4U);
        ASSERT_TRUE(fdset_contains(fdset, 10));
        ASSERT_TRUE(fdset_contains(fdset, 11));
        ASSERT_TRUE(fdset_contains(fdset, 12));
        ASSERT_TRUE(fdset_contains(fdset, 13));
}

DEFINE_TEST_MAIN(LOG_INFO);
