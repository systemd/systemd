/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "fd-util.h"
#include "fdset.h"
#include "fs-util.h"
#include "macro.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(fdset_new_fill) {
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int fd = -EBADF, flags;

        log_close();
        log_set_open_when_needed(true);

        fd = open("/dev/null", O_CLOEXEC|O_RDONLY);
        ASSERT_OK(fd);

        assert_se(fdset_new_fill(/* filter_cloexec= */ -1, &fdset) >= 0);
        ASSERT_TRUE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_LT(fcntl(fd, F_GETFD), 0);
        assert_se(errno == EBADF);

        fd = open("/dev/null", O_CLOEXEC|O_RDONLY);
        ASSERT_OK(fd);

        assert_se(fdset_new_fill(/* filter_cloexec= */ 0, &fdset) >= 0);
        ASSERT_FALSE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_OK(fcntl(fd, F_GETFD));

        assert_se(fdset_new_fill(/* filter_cloexec= */ 1, &fdset) >= 0);
        ASSERT_TRUE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_LT(fcntl(fd, F_GETFD), 0);
        assert_se(errno == EBADF);

        fd = open("/dev/null", O_RDONLY);
        ASSERT_OK(fd);

        assert_se(fdset_new_fill(/* filter_cloexec= */ 1, &fdset) >= 0);
        ASSERT_FALSE(fdset_contains(fdset, fd));
        fdset = fdset_free(fdset);
        ASSERT_OK(fcntl(fd, F_GETFD));

        assert_se(fdset_new_fill(/* filter_cloexec= */ 0, &fdset) >= 0);
        ASSERT_TRUE(fdset_contains(fdset, fd));
        flags = fcntl(fd, F_GETFD);
        ASSERT_OK(flags);
        ASSERT_TRUE(FLAGS_SET(flags, FD_CLOEXEC));
        fdset = fdset_free(fdset);
        ASSERT_LT(fcntl(fd, F_GETFD), 0);
        assert_se(errno == EBADF);

        log_open();
}

TEST(fdset_put_dup) {
        _cleanup_close_ int fd = -EBADF;
        int copyfd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_put_dup.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);
        copyfd = fdset_put_dup(fdset, fd);
        assert_se(copyfd >= 0 && copyfd != fd);
        ASSERT_TRUE(fdset_contains(fdset, copyfd));
        ASSERT_FALSE(fdset_contains(fdset, fd));
}

TEST(fdset_cloexec) {
        int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int flags = -1;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_cloexec.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);
        ASSERT_TRUE(fdset_put(fdset, fd));

        ASSERT_OK(fdset_cloexec(fdset, false));
        flags = fcntl(fd, F_GETFD);
        ASSERT_OK(flags);
        assert_se(!(flags & FD_CLOEXEC));

        ASSERT_OK(fdset_cloexec(fdset, true));
        flags = fcntl(fd, F_GETFD);
        ASSERT_OK(flags);
        assert_se(flags & FD_CLOEXEC);
}

TEST(fdset_close_others) {
        int fd = -EBADF;
        int copyfd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int flags = -1;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_close_others.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);
        copyfd = fdset_put_dup(fdset, fd);
        ASSERT_OK(copyfd);

        ASSERT_OK(fdset_close_others(fdset));
        flags = fcntl(fd, F_GETFD);
        ASSERT_LT(flags, 0);
        flags = fcntl(copyfd, F_GETFD);
        ASSERT_OK(flags);
}

TEST(fdset_remove) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_remove.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_remove(fdset, fd));
        ASSERT_FALSE(fdset_contains(fdset, fd));

        ASSERT_OK(fcntl(fd, F_GETFD));
}

TEST(fdset_iterate) {
        int fd = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_iterate.XXXXXX";
        int c = 0;
        int a;

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_OK(fdset_put(fdset, fd));

        FDSET_FOREACH(a, fdset) {
                c++;
                assert_se(a == fd);
        }
        ASSERT_EQ(c, 1);
}

TEST(fdset_isempty) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_isempty.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);

        ASSERT_TRUE(fdset_isempty(fdset));
        ASSERT_OK(fdset_put(fdset, fd));
        ASSERT_FALSE(fdset_isempty(fdset));
}

TEST(fdset_steal_first) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fdset_steal_first.XXXXXX";

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);

        fdset = fdset_new();
        ASSERT_TRUE(fdset);

        ASSERT_LT(fdset_steal_first(fdset), 0);
        ASSERT_OK(fdset_put(fdset, fd));
        assert_se(fdset_steal_first(fdset) == fd);
        ASSERT_LT(fdset_steal_first(fdset), 0);
        ASSERT_OK(fdset_put(fdset, fd));
}

TEST(fdset_new_array) {
        int fds[] = {10, 11, 12, 13};
        _cleanup_fdset_free_ FDSet *fdset = NULL;

        assert_se(fdset_new_array(&fdset, fds, 4) >= 0);
        ASSERT_EQ(fdset_size(fdset), 4u);
        ASSERT_TRUE(fdset_contains(fdset, 10));
        ASSERT_TRUE(fdset_contains(fdset, 11));
        ASSERT_TRUE(fdset_contains(fdset, 12));
        ASSERT_TRUE(fdset_contains(fdset, 13));
}

DEFINE_TEST_MAIN(LOG_INFO);
