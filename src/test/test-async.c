/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "async.h"
#include "fs-util.h"
#include "process-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static bool test_async = false;

static void *async_func(void *arg) {
        test_async = true;

        return NULL;
}

TEST(test_async) {
        assert_se(asynchronous_job(async_func, NULL) >= 0);
        assert_se(asynchronous_sync(NULL) >= 0);

        assert_se(test_async);
}

TEST(asynchronous_close) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-asynchronous_close.XXXXXX";
        int fd, r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        asynchronous_close(fd);

        sleep(1);

        assert_se(fcntl(fd, F_GETFD) == -1);
        assert_se(errno == EBADF);

        r = safe_fork("(subreaper)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        assert(r >= 0);

        if (r == 0) {
                /* child */

                assert(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) >= 0);

                fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
                assert_se(fd >= 0);
                asynchronous_close(fd);

                sleep(1);

                assert_se(fcntl(fd, F_GETFD) == -1);
                assert_se(errno == EBADF);

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
