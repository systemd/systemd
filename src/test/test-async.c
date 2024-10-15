/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "async.h"
#include "fs-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "time-util.h"
#include "tests.h"
#include "tmpfile-util.h"

TEST(asynchronous_sync) {
        ASSERT_OK(asynchronous_sync(NULL));
}

static void wait_fd_closed(int fd) {
        for (unsigned trial = 0; trial < 100; trial++) {
                usleep_safe(100 * USEC_PER_MSEC);
                if (fcntl(fd, F_GETFD) < 0) {
                        assert_se(errno == EBADF);
                        return;
                }
        }

        assert_not_reached();
}

TEST(asynchronous_close) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-asynchronous_close.XXXXXX";
        int fd, r;

        fd = mkostemp_safe(name);
        ASSERT_OK(fd);
        asynchronous_close(fd);
        wait_fd_closed(fd);

        r = safe_fork("(subreaper)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL|FORK_LOG|FORK_WAIT, NULL);
        ASSERT_OK(r);

        if (r == 0) {
                /* child */

                ASSERT_OK(make_reaper_process(true));

                fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
                ASSERT_OK(fd);
                asynchronous_close(fd);
                wait_fd_closed(fd);

                _exit(EXIT_SUCCESS);
        }
}

static void wait_rm_rf(const char *path) {
        for (unsigned trial = 0; trial < 100; trial++) {
                usleep_safe(100 * USEC_PER_MSEC);
                if (access(path, F_OK) < 0) {
                        assert_se(errno == ENOENT);
                        return;
                }
        }

        assert_not_reached();
}

TEST(asynchronous_rm_rf) {
        _cleanup_free_ char *t = NULL, *k = NULL;
        int r;

        ASSERT_OK(mkdtemp_malloc(NULL, &t));
        assert_se(k = path_join(t, "somefile"));
        ASSERT_OK(touch(k));
        ASSERT_OK(asynchronous_rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
        wait_rm_rf(t);

        /* Do this once more, from a subreaper. Which is nice, because we can watch the async child even
         * though detached */

        r = safe_fork("(subreaper)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT, NULL);
        ASSERT_OK(r);

        if (r == 0) {
                _cleanup_free_ char *tt = NULL, *kk = NULL;

                /* child */

                ASSERT_OK(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD));
                ASSERT_OK(make_reaper_process(true));

                ASSERT_OK(mkdtemp_malloc(NULL, &tt));
                assert_se(kk = path_join(tt, "somefile"));
                ASSERT_OK(touch(kk));
                ASSERT_OK(asynchronous_rm_rf(tt, REMOVE_ROOT|REMOVE_PHYSICAL));

                for (;;) {
                        siginfo_t si = {};

                        ASSERT_OK(waitid(P_ALL, 0, &si, WEXITED));

                        if (access(tt, F_OK) < 0) {
                                assert_se(errno == ENOENT);
                                break;
                        }

                        /* wasn't the rm_rf() call. let's wait longer */
                }

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
