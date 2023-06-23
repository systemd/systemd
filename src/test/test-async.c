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
#include "tests.h"
#include "tmpfile-util.h"

TEST(test_asynchronous_sync) {
        assert_se(asynchronous_sync(NULL) >= 0);
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

                assert(make_reaper_process(true) >= 0);

                fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
                assert_se(fd >= 0);
                asynchronous_close(fd);

                sleep(1);

                assert_se(fcntl(fd, F_GETFD) == -1);
                assert_se(errno == EBADF);

                _exit(EXIT_SUCCESS);
        }
}

TEST(asynchronous_rm_rf) {
        _cleanup_free_ char *t = NULL, *k = NULL;
        int r;

        assert_se(mkdtemp_malloc(NULL, &t) >= 0);
        assert_se(k = path_join(t, "somefile"));
        assert_se(touch(k) >= 0);
        assert_se(asynchronous_rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        /* Do this once more, form a subreaper. Which is nice, because we can watch the async child even
         * though detached */

        r = safe_fork("(subreaper)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        assert_se(r >= 0);

        if (r == 0) {
                _cleanup_free_ char *tt = NULL, *kk = NULL;

                /* child */

                assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, -1) >= 0);
                assert_se(make_reaper_process(true) >= 0);

                assert_se(mkdtemp_malloc(NULL, &tt) >= 0);
                assert_se(kk = path_join(tt, "somefile"));
                assert_se(touch(kk) >= 0);
                assert_se(asynchronous_rm_rf(tt, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

                for (;;) {
                        siginfo_t si = {};

                        assert_se(waitid(P_ALL, 0, &si, WEXITED) >= 0);

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
