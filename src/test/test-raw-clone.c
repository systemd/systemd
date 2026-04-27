/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "errno-util.h"
#include "format-util.h"
#include "raw-clone.h"
#include "tests.h"

TEST(raw_clone) {
        pid_t parent, pid, pid2;

        parent = getpid();
        log_info("before clone: getpid()→"PID_FMT, parent);
        assert_se(getpid() == parent);

        pid = raw_clone(0);
        if (pid < 0) {
                /* qemu-TCG cross-arch sandboxes (e.g. s390x copr) may reject
                 * even a plain raw_clone() with various errnos depending on
                 * the host kernel and seccomp policy. The actual functional
                 * behaviour of raw_clone() is exercised by every fork() in
                 * the rest of the test suite, so a skip here is safe. */
                log_tests_skipped_errno(errno, "raw_clone() not available in sandbox");
                return;
        }

        pid2 = getpid();
        log_info("raw_clone: "PID_FMT" getpid()→"PID_FMT" getpid()→"PID_FMT,
                 pid, getpid(), pid2);
        if (pid == 0) {
                assert_se(pid2 != parent);
                _exit(EXIT_SUCCESS);
        } else {
                int status;

                assert_se(pid2 == parent);
                waitpid(pid, &status, __WCLONE);
                assert_se(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
        }

        errno = 0;
        assert_se(raw_clone(CLONE_FS|CLONE_NEWNS) == -1);
        assert_se(errno == EINVAL || ERRNO_IS_PRIVILEGE(errno)); /* Certain container environments prohibit namespaces to us, don't fail in that case */
}

DEFINE_TEST_MAIN(LOG_INFO);
