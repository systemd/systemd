/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "errno-util.h"
#include "tests.h"

TEST(ASSERT) {
        char *null = NULL;

        ASSERT_OK(0);
        ASSERT_OK(255);
        ASSERT_OK(printf("Hello world\n"));
        ASSERT_SIGNAL(ASSERT_OK(-1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK(-ENOANO), SIGABRT);

        ASSERT_OK_POSITIVE(1);
        ASSERT_OK_POSITIVE(255);
        ASSERT_SIGNAL(ASSERT_OK_POSITIVE(0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_POSITIVE(-1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_POSITIVE(-ENOANO), SIGABRT);

        ASSERT_OK_ZERO(0);
        ASSERT_SIGNAL(ASSERT_OK_ZERO(1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO(255), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO(-1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO(-ENOANO), SIGABRT);

        ASSERT_OK_EQ(0, 0);
        ASSERT_SIGNAL(ASSERT_OK_EQ(1, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ(255, 5), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ(-1, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ(-ENOANO, 0), SIGABRT);

        ASSERT_OK_ERRNO(0 >= 0);
        ASSERT_OK_ERRNO(255 >= 0);
        ASSERT_OK_ERRNO(printf("Hello world\n"));
        ASSERT_SIGNAL(ASSERT_OK_ERRNO(-1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ERRNO(-ENOANO), SIGABRT);

        ASSERT_OK_ZERO_ERRNO(0);
        ASSERT_SIGNAL(ASSERT_OK_ZERO_ERRNO(1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO_ERRNO(255), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO_ERRNO(-1), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_ZERO_ERRNO(-ENOANO), SIGABRT);

        ASSERT_OK_EQ_ERRNO(0, 0);
        ASSERT_SIGNAL(ASSERT_OK_EQ_ERRNO(1, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ_ERRNO(255, 5), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ_ERRNO(-1, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_OK_EQ_ERRNO(-ENOANO, 0), SIGABRT);

        ASSERT_FAIL(-ENOENT);
        ASSERT_FAIL(-EPERM);
        ASSERT_SIGNAL(ASSERT_FAIL(0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_FAIL(255), SIGABRT);

        ASSERT_ERROR(-ENOENT, ENOENT);
        ASSERT_ERROR(RET_NERRNO(mkdir("/i/will/fail/with/enoent", 666)), ENOENT);
        ASSERT_SIGNAL(ASSERT_ERROR(0, ENOENT), SIGABRT);
        ASSERT_SIGNAL(ASSERT_ERROR(RET_NERRNO(mkdir("/i/will/fail/with/enoent", 666)), ENOANO), SIGABRT);

        errno = ENOENT;
        ASSERT_ERROR_ERRNO(-1, ENOENT);
        errno = 0;
        ASSERT_ERROR_ERRNO(mkdir("/i/will/fail/with/enoent", 666), ENOENT);
        ASSERT_SIGNAL(ASSERT_ERROR_ERRNO(0, ENOENT), SIGABRT);
        errno = 0;
        ASSERT_SIGNAL(ASSERT_ERROR_ERRNO(mkdir("/i/will/fail/with/enoent", 666), ENOANO), SIGABRT);

        ASSERT_TRUE(true);
        ASSERT_TRUE(255);
        ASSERT_TRUE(getpid());
        ASSERT_SIGNAL(ASSERT_TRUE(1 == 0), SIGABRT);

        ASSERT_FALSE(false);
        ASSERT_FALSE(1 == 0);
        ASSERT_SIGNAL(ASSERT_FALSE(1 > 0), SIGABRT);

        ASSERT_NULL(NULL);
        ASSERT_SIGNAL(ASSERT_NULL(signal_to_string(SIGINT)), SIGABRT);

        ASSERT_NOT_NULL(signal_to_string(SIGTERM));
        ASSERT_SIGNAL(ASSERT_NOT_NULL(NULL), SIGABRT);

        ASSERT_STREQ(NULL, null);
        ASSERT_STREQ("foo", "foo");
        ASSERT_SIGNAL(ASSERT_STREQ(null, "bar"), SIGABRT);
        ASSERT_SIGNAL(ASSERT_STREQ("foo", "bar"), SIGABRT);

        ASSERT_NOT_STREQ("foo", "bar");
        ASSERT_NOT_STREQ("foo", NULL);
        ASSERT_SIGNAL(ASSERT_NOT_STREQ("foo", "foo"), SIGABRT);
        ASSERT_SIGNAL(ASSERT_NOT_STREQ(NULL, NULL), SIGABRT);

        ASSERT_EQ(0, 0);
        ASSERT_EQ(-1, -1);
        ASSERT_SIGNAL(ASSERT_EQ(255, -1), SIGABRT);

        ASSERT_GE(0, 0);
        ASSERT_GE(1, -1);
        ASSERT_SIGNAL(ASSERT_GE(-1, 1), SIGABRT);

        ASSERT_LE(0, 0);
        ASSERT_LE(-1, 1);
        ASSERT_SIGNAL(ASSERT_LE(1, -1), SIGABRT);

        ASSERT_NE(0, (int64_t) UINT_MAX);
        ASSERT_NE(-1, 1);
        ASSERT_SIGNAL(ASSERT_NE(0, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_NE(-1, -1), SIGABRT);

        ASSERT_GT(1, 0);
        ASSERT_GT(1, -1);
        ASSERT_SIGNAL(ASSERT_GT(0, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_GT(-1, 1), SIGABRT);

        ASSERT_LT(0, 1);
        ASSERT_LT(-1, 1);
        ASSERT_SIGNAL(ASSERT_LT(0, 0), SIGABRT);
        ASSERT_SIGNAL(ASSERT_LT(1, -1), SIGABRT);

        ASSERT_EQ_ID128(SD_ID128_NULL, SD_ID128_NULL);
        ASSERT_NE_ID128(SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8),
                        SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e));
        ASSERT_SIGNAL(
                ASSERT_EQ_ID128(SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8),
                                SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e)),
                SIGABRT);
        ASSERT_SIGNAL(ASSERT_NE_ID128(SD_ID128_NULL, SD_ID128_NULL), SIGABRT);
}

TEST(ASSERT_OK_OR) {
        ASSERT_OK_OR(0, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(99, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(-EINVAL, -EINVAL, -EUCLEAN);
        ASSERT_OK_OR(-EUCLEAN, -EUCLEAN);
        ASSERT_OK_OR(-1, -EPERM);

        ASSERT_SIGNAL(ASSERT_OK_OR(-1, -2), SIGABRT);
}

/* Regression test for issue where assert_signal_internal() wasn't checking si_code before returning
 * si_status.
 *
 * In the bug case, siginfo.si_status has different meanings depending on siginfo.si_code:
 *
 *   - If si_code == CLD_EXITED: si_status is the exit code (0-255)
 *   - If si_code == CLD_KILLED/CLD_DUMPED: si_status is the signal number
 *
 * In the bug case where st_code is not checked, exit codes would be confused with signal numbers. For
 * example, if a child exits with code 6, it would incorrectly look like SIGABRT.
 *
 * This test verifies that exit codes are NOT confused with signal numbers, even when the exit code
 * numerically matches a signal number.
 */
TEST(ASSERT_SIGNAL_exit_code_vs_signal) {
        /* These exit codes numerically match common signal numbers, but ASSERT_SIGNAL should correctly
         * identify them as exit codes (si_code==CLD_EXITED), not signals. The inner ASSERT_SIGNAL expects a
         * signal but gets an exit code, so it should fail (aborting with SIGABRT), which the outer
         * ASSERT_SIGNAL then catches. */

        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(6), SIGABRT), SIGABRT);  /* 6 = SIGABRT */
        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(9), SIGKILL), SIGABRT);  /* 9 = SIGKILL */
        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(11), SIGSEGV), SIGABRT); /* 11 = SIGSEGV */
        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(15), SIGTERM), SIGABRT); /* 15 = SIGTERM */

        /* _exit(0) should not be confused with any signal */
        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(0), SIGABRT), SIGABRT);
}

/* Regression test for issue where returning 0 from assert_signal_internal() was ambiguous.
 *
 * In the bug case, when assert_signal_internal() returned 0, it could mean two different things:
 *
 *   1. We're in the child process (fork() just returned 0)
 *   2. We're in the parent and the child exited normally (no signal)
 *
 * The ASSERT_SIGNAL macro couldn't distinguish between these cases. When case #2 occurred, the macro would
 * re-enter the "if (_r == 0)" block, re-run the expression in the parent, and call _exit(EXIT_SUCCESS),
 * causing tests to incorrectly pass even when no signal occurred.
 *
 * The fix separates the question of which process we are in from which signal occurred:
 *
 *   - assert_signal_internal() now returns ASSERT_SIGNAL_FORK_CHILD (0) or ASSERT_SIGNAL_FORK_PARENT (1) to
 *     indicate execution path
 *   - The actual signal/status is passed via an output parameter (*ret_status)
 *
 * This allows the macro to unambiguously distinguish between being the child (path ==
 * ASSERT_SIGNAL_FORK_CHILD) and being the parent when the child has exited normally (path ==
 * ASSERT_SIGNAL_FORK_PARENT && status == 0).
 *
 * This test verifies that when a child exits normally (with exit code 0), ASSERT_SIGNAL correctly detects
 * that NO signal was raised, rather than being confused and thinking it's still in the child process.
 */
TEST(ASSERT_SIGNAL_exit_vs_child_process) {
        /* When a child calls _exit(0), it exits normally with code 0 (no signal). The parent's
         * assert_signal_internal() returns ASSERT_SIGNAL_FORK_PARENT, and sets ret_status to 0, meaning
         * there was no signal. This should NOT be confused with being the child process. The inner
         * ASSERT_SIGNAL expects SIGABRT but sees no signal, so it should fail, which the outerj
         * ASSERT_SIGNAL catches. */
        ASSERT_SIGNAL(ASSERT_SIGNAL(_exit(EXIT_SUCCESS), SIGABRT), SIGABRT);
}

TEST(ASSERT_SIGNAL_basic) {
        /* Correct behavior: expression raises expected signal */
        ASSERT_SIGNAL(abort(), SIGABRT);
        ASSERT_SIGNAL(raise(SIGTERM), SIGTERM);
        ASSERT_SIGNAL(raise(SIGSEGV), SIGSEGV);
        ASSERT_SIGNAL(raise(SIGILL), SIGILL);

        /* Wrong signal: inner ASSERT_SIGNAL expects SIGABRT but gets SIGTERM, so it fails (aborts), which
         * outer ASSERT_SIGNAL catches. */
        ASSERT_SIGNAL(ASSERT_SIGNAL(raise(SIGTERM), SIGABRT), SIGABRT);
        ASSERT_SIGNAL(ASSERT_SIGNAL(raise(SIGKILL), SIGTERM), SIGABRT);
}

DEFINE_TEST_MAIN(LOG_INFO);
