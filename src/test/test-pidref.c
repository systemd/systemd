/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "format-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stdio-util.h"
#include "tests.h"
#include "time-util.h"

TEST(pidref_is_set) {
        ASSERT_FALSE(pidref_is_set(NULL));
        ASSERT_FALSE(pidref_is_set(&PIDREF_NULL));
        ASSERT_TRUE(pidref_is_set(&PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_equal) {
        ASSERT_TRUE(pidref_equal(NULL, NULL));
        ASSERT_TRUE(pidref_equal(NULL, &PIDREF_NULL));
        ASSERT_TRUE(pidref_equal(&PIDREF_NULL, NULL));
        ASSERT_TRUE(pidref_equal(&PIDREF_NULL, &PIDREF_NULL));

        ASSERT_FALSE(pidref_equal(NULL, &PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_equal(&PIDREF_MAKE_FROM_PID(1), NULL));
        ASSERT_FALSE(pidref_equal(&PIDREF_NULL, &PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_NULL));
        ASSERT_TRUE(pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_MAKE_FROM_PID(2)));
}

TEST(pidref_set_pid) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        r = pidref_set_pid(&pidref, 1);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        ASSERT_OK(r);

        ASSERT_TRUE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(2)));
}

TEST(pidref_set_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        ASSERT_OK(pidref_set_self(&pidref));
        ASSERT_TRUE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_FALSE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_set_pidstr) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        char buf[DECIMAL_STR_MAX(pid_t)];

        xsprintf(buf, PID_FMT, getpid_cached());
        ASSERT_OK(pidref_set_pidstr(&pidref, buf));
        ASSERT_TRUE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_FALSE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_set_pidfd) {
        _cleanup_(pidref_done) PidRef a = PIDREF_NULL, b = PIDREF_NULL, c = PIDREF_NULL, d = PIDREF_NULL;

        ASSERT_OK(pidref_set_self(&a));
        if (a.fd < 0)
                return (void) log_tests_skipped("PIDFD not supported");

        ASSERT_OK(pidref_set_pidfd(&b, a.fd));
        ASSERT_TRUE(pidref_equal(&a, &b));
        ASSERT_OK(pidref_set_pidfd_take(&c, b.fd));
        b.fd = -EBADF;
        ASSERT_TRUE(pidref_equal(&a, &c));
        ASSERT_OK(pidref_set_pidfd_consume(&d, TAKE_FD(c.fd)));
        ASSERT_TRUE(pidref_equal(&a, &d));
}

TEST(pidref_is_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        ASSERT_OK(pidref_set_self(&pidref));
        ASSERT_TRUE(pidref_is_self(&pidref));

        ASSERT_FALSE(pidref_is_self(NULL));
        ASSERT_FALSE(pidref_is_self(&PIDREF_NULL));
        ASSERT_TRUE(pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_FALSE(pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_copy) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        ASSERT_OK(pidref_copy(NULL, &pidref));
        ASSERT_FALSE(pidref_is_set(&pidref));

        ASSERT_OK(pidref_copy(&PIDREF_NULL, &pidref));
        ASSERT_FALSE(pidref_is_set(&pidref));

        ASSERT_OK(pidref_copy(&PIDREF_MAKE_FROM_PID(getpid_cached()), &pidref));
        ASSERT_TRUE(pidref_is_self(&pidref));
        pidref_done(&pidref);

        r = pidref_copy(&PIDREF_MAKE_FROM_PID(1), &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        ASSERT_OK(r);
        ASSERT_TRUE(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_dup) {
        _cleanup_(pidref_freep) PidRef *pidref = NULL;
        int r;

        ASSERT_OK(pidref_dup(NULL, &pidref));
        ASSERT_NOT_NULL(pidref);
        ASSERT_FALSE(pidref_is_set(pidref));
        pidref = pidref_free(pidref);

        ASSERT_OK(pidref_dup(&PIDREF_NULL, &pidref));
        ASSERT_NOT_NULL(pidref);
        ASSERT_FALSE(pidref_is_set(pidref));
        pidref = pidref_free(pidref);

        ASSERT_OK(pidref_dup(&PIDREF_MAKE_FROM_PID(getpid_cached()), &pidref));
        ASSERT_TRUE(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        r = pidref_dup(&PIDREF_MAKE_FROM_PID(1), &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        ASSERT_OK(r);
        ASSERT_TRUE(pidref_equal(pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_new_from_pid) {
        _cleanup_(pidref_freep) PidRef *pidref = NULL;
        int r;

        ASSERT_ERROR(pidref_new_from_pid(-1, &pidref), ESRCH);
        ASSERT_NULL(pidref);

        ASSERT_OK(pidref_new_from_pid(0, &pidref));
        ASSERT_TRUE(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        ASSERT_OK(pidref_new_from_pid(getpid_cached(), &pidref));
        ASSERT_TRUE(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        r = pidref_new_from_pid(1, &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        ASSERT_OK(r);
        ASSERT_TRUE(pidref_equal(pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_kill) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-kill)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));

        ASSERT_OK(pidref_kill(&pidref, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_signo, SIGCHLD);
}

TEST(pidref_kill_and_sigcont) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-kill-and-sigcont)", FORK_DEATHSIG_SIGTERM|FORK_FREEZE, &pidref));

        ASSERT_OK(pidref_kill_and_sigcont(&pidref, SIGTERM));
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_signo, SIGCHLD);
}

TEST(pidref_sigqueue) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-sigqueue)", FORK_DEATHSIG_SIGTERM|FORK_FREEZE, &pidref));

        ASSERT_OK(pidref_sigqueue(&pidref, SIGTERM, 42));
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_signo, SIGCHLD);
}

TEST(pidref_done_sigkill_wait) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-done-sigkill-wait)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));
}

TEST(pidref_verify) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        ASSERT_ERROR(pidref_verify(NULL), ESRCH);
        ASSERT_ERROR(pidref_verify(&PIDREF_NULL), ESRCH);

        ASSERT_OK_POSITIVE(pidref_verify(&PIDREF_MAKE_FROM_PID(1)));
        ASSERT_OK_ZERO(pidref_verify(&PIDREF_MAKE_FROM_PID(getpid_cached())));

        ASSERT_OK(pidref_set_self(&pidref));
        ASSERT_OK(r = pidref_verify(&pidref));
        ASSERT_EQ(r, (pidref.fd >= 0));
}

TEST(pidref_is_automatic) {
        ASSERT_FALSE(pidref_is_automatic(NULL));
        ASSERT_FALSE(pidref_is_automatic(&PIDREF_NULL));
        ASSERT_FALSE(pidref_is_automatic(&PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_is_automatic(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_TRUE(pidref_is_automatic(&PIDREF_AUTOMATIC));

        ASSERT_FALSE(pid_is_automatic(0));
        ASSERT_FALSE(pid_is_automatic(1));
        ASSERT_FALSE(pid_is_automatic(getpid_cached()));
        ASSERT_TRUE(pid_is_automatic(PID_AUTOMATIC));

        ASSERT_FALSE(pidref_is_set(&PIDREF_AUTOMATIC));
        ASSERT_FALSE(pid_is_valid(PID_AUTOMATIC));
}

TEST(pidref_is_remote) {
        ASSERT_FALSE(pidref_is_remote(NULL));
        ASSERT_FALSE(pidref_is_remote(&PIDREF_NULL));
        ASSERT_FALSE(pidref_is_remote(&PIDREF_MAKE_FROM_PID(1)));
        ASSERT_FALSE(pidref_is_remote(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_FALSE(pidref_is_remote(&PIDREF_AUTOMATIC));

        PidRef p = {
                .pid = 1,
                .fd = -EREMOTE,
                .fd_id = 4711,
        };

        ASSERT_TRUE(pidref_is_set(&p));
        ASSERT_TRUE(pidref_is_remote(&p));
        ASSERT_FALSE(pidref_is_automatic(&p));
        ASSERT_ERROR(pidref_kill(&p, SIGTERM), EREMOTE);
        ASSERT_ERROR(pidref_kill_and_sigcont(&p, SIGTERM), EREMOTE);
        ASSERT_ERROR(pidref_wait_for_terminate(&p, NULL), EREMOTE);
        ASSERT_ERROR(pidref_verify(&p), EREMOTE);
}

TEST(pidref_wait_for_terminate_timeout) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        /* Test successful termination within timeout */
        ASSERT_OK(pidref_safe_fork("(test-pidref-wait-timeout)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));

        assert_se(pidref_kill(&pidref, SIGKILL) >= 0);
        ASSERT_OK(pidref_wait_for_terminate_full(&pidref, 5 * USEC_PER_SEC, &si));
        ASSERT_EQ(si.si_signo, SIGCHLD);

        pidref_done(&pidref);

        /* Test timeout when process doesn't terminate */
        ASSERT_OK(pidref_safe_fork("(test-pidref-wait-timeout-expired)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));
        ASSERT_ERROR(pidref_wait_for_terminate_full(&pidref, 100 * USEC_PER_MSEC, NULL), ETIMEDOUT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
