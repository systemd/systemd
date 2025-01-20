/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "tests.h"

TEST(pidref_is_set) {
        assert_se(!pidref_is_set(NULL));
        assert_se(!pidref_is_set(&PIDREF_NULL));
        assert_se(pidref_is_set(&PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_equal) {
        assert_se(pidref_equal(NULL, NULL));
        assert_se(pidref_equal(NULL, &PIDREF_NULL));
        assert_se(pidref_equal(&PIDREF_NULL, NULL));
        assert_se(pidref_equal(&PIDREF_NULL, &PIDREF_NULL));

        assert_se(!pidref_equal(NULL, &PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_equal(&PIDREF_MAKE_FROM_PID(1), NULL));
        assert_se(!pidref_equal(&PIDREF_NULL, &PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_NULL));
        assert_se(pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_equal(&PIDREF_MAKE_FROM_PID(1), &PIDREF_MAKE_FROM_PID(2)));
}

TEST(pidref_set_pid) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        r = pidref_set_pid(&pidref, 1);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        assert_se(r >= 0);

        assert_se(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(2)));
}

TEST(pidref_set_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        assert_se(pidref_set_self(&pidref) >= 0);
        assert_se(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached())));
        assert_se(!pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_set_pidstr) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        char buf[DECIMAL_STR_MAX(pid_t)];

        xsprintf(buf, PID_FMT, getpid_cached());
        assert_se(pidref_set_pidstr(&pidref, buf) >= 0);
        assert_se(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached())));
        assert_se(!pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_set_pidfd) {
        _cleanup_(pidref_done) PidRef a = PIDREF_NULL, b = PIDREF_NULL, c = PIDREF_NULL, d = PIDREF_NULL;

        assert_se(pidref_set_self(&a) >= 0);
        if (a.fd < 0)
                return (void) log_tests_skipped("PIDFD not supported");

        assert_se(pidref_set_pidfd(&b, a.fd) >= 0);
        assert_se(pidref_equal(&a, &b));
        assert_se(pidref_set_pidfd_take(&c, b.fd) >= 0);
        b.fd = -EBADF;
        assert_se(pidref_equal(&a, &c));
        assert_se(pidref_set_pidfd_consume(&d, TAKE_FD(c.fd)) >= 0);
        assert_se(pidref_equal(&a, &d));
}

TEST(pidref_is_self) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        assert_se(pidref_set_self(&pidref) >= 0);
        assert_se(pidref_is_self(&pidref));

        assert_se(!pidref_is_self(NULL));
        assert_se(!pidref_is_self(&PIDREF_NULL));
        assert_se(pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        assert_se(!pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_copy) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        assert_se(pidref_copy(NULL, &pidref) >= 0);
        assert_se(!pidref_is_set(&pidref));

        assert_se(pidref_copy(&PIDREF_NULL, &pidref) >= 0);
        assert_se(!pidref_is_set(&pidref));

        assert_se(pidref_copy(&PIDREF_MAKE_FROM_PID(getpid_cached()), &pidref) >= 0);
        assert_se(pidref_is_self(&pidref));
        pidref_done(&pidref);

        r = pidref_copy(&PIDREF_MAKE_FROM_PID(1), &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        assert_se(r >= 0);
        assert_se(pidref_equal(&pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_dup) {
        _cleanup_(pidref_freep) PidRef *pidref = NULL;
        int r;

        assert_se(pidref_dup(NULL, &pidref) >= 0);
        assert_se(pidref);
        assert_se(!pidref_is_set(pidref));
        pidref = pidref_free(pidref);

        assert_se(pidref_dup(&PIDREF_NULL, &pidref) >= 0);
        assert_se(pidref);
        assert_se(!pidref_is_set(pidref));
        pidref = pidref_free(pidref);

        assert_se(pidref_dup(&PIDREF_MAKE_FROM_PID(getpid_cached()), &pidref) >= 0);
        assert_se(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        r = pidref_dup(&PIDREF_MAKE_FROM_PID(1), &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        assert_se(r >= 0);
        assert_se(pidref_equal(pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_new_from_pid) {
        _cleanup_(pidref_freep) PidRef *pidref = NULL;
        int r;

        assert_se(pidref_new_from_pid(-1, &pidref) == -ESRCH);
        assert_se(!pidref);

        assert_se(pidref_new_from_pid(0, &pidref) >= 0);
        assert_se(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        assert_se(pidref_new_from_pid(getpid_cached(), &pidref) >= 0);
        assert_se(pidref_is_self(pidref));
        pidref = pidref_free(pidref);

        r = pidref_new_from_pid(1, &pidref);
        if (r == -ESRCH)
                return (void) log_tests_skipped_errno(r, "PID1 does not exist");
        assert_se(r >= 0);
        assert_se(pidref_equal(pidref, &PIDREF_MAKE_FROM_PID(1)));
}

TEST(pidref_kill) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-kill)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));

        assert_se(pidref_kill(&pidref, SIGKILL) >= 0);
        assert_se(pidref_wait_for_terminate(&pidref, &si) >= 0);
        assert_se(si.si_signo == SIGCHLD);
}

TEST(pidref_kill_and_sigcont) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-kill-and-sigcont)", FORK_DEATHSIG_SIGTERM|FORK_FREEZE, &pidref));

        assert_se(pidref_kill_and_sigcont(&pidref, SIGTERM) >= 0);
        assert_se(pidref_wait_for_terminate(&pidref, &si) >= 0);
        assert_se(si.si_signo == SIGCHLD);
}

TEST(pidref_sigqueue) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-sigqueue)", FORK_DEATHSIG_SIGTERM|FORK_FREEZE, &pidref));

        assert_se(pidref_sigqueue(&pidref, SIGTERM, 42) >= 0);
        assert_se(pidref_wait_for_terminate(&pidref, &si) >= 0);
        assert_se(si.si_signo == SIGCHLD);
}

TEST(pidref_done_sigkill_wait) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;

        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-pidref-done-sigkill-wait)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));
}

TEST(pidref_verify) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

        assert_se(pidref_verify(NULL) == -ESRCH);
        assert_se(pidref_verify(&PIDREF_NULL) == -ESRCH);

        assert_se(pidref_verify(&PIDREF_MAKE_FROM_PID(1)) == 1);
        assert_se(pidref_verify(&PIDREF_MAKE_FROM_PID(getpid_cached())) == 0);

        assert_se(pidref_set_self(&pidref) >= 0);
        assert_se(pidref_verify(&pidref) == (pidref.fd >= 0));
}

TEST(pidref_is_automatic) {
        assert_se(!pidref_is_automatic(NULL));
        assert_se(!pidref_is_automatic(&PIDREF_NULL));
        assert_se(!pidref_is_automatic(&PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_is_automatic(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        assert_se(pidref_is_automatic(&PIDREF_AUTOMATIC));

        assert_se(!pid_is_automatic(0));
        assert_se(!pid_is_automatic(1));
        assert_se(!pid_is_automatic(getpid_cached()));
        assert_se(pid_is_automatic(PID_AUTOMATIC));

        assert_se(!pidref_is_set(&PIDREF_AUTOMATIC));
        assert_se(!pid_is_valid(PID_AUTOMATIC));
}

TEST(pidref_is_remote) {
        assert_se(!pidref_is_remote(NULL));
        assert_se(!pidref_is_remote(&PIDREF_NULL));
        assert_se(!pidref_is_remote(&PIDREF_MAKE_FROM_PID(1)));
        assert_se(!pidref_is_remote(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        assert_se(!pidref_is_remote(&PIDREF_AUTOMATIC));

        PidRef p = {
                .pid = 1,
                .fd = -EREMOTE,
                .fd_id = 4711,
        };

        assert_se(pidref_is_set(&p));
        assert_se(pidref_is_remote(&p));
        assert_se(!pidref_is_automatic(&p));
        assert_se(pidref_kill(&p, SIGTERM) == -EREMOTE);
        assert_se(pidref_kill_and_sigcont(&p, SIGTERM) == -EREMOTE);
        assert_se(pidref_wait_for_terminate(&p, /* ret= */ NULL) == -EREMOTE);
        assert_se(pidref_verify(&p) == -EREMOTE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
