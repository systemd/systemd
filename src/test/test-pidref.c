/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>

#include "sd-event.h"
#include "sd-future.h"

#include "fd-util.h"
#include "format-util.h"
#include "pidref.h"
#include "process-util.h"
#include "stdio-util.h"
#include "tests.h"
#include "time-util.h"

TEST(pidref_is_set) {
        ASSERT_FALSE(pidref_is_set(/* pidref= */ NULL));
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

        ASSERT_FALSE(pidref_is_self(/* pidref= */ NULL));
        ASSERT_FALSE(pidref_is_self(&PIDREF_NULL));
        ASSERT_TRUE(pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached())));
        ASSERT_FALSE(pidref_is_self(&PIDREF_MAKE_FROM_PID(getpid_cached()+1)));
}

TEST(pidref_copy) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        ASSERT_OK(pidref_copy(/* pidref= */ NULL, &pidref));
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

        ASSERT_OK(pidref_dup(/* pidref= */ NULL, &pidref));
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

        ASSERT_OK(pidref_new_from_pid(/* pid= */ 0, &pidref));
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

        ASSERT_ERROR(pidref_verify(/* pidref= */ NULL), ESRCH);
        ASSERT_ERROR(pidref_verify(&PIDREF_NULL), ESRCH);

        ASSERT_OK_POSITIVE(pidref_verify(&PIDREF_MAKE_FROM_PID(1)));
        ASSERT_OK_ZERO(pidref_verify(&PIDREF_MAKE_FROM_PID(getpid_cached())));

        ASSERT_OK(pidref_set_self(&pidref));
        ASSERT_OK(r = pidref_verify(&pidref));
        ASSERT_EQ(r, (pidref.fd >= 0));
}

TEST(pidref_is_automatic) {
        ASSERT_FALSE(pidref_is_automatic(/* pidref= */ NULL));
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
        ASSERT_FALSE(pidref_is_remote(/* pidref= */ NULL));
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
        ASSERT_ERROR(pidref_wait_for_terminate(&p, /* ret_si= */ NULL), EREMOTE);
        ASSERT_ERROR(pidref_verify(&p), EREMOTE);
}

TEST(pidref_wait_for_terminate_timeout) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;

        /* Test successful termination within timeout */
        ASSERT_OK(pidref_safe_fork("(test-pidref-wait-timeout)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));

        ASSERT_OK(pidref_kill(&pidref, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate_full(&pidref, 5 * USEC_PER_SEC, &si));
        ASSERT_EQ(si.si_signo, SIGCHLD);

        pidref_done(&pidref);

        /* Test timeout when process doesn't terminate */
        ASSERT_OK(pidref_safe_fork("(test-pidref-wait-timeout-expired)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &pidref));
        ASSERT_ERROR(pidref_wait_for_terminate_full(&pidref, 100 * USEC_PER_MSEC, /* ret_si= */ NULL), ETIMEDOUT);
}

static int wait_uninterruptible_fiber(void *userdata) {
        PidRef *pidref = ASSERT_PTR(userdata);

        /* The test cancels the fiber twice during the wait. The shield of the wait hides the first
         * cancel. The second one makes the cancellation hard, which kills the child with SIGKILL. The
         * wait goes on until the child is gone. */
        ASSERT_OK(pidref_wait_for_terminate_uninterruptible(pidref));

        /* The cancellation stays in effect. */
        ASSERT_ERROR(sd_fiber_interrupted(), ECANCELED);

        /* The child was reaped. */
        siginfo_t si = {};
        ASSERT_ERROR_ERRNO(waitid(P_PIDFD, pidref->fd, &si, WEXITED|WNOHANG), ECHILD);
        return 0;
}

TEST(pidref_wait_for_terminate_uninterruptible) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        r = ASSERT_OK(pidref_safe_fork("(test-wait)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref));
        if (r == 0) {
                (void) usleep_safe(10 * USEC_PER_SEC);
                _exit(EXIT_SUCCESS);
        }

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_fiber_new(e, "wait-uninterruptible", wait_uninterruptible_fiber, &pidref, &f));

        while (sd_fiber_get_awaiting(f) == NULL)
                ASSERT_OK(sd_event_run(e, 0));

        usec_t start = now(CLOCK_MONOTONIC);

        ASSERT_OK_POSITIVE(sd_future_cancel(f));
        ASSERT_OK(sd_event_run(e, 100 * USEC_PER_MSEC));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);
        ASSERT_NOT_NULL(sd_fiber_get_awaiting(f));

        ASSERT_OK_POSITIVE(sd_future_cancel(f));

        while (sd_future_state(f) == SD_FUTURE_PENDING)
                ASSERT_OK(sd_event_run(e, UINT64_MAX));
        ASSERT_OK_ZERO(sd_future_result(f));
        ASSERT_LT(usec_sub_unsigned(now(CLOCK_MONOTONIC), start), 5 * USEC_PER_SEC);
}

static int wait_on_exit_fiber(void *userdata) {
        PidRef *pidref = ASSERT_PTR(userdata);

        /* The event loop exit cancels the sleep. */
        ASSERT_ERROR(sd_fiber_sleep(USEC_INFINITY), ECANCELED);

        /* While the event loop exits, every suspension point fails right away. The wait has to block
         * instead of retrying in a busy loop until the child exits. */
        struct rusage before, after;
        ASSERT_OK_ERRNO(getrusage(RUSAGE_SELF, &before));
        pidref_done_sigterm_wait(pidref);
        ASSERT_OK_ERRNO(getrusage(RUSAGE_SELF, &after));

        usec_t cpu = timeval_load(&after.ru_utime) + timeval_load(&after.ru_stime) -
                     timeval_load(&before.ru_utime) - timeval_load(&before.ru_stime);
        log_info("Waiting for the child during exit took %s of CPU time.", FORMAT_TIMESPAN(cpu, USEC_PER_MSEC));
        ASSERT_LT(cpu, 300 * USEC_PER_MSEC);
        return 0;
}

TEST(pidref_wait_for_terminate_uninterruptible_on_exit) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pfd, O_CLOEXEC));

        r = ASSERT_OK(pidref_safe_fork("(test-wait-exit)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pidref));
        if (r == 0) {
                /* Ignore the SIGTERM of pidref_done_sigterm_wait(), so that the wait takes a while. */
                (void) signal(SIGTERM, SIG_IGN);
                pfd[0] = safe_close(pfd[0]);
                pfd[1] = safe_close(pfd[1]);
                (void) usleep_safe(1 * USEC_PER_SEC);
                _exit(EXIT_SUCCESS);
        }

        /* The read returns EOF once the child ignores SIGTERM and has closed its end of the pipe. */
        pfd[1] = safe_close(pfd[1]);
        char x;
        ASSERT_OK_ZERO_ERRNO(read(pfd[0], &x, 1));

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_fiber_new(e, "wait-on-exit", wait_on_exit_fiber, &pidref, &f));

        /* Run the fiber until it sleeps. */
        ASSERT_OK(sd_event_run(e, 0));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_PENDING);

        ASSERT_OK(sd_event_exit(e, 0));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_state(f), SD_FUTURE_RESOLVED);
        ASSERT_OK_ZERO(sd_future_result(f));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
