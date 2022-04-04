/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * IPC barrier tests
 * These tests verify the correct behavior of the IPC Barrier implementation.
 * Note that the tests use alarm-timers to verify dead-locks and timeouts. These
 * might not work on slow machines where 20ms are too short to perform specific
 * operations (though, very unlikely). In case that turns out true, we have to
 * increase it at the slightly cost of lengthen test-duration on other machines.
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "barrier.h"
#include "errno-util.h"
#include "tests.h"
#include "time-util.h"
#include "util.h"
#include "virt.h"

/* 20ms to test deadlocks; All timings use multiples of this constant as
 * alarm/sleep timers. If this timeout is too small for slow machines to perform
 * the requested operations, we have to increase it. On an i7 this works fine
 * with 1ms base-time, so 20ms should be just fine for everyone. */
#define BASE_TIME (20 * USEC_PER_MSEC)

static void set_alarm(usec_t usecs) {
        struct itimerval v = { };

        timeval_store(&v.it_value, usecs);
        assert_se(setitimer(ITIMER_REAL, &v, NULL) >= 0);
}

static void sleep_for(usec_t usecs) {
        /* stupid usleep() might fail if >1000000 */
        assert_se(usecs < USEC_PER_SEC);
        usleep(usecs);
}

#define TEST_BARRIER(_FUNCTION, _CHILD_CODE, _WAIT_CHILD, _PARENT_CODE, _WAIT_PARENT)  \
        TEST(_FUNCTION) {                                               \
                Barrier b = BARRIER_NULL;                               \
                pid_t pid1, pid2;                                       \
                                                                        \
                assert_se(barrier_create(&b) >= 0);                     \
                assert_se(b.me > 0);                                    \
                assert_se(b.them > 0);                                  \
                assert_se(b.pipe[0] > 0);                               \
                assert_se(b.pipe[1] > 0);                               \
                                                                        \
                pid1 = fork();                                          \
                assert_se(pid1 >= 0);                                   \
                if (pid1 == 0) {                                        \
                        barrier_set_role(&b, BARRIER_CHILD);            \
                        { _CHILD_CODE; }                                \
                        exit(42);                                       \
                }                                                       \
                                                                        \
                pid2 = fork();                                          \
                assert_se(pid2 >= 0);                                   \
                if (pid2 == 0) {                                        \
                        barrier_set_role(&b, BARRIER_PARENT);           \
                        { _PARENT_CODE; }                               \
                        exit(42);                                       \
                }                                                       \
                                                                        \
                barrier_destroy(&b);                                    \
                set_alarm(999999);                                      \
                { _WAIT_CHILD; }                                        \
                { _WAIT_PARENT; }                                       \
                set_alarm(0);                                           \
        }

#define TEST_BARRIER_WAIT_SUCCESS(_pid) \
                ({                                                      \
                        int pidr, status;                               \
                        pidr = waitpid(_pid, &status, 0);               \
                        assert_se(pidr == _pid);                        \
                        assert_se(WIFEXITED(status));                   \
                        assert_se(WEXITSTATUS(status) == 42);           \
                })

#define TEST_BARRIER_WAIT_ALARM(_pid) \
                ({                                                      \
                        int pidr, status;                               \
                        pidr = waitpid(_pid, &status, 0);               \
                        assert_se(pidr == _pid);                        \
                        assert_se(WIFSIGNALED(status));                 \
                        assert_se(WTERMSIG(status) == SIGALRM);         \
                })

/*
 * Test basic sync points
 * This places a barrier in both processes and waits synchronously for them.
 * The timeout makes sure the sync works as expected. The sleep_for() on one side
 * makes sure the exit of the parent does not overwrite previous barriers. Due
 * to the sleep_for(), we know that the parent already exited, thus there's a
 * pending HUP on the pipe. However, the barrier_sync() prefers reads on the
 * eventfd, thus we can safely wait on the barrier.
 */
TEST_BARRIER(barrier_sync,
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                sleep_for(BASE_TIME * 2);
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test wait_next()
 * This places a barrier in the parent and syncs on it. The child sleeps while
 * the parent places the barrier and then waits for a barrier. The wait will
 * succeed as the child hasn't read the parent's barrier, yet. The following
 * barrier and sync synchronize the exit.
 */
TEST_BARRIER(barrier_wait_next,
        ({
                sleep_for(BASE_TIME);
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 4);
                assert_se(barrier_place(&b));
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test wait_next() multiple times
 * This places two barriers in the parent and waits for the child to exit. The
 * child sleeps 20ms so both barriers _should_ be in place. It then waits for
 * the parent to place the next barrier twice. The first call will fetch both
 * barriers and return. However, the second call will stall as the parent does
 * not place a 3rd barrier (the sleep caught two barriers). wait_next() is does
 * not look at barrier-links so this stall is expected. Thus this test times
 * out.
 */
TEST_BARRIER(barrier_wait_next_twice,
        ({
                sleep_for(BASE_TIME);
                set_alarm(BASE_TIME);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_wait_next(&b));
                assert_se(0);
        }),
        TEST_BARRIER_WAIT_ALARM(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                sleep_for(BASE_TIME * 4);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test wait_next() with local barriers
 * This is the same as test_barrier_wait_next_twice, but places local barriers
 * between both waits. This does not have any effect on the wait so it times out
 * like the other test.
 */
TEST_BARRIER(barrier_wait_next_twice_local,
        ({
                sleep_for(BASE_TIME);
                set_alarm(BASE_TIME);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_wait_next(&b));
                assert_se(0);
        }),
        TEST_BARRIER_WAIT_ALARM(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                sleep_for(BASE_TIME * 4);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test wait_next() with sync_next()
 * This is again the same as test_barrier_wait_next_twice but uses a
 * synced wait as the second wait. This works just fine because the local state
 * has no barriers placed, therefore, the remote is always in sync.
 */
TEST_BARRIER(barrier_wait_next_twice_sync,
        ({
                sleep_for(BASE_TIME);
                set_alarm(BASE_TIME);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_sync_next(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test wait_next() with sync_next() and local barriers
 * This is again the same as test_barrier_wait_next_twice_local but uses a
 * synced wait as the second wait. This works just fine because the local state
 * is in sync with the remote.
 */
TEST_BARRIER(barrier_wait_next_twice_local_sync,
        ({
                sleep_for(BASE_TIME);
                set_alarm(BASE_TIME);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_sync_next(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test sync_next() and sync()
 * This tests sync_*() synchronizations and makes sure they work fine if the
 * local state is behind the remote state.
 */
TEST_BARRIER(barrier_sync_next,
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_sync_next(&b));
                assert_se(barrier_sync(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_sync_next(&b));
                assert_se(barrier_sync_next(&b));
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                sleep_for(BASE_TIME);
                assert_se(barrier_place(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test sync_next() and sync() with local barriers
 * This tests timeouts if sync_*() is used if local barriers are placed but the
 * remote didn't place any.
 */
TEST_BARRIER(barrier_sync_next_local,
        ({
                set_alarm(BASE_TIME);
                assert_se(barrier_place(&b));
                assert_se(barrier_sync_next(&b));
                assert_se(0);
        }),
        TEST_BARRIER_WAIT_ALARM(pid1),
        ({
                sleep_for(BASE_TIME * 2);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test sync_next() and sync() with local barriers and abortion
 * This is the same as test_barrier_sync_next_local but aborts the sync in the
 * parent. Therefore, the sync_next() succeeds just fine due to the abortion.
 */
TEST_BARRIER(barrier_sync_next_local_abort,
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(!barrier_sync_next(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                assert_se(barrier_abort(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test matched wait_abortion()
 * This runs wait_abortion() with remote abortion.
 */
TEST_BARRIER(barrier_wait_abortion,
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_wait_abortion(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                assert_se(barrier_abort(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test unmatched wait_abortion()
 * This runs wait_abortion() without any remote abortion going on. It thus must
 * timeout.
 */
TEST_BARRIER(barrier_wait_abortion_unmatched,
        ({
                set_alarm(BASE_TIME);
                assert_se(barrier_wait_abortion(&b));
                assert_se(0);
        }),
        TEST_BARRIER_WAIT_ALARM(pid1),
        ({
                sleep_for(BASE_TIME * 2);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test matched wait_abortion() with local abortion
 * This runs wait_abortion() with local and remote abortion.
 */
TEST_BARRIER(barrier_wait_abortion_local,
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_abort(&b));
                assert_se(!barrier_wait_abortion(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                assert_se(barrier_abort(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test unmatched wait_abortion() with local abortion
 * This runs wait_abortion() with only local abortion. This must time out.
 */
TEST_BARRIER(barrier_wait_abortion_local_unmatched,
        ({
                set_alarm(BASE_TIME);
                assert_se(barrier_abort(&b));
                assert_se(!barrier_wait_abortion(&b));
                assert_se(0);
        }),
        TEST_BARRIER_WAIT_ALARM(pid1),
        ({
                sleep_for(BASE_TIME * 2);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test child exit
 * Place barrier and sync with the child. The child only exits()s, which should
 * cause an implicit abortion and wake the parent.
 */
TEST_BARRIER(barrier_exit,
        ({
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME * 10);
                assert_se(barrier_place(&b));
                assert_se(!barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));

/*
 * Test child exit with sleep
 * Same as test_barrier_exit but verifies the test really works due to the
 * child-exit. We add a usleep() which triggers the alarm in the parent and
 * causes the test to time out.
 */
TEST_BARRIER(barrier_no_exit,
        ({
                sleep_for(BASE_TIME * 2);
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                set_alarm(BASE_TIME);
                assert_se(barrier_place(&b));
                assert_se(!barrier_sync(&b));
        }),
        TEST_BARRIER_WAIT_ALARM(pid2));

/*
 * Test pending exit against sync
 * The parent places a barrier *and* exits. The 20ms wait in the child
 * guarantees both are pending. However, our logic prefers pending barriers over
 * pending exit-abortions (unlike normal abortions), thus the wait_next() must
 * succeed, same for the sync_next() as our local barrier-count is smaller than
 * the remote. Once we place a barrier our count is equal, so the sync still
 * succeeds. Only if we place one more barrier, we're ahead of the remote, thus
 * we will fail due to HUP on the pipe.
 */
TEST_BARRIER(barrier_pending_exit,
        ({
                set_alarm(BASE_TIME * 4);
                sleep_for(BASE_TIME * 2);
                assert_se(barrier_wait_next(&b));
                assert_se(barrier_sync_next(&b));
                assert_se(barrier_place(&b));
                assert_se(barrier_sync_next(&b));
                assert_se(barrier_place(&b));
                assert_se(!barrier_sync_next(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid1),
        ({
                assert_se(barrier_place(&b));
        }),
        TEST_BARRIER_WAIT_SUCCESS(pid2));


static int intro(void) {
        if (!slow_tests_enabled())
                return log_tests_skipped("slow tests are disabled");

        /*
         * This test uses real-time alarms and sleeps to test for CPU races explicitly. This is highly
         * fragile if your system is under load. We already increased the BASE_TIME value to make the tests
         * more robust, but that just makes the test take significantly longer. Given the recent issues when
         * running the test in a virtualized environments, limit it to bare metal machines only, to minimize
         * false-positives in CIs.
         */

        Virtualization v = detect_virtualization();
        if (v < 0 && ERRNO_IS_PRIVILEGE(v))
                return log_tests_skipped("Cannot detect virtualization");

        if (v != VIRTUALIZATION_NONE)
                return log_tests_skipped("This test requires a baremetal machine");

        return EXIT_SUCCESS;
 }

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
