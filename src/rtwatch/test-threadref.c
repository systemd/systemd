/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"
#include "threadref.h"
#include "time-util.h"

/* Thread pidfds (PIDFD_THREAD) are only available since kernel 6.9, hence we run every test twice: once
 * with whatever the kernel supports, and once with the thread pidfd closed, i.e. in the state
 * threadref_set() leaves the ThreadRef in on older kernels. */
static void maybe_drop_thread_pidfd(ThreadRef *t, bool drop) {
        ASSERT_NOT_NULL(t);

        if (drop)
                t->thread_pidfd = safe_close(t->thread_pidfd);
}

typedef struct TestThread {
        pthread_t thread;
        int tid_pipe[2];
        int quit_pipe[2];
        pid_t tid;
} TestThread;

static void* test_thread(void *userdata) {
        TestThread *tt = ASSERT_PTR(userdata);
        pid_t tid = gettid();
        char c;

        assert_se(write(tt->tid_pipe[1], &tid, sizeof(tid)) == sizeof(tid));
        (void) read(tt->quit_pipe[0], &c, sizeof(c)); /* Returns once the write end is closed */
        return NULL;
}

static void test_thread_start(TestThread *tt) {
        ASSERT_NOT_NULL(tt);

        *tt = (TestThread) {
                .tid_pipe = EBADF_PAIR,
                .quit_pipe = EBADF_PAIR,
        };

        ASSERT_OK_ERRNO(pipe2(tt->tid_pipe, O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(tt->quit_pipe, O_CLOEXEC));
        ASSERT_EQ(pthread_create(&tt->thread, /* attr= */ NULL, test_thread, tt), 0);
        ASSERT_EQ(read(tt->tid_pipe[0], &tt->tid, sizeof(tt->tid)), (ssize_t) sizeof(tt->tid));
        ASSERT_GT(tt->tid, 0);
        ASSERT_NE(tt->tid, getpid_cached());
}

static void test_thread_stop(TestThread *tt) {
        ASSERT_NOT_NULL(tt);

        tt->quit_pipe[1] = safe_close(tt->quit_pipe[1]);
        ASSERT_EQ(pthread_join(tt->thread, /* retval= */ NULL), 0);
        safe_close_pair(tt->tid_pipe);
        safe_close_pair(tt->quit_pipe);
}

static int threadref_verify_until_gone(const ThreadRef *t) {
        int r;

        /* pthread_join() returns as soon as the kernel cleared the TID, which happens slightly before the
         * thread is fully gone, hence wait a bit */
        for (usec_t end = usec_add(now(CLOCK_MONOTONIC), 10 * USEC_PER_SEC);;) {
                r = threadref_verify(t);
                if (r < 0 || now(CLOCK_MONOTONIC) > end)
                        return r;

                usleep_safe(10 * USEC_PER_MSEC);
        }
}

static void test_main_thread_one(bool drop) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;

        log_info("/* %s(drop=%s) */", __func__, yes_no(drop));

        ASSERT_OK(pidref_set_self(&self));

        /* A TID of zero refers to the main thread */
        ASSERT_OK(threadref_set(&t, &self, /* tid= */ 0));
        maybe_drop_thread_pidfd(&t, drop);
        ASSERT_TRUE(threadref_is_set(&t));
        ASSERT_EQ(t.thread_id, getpid_cached());
        ASSERT_OK(threadref_verify(&t));
        ASSERT_TRUE(threadref_equal(&t, &t));

        /* Copies are independent, and equally valid */
        _cleanup_(threadref_done) ThreadRef copy = THREADREF_NULL;
        ASSERT_OK(threadref_copy(&t, &copy));
        ASSERT_EQ(copy.thread_id, t.thread_id);
        ASSERT_EQ(copy.thread_pidfd >= 0, t.thread_pidfd >= 0);
        if (t.thread_pidfd >= 0)
                ASSERT_NE(copy.thread_pidfd, t.thread_pidfd);
        ASSERT_OK(threadref_verify(&copy));
        ASSERT_TRUE(threadref_equal(&t, &copy));
        ASSERT_TRUE(threadref_equal(&copy, &t));

        /* Pinning the same thread again yields an equal reference, whether specified by TID or not */
        _cleanup_(threadref_done) ThreadRef same = THREADREF_NULL;
        ASSERT_OK(threadref_set(&same, &self, getpid_cached()));
        ASSERT_TRUE(threadref_equal(&t, &same));
        ASSERT_FALSE(threadref_equal(&t, &THREADREF_NULL));

        /* The inode number of the thread pidfd is acquired lazily, and copied along */
        if (t.thread_pidfd < 0)
                ASSERT_ERROR(threadref_acquire_pidfd_id(&t), ENOMEDIUM);
        else {
                ASSERT_OK(threadref_acquire_pidfd_id(&t));
                ASSERT_GT(t.thread_pidfd_id, UINT64_C(0));

                /* Thread pidfds live on pidfs, like process pidfds, hence the main thread's pidfd has the
                 * same inode number as the process' pidfd */
                if (pidref_acquire_pidfd_id(&self) >= 0)
                        ASSERT_EQ(t.thread_pidfd_id, self.fd_id);

                threadref_done(&copy);
                ASSERT_OK(threadref_copy(&t, &copy));
                ASSERT_EQ(copy.thread_pidfd_id, t.thread_pidfd_id);

                /* Pinning with the right inode number works, with the wrong one it doesn't */
                _cleanup_(threadref_done) ThreadRef again = THREADREF_NULL;
                ASSERT_OK(threadref_set_full(&again, &self, /* tid= */ 0, t.thread_pidfd_id));
                ASSERT_EQ(again.thread_pidfd_id, t.thread_pidfd_id);
                threadref_done(&again);
                ASSERT_ERROR(threadref_set_full(&again, &self, /* tid= */ 0, t.thread_pidfd_id + 1), ENXIO);
        }

        threadref_done(&t);
        ASSERT_OK(threadref_verify(&copy));
        ASSERT_FALSE(threadref_is_set(&t));
        ASSERT_EQ(t.thread_pidfd, -EBADF);
        ASSERT_EQ(t.thread_pidfd_id, UINT64_C(0));
}

TEST(main_thread) {
        test_main_thread_one(/* drop= */ false);
        test_main_thread_one(/* drop= */ true);
}

static void test_other_thread_one(bool drop) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;
        _cleanup_free_ char *comm = NULL, *thread_comm = NULL;
        TestThread tt;

        log_info("/* %s(drop=%s) */", __func__, yes_no(drop));

        ASSERT_OK(pidref_set_self(&self));

        test_thread_start(&tt);

        ASSERT_OK(threadref_set(&t, &self, tt.tid));
        maybe_drop_thread_pidfd(&t, drop);
        ASSERT_EQ(t.thread_id, tt.tid);
        ASSERT_OK(threadref_verify(&t));

        /* The main thread is a different thread of the same process */
        _cleanup_(threadref_done) ThreadRef main_thread = THREADREF_NULL;
        ASSERT_OK(threadref_set(&main_thread, &self, /* tid= */ 0));
        ASSERT_FALSE(threadref_equal(&t, &main_thread));

        /* The thread inherited the name of the main thread */
        ASSERT_OK(pid_get_comm(/* pid= */ 0, &comm));
        ASSERT_OK(threadref_get_comm(&t, &thread_comm));
        ASSERT_STREQ(comm, thread_comm);
        thread_comm = mfree(thread_comm);

        /* Once the thread is gone, it's reported as -ENXIO, while the process is still around */
        test_thread_stop(&tt);
        ASSERT_ERROR(threadref_verify_until_gone(&t), ENXIO);
        ASSERT_ERROR(threadref_get_comm(&t, &thread_comm), ENXIO);

        /* A thread that doesn't exist anymore cannot be pinned anymore either */
        ASSERT_ERROR(threadref_set(&t, &self, tt.tid), ENXIO);
}

TEST(other_thread) {
        test_other_thread_one(/* drop= */ false);
        test_other_thread_one(/* drop= */ true);
}

static void test_foreign_thread_one(bool drop) {
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;

        log_info("/* %s(drop=%s) */", __func__, yes_no(drop));

        ASSERT_OK(pidref_set_self(&self));
        ASSERT_OK_POSITIVE(pidref_safe_fork("(test-threadref)", FORK_DEATHSIG_SIGKILL|FORK_FREEZE, &child));

        /* The main thread of another process is not a thread of ours */
        ASSERT_ERROR(threadref_set(&t, &self, child.pid), ENXIO);

        /* Same if the ThreadRef is assembled manually, i.e. bypassing threadref_set()'s checks */
        ASSERT_OK(pidref_copy(&self, &t.process));
        t.thread_id = child.pid;
        if (!drop)
                t.thread_pidfd = pidfd_open(child.pid, PIDFD_THREAD); /* might fail on old kernels, that's fine */
        ASSERT_ERROR(threadref_verify(&t), ENXIO);
        threadref_done(&t);

        /* But it is the main thread of the child, of course */
        ASSERT_OK(threadref_set(&t, &child, /* tid= */ 0));
        maybe_drop_thread_pidfd(&t, drop);
        ASSERT_OK(threadref_verify(&t));

        /* Once the child is gone, it's reported as -ESRCH, since the process is gone */
        ASSERT_OK(pidref_kill(&child, SIGKILL));
        ASSERT_OK(pidref_wait_for_terminate(&child, /* ret_si= */ NULL));
        ASSERT_ERROR(threadref_verify(&t), ESRCH);
        ASSERT_ERROR(threadref_set(&t, &child, /* tid= */ 0), ESRCH);
        pidref_done(&child);
}

TEST(foreign_thread) {
        test_foreign_thread_one(/* drop= */ false);
        test_foreign_thread_one(/* drop= */ true);
}

TEST(invalid) {
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;
        _cleanup_free_ char *comm = NULL;

        ASSERT_FALSE(threadref_is_set(&t));
        ASSERT_FALSE(threadref_is_set(/* t= */ NULL));
        ASSERT_ERROR(threadref_set(&t, &PIDREF_NULL, /* tid= */ 0), ESRCH);
        ASSERT_ERROR(threadref_verify(&t), ESRCH);
        ASSERT_ERROR(threadref_get_comm(&t, &comm), ESRCH);

        /* Two unset ThreadRefs are equal */
        ASSERT_TRUE(threadref_equal(&t, &THREADREF_NULL));
        ASSERT_TRUE(threadref_equal(/* a= */ NULL, /* b= */ NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
