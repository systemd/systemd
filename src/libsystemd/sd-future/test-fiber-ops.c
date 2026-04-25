/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "cleanup-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"
#include "time-util.h"

/* Test: wait_for_terminate basic functionality */
static int wait_simple_fiber(void *userdata) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;
        int r;

        /* Fork a child that exits immediately */
        r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref);
        if (r < 0)
                return r;

        if (r == 0)
                _exit(42);

        /* Parent - wait for child */
        r = pidref_wait_for_terminate(&pidref, &si);
        if (r < 0)
                return r;

        pidref_done(&pidref);

        /* Verify child exited with status 42 */
        if (si.si_code != CLD_EXITED || si.si_status != 42)
                return -EIO;

        return 0;
}

TEST(wait_for_terminate_fiber_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "wait-simple", wait_simple_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: wait_for_terminate with multiple children */
static int wait_multiple_fiber(void *userdata) {
        PidRef pidrefs[3] = { PIDREF_NULL, PIDREF_NULL, PIDREF_NULL };
        siginfo_t si;
        int r;

        /* Fork three children with different exit codes */
        for (size_t i = 0; i < 3; i++) {
                r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidrefs[i]);
                if (r < 0)
                        goto cleanup;

                if (r == 0)
                        /* Child process */
                        _exit(10 + i);
        }

        /* Wait for all three in order */
        for (size_t i = 0; i < 3; i++) {
                r = pidref_wait_for_terminate(&pidrefs[i], &si);
                if (r < 0)
                        goto cleanup;

                pidref_done(&pidrefs[i]);

                if (si.si_code != CLD_EXITED || si.si_status != (int) (10 + i)) {
                        r = -EIO;
                        goto cleanup;
                }
        }

        return 0;

cleanup:
        for (size_t i = 0; i < 3; i++)
                pidref_done(&pidrefs[i]);

        return r;
}

TEST(wait_for_terminate_fiber_multiple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "wait-multiple", wait_multiple_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

static int concurrent_wait_fiber(void *userdata) {
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        siginfo_t si;
        int r;

        r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref);
        if (r < 0)
                return r;

        if (r == 0)
                /* Child exits with specified status */
                _exit(PTR_TO_INT(userdata));

        r = pidref_wait_for_terminate(&pidref, &si);
        if (r < 0)
                return r;

        pidref_done(&pidref);

        if (si.si_code != CLD_EXITED || si.si_status != PTR_TO_INT(userdata))
                return -EIO;

        return 0;
}

TEST(wait_for_terminate_fiber_concurrent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future *fibers[3] = {};
        CLEANUP_ELEMENTS(fibers, sd_future_unref_array_clear);

        /* Create 3 fibers, each waiting for a different child */
        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK(sd_fiber_new(e, "concurrent-wait", concurrent_wait_fiber, INT_TO_PTR(20 + i), /* destroy= */ NULL, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* All fibers should complete successfully */
        for (size_t i = 0; i < ELEMENTSOF(fibers); i++)
                ASSERT_OK(sd_future_result(fibers[i]));
}

typedef struct LoopIOContext {
        int *pipefd;
        const char *data;
        size_t len;
        int order;
} LoopIOContext;

static int loop_read_suspend_fiber(void *userdata) {
        LoopIOContext *ctx = ASSERT_PTR(userdata);
        char buf[64];

        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        ssize_t n = loop_read(ctx->pipefd[0], buf, sizeof(buf), /* do_poll= */ true);

        /* While we were suspended, the writer fiber should have run. */
        ASSERT_EQ(ctx->order, 2);

        if (n < 0)
                return (int) n;
        if ((size_t) n != ctx->len || memcmp(buf, ctx->data, ctx->len) != 0)
                return -EIO;

        return (int) n;
}

static int loop_write_suspend_fiber(void *userdata) {
        LoopIOContext *ctx = ASSERT_PTR(userdata);

        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        int r = loop_write(ctx->pipefd[1], ctx->data, ctx->len);
        if (r < 0)
                return r;

        /* Close the write end so the reader sees EOF after reading the data. */
        ctx->pipefd[1] = safe_close(ctx->pipefd[1]);
        return 0;
}

/* Test: two fibers cooperatively pass a small payload through a blocking pipe using the suspending
 * loop helpers. Exercises the non-blocking flip, event-loop yielding, and the blocking-mode restore. */
TEST(loop_read_write_suspend) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        static const char payload[] = "loop-suspend";
        LoopIOContext ctx = {
                .pipefd = pipefd,
                .data = payload,
                .len = sizeof(payload) - 1,
        };

        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-read", loop_read_suspend_fiber, &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "loop-write", loop_write_suspend_fiber, &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 1));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(fr), (int) ctx.len);
        ASSERT_OK_ZERO(sd_future_result(fw));

        /* The read fd started out blocking and loop_read() must have restored it before returning. */
        ASSERT_OK_ZERO(fcntl(pipefd[0], F_GETFL) & O_NONBLOCK);
}

static int loop_read_exact_short_fiber(void *userdata) {
        int fd = PTR_TO_INT(userdata);
        char buf[16];

        /* Requesting more bytes than the peer writes should return -EIO once EOF is hit. */
        return loop_read_exact(fd, buf, sizeof(buf), /* do_poll= */ true);
}

/* Test: loop_read_exact() returns -EIO when the peer closes early. */
TEST(loop_read_exact_short) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-read-exact", loop_read_exact_short_fiber,
                               INT_TO_PTR(pipefd[0]), /* destroy= */ NULL, &f));

        /* Write a few bytes and close the write end — less than the fiber asked for. */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "abc", 3), (ssize_t) 3);
        pipefd[1] = safe_close(pipefd[1]);

        ASSERT_OK(sd_event_loop(e));

        ASSERT_ERROR(sd_future_result(f), EIO);
}

typedef struct LoopWriteTimeoutContext {
        int fd;
        int result;
} LoopWriteTimeoutContext;

static int loop_write_timeout_fiber(void *userdata) {
        LoopWriteTimeoutContext *ctx = ASSERT_PTR(userdata);

        /* Try to write much more than the pipe buffer can hold with a short timeout. The write will
         * succeed partially and then hit -ETIME after exhausting the timeout while blocked. */
        static const char big_buf[128 * 1024] = { 0 };
        ctx->result = loop_write_full(ctx->fd, big_buf, sizeof(big_buf), 100 * USEC_PER_MSEC);
        return 0;
}

/* Test: loop_write_full() returns -ETIME when the peer never drains. */
TEST(loop_write_full_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        /* Shrink the pipe buffer to its minimum (one page) so the 128K write below is guaranteed to block
         * regardless of the architecture's page size. The default pipe buffer is 16 pages, which on
         * 64K-page architectures (e.g. ppc64le) is 1 MiB — enough to absorb the entire write without ever
         * blocking, defeating the purpose of the timeout. */
        ASSERT_OK_ERRNO(fcntl(pipefd[1], F_SETPIPE_SZ, 1));

        LoopWriteTimeoutContext ctx = { .fd = pipefd[1], .result = 0 };
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-write-timeout", loop_write_timeout_fiber, &ctx, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_ZERO(sd_future_result(f));
        ASSERT_ERROR(ctx.result, ETIME);
}

typedef struct PpollDispatchContext {
        int *pipefd;
        int order;
} PpollDispatchContext;

static int ppoll_dispatch_read_fiber(void *userdata) {
        PpollDispatchContext *ctx = ASSERT_PTR(userdata);
        struct pollfd pfd = {
                .fd = ctx->pipefd[0],
                .events = POLLIN,
        };

        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        /* Direct ppoll_usec() call from a fiber must dispatch through sd_fiber_poll(), suspending the
         * fiber instead of blocking the entire thread. If dispatch fails, the writer fiber never gets a
         * chance to run and the test deadlocks. */
        int r = ppoll_usec(&pfd, 1, USEC_INFINITY);
        if (r < 0)
                return r;

        ASSERT_EQ(ctx->order, 2);

        if (r != 1 || !FLAGS_SET(pfd.revents, POLLIN))
                return -EIO;

        return 0;
}

static int ppoll_dispatch_write_fiber(void *userdata) {
        PpollDispatchContext *ctx = ASSERT_PTR(userdata);

        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        if (write(ctx->pipefd[1], "x", 1) != 1)
                return -errno;

        return 0;
}

/* Test: ppoll_usec() called from a fiber dispatches through the FiberOps hook to sd_fiber_poll(),
 * yielding to the event loop instead of blocking. */
TEST(ppoll_usec_dispatch) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        PpollDispatchContext ctx = { .pipefd = pipefd };

        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new(e, "ppoll-read", ppoll_dispatch_read_fiber, &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "ppoll-write", ppoll_dispatch_write_fiber, &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 1));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(fr));
        ASSERT_OK(sd_future_result(fw));
}

static int loop_write_zero_timeout_nonblock_fiber(void *userdata) {
        int fd = PTR_TO_INT(userdata);

        /* Fill the pipe so the next write would block. The fd is non-blocking, so on a fiber
         * loop_write_full(timeout=0) must take the non-fiber path and return -EAGAIN immediately
         * rather than suspending. */
        static const char big_buf[128 * 1024] = { 0 };
        return loop_write_full(fd, big_buf, sizeof(big_buf), /* timeout= */ 0);
}

/* Test: timeout == 0 on a non-blocking fd from a fiber preserves the "don't wait" semantic and
 * returns -EAGAIN when the pipe buffer is full, instead of suspending the fiber. */
TEST(loop_write_zero_timeout_nonblock) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));
        ASSERT_OK_ERRNO(fcntl(pipefd[1], F_SETPIPE_SZ, 1));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-write-zt-nb", loop_write_zero_timeout_nonblock_fiber,
                               INT_TO_PTR(pipefd[1]), /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), EAGAIN);
}

typedef struct LoopWriteZeroBlockingContext {
        int *pipefd;
        size_t total;
        int order;
} LoopWriteZeroBlockingContext;

static int loop_write_zero_blocking_writer_fiber(void *userdata) {
        LoopWriteZeroBlockingContext *ctx = ASSERT_PTR(userdata);

        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        /* timeout == 0 on a *blocking* fd from a fiber: the fast EAGAIN return isn't possible, so
         * loop_write_full() takes the fiber path. The reader fiber drains the pipe, letting our
         * write complete via fiber suspension/resume. */
        _cleanup_free_ char *big_buf = malloc0(ctx->total);
        ASSERT_NOT_NULL(big_buf);
        int r = loop_write_full(ctx->pipefd[1], big_buf, ctx->total, /* timeout= */ 0);

        ASSERT_EQ(ctx->order, 2);
        return r;
}

static int loop_write_zero_blocking_reader_fiber(void *userdata) {
        LoopWriteZeroBlockingContext *ctx = ASSERT_PTR(userdata);

        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        _cleanup_free_ char *buf = malloc(ctx->total);
        ASSERT_NOT_NULL(buf);
        ssize_t n = loop_read(ctx->pipefd[0], buf, ctx->total, /* do_poll= */ true);
        if (n < 0)
                return (int) n;
        return (int) n;
}

/* Test: timeout == 0 on a blocking fd from a fiber takes the fiber path (suspends until the peer
 * drains) instead of blocking the entire thread. */
TEST(loop_write_zero_timeout_blocking) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));
        ASSERT_OK_ERRNO(fcntl(pipefd[1], F_SETPIPE_SZ, 1));

        /* F_SETPIPE_SZ rounds up to the kernel's pipe minimum (typically a page); query the actual
         * size and write more than that, so the write must wait on the reader regardless of page size. */
        int pipe_sz = fcntl(pipefd[1], F_GETPIPE_SZ);
        ASSERT_OK_ERRNO(pipe_sz);

        LoopWriteZeroBlockingContext ctx = { .pipefd = pipefd, .total = (size_t) pipe_sz * 2 };

        _cleanup_(sd_future_unrefp) sd_future *fw = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-write-zt-blk", loop_write_zero_blocking_writer_fiber,
                               &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 0));
        ASSERT_OK(sd_fiber_new(e, "loop-read-zt-blk", loop_write_zero_blocking_reader_fiber,
                               &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(fw));
        ASSERT_OK_EQ(sd_future_result(fr), (int) ctx.total);
}

static int loop_read_no_poll_nonblock_fiber(void *userdata) {
        int fd = PTR_TO_INT(userdata);
        char buf[64];

        /* Empty non-blocking pipe + do_poll=false: on a fiber loop_read() must take the non-fiber
         * path and return -EAGAIN immediately rather than suspending. */
        return (int) loop_read(fd, buf, sizeof(buf), /* do_poll= */ false);
}

/* Test: do_poll == false on a non-blocking fd from a fiber preserves the "don't wait" semantic
 * and returns -EAGAIN when no data is available, instead of suspending the fiber. */
TEST(loop_read_no_poll_nonblock) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-read-np-nb", loop_read_no_poll_nonblock_fiber,
                               INT_TO_PTR(pipefd[0]), /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), EAGAIN);
}

typedef struct LoopReadNoPollBlockingContext {
        int *pipefd;
        const char *data;
        size_t len;
        int order;
} LoopReadNoPollBlockingContext;

static int loop_read_no_poll_blocking_reader_fiber(void *userdata) {
        LoopReadNoPollBlockingContext *ctx = ASSERT_PTR(userdata);
        char buf[64];

        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        /* do_poll == false on a *blocking* fd from a fiber: the fast EAGAIN return isn't possible,
         * so loop_read() takes the fiber path and suspends until the writer fiber feeds data. */
        ssize_t n = loop_read(ctx->pipefd[0], buf, sizeof(buf), /* do_poll= */ false);

        ASSERT_EQ(ctx->order, 2);

        if (n < 0)
                return (int) n;
        if ((size_t) n != ctx->len || memcmp(buf, ctx->data, ctx->len) != 0)
                return -EIO;

        return (int) n;
}

static int loop_read_no_poll_blocking_writer_fiber(void *userdata) {
        LoopReadNoPollBlockingContext *ctx = ASSERT_PTR(userdata);

        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        int r = loop_write(ctx->pipefd[1], ctx->data, ctx->len);
        if (r < 0)
                return r;

        ctx->pipefd[1] = safe_close(ctx->pipefd[1]);
        return 0;
}

/* Test: do_poll == false on a blocking fd from a fiber takes the fiber path (suspends until the
 * peer feeds data) instead of blocking the entire thread. */
TEST(loop_read_no_poll_blocking) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        static const char payload[] = "no-poll";
        LoopReadNoPollBlockingContext ctx = {
                .pipefd = pipefd,
                .data = payload,
                .len = sizeof(payload) - 1,
        };

        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-read-np-blk", loop_read_no_poll_blocking_reader_fiber,
                               &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "loop-write-np-blk", loop_read_no_poll_blocking_writer_fiber,
                               &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 1));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_EQ(sd_future_result(fr), (int) ctx.len);
        ASSERT_OK_ZERO(sd_future_result(fw));
}

/* Test: loop_*() helpers transparently fall back to blocking I/O when called outside any
 * fiber context. */
TEST(loop_read_write_fallback) {
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        ASSERT_OK(loop_write(pipefd[1], "fallback", STRLEN("fallback")));

        char buf[16];
        ssize_t n = loop_read(pipefd[0], buf, STRLEN("fallback"), /* do_poll= */ true);
        ASSERT_OK_EQ(n, (ssize_t) STRLEN("fallback"));
        ASSERT_EQ(memcmp(buf, "fallback", STRLEN("fallback")), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
