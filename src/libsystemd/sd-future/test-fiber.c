/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "cleanup-util.h"
#include "fd-util.h"
#include "fiber-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"
#include "time-util.h"

static int simple_fiber(void *userdata) {
        int *value = ASSERT_PTR(userdata);
        return *value;
}

TEST(fiber_simple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 5;
        ASSERT_OK(sd_future_new_fiber(e, "simple", simple_fiber, &value, NULL, &f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(f), 5);
}

/* Fiber that yields once */
static int yielding_fiber(void *userdata) {
        int *counter = userdata;
        (*counter)++;

        sd_fiber_yield();

        (*counter)++;
        return 0;
}

/* Test: Single fiber that yields */
TEST(fiber_single_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_future_new_fiber(e, "yielding", yielding_fiber, &counter, /* destroy= */ NULL, &f));

        /* First iteration: fiber runs until first yield */
        ASSERT_EQ(counter, 0);
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counter, 1);

        /* Second iteration: fiber runs from yield to completion */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counter, 2);

        /* No more fibers to run */
        ASSERT_OK_ZERO(sd_event_loop(e));
}

static int counting_fiber(void *userdata) {
        int counter = 0;

        for (int i = 0; i < 5; i++) {
                counter++;
                sd_fiber_yield();
        }

        return counter;
}

/* Test: Multiple fibers yielding cooperatively */
TEST(fiber_multiple_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 5;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < n_fibers; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "counting-%zu", i));
                ASSERT_OK(sd_future_new_fiber(e, name, counting_fiber, NULL, /* destroy= */ NULL, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK_EQ(sd_future_result(fibers[i]), 5);
}

static int priority_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);

        (*counter)++;
        sd_fiber_yield();

        return *counter;
}

/* Test: Priority-based scheduling */
TEST(fiber_priority_ascending) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 5;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);
        int counter = 0;

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < n_fibers; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_future_new_fiber(e, name, priority_fiber, &counter, /* destroy= */ NULL, &fibers[i]));
                ASSERT_OK(sd_future_set_priority(fibers[i], i));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have ascending priorities, so we the first one to run to completion,
         * followed by the second one, etc. */

        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_EQ(sd_future_result(fibers[i]), (int) i + 1);
}

TEST(fiber_priority_identical) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 5;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);
        int counter = 0;

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < 5; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_future_new_fiber(e, name, priority_fiber, &counter, /* destroy= */ NULL, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have the same priorities, so we expect all of them to run once first, and then they'll
         * all run again another time, so they should all return the same value. */

        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_EQ(sd_future_result(fibers[i]), (int) 5);
}

static int error_fiber(void *userdata) {
        return -ENOENT;
}

TEST(fiber_error_return) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "error", error_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_future_result(f), -ENOENT);
}

static int cancel_fiber(void *userdata) {
        return sd_fiber_yield();
}

TEST(fiber_cancel_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 42;
        ASSERT_OK(sd_future_new_fiber(e, "cancel", cancel_fiber, &value, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_future_cancel(f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
}

static int fiber_that_yields(void *userdata) {
        int *yield_count = userdata;
        int r;

        for (int i = 0; i < 5; i++) {
                (*yield_count)++;
                r = sd_fiber_yield();
                if (r < 0)
                        return r;  /* Propagate cancellation error */
        }

        return 0;
}

/* Test: fiber_yield() returns error when fiber is cancelled externally */
TEST(fiber_cancel_propagation_via_yield) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int yield_count = 0;
        ASSERT_OK(sd_future_new_fiber(e, "yielding", fiber_that_yields, &yield_count, /* destroy= */ NULL, &f));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 1);
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 2);

        ASSERT_OK(sd_future_cancel(f));

        ASSERT_OK(sd_event_loop(e));

        /* sd_fiber should have been cancelled */
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
        ASSERT_EQ(yield_count, 2);
}

/* Test: Cancel a fiber that has already completed */
TEST(fiber_cancel_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int value = 42;
        ASSERT_OK(sd_future_new_fiber(e, "simple", simple_fiber, &value, /* destroy= */ NULL, &f));

        /* Run the fiber to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Canceling a completed fiber should be a no-op */
        ASSERT_OK(sd_future_cancel(f));
        ASSERT_EQ(sd_future_result(f), 42);
}

static int multiple_yield_fiber(void *userdata) {
        int *counter = userdata;
        int r;

        for (int i = 0; i < 3; i++) {
                (*counter)++;
                r = sd_fiber_yield();
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Test: Cancel one fiber among multiple */
TEST(fiber_cancel_one_of_many) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 3;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        int counters[3] = {0, 0, 0};
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK(sd_future_new_fiber(e, "multiple-yield", multiple_yield_fiber, &counters[i], /* destroy= */ NULL, &fibers[i]));

        /* Run one iteration - all fibers yield after incrementing once */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counters[0], 1);
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(counters[2], 1);

        /* Cancel the second fiber */
        ASSERT_OK(sd_future_cancel(fibers[1]));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* First and third fibers should complete normally */
        ASSERT_EQ(counters[0], 3);
        ASSERT_EQ(counters[2], 3);
        ASSERT_EQ(sd_future_result(fibers[0]), 0);
        ASSERT_EQ(sd_future_result(fibers[2]), 0);

        /* Second fiber should be canceled with counter at 1 */
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(sd_future_result(fibers[1]), -ECANCELED);
}

/* Test: Basic pipe I/O with sd-event */
static int pipe_read_fiber(void *userdata) {
        int *pipefd = userdata;
        char buf[64];
        ssize_t n;

        n = sd_fiber_read(pipefd[0], buf, sizeof(buf));
        if (n < 0)
                return (int) n;

        /* Verify we read "hello" */
        if (n != 5 || memcmp(buf, "hello", 5) != 0)
                return -EIO;

        return (int) n;
}

TEST(fiber_io_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "pipe-read", pipe_read_fiber, pipefd, /* destroy= */ NULL, &f));

        /* Write data to the pipe */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "hello", 5), 5);

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_future_result(f), 5);
}

static int pipe_write_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);

        return sd_fiber_write(pipefd[1], "hello", STRLEN("hello"));
}

TEST(fiber_io_read_write) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Higher priority for the read fiber, which will run first and then suspend because no data is
         * available. The write fiber will run second, write data to the pipe, causing the read fiber to get
         * resumed. */
        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "pipe-read", pipe_read_fiber,  pipefd, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "pipe-write", pipe_write_fiber, pipefd, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 0));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_future_result(fr), 5);
        ASSERT_OK_EQ(sd_future_result(fw), 5);
}

/* Test: Multiple concurrent reads */
static int concurrent_read_fiber(void *userdata) {
        int *args = userdata;
        int fd = args[0];
        int expected = args[1];
        char buf[64];
        ssize_t n;

        n = sd_fiber_read(fd, buf, sizeof buf);
        if (n < 0)
                return (int) n;

        if (n != 1 || buf[0] != (char) expected)
                return -EIO;

        return 0;
}

TEST(fiber_io_concurrent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 3;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        int pipes[3][2];
        int args[3][2];
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                ASSERT_OK(sd_future_new_fiber(e, "concurrent-read", concurrent_read_fiber, args[i], /* destroy= */ NULL, &fibers[i]));
        }

        /* Write data in reverse order */
        ASSERT_EQ(write(pipes[2][1], "C", 1), 1);
        ASSERT_EQ(write(pipes[1][1], "B", 1), 1);
        ASSERT_EQ(write(pipes[0][1], "A", 1), 1);

        /* Run until all complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully */
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK(sd_future_result(fibers[i]));
                safe_close_pair(pipes[i]);
        }
}

/* Test: Cancel fiber during I/O */
static int blocking_read_fiber(void *userdata) {
        int fd = PTR_TO_INT(userdata);
        char buf[64];
        ssize_t n;

        n = sd_fiber_read(fd, buf, sizeof(buf));
        return (int) n;
}

TEST(fiber_io_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "blocking-read", blocking_read_fiber, INT_TO_PTR(pipefd[0]), /* destroy= */ NULL, &f));

        /* Run once - fiber will suspend on read */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Fiber should be suspended now - add explicit check via state tracking */

        /* Cancel the fiber */
        ASSERT_OK(sd_future_cancel(f));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Should be cancelled */
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
}

TEST(fiber_io_fallback) {
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));  /* Note: blocking pipe */

        char buf[STRLEN("fallback")] = {};
        ASSERT_OK_EQ(sd_fiber_write(pipefd[1], "fallback", sizeof(buf)), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(sd_fiber_read(pipefd[0], buf, sizeof(buf)), (ssize_t) sizeof(buf));
}

static int pipe_readv_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        char buf1[5], buf2[5];
        struct iovec iov[] = {
                { .iov_base = buf1, .iov_len = sizeof(buf1) },
                { .iov_base = buf2, .iov_len = sizeof(buf2) },
        };
        ssize_t n;

        /* This will initially block since no data is available */
        n = sd_fiber_readv(pipefd[0], iov, ELEMENTSOF(iov));
        if (n < 0)
                return (int) n;

        if (n != 10 || memcmp(buf1, "fiber", 5) != 0 || memcmp(buf2, "readv", 5) != 0)
                return -EIO;

        return (int) n;
}

static int pipe_writev_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        const char *part1 = "fiber";
        const char *part2 = "readv";
        struct iovec iov[] = {
                { .iov_base = (void*) part1, .iov_len = 5 },
                { .iov_base = (void*) part2, .iov_len = 5 },
        };

        return sd_fiber_writev(pipefd[1], iov, ELEMENTSOF(iov));
}

TEST(fiber_io_readv_writev) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Higher priority for the read fiber, which will run first and then suspend because no data is
         * available. The write fiber will run second, write data to the pipe, causing the read fiber to get
         * resumed. */
        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "pipe-readv", pipe_readv_fiber,  pipefd, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "pipe-writev", pipe_writev_fiber, pipefd, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 0));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify both fibers completed successfully */
        ASSERT_OK_EQ(sd_future_result(fr), 10);
        ASSERT_OK_EQ(sd_future_result(fw), 10);
}

static int concurrent_readv_fiber(void *userdata) {
        int *args = userdata;
        int fd = args[0];
        int expected1 = args[1];
        int expected2 = args[2];
        char buf1[1], buf2[1];
        struct iovec iov[] = {
                { .iov_base = buf1, .iov_len = sizeof(buf1) },
                { .iov_base = buf2, .iov_len = sizeof(buf2) },
        };
        ssize_t n;

        n = sd_fiber_readv(fd, iov, ELEMENTSOF(iov));
        if (n < 0)
                return (int) n;

        if (n != 2 || buf1[0] != (char) expected1 || buf2[0] != (char) expected2)
                return -EIO;

        return 0;
}

TEST(fiber_io_readv_concurrent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 3;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new0(sd_future*, 3));
        int pipes[3][2];
        int args[3][3];
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                args[i][2] = 'a' + i;
                ASSERT_OK(sd_future_new_fiber(e, "concurrent-readv", concurrent_readv_fiber, args[i], /* destroy= */ NULL, &fibers[i]));
        }

        /* Write data in reverse order */
        ASSERT_EQ(write(pipes[2][1], "Cc", 2), 2);
        ASSERT_EQ(write(pipes[1][1], "Bb", 2), 2);
        ASSERT_EQ(write(pipes[0][1], "Aa", 2), 2);

        /* Run until all complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully */
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK(sd_future_result(fibers[i]));
                safe_close_pair(pipes[i]);
        }
}

static int socket_send_fiber(void *userdata) {
        int *sockfd = ASSERT_PTR(userdata);

        return sd_fiber_send(sockfd[0], "socket", STRLEN("socket"), 0);
}

static int socket_recv_fiber(void *userdata) {
        int *sockfd = ASSERT_PTR(userdata);
        char buf[64];
        ssize_t n;

        n = sd_fiber_recv(sockfd[1], buf, sizeof(buf), 0);
        if (n < 0)
                return (int) n;

        /* Verify we received "socket" */
        if (n != 6 || memcmp(buf, "socket", 6) != 0)
                return -EIO;

        return (int) n;
}

TEST(fiber_io_recv_send) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        /* Higher priority for the recv fiber, which will run first and suspend */
        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "socket-recv", socket_recv_fiber, sockfd, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "socket-send", socket_send_fiber, sockfd, /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fs, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(fr), 6);
        ASSERT_OK_EQ(sd_future_result(fs), 6);
}

static int socket_recv_peek_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        char buf1[64], buf2[64];
        ssize_t n1, n2;

        /* First peek at the data */
        n1 = sd_fiber_recv(sockfd, buf1, sizeof(buf1), MSG_PEEK);
        if (n1 < 0)
                return (int) n1;

        /* Then actually read it */
        n2 = sd_fiber_recv(sockfd, buf2, sizeof(buf2), 0);
        if (n2 < 0)
                return (int) n2;

        /* Both should have read the same data */
        if (n1 != n2 || memcmp(buf1, buf2, n1) != 0)
                return -EIO;

        if (n1 != 4 || memcmp(buf1, "peek", 4) != 0)
                return -EIO;

        return 0;
}

TEST(fiber_io_recv_peek) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "socket-recv-peek", socket_recv_peek_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &f));

        /* Write data to the socket */
        ASSERT_OK_EQ_ERRNO(write(sockfd[0], "peek", 4), 4);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

static int socket_connect_fiber(void *userdata) {
        struct sockaddr_un *addr = userdata;
        _cleanup_close_ int sockfd = -EBADF;

        sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        return sd_fiber_connect(sockfd, (struct sockaddr*) addr, sizeof(*addr));
}

TEST(fiber_io_connect) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create listening socket with abstract namespace */
        _cleanup_close_ int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        ASSERT_OK(listen_fd);

        /* Use abstract socket (starts with null byte) */
        struct sockaddr_un addr = {
                .sun_family = AF_UNIX,
        };
        addr.sun_path[0] = '\0';
        snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "test-fiber-connect-%d", getpid());

        ASSERT_OK(bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK(listen(listen_fd, 1));

        /* Create fiber to connect */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "socket-connect", socket_connect_fiber, &addr, /* destroy= */ NULL, &f));

        /* Run the event loop - connection should complete */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

static int socket_sendmsg_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        struct iovec iov = {
                .iov_base = (void*) "message",
                .iov_len = STRLEN("message"),
        };
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };

        return sd_fiber_sendmsg(sockfd, &msg, 0);
}

static int socket_recvmsg_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        char buf[64];
        struct iovec iov = {
                .iov_base = buf,
                .iov_len = sizeof(buf),
        };
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        ssize_t n;

        n = sd_fiber_recvmsg(sockfd, &msg, 0);
        if (n < 0)
                return (int) n;

        if (n != 7 || memcmp(buf, "message", 7) != 0)
                return -EIO;

        return (int) n;
}

TEST(fiber_io_recvmsg_sendmsg) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "socket-recvmsg", socket_recvmsg_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "socket-sendmsg", socket_sendmsg_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fs, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(fr), 7);
        ASSERT_OK_EQ(sd_future_result(fs), 7);
}

static int socket_sendto_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);

        /* For socketpair dgram sockets, we can use NULL address since they're connected */
        return sd_fiber_sendto(sockfd, "datagram", STRLEN("datagram"), 0, NULL, 0);
}

static int socket_recvfrom_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        char buf[64];
        struct sockaddr_un addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t n;

        n = sd_fiber_recvfrom(sockfd, buf, sizeof(buf), 0,
                              (struct sockaddr*) &addr, &addr_len);
        if (n < 0)
                return (int) n;

        if (n != 8 || memcmp(buf, "datagram", 8) != 0)
                return -EIO;

        return (int) n;
}

TEST(fiber_io_recvfrom_sendto) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "socket-recvfrom", socket_recvfrom_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "socket-sendto", socket_sendto_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fs, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(fr), 8);
        ASSERT_OK_EQ(sd_future_result(fs), 8);
}

static int socket_sendmsg_fd_fiber(void *userdata) {
        int *args = userdata;
        int sockfd = args[0];
        int fd_to_send = args[1];
        struct iovec iov = {
                .iov_base = (void*) "X",
                .iov_len = 1,
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

        return sd_fiber_sendmsg(sockfd, &msg, 0);
}

static int socket_recvmsg_fd_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        char buf[1];
        struct iovec iov = {
                .iov_base = buf,
                .iov_len = sizeof(buf),
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr msg = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        int received_fd;
        ssize_t n;

        n = sd_fiber_recvmsg(sockfd, &msg, 0);
        if (n < 0)
                return (int) n;

        if (n != 1 || buf[0] != 'X')
                return -EIO;

        /* Extract the file descriptor */
        cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
                return -EIO;

        memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

        /* Verify we can use the fd */
        if (fcntl(received_fd, F_GETFD) < 0)
                return -errno;

        close(received_fd);
        return 0;
}

TEST(fiber_io_sendmsg_recvmsg_fd) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        /* Create a test file descriptor to send */
        _cleanup_close_ int test_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT_OK_ERRNO(test_fd);

        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        int args[2] = { sockfd[0], test_fd };
        ASSERT_OK(sd_future_new_fiber(e, "socket-recvmsg-fd", socket_recvmsg_fd_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_future_new_fiber(e, "socket-sendmsg-fd", socket_sendmsg_fd_fiber, args, /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fr, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(fr));
        ASSERT_OK_EQ(sd_future_result(fs), 1);
}

TEST(fiber_io_socket_fallback) {
        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        char buf[STRLEN("fallback")] = {};

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockfd));

        /* Test send/recv without fiber context */
        ASSERT_OK_EQ(sd_fiber_send(sockfd[0], "fallback", sizeof(buf), 0), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(sd_fiber_recv(sockfd[1], buf, sizeof(buf), 0), (ssize_t) sizeof(buf));

        /* Test sendto/recvfrom without fiber context */
        ASSERT_OK_EQ(sd_fiber_sendto(sockfd[0], "fallback", sizeof(buf), 0, NULL, 0), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(sd_fiber_recvfrom(sockfd[1], buf, sizeof(buf), 0, NULL, NULL), (ssize_t) sizeof(buf));
}

static int blocking_recv_fiber(void *userdata) {
        int sockfd = PTR_TO_INT(userdata);
        char buf[64];

        return sd_fiber_recv(sockfd, buf, sizeof(buf), 0);
}

TEST(fiber_io_socket_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int sockfd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockfd));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "blocking-recv", blocking_recv_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &f));

        /* Run once - fiber will suspend on recv */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Cancel the fiber */
        ASSERT_OK(sd_future_cancel(f));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Should be cancelled */
        ASSERT_ERROR(sd_future_result(f), ECANCELED);
}

/* Test: Basic accept operation */
static int accept_fiber(void *userdata) {
        int listen_fd = PTR_TO_INT(userdata);
        struct sockaddr_un addr;
        socklen_t addr_len = sizeof(addr);
        int client_fd;

        client_fd = sd_fiber_accept(listen_fd, (struct sockaddr*) &addr, &addr_len, SOCK_CLOEXEC);
        if (client_fd < 0)
                return client_fd;

        close(client_fd);
        return 0;
}

TEST(fiber_io_accept_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create listening socket with abstract namespace */
        _cleanup_close_ int listen_fd = -EBADF;
        ASSERT_OK_ERRNO(listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));

        struct sockaddr_un addr = {
                .sun_family = AF_UNIX,
        };
        addr.sun_path[0] = '\0';
        snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "test-fiber-accept-%d", getpid());

        ASSERT_OK_ERRNO(bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK_ERRNO(listen(listen_fd, 1));

        /* Create fiber to accept connection */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "accept", accept_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

        /* Connect from outside fiber context */
        _cleanup_close_ int connect_fd = -EBADF;
        ASSERT_OK(connect_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(connect_fd, (struct sockaddr*) &addr, sizeof(addr)));

        /* Run the event loop - accept should complete */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: Multiple sequential accepts */
static int accept_multiple_fiber(void *userdata) {
        int listen_fd = PTR_TO_INT(userdata);
        struct sockaddr_un addr;
        socklen_t addr_len;
        int count = 0;

        for (int i = 0; i < 3; i++) {
                _cleanup_close_ int client_fd = -EBADF;

                addr_len = sizeof(addr);
                client_fd = sd_fiber_accept(listen_fd, (struct sockaddr*) &addr, &addr_len, SOCK_CLOEXEC);
                if (client_fd < 0)
                        return client_fd;

                count++;
        }

        return count;
}

TEST(fiber_io_accept_multiple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create listening socket */
        _cleanup_close_ int listen_fd = -EBADF;
        ASSERT_OK(listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));

        struct sockaddr_un addr = {
                .sun_family = AF_UNIX,
        };
        addr.sun_path[0] = '\0';
        snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "test-fiber-accept-multi-%d", getpid());

        ASSERT_OK(bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK(listen(listen_fd, 5));

        /* Create fiber to accept multiple connections */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "accept-multiple", accept_multiple_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

        /* Connect multiple times */
        int connect_fds[3] = { -EBADF, -EBADF, -EBADF };
        for (size_t i = 0; i < 3; i++) {
                connect_fds[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                ASSERT_OK(connect_fds[i]);
                ASSERT_OK(connect(connect_fds[i], (struct sockaddr*) &addr, sizeof(addr)));
        }

        /* Run the event loop */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_EQ(sd_future_result(f), 3);

        /* Clean up connection fds */
        for (size_t i = 0; i < 3; i++)
                safe_close(connect_fds[i]);
}

/* Test: Accept and exchange data */
static int accept_and_read_fiber(void *userdata) {
        int listen_fd = PTR_TO_INT(userdata);
        _cleanup_close_ int client_fd = -EBADF;
        char buf[64];
        ssize_t n;

        client_fd = sd_fiber_accept(listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0)
                return client_fd;

        n = sd_fiber_read(client_fd, buf, sizeof(buf));
        if (n < 0)
                return (int) n;

        if (n != 5 || memcmp(buf, "hello", 5) != 0)
                return -EIO;

        return 0;
}

TEST(fiber_io_accept_and_read) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create listening socket */
        _cleanup_close_ int listen_fd = -EBADF;
        ASSERT_OK(listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));

        struct sockaddr_un addr = {
                .sun_family = AF_UNIX,
        };
        addr.sun_path[0] = '\0';
        snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "test-fiber-accept-read-%d", getpid());

        ASSERT_OK(bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK(listen(listen_fd, 1));

        /* Create fiber to accept and read */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "accept-and-read", accept_and_read_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

        /* Connect and send data */
        _cleanup_close_ int connect_fd = -EBADF;
        ASSERT_OK(connect_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(connect_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK_EQ_ERRNO(write(connect_fd, "hello", 5), 5);

        /* Run the event loop */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: ppoll with single fd ready immediately */
static int ppoll_immediate_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        /* Should have one fd ready */
        if (r != 1)
                return -EIO;

        if (!(fds[0].revents & POLLIN))
                return -EIO;

        return 0;
}

TEST(fiber_ppoll_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Write data before creating fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-immediate", ppoll_immediate_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: ppoll with fd that becomes ready after suspension */
static int ppoll_suspend_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        if (r != 1 || !(fds[0].revents & POLLIN))
                return -EIO;

        /* Read the data */
        char buf[1];
        if (read(pipefd[0], buf, 1) != 1 || buf[0] != 'Y')
                return -EIO;

        return 0;
}

TEST(fiber_ppoll_suspend) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-suspend", ppoll_suspend_fiber, pipefd, /* destroy= */ NULL, &f));

        /* Run once - fiber will suspend on ppoll */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write data to wake it up */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "Y", 1), 1);

        /* Complete execution */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: ppoll with multiple fds */
static int ppoll_multiple_fiber(void *userdata) {
        int (*pipes)[2] = userdata;
        struct pollfd fds[] = {
                { .fd = pipes[0][0], .events = POLLIN },
                { .fd = pipes[1][0], .events = POLLIN },
                { .fd = pipes[2][0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        /* Should have all three ready */
        if (r != 3)
                return -EIO;

        for (size_t i = 0; i < 3; i++) {
                if (!(fds[i].revents & POLLIN))
                        return -EIO;

                char buf[1];
                if (read(fds[i].fd, buf, 1) != 1 || buf[0] != (char) ('A' + i))
                        return -EIO;
        }

        return 0;
}

TEST(fiber_ppoll_multiple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create three pipes */
        int pipes[3][2];
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-multiple", ppoll_multiple_fiber, pipes, /* destroy= */ NULL, &f));

        /* Run once - fiber will suspend waiting for data */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write to all three pipes in different order */
        ASSERT_OK_EQ_ERRNO(write(pipes[2][1], "C", 1), 1);
        ASSERT_OK_EQ_ERRNO(write(pipes[0][1], "A", 1), 1);
        ASSERT_OK_EQ_ERRNO(write(pipes[1][1], "B", 1), 1);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));

        for (size_t i = 0; i < 3; i++)
                safe_close_pair(pipes[i]);
}

/* Test: ppoll with POLLOUT (write readiness) */
static int ppoll_pollout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[1], .events = POLLOUT },
        };
        int r;

        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        if (r != 1 || !(fds[0].revents & POLLOUT))
                return -EIO;

        /* Pipe should be writable */
        if (write(pipefd[1], "Z", 1) != 1)
                return -errno;

        return 0;
}

TEST(fiber_ppoll_pollout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-pollout", ppoll_pollout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));

        /* Verify data was written */
        char buf[1];
        ASSERT_OK_EQ_ERRNO(read(pipefd[0], buf, 1), 1);
        ASSERT_EQ(buf[0], 'Z');
}

/* Test: ppoll with timeout that expires */
static int ppoll_timeout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        /* Poll with 100ms timeout - no data will arrive */
        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), 100 * USEC_PER_MSEC);
        if (r < 0)
                return r;

        /* Should timeout with no fds ready */
        if (r != 0)
                return -EIO;

        return 0;
}

TEST(fiber_ppoll_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-timeout", ppoll_timeout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: ppoll with zero timeout (should not block) */
static int ppoll_zero_timeout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        /* Poll with zero timeout - should return immediately */
        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), 0);
        if (r < 0)
                return r;

        /* No data available, so should return 0 */
        if (r != 0)
                return -EIO;

        /* Now write data */
        if (write(pipefd[1], "Q", 1) != 1)
                return -errno;

        /* Poll again with zero timeout - should see data */
        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), 0);
        if (r < 0)
                return r;

        if (r != 1 || !(fds[0].revents & POLLIN))
                return -EIO;

        return 0;
}

TEST(fiber_ppoll_zero_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-zero-timeout", ppoll_zero_timeout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: ppoll with negative fd (should be ignored) */
static int ppoll_negative_fd_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = -1, .events = POLLIN },
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_ppoll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        /* Only the second fd should be ready */
        if (r != 1 || !(fds[1].revents & POLLIN))
                return -EIO;

        /* First fd should have no events */
        if (fds[0].revents != 0)
                return -EIO;

        return 0;
}

TEST(fiber_ppoll_negative_fd) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Write data before creating fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "N", 1), 1);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "ppoll-negative-fd", ppoll_negative_fd_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: Multiple fibers waiting on the same fd */
typedef struct SharedFdArgs {
        int pipefd;
        int *counter;
} SharedFdArgs;

static int shared_fd_read_fiber(void *userdata) {
        SharedFdArgs *args = ASSERT_PTR(userdata);
        char buf[1];
        ssize_t n;

        n = sd_fiber_read(args->pipefd, buf, sizeof(buf));
        if (n < 0)
                return (int) n;

        if (n != 1)
                return -EIO;

        /* Increment counter to track successful reads */
        (*args->counter)++;

        return 0;
}

TEST(fiber_io_same_fd_multiple_fibers) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Create 3 fibers all waiting on the same pipe read end */
        sd_future **fibers = NULL;
        size_t n_fibers = 3;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);
        SharedFdArgs args[3];
        int counter = 0;

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < 3; i++) {
                args[i].pipefd = pipefd[0];
                args[i].counter = &counter;
                ASSERT_OK(sd_future_new_fiber(e, "shared-fd-read", shared_fd_read_fiber, &args[i], /* destroy= */ NULL, &fibers[i]));
        }

        /* All fibers should suspend waiting for data */
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write 3 bytes - each byte will wake one fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "ABC", 3), 3);

        /* Run until all fibers complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully and each should have read one byte */
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK(sd_future_result(fibers[i]));

        ASSERT_EQ(counter, 3);
}

/* Test: sd_fiber_await() - wait for a fiber to complete */
static int slow_fiber(void *userdata) {
        int *counter = userdata;

        for (int i = 0; i < 3; i++) {
                (*counter)++;
                sd_fiber_yield();
        }

        return 42;
}

static int waiting_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        r = sd_future_result(target);
        return r == 42 ? 0 : -EIO;
}

TEST(fiber_wait_for_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create target fiber with lower priority (runs second) */
        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_future_new_fiber(e, "slow", slow_fiber, &counter, /* destroy= */ NULL, &target));
        ASSERT_OK(sd_future_set_priority(target, 1));

        /* Create waiter fiber with higher priority (runs first) */
        ASSERT_OK(sd_future_new_fiber(e, "waiting", waiting_fiber, target, /* destroy= */ NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 0));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(waiter));
        ASSERT_OK_EQ(sd_future_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: wait for already completed fiber */
static int wait_for_completed_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int value = 100;

        /* Create target fiber with higher priority (runs first) */
        ASSERT_OK(sd_future_new_fiber(e, "simple", simple_fiber, &value, /* destroy= */ NULL, &target));
        ASSERT_OK(sd_future_set_priority(target, 0));
        /* Create waiter fiber with lower priority (runs second, after target completes) */
        ASSERT_OK(sd_future_new_fiber(e, "wait-for-completed", wait_for_completed_fiber, target, /* destroy= */ NULL, &waiter));
        ASSERT_OK(sd_future_set_priority(waiter, 1));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_future_result(waiter), 100);
        ASSERT_OK_EQ(sd_future_result(target), 100);
}

/* Test: wait for cancelled fiber */
static int wait_for_cancelled_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_cancelled) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_future_new_fiber(e, "yielding", fiber_that_yields, &counter, /* destroy= */ NULL, &target));
        ASSERT_OK(sd_future_new_fiber(e, "wait-for-cancelled", wait_for_cancelled_fiber, target, /* destroy= */ NULL, &waiter));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        ASSERT_OK(sd_future_cancel(target));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_ERROR(sd_future_result(waiter), ECANCELED);
        ASSERT_ERROR(sd_future_result(target), ECANCELED);
}

/* Test: multiple fibers waiting for the same target */
static int multi_waiter_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        return sd_future_result(target);
}

TEST(fiber_wait_for_multiple_waiters) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *target = NULL;
        int counter = 0;
        ASSERT_OK(sd_future_new_fiber(e, "slow", slow_fiber, &counter, /* destroy= */ NULL, &target));

        sd_future **waiters = NULL;
        size_t n_waiters = 3;
        CLEANUP_ARRAY(waiters, n_waiters, sd_future_unref_many);

        ASSERT_NOT_NULL(waiters = new0(sd_future*, n_waiters));
        for (size_t i = 0; i < n_waiters; i++)
                ASSERT_OK(sd_future_new_fiber(e, "multi-waiter", multi_waiter_fiber, target, /* destroy= */ NULL, &waiters[i]));

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < n_waiters; i++)
                ASSERT_OK_EQ(sd_future_result(waiters[i]), 42);

        ASSERT_OK_EQ(sd_future_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: chain of waiting fibers */
static int chain_waiter_fiber(void *userdata) {
        sd_future *target = userdata;
        int r;

        r = sd_fiber_await(target);
        if (r < 0)
                return r;

        r = sd_future_result(target);
        return r + 1;
}

TEST(fiber_wait_for_chain) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_future **fibers = NULL;
        size_t n_fibers = 5;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);
        int value = 10;

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        ASSERT_OK(sd_future_new_fiber(e, "simple", simple_fiber, &value, /* destroy= */ NULL, &fibers[0]));

        /* Each subsequent fiber waits for the previous and adds 1 */
        for (size_t i = 1; i < n_fibers; i++)
                ASSERT_OK(sd_future_new_fiber(e, "chain-waiter", chain_waiter_fiber, fibers[i - 1], /* destroy= */ NULL, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* Check results: 10, 11, 12, 13, 14 */
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK_EQ(sd_future_result(fibers[i]), 10 + (int) i);
}

/* Test: wait_for_terminate basic functionality */
static int wait_simple_fiber(void *userdata) {
        _cleanup_(pidref_done_sigkill_wait_suspend) PidRef pidref = PIDREF_NULL;
        siginfo_t si;
        int r;

        /* Fork a child that exits immediately */
        r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref);
        if (r < 0)
                return r;

        if (r == 0)
                _exit(42);

        /* Parent - wait for child */
        r = pidref_wait_for_terminate_suspend(&pidref, &si);
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
        ASSERT_OK(sd_future_new_fiber(e, "wait-simple", wait_simple_fiber, NULL, /* destroy= */ NULL, &f));

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
                r = pidref_wait_for_terminate_suspend(&pidrefs[i], &si);
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
        ASSERT_OK(sd_future_new_fiber(e, "wait-multiple", wait_multiple_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

static int concurrent_wait_fiber(void *userdata) {
        _cleanup_(pidref_done_sigkill_wait_suspend) PidRef pidref = PIDREF_NULL;
        siginfo_t si;
        int r;

        r = pidref_safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref);
        if (r < 0)
                return r;

        if (r == 0)
                /* Child exits with specified status */
                _exit(PTR_TO_INT(userdata));

        r = pidref_wait_for_terminate_suspend(&pidref, &si);
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

        sd_future **fibers = NULL;
        size_t n_fibers = 3;
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_many);

        /* Create 3 fibers, each waiting for a different child */
        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK(sd_future_new_fiber(e, "concurrent-wait", concurrent_wait_fiber, INT_TO_PTR(20 + i), /* destroy= */ NULL, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* All fibers should complete successfully */
        for (size_t i = 0; i < n_fibers; i++)
                ASSERT_OK(sd_future_result(fibers[i]));
}

static int timer_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        int *count = ASSERT_PTR(userdata);
        int r;

        (*count)++;

        r = sd_event_source_set_time_relative(s, 5 * MSEC_PER_SEC);
        if (r < 0)
                return r;

        if (sd_fiber_is_running() && *count >= 3)
                sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

static int event_run_fiber_func(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *inner_timer = NULL;
        int r;

        /* Create inner event loop from within the fiber */
        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Add a timer to the inner event loop that fires every 50ms */
        r = sd_event_add_time_relative(inner, &inner_timer, CLOCK_MONOTONIC,
                                       5 * USEC_PER_MSEC, 0, timer_callback,
                                       userdata);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(inner_timer, SD_EVENT_ON);
        if (r < 0)
                return r;

        return sd_event_loop(inner);
}

TEST(sd_event_loop_fiber) {
        /* Create outer event loop for the fiber scheduler */
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        /* Add a timer to the outer event loop that fires every 75ms */
        _cleanup_(sd_event_source_unrefp) sd_event_source *outer_timer = NULL;
        int outer_timer_count = 0;
        ASSERT_OK(sd_event_add_time_relative(outer, &outer_timer, CLOCK_MONOTONIC,
                                             5 * USEC_PER_MSEC, 0, timer_callback,
                                             &outer_timer_count));

        /* Create a fiber that will create and run the inner event loop */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int inner_timer_count = 0;
        ASSERT_OK(sd_future_new_fiber(outer, "event-runner", event_run_fiber_func, &inner_timer_count, /* destroy= */ NULL, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully */
        ASSERT_OK(sd_future_result(f));

        /* Both timers should have fired at least once */
        ASSERT_EQ(inner_timer_count, 3);
        ASSERT_GT(outer_timer_count, 0);
}

static int event_run_fiber_timeout_func(void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *inner = NULL;
        int r;

        /* Create inner event loop from within the fiber */
        r = sd_event_new(&inner);
        if (r < 0)
                return r;

        /* Run with a short timeout - should timeout since there are no events */
        return sd_event_run_suspend(inner, 10 * USEC_PER_MSEC);
}

TEST(sd_event_run_fiber_timeout) {
        /* Create outer event loop for the fiber scheduler */
        _cleanup_(sd_event_unrefp) sd_event *outer = NULL;
        ASSERT_OK(sd_event_new(&outer));
        ASSERT_OK(sd_event_set_exit_on_idle(outer, true));

        /* Create a fiber that will run sd_event_run_fiber() with timeout */
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_future_new_fiber(outer, "event-timeout", event_run_fiber_timeout_func, NULL, /* destroy= */ NULL, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully (timeout returns 0) */
        ASSERT_OK_ZERO(sd_future_result(f));
}

static int nested_cancellation_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        _cleanup_(sd_fiber_cancel_wait_unrefp) sd_future *nested = NULL;
        int r;

        if (*counter >= 5)
                return sd_fiber_sleep(10 * USEC_PER_SEC);

        (*counter)++;

        _cleanup_free_ char *name = NULL;
        if (asprintf(&name, "nested-cancellation-%i", *counter) < 0)
                return -ENOMEM;

        /* Create a nested fiber within this fiber */
        r = sd_future_new_fiber(sd_fiber_get_event(), name, nested_cancellation_fiber, counter, /* destroy= */ NULL, &nested);
        if (r < 0)
                return r;

        /* Wait for the nested fiber to complete */
        r = sd_fiber_await(nested);
        if (r < 0)
                return r;

        /* If we got here without cancellation, verify the nested fiber completed */
        return sd_future_result(nested);
}

static int exit_loop_fiber(void *userdata) {
        /* Just exit the event loop, causing the outer fiber to be cancelled */
        return sd_event_exit(sd_fiber_get_event(), 0);
}

TEST(fiber_nested_cancellation) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));

        int counter = 0;

        /* Create outer fiber with higher priority (runs first) */
        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "outer", nested_cancellation_fiber, &counter, /* destroy= */ NULL, &outer));

        /* Create exit fiber with lower priority (runs after all nested fibers have suspended) */
        _cleanup_(sd_future_unrefp) sd_future *exit_fiber = NULL;
        ASSERT_OK(sd_future_new_fiber(e, "exit-loop", exit_loop_fiber, NULL, /* destroy= */ NULL, &exit_fiber));
        ASSERT_OK(sd_future_set_priority(exit_fiber, 1));

        /* Run the event loop - the exit fiber should cause it to exit,
         * which should cancel the outer fiber, which should cancel the nested fiber, and so forth. */
        ASSERT_OK(sd_event_loop(e));

        /* The exit fiber should have completed successfully */
        ASSERT_OK(sd_future_result(exit_fiber));

        /* The outer fiber should have been cancelled */
        ASSERT_ERROR(sd_future_result(outer), ECANCELED);

        /* The nested fiber was created and incremented counter once before being cancelled */
        ASSERT_GT(counter, 0);
}

static int nested_fiber_cleanup_nested_fiber(void *userdata) {
        int *counter = ASSERT_PTR(userdata);
        int r;

        r = sd_fiber_sleep(10 * USEC_PER_SEC);
        if (r == -ECANCELED)
                (*counter)++;
        else if (r < 0)
                return r;

        return 0;
}

static int nested_fiber_cleanup_fiber(void *userdata) {
        _cleanup_(sd_fiber_cancel_wait_unrefp) sd_future *nested = NULL;
        int r;

        /* Create a nested fiber within this fiber. */
        r = sd_future_new_fiber(sd_fiber_get_event(), "nested", nested_fiber_cleanup_nested_fiber, userdata, /* destroy= */ NULL, &nested);
        if (r < 0)
                return r;

        /* Yield and then exit, the nested fiber should be cancelled. */
        return sd_fiber_yield();
}

TEST(nested_fiber_cleanup) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *outer = NULL;
        int counter = 0;
        ASSERT_OK(sd_future_new_fiber(e, "outer", nested_fiber_cleanup_fiber, &counter, /* destroy= */ NULL, &outer));

        ASSERT_OK(sd_event_loop(e));

        /* The outer fiber should have finished normally */
        ASSERT_OK(sd_future_result(outer));

        /* The nested fiber was created and incremented its counter once when it was cancelled. */
        ASSERT_GT(counter, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
