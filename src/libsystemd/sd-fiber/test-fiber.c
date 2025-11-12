/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-fiber.h"

#include "cleanup-util.h"
#include "fd-util.h"
#include "fiber-util.h"
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int value = 5;
        ASSERT_OK(sd_fiber_new_full(e, "simple", simple_fiber, &value, SD_FIBER_PRIORITY_DEFAULT, &f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_fiber_result(f), 5);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new_full(e, "yielding", yielding_fiber, &counter, SD_FIBER_PRIORITY_DEFAULT, &f));

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

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 5));
        for (size_t i = 0; i < 5; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "counting-%zu", i));
                ASSERT_OK(sd_fiber_new_full(e, name, counting_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < 5; i++)
                ASSERT_OK_EQ(sd_fiber_result(fibers[i]), 5);
}

static int priority_fiber(void *userdata) {
        static int execution_order = 0;

        execution_order++;
        sd_fiber_yield();

        return execution_order;
}

/* Test: Priority-based scheduling */
TEST(fiber_priority_ascending) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 5));
        for (size_t i = 0; i < 5; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_fiber_new_full(e, name, priority_fiber, NULL, i, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have ascending priorities, so we the first one to run to completion,
         * followed by the second one, etc. */

        for (size_t i = 0; i < 5; i++)
                ASSERT_EQ(sd_fiber_result(fibers[i]), (int) i + 1);
}

TEST(fiber_priority_identical) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 5));
        for (size_t i = 0; i < 5; i++) {
                _cleanup_free_ char *name = NULL;
                ASSERT_OK(asprintf(&name, "priority-%zu", i));
                ASSERT_OK(sd_fiber_new_full(e, name, priority_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        /* The fibers have the same priorities, so we expect all of them to run once first, and then they'll
         * all run again another time, so they should all return the same value. */

        for (size_t i = 0; i < 5; i++)
                ASSERT_EQ(sd_fiber_result(fibers[i]), (int) 10);
}

static int error_fiber(void *userdata) {
        return -ENOENT;
}

TEST(fiber_error_return) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "error", error_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_EQ(sd_fiber_result(f), -ENOENT);
}

static int cancel_fiber(void *userdata) {
        return sd_fiber_yield();
}

TEST(fiber_cancel_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int value = 42;
        ASSERT_OK(sd_fiber_new_full(e, "cancel", cancel_fiber, &value, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_fiber_cancel(f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_fiber_result(f), ECANCELED);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int yield_count = 0;
        ASSERT_OK(sd_fiber_new_full(e, "yielding", fiber_that_yields, &yield_count, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 1);
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(yield_count, 2);

        ASSERT_OK(sd_fiber_cancel(f));

        ASSERT_OK(sd_event_loop(e));

        /* sd_fiber should have been cancelled */
        ASSERT_ERROR(sd_fiber_result(f), ECANCELED);
        ASSERT_EQ(yield_count, 2);
}

/* Test: Cancel a fiber that has already completed */
TEST(fiber_cancel_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int value = 42;
        ASSERT_OK(sd_fiber_new_full(e, "simple", simple_fiber, &value, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run the fiber to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Canceling a completed fiber should be a no-op */
        ASSERT_OK(sd_fiber_cancel(f));
        ASSERT_EQ(sd_fiber_result(f), 42);
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

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        int counters[3] = {0, 0, 0};
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_new_full(e, "multiple-yield", multiple_yield_fiber, &counters[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));

        /* Run one iteration - all fibers yield after incrementing once */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_EQ(counters[0], 1);
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(counters[2], 1);

        /* Cancel the second fiber */
        ASSERT_OK(sd_fiber_cancel(fibers[1]));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* First and third fibers should complete normally */
        ASSERT_EQ(counters[0], 3);
        ASSERT_EQ(counters[2], 3);
        ASSERT_EQ(sd_fiber_result(fibers[0]), 0);
        ASSERT_EQ(sd_fiber_result(fibers[2]), 0);

        /* Second fiber should be canceled with counter at 1 */
        ASSERT_EQ(counters[1], 1);
        ASSERT_EQ(sd_fiber_result(fibers[1]), -ECANCELED);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "pipe-read", pipe_read_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Write data to the pipe */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "hello", 5), 5);

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_fiber_result(f), 5);
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "pipe-read", pipe_read_fiber,  pipefd, 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "pipe-write", pipe_write_fiber, pipefd, 0, &fw));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_fiber_result(fr), 5);
        ASSERT_OK_EQ(sd_fiber_result(fw), 5);
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

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        int pipes[3][2];
        int args[3][2];
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                ASSERT_OK(sd_fiber_new_full(e, "concurrent-read", concurrent_read_fiber, args[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
        }

        /* Write data in reverse order */
        ASSERT_EQ(write(pipes[2][1], "C", 1), 1);
        ASSERT_EQ(write(pipes[1][1], "B", 1), 1);
        ASSERT_EQ(write(pipes[0][1], "A", 1), 1);

        /* Run until all complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully */
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_result(fibers[i]));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "blocking-read", blocking_read_fiber, INT_TO_PTR(pipefd[0]), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run once - fiber will suspend on read */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Fiber should be suspended now - add explicit check via state tracking */

        /* Cancel the fiber */
        ASSERT_OK(sd_fiber_cancel(f));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Should be cancelled */
        ASSERT_ERROR(sd_fiber_result(f), ECANCELED);
}

TEST(fiber_io_fallback) {
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));  /* Note: blocking pipe */

        char buf[STRLEN("fallback")] = {};
        ASSERT_OK_EQ(sd_fiber_write(pipefd[1], "fallback", sizeof(buf)), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(sd_fiber_read(pipefd[0], buf, sizeof(buf)), (ssize_t) sizeof(buf));
}

static int pipe_readv_fiber(void *userdata) {
        int *pipefd = userdata;
        char buf1[5], buf2[5];
        struct iovec iov[] = {
                { .iov_base = buf1, .iov_len = sizeof(buf1) },
                { .iov_base = buf2, .iov_len = sizeof(buf2) },
        };
        ssize_t n;

        n = sd_fiber_readv(pipefd[0], iov, ELEMENTSOF(iov));
        if (n < 0)
                return (int) n;

        /* Verify we read 10 bytes: "hello" (5) + "world" (5) */
        if (n != 10 || memcmp(buf1, "hello", 5) != 0 || memcmp(buf2, "world", 5) != 0)
                return -EIO;

        return (int) n;
}

TEST(fiber_io_readv_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "pipe-readv", pipe_readv_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Write data to the pipe */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "helloworld", 10), 10);

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_fiber_result(f), 10);
}

static int pipe_writev_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        const char *part1 = "scatter";
        const char *part2 = "gather";
        struct iovec iov[] = {
                { .iov_base = (void*) part1, .iov_len = STRLEN("scatter") },
                { .iov_base = (void*) part2, .iov_len = STRLEN("gather") },
        };

        return sd_fiber_writev(pipefd[1], iov, ELEMENTSOF(iov));
}

TEST(fiber_io_writev_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "pipe-writev", pipe_writev_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber wrote the data */
        ASSERT_OK_EQ(sd_fiber_result(f), 13);

        /* Read and verify the data */
        char buf[64];
        ASSERT_OK_EQ_ERRNO(read(pipefd[0], buf, sizeof(buf)), 13);
        ASSERT_TRUE(memcmp(buf, "scattergather", 13) == 0);
}

static int pipe_readv_suspend_fiber(void *userdata) {
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

static int pipe_writev_suspend_fiber(void *userdata) {
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "pipe-readv-suspend", pipe_readv_suspend_fiber, pipefd, 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "pipe-writev-suspend", pipe_writev_suspend_fiber, pipefd, 0, &fw));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify both fibers completed successfully */
        ASSERT_OK_EQ(sd_fiber_result(fr), 10);
        ASSERT_OK_EQ(sd_fiber_result(fw), 10);
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

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        int pipes[3][2];
        int args[3][3];
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                args[i][2] = 'a' + i;
                ASSERT_OK(sd_fiber_new_full(e, "concurrent-readv", concurrent_readv_fiber, args[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
        }

        /* Write data in reverse order */
        ASSERT_EQ(write(pipes[2][1], "Cc", 2), 2);
        ASSERT_EQ(write(pipes[1][1], "Bb", 2), 2);
        ASSERT_EQ(write(pipes[0][1], "Aa", 2), 2);

        /* Run until all complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully */
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_result(fibers[i]));
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "socket-recv", socket_recv_fiber, sockfd, 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "socket-send", socket_send_fiber, sockfd, 0, &fs));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_fiber_result(fr), 6);
        ASSERT_OK_EQ(sd_fiber_result(fs), 6);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "socket-recv-peek", socket_recv_peek_fiber, INT_TO_PTR(sockfd[1]), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Write data to the socket */
        ASSERT_OK_EQ_ERRNO(write(sockfd[0], "peek", 4), 4);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "socket-connect", socket_connect_fiber, &addr, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run the event loop - connection should complete */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "socket-recvmsg", socket_recvmsg_fiber, INT_TO_PTR(sockfd[1]), 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "socket-sendmsg", socket_sendmsg_fiber, INT_TO_PTR(sockfd[0]), 0, &fs));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_fiber_result(fr), 7);
        ASSERT_OK_EQ(sd_fiber_result(fs), 7);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "socket-recvfrom", socket_recvfrom_fiber, INT_TO_PTR(sockfd[1]), 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "socket-sendto", socket_sendto_fiber, INT_TO_PTR(sockfd[0]), 0, &fs));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_fiber_result(fr), 8);
        ASSERT_OK_EQ(sd_fiber_result(fs), 8);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *fs = NULL, *fr = NULL;
        int args[2] = { sockfd[0], test_fd };
        ASSERT_OK(sd_fiber_new_full(e, "socket-recvmsg-fd", socket_recvmsg_fd_fiber, INT_TO_PTR(sockfd[1]), 1, &fr));
        ASSERT_OK(sd_fiber_new_full(e, "socket-sendmsg-fd", socket_sendmsg_fd_fiber, args, 0, &fs));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_fiber_result(fr));
        ASSERT_OK_EQ(sd_fiber_result(fs), 1);
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "blocking-recv", blocking_recv_fiber, INT_TO_PTR(sockfd[0]), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run once - fiber will suspend on recv */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Cancel the fiber */
        ASSERT_OK(sd_fiber_cancel(f));

        /* Run to completion */
        ASSERT_OK(sd_event_loop(e));

        /* Should be cancelled */
        ASSERT_ERROR(sd_fiber_result(f), ECANCELED);
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "accept", accept_fiber, INT_TO_PTR(listen_fd), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Connect from outside fiber context */
        _cleanup_close_ int connect_fd = -EBADF;
        ASSERT_OK(connect_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(connect_fd, (struct sockaddr*) &addr, sizeof(addr)));

        /* Run the event loop - accept should complete */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "accept-multiple", accept_multiple_fiber, INT_TO_PTR(listen_fd), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Connect multiple times */
        int connect_fds[3] = { -EBADF, -EBADF, -EBADF };
        for (size_t i = 0; i < 3; i++) {
                connect_fds[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
                ASSERT_OK(connect_fds[i]);
                ASSERT_OK(connect(connect_fds[i], (struct sockaddr*) &addr, sizeof(addr)));
        }

        /* Run the event loop */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_EQ(sd_fiber_result(f), 3);

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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "accept-and-read", accept_and_read_fiber, INT_TO_PTR(listen_fd), SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Connect and send data */
        _cleanup_close_ int connect_fd = -EBADF;
        ASSERT_OK(connect_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(connect_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK_EQ_ERRNO(write(connect_fd, "hello", 5), 5);

        /* Run the event loop */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-immediate", ppoll_immediate_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-suspend", ppoll_suspend_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run once - fiber will suspend on ppoll */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write data to wake it up */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "Y", 1), 1);

        /* Complete execution */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-multiple", ppoll_multiple_fiber, pipes, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run once - fiber will suspend waiting for data */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write to all three pipes in different order */
        ASSERT_OK_EQ_ERRNO(write(pipes[2][1], "C", 1), 1);
        ASSERT_OK_EQ_ERRNO(write(pipes[0][1], "A", 1), 1);
        ASSERT_OK_EQ_ERRNO(write(pipes[1][1], "B", 1), 1);

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));

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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-pollout", ppoll_pollout_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));

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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-timeout", ppoll_timeout_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-zero-timeout", ppoll_zero_timeout_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "ppoll-negative-fd", ppoll_negative_fd_fiber, pipefd, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
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
        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);
        SharedFdArgs args[3];
        int counter = 0;

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++) {
                args[i].pipefd = pipefd[0];
                args[i].counter = &counter;
                ASSERT_OK(sd_fiber_new_full(e, "shared-fd-read", shared_fd_read_fiber, &args[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
        }

        /* All fibers should suspend waiting for data */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write 3 bytes - each byte will wake one fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "ABC", 3), 3);

        /* Run until all fibers complete */
        ASSERT_OK(sd_event_loop(e));

        /* All should complete successfully and each should have read one byte */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_result(fibers[i]));

        ASSERT_EQ(counter, 3);
}

/* Test: sd_fiber_wait_for() - wait for a fiber to complete */
static int slow_fiber(void *userdata) {
        int *counter = userdata;

        for (int i = 0; i < 3; i++) {
                (*counter)++;
                sd_fiber_yield();
        }

        return 42;
}

static int waiting_fiber(void *userdata) {
        sd_fiber *target = userdata;
        int r;

        r = sd_fiber_wait_for(target);
        if (r < 0)
                return r;

        r = sd_fiber_result(target);
        return r == 42 ? 0 : -EIO;
}

TEST(fiber_wait_for_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create target fiber with lower priority (runs second) */
        _cleanup_(sd_fiber_unrefp) sd_fiber *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new_full(e, "slow", slow_fiber, &counter, 1, &target));

        /* Create waiter fiber with higher priority (runs first) */
        ASSERT_OK(sd_fiber_new_full(e, "waiting", waiting_fiber, target, 0, &waiter));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_fiber_result(waiter));
        ASSERT_OK_EQ(sd_fiber_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: wait for already completed fiber */
static int wait_for_completed_fiber(void *userdata) {
        sd_fiber *target = userdata;
        int r;

        r = sd_fiber_wait_for(target);
        if (r < 0)
                return r;

        return sd_fiber_result(target);
}

TEST(fiber_wait_for_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *target = NULL, *waiter = NULL;
        int value = 100;

        /* Create target fiber with higher priority (runs first) */
        ASSERT_OK(sd_fiber_new_full(e, "simple", simple_fiber, &value, 0, &target));
        /* Create waiter fiber with lower priority (runs second, after target completes) */
        ASSERT_OK(sd_fiber_new_full(e, "wait-for-completed", wait_for_completed_fiber, target, 1, &waiter));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK_EQ(sd_fiber_result(waiter), 100);
        ASSERT_OK_EQ(sd_fiber_result(target), 100);
}

/* Test: wait for cancelled fiber */
static int wait_for_cancelled_fiber(void *userdata) {
        sd_fiber *target = userdata;
        int r;

        r = sd_fiber_wait_for(target);
        if (r < 0)
                return r;

        return sd_fiber_result(target);
}

TEST(fiber_wait_for_cancelled) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *target = NULL, *waiter = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new_full(e, "yielding", fiber_that_yields, &counter, SD_FIBER_PRIORITY_DEFAULT, &target));
        ASSERT_OK(sd_fiber_new_full(e, "wait-for-cancelled", wait_for_cancelled_fiber, target, SD_FIBER_PRIORITY_DEFAULT, &waiter));

        ASSERT_OK_POSITIVE(sd_event_run(e, 0));
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        ASSERT_OK(sd_fiber_cancel(target));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_ERROR(sd_fiber_result(waiter), ECANCELED);
        ASSERT_ERROR(sd_fiber_result(target), ECANCELED);
}

/* Test: multiple fibers waiting for the same target */
static int multi_waiter_fiber(void *userdata) {
        sd_fiber *target = userdata;
        int r;

        r = sd_fiber_wait_for(target);
        if (r < 0)
                return r;

        return sd_fiber_result(target);
}

TEST(fiber_wait_for_multiple_waiters) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *target = NULL;
        int counter = 0;
        ASSERT_OK(sd_fiber_new_full(e, "slow", slow_fiber, &counter, SD_FIBER_PRIORITY_DEFAULT, &target));

        sd_fiber **waiters = NULL;
        size_t n_waiters = 0;
        CLEANUP_ARRAY(waiters, n_waiters, sd_fiber_unref_many);

        ASSERT_NOT_NULL(waiters = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_new_full(e, "multi-waiter", multi_waiter_fiber, target, SD_FIBER_PRIORITY_DEFAULT, &waiters[i]));

        ASSERT_OK(sd_event_loop(e));

        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_EQ(sd_fiber_result(waiters[i]), 42);

        ASSERT_OK_EQ(sd_fiber_result(target), 42);
        ASSERT_EQ(counter, 3);
}

/* Test: chain of waiting fibers */
static int chain_waiter_fiber(void *userdata) {
        sd_fiber *target = userdata;
        int r;

        r = sd_fiber_wait_for(target);
        if (r < 0)
                return r;

        r = sd_fiber_result(target);
        return r + 1;
}

TEST(fiber_wait_for_chain) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);
        int value = 10;

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 5));
        ASSERT_OK(sd_fiber_new_full(e, "simple", simple_fiber, &value, SD_FIBER_PRIORITY_DEFAULT, &fibers[0]));

        /* Each subsequent fiber waits for the previous and adds 1 */
        for (size_t i = 1; i < 5; i++)
                ASSERT_OK(sd_fiber_new_full(e, "chain-waiter", chain_waiter_fiber, fibers[i - 1], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* Check results: 10, 11, 12, 13, 14 */
        for (size_t i = 0; i < 5; i++)
                ASSERT_OK_EQ(sd_fiber_result(fibers[i]), 10 + (int) i);
}

/* Test: waitgroup with all successful fibers */
static int success_fiber(void *userdata) {
        int value = PTR_TO_INT(userdata);
        sd_fiber_yield();
        return value;
}

TEST(fiber_waitgroup_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        /* Create 3 fibers with different return values */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_new_full(e, "success", success_fiber, INT_TO_PTR(10 + i), SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
                ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[i]));
        }

        ASSERT_OK(sd_event_loop(e));

        /* Check individual results */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_EQ(sd_fiber_result(fibers[i]), 10 + (int) i);

        /* Waitgroup check should be 0 (all successful) */
        ASSERT_OK(sd_fiber_waitgroup_check(wg, NULL));
}

/* Test: waitgroup with one failing fiber */
static int failing_fiber(void *userdata) {
        sd_fiber_yield();
        return -ENOENT;
}

TEST(fiber_waitgroup_with_failure) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));

        /* First two succeed */
        ASSERT_OK(sd_fiber_new_full(e, "success", success_fiber, INT_TO_PTR(1), SD_FIBER_PRIORITY_DEFAULT, &fibers[0]));
        ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[0]));

        /* Third fails */
        ASSERT_OK(sd_fiber_new_full(e, "failing", failing_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &fibers[1]));
        ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[1]));

        /* Fourth succeeds */
        ASSERT_OK(sd_fiber_new_full(e, "success", success_fiber, INT_TO_PTR(3), SD_FIBER_PRIORITY_DEFAULT, &fibers[2]));
        ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[2]));

        ASSERT_OK(sd_event_loop(e));

        /* Check individual results */
        ASSERT_OK_EQ(sd_fiber_result(fibers[0]), 1);
        ASSERT_ERROR(sd_fiber_result(fibers[1]), ENOENT);
        ASSERT_OK_EQ(sd_fiber_result(fibers[2]), 3);

        /* Waitgroup check should return the first error and the failed fiber */
        _cleanup_(sd_fiber_unrefp) sd_fiber *failed = NULL;
        ASSERT_ERROR(sd_fiber_waitgroup_check(wg, &failed), ENOENT);
        ASSERT_NOT_NULL(failed);
        ASSERT_TRUE(failed == fibers[1]);
}

/* Test: fiber that waits for waitgroup */
static int waitgroup_wait_fiber(void *userdata) {
        sd_fiber_waitgroup *wg = userdata;
        int r;

        /* Wait for all fibers in the waitgroup */
        r = sd_fiber_waitgroup_wait(wg);
        if (r < 0)
                return r;

        /* Get the combined result */
        return sd_fiber_waitgroup_check(wg, NULL);
}

TEST(fiber_waitgroup_wait) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);
        int counters[3] = {0, 0, 0};

        /* Create fibers that yield multiple times */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_new_full(e, "multiple-yield", multiple_yield_fiber, &counters[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
                ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[i]));
        }

        /* Create waiter fiber with higher priority so it runs first */
        _cleanup_(sd_fiber_unrefp) sd_fiber *waiter = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "waitgroup-waiter", waitgroup_wait_fiber, wg, -1, &waiter));

        ASSERT_OK(sd_event_loop(e));

        /* All target fibers should have completed */
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_result(fibers[i]));
                ASSERT_EQ(counters[i], 3);
        }

        /* Waiter should have completed successfully */
        ASSERT_OK(sd_fiber_result(waiter));
}

/* Test: waitgroup with already completed fibers */
TEST(fiber_waitgroup_already_completed) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);
        int values[3] = {10, 20, 30};

        /* Create fibers with higher priority so they complete first */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_new_full(e, "simple", simple_fiber, &values[i], -1, &fibers[i]));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        /* Add already completed fibers to waitgroup */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[i]));

        /* Create waiter fiber with lower priority (runs after all complete) */
        _cleanup_(sd_fiber_unrefp) sd_fiber *waiter = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "waitgroup-waiter", waitgroup_wait_fiber, wg, 1, &waiter));

        ASSERT_OK(sd_event_loop(e));

        /* Waiter should complete immediately since all fibers are done */
        ASSERT_OK(sd_fiber_result(waiter));
}

TEST(fiber_waitgroup_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "empty-waitgroup", waitgroup_wait_fiber, wg, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
}

/* Test: waitgroup with cancelled fiber */
TEST(fiber_waitgroup_with_cancelled) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_waitgroup_freep) sd_fiber_waitgroup *wg = NULL;
        ASSERT_OK(sd_fiber_waitgroup_new(&wg));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);
        int counters[3] = {0, 0, 0};

        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++) {
                ASSERT_OK(sd_fiber_new_full(e, "multiple-yield", multiple_yield_fiber, &counters[i], SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));
                ASSERT_OK(sd_fiber_waitgroup_add(wg, fibers[i]));
        }

        /* Run once so all fibers yield */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Cancel the second fiber */
        ASSERT_OK(sd_fiber_cancel(fibers[1]));

        ASSERT_OK(sd_event_loop(e));

        /* First and third should complete normally */
        ASSERT_OK(sd_fiber_result(fibers[0]));
        ASSERT_OK(sd_fiber_result(fibers[2]));

        /* Second should be cancelled */
        ASSERT_ERROR(sd_fiber_result(fibers[1]), ECANCELED);

        /* Waitgroup check should report the cancellation and return the cancelled fiber */
        _cleanup_(sd_fiber_unrefp) sd_fiber *failed = NULL;
        ASSERT_ERROR(sd_fiber_waitgroup_check(wg, &failed), ECANCELED);
        ASSERT_NOT_NULL(failed);
        ASSERT_TRUE(failed == fibers[1]);
}

/* Test: wait_for_terminate basic functionality */
static int wait_simple_fiber(void *userdata) {
        _cleanup_(sigkill_wait_suspendp) pid_t pid = 0;
        siginfo_t si;
        int r;

        /* Fork a child that exits immediately */
        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
        if (r < 0)
                return r;

        if (r == 0)
                _exit(42);

        /* Parent - wait for child */
        r = wait_for_terminate_suspend(pid, &si);
        if (r < 0)
                return r;

        TAKE_PID(pid);

        /* Verify child exited with status 42 */
        if (si.si_code != CLD_EXITED || si.si_status != 42)
                return -EIO;

        return 0;
}

TEST(wait_for_terminate_fiber_basic) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "wait-simple", wait_simple_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
}

/* Test: wait_for_terminate with multiple children */
static int wait_multiple_fiber(void *userdata) {
        pid_t pids[3] = {};
        siginfo_t si;
        int r;

        /* Fork three children with different exit codes */
        for (size_t i = 0; i < 3; i++) {
                r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pids[i]);
                if (r < 0)
                        goto cleanup;

                if (r == 0)
                        /* Child process */
                        _exit(10 + i);
        }

        /* Wait for all three in order */
        for (size_t i = 0; i < 3; i++) {
                r = wait_for_terminate_suspend(pids[i], &si);
                if (r < 0)
                        goto cleanup;

                if (si.si_code != CLD_EXITED || si.si_status != (int) (10 + i)) {
                        r = -EIO;
                        goto cleanup;
                }

                TAKE_PID(pids[i]);
        }

        return 0;

cleanup:
        for (size_t i = 0; i < 3; i++)
                sigkill_wait_suspendp(&pids[i]);

        return r;
}

TEST(wait_for_terminate_fiber_multiple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "wait-multiple", wait_multiple_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
}

/* Test: wait_for_terminate_with_timeout - child exits before timeout */
static int wait_timeout_success_fiber(void *userdata) {
        _cleanup_(sigkill_wait_suspendp) pid_t pid = 0;
        int r;

        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
        if (r < 0)
                return r;

        if (r == 0)
                /* Child exits immediately */
                _exit(0);

        /* Wait with 5 second timeout - child should exit before that */
        r = wait_for_terminate_with_timeout_suspend(pid, 5 * USEC_PER_SEC);
        if (r < 0)
                return r;

        TAKE_PID(pid);

        return 0;
}

TEST(fiber_wait_for_terminate_with_timeout_success) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "wait-timeout-success", wait_timeout_success_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
}

/* Test: wait_for_terminate_with_timeout - child times out */
static int wait_timeout_expire_fiber(void *userdata) {
        _cleanup_(sigkill_wait_suspendp) pid_t pid = 0;
        int r;

        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
        if (r < 0)
                return r;

        if (r == 0) {
                /* Child sleeps longer than timeout */
                usleep(500 * USEC_PER_MSEC);
                _exit(0);
        }

        /* Wait with 100ms timeout - should timeout */
        r = wait_for_terminate_with_timeout_suspend(pid, 100 * USEC_PER_MSEC);
        if (r == -ETIMEDOUT)
                return 0;
        if (r < 0)
                return r;

        TAKE_PID(pid);

        return -EIO;
}

TEST(fiber_wait_for_terminate_with_timeout_expire) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(e, "wait-timeout-expire", wait_timeout_expire_fiber, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_fiber_result(f));
}

static int concurrent_wait_fiber(void *userdata) {
        _cleanup_(sigkill_wait_suspendp) pid_t pid = 0;
        siginfo_t si;
        int r;

        r = safe_fork("(test-child)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
        if (r < 0)
                return r;

        if (r == 0)
                /* Child exits with specified status */
                _exit(PTR_TO_INT(userdata));

        r = wait_for_terminate_suspend(pid, &si);
        if (r < 0)
                return r;

        if (si.si_code != CLD_EXITED || si.si_status != PTR_TO_INT(userdata))
                return -EIO;

        TAKE_PID(pid);

        return 0;
}

TEST(wait_for_terminate_fiber_concurrent) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        sd_fiber **fibers = NULL;
        size_t n_fibers = 0;
        CLEANUP_ARRAY(fibers, n_fibers, sd_fiber_unref_many);

        /* Create 3 fibers, each waiting for a different child */
        ASSERT_NOT_NULL(fibers = new(sd_fiber*, 3));
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_new_full(e, "concurrent-wait", concurrent_wait_fiber, INT_TO_PTR(20 + i), SD_FIBER_PRIORITY_DEFAULT, &fibers[i]));

        ASSERT_OK(sd_event_loop(e));

        /* All fibers should complete successfully */
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK(sd_fiber_result(fibers[i]));
}

static int timer_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        int *count = ASSERT_PTR(userdata);
        int r;

        (*count)++;

        r = sd_event_source_set_time_relative(s, 5 * MSEC_PER_SEC);
        if (r < 0)
                return r;

        if (sd_fiber_current() && *count >= 3)
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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        int inner_timer_count = 0;
        ASSERT_OK(sd_fiber_new_full(outer, "event-runner", event_run_fiber_func, &inner_timer_count, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully */
        ASSERT_OK(sd_fiber_result(f));

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
        _cleanup_(sd_fiber_unrefp) sd_fiber *f = NULL;
        ASSERT_OK(sd_fiber_new_full(outer, "event-timeout", event_run_fiber_timeout_func, NULL, SD_FIBER_PRIORITY_DEFAULT, &f));

        /* Run the outer event loop */
        ASSERT_OK(sd_event_loop(outer));

        /* Fiber should have completed successfully (timeout returns 0) */
        ASSERT_OK_ZERO(sd_fiber_result(f));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
