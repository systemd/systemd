/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "fd-util.h"
#include "tests.h"
#include "time-util.h"

/* Test: Basic pipe I/O with sd-event */

typedef struct PipeIOContext {
        int *pipefd;
        int order;
} PipeIOContext;

static int pipe_read_fiber(void *userdata) {
        PipeIOContext *ctx = ASSERT_PTR(userdata);
        char buf[64];
        ssize_t n;

        n = sd_fiber_read(ctx->pipefd[0], buf, sizeof(buf));
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

        PipeIOContext ctx = { .pipefd = pipefd };

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "pipe-read", pipe_read_fiber, &ctx, /* destroy= */ NULL, &f));

        /* Write data to the pipe */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "hello", 5), 5);

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify fiber read the data */
        ASSERT_OK_EQ(sd_future_result(f), 5);
}

static int pipe_read_order_fiber(void *userdata) {
        PipeIOContext *ctx = ASSERT_PTR(userdata);
        char buf[64];
        ssize_t n;

        /* Record that the read fiber started before attempting the blocking read */
        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        n = sd_fiber_read(ctx->pipefd[0], buf, sizeof(buf));
        if (n < 0)
                return (int) n;

        /* After resuming, verify the write fiber ran while we were suspended */
        ASSERT_EQ(ctx->order, 2);

        /* Verify we read "hello" */
        if (n != 5 || memcmp(buf, "hello", 5) != 0)
                return -EIO;

        return (int) n;
}

static int pipe_write_order_fiber(void *userdata) {
        PipeIOContext *ctx = ASSERT_PTR(userdata);

        /* Verify the read fiber already ran and suspended before we started */
        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        return sd_fiber_write(ctx->pipefd[1], "hello", STRLEN("hello"));
}

TEST(fiber_io_read_write) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        PipeIOContext ctx = { .pipefd = pipefd };

        /* Higher priority for the read fiber, which will run first and then suspend because no data is
         * available. The write fiber will run second, write data to the pipe, causing the read fiber to get
         * resumed. */
        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new(e, "pipe-read", pipe_read_order_fiber, &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "pipe-write", pipe_write_order_fiber, &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 1));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify both fibers completed and the full read->suspend->write->resume sequence occurred */
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
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_array);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        int pipes[3][2];
        int args[3][2];
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                ASSERT_OK(sd_fiber_new(e, "concurrent-read", concurrent_read_fiber, args[i], /* destroy= */ NULL, &fibers[i]));
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
        ASSERT_OK(sd_fiber_new(e, "blocking-read", blocking_read_fiber, INT_TO_PTR(pipefd[0]), /* destroy= */ NULL, &f));

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

static int pipe_readv_order_fiber(void *userdata) {
        PipeIOContext *ctx = ASSERT_PTR(userdata);
        char buf1[5], buf2[5];
        struct iovec iov[] = {
                { .iov_base = buf1, .iov_len = sizeof(buf1) },
                { .iov_base = buf2, .iov_len = sizeof(buf2) },
        };
        ssize_t n;

        /* Record that the read fiber started before attempting the blocking read */
        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        /* This will initially block since no data is available */
        n = sd_fiber_readv(ctx->pipefd[0], iov, ELEMENTSOF(iov));
        if (n < 0)
                return (int) n;

        /* After resuming, verify the write fiber ran while we were suspended */
        ASSERT_EQ(ctx->order, 2);

        if (n != 10 || memcmp(buf1, "fiber", 5) != 0 || memcmp(buf2, "readv", 5) != 0)
                return -EIO;

        return (int) n;
}

static int pipe_writev_order_fiber(void *userdata) {
        PipeIOContext *ctx = ASSERT_PTR(userdata);
        const char *part1 = "fiber";
        const char *part2 = "readv";
        struct iovec iov[] = {
                { .iov_base = (void*) part1, .iov_len = 5 },
                { .iov_base = (void*) part2, .iov_len = 5 },
        };

        /* Verify the read fiber already ran and suspended before we started */
        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        return sd_fiber_writev(ctx->pipefd[1], iov, ELEMENTSOF(iov));
}

TEST(fiber_io_readv_writev) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        PipeIOContext ctx = { .pipefd = pipefd };

        /* Higher priority for the read fiber, which will run first and then suspend because no data is
         * available. The write fiber will run second, write data to the pipe, causing the read fiber to get
         * resumed. */
        _cleanup_(sd_future_unrefp) sd_future *fr = NULL, *fw = NULL;
        ASSERT_OK(sd_fiber_new(e, "pipe-readv", pipe_readv_order_fiber, &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "pipe-writev", pipe_writev_order_fiber, &ctx, /* destroy= */ NULL, &fw));
        ASSERT_OK(sd_future_set_priority(fw, 1));

        /* Run the scheduler - should process the I/O */
        ASSERT_OK(sd_event_loop(e));

        /* Verify both fibers completed and the full read->suspend->write->resume sequence occurred */
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
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_array);

        /* Create 3 pipes and 3 fibers */
        ASSERT_NOT_NULL(fibers = new0(sd_future*, 3));
        int pipes[3][2];
        int args[3][3];
        for (size_t i = 0; i < n_fibers; i++) {
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));
                args[i][0] = pipes[i][0];
                args[i][1] = 'A' + i;
                args[i][2] = 'a' + i;
                ASSERT_OK(sd_fiber_new(e, "concurrent-readv", concurrent_readv_fiber, args[i], /* destroy= */ NULL, &fibers[i]));
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

typedef struct SocketIOContext {
        int *sockfd;
        int order;
} SocketIOContext;

static int socket_send_order_fiber(void *userdata) {
        SocketIOContext *ctx = ASSERT_PTR(userdata);

        /* Verify the recv fiber already ran and suspended before we started */
        ASSERT_EQ(ctx->order, 1);
        ctx->order = 2;

        return sd_fiber_send(ctx->sockfd[0], "socket", STRLEN("socket"), 0);
}

static int socket_recv_order_fiber(void *userdata) {
        SocketIOContext *ctx = ASSERT_PTR(userdata);
        char buf[64];
        ssize_t n;

        /* Record that the recv fiber started before attempting the blocking recv */
        ASSERT_EQ(ctx->order, 0);
        ctx->order = 1;

        n = sd_fiber_recv(ctx->sockfd[1], buf, sizeof(buf), 0);
        if (n < 0)
                return (int) n;

        /* After resuming, verify the send fiber ran while we were suspended */
        ASSERT_EQ(ctx->order, 2);

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

        SocketIOContext ctx = { .sockfd = sockfd };

        /* Higher priority for the recv fiber, which will run first and suspend */
        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new(e, "socket-recv", socket_recv_order_fiber, &ctx, /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 0));
        ASSERT_OK(sd_fiber_new(e, "socket-send", socket_send_order_fiber, &ctx, /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fs, 1));

        ASSERT_OK(sd_event_loop(e));

        /* Verify both fibers completed and the full recv->suspend->send->resume sequence occurred */
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
        ASSERT_OK(sd_fiber_new(e, "socket-recv-peek", socket_recv_peek_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &f));

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
        ASSERT_OK(sd_fiber_new(e, "socket-connect", socket_connect_fiber, &addr, /* destroy= */ NULL, &f));

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
        ASSERT_OK(sd_fiber_new(e, "socket-recvmsg", socket_recvmsg_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_fiber_new(e, "socket-sendmsg", socket_sendmsg_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &fs));
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
        ASSERT_OK(sd_fiber_new(e, "socket-recvfrom", socket_recvfrom_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_fiber_new(e, "socket-sendto", socket_sendto_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &fs));
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
        ASSERT_OK(sd_fiber_new(e, "socket-recvmsg-fd", socket_recvmsg_fd_fiber, INT_TO_PTR(sockfd[1]), /* destroy= */ NULL, &fr));
        ASSERT_OK(sd_future_set_priority(fr, 1));
        ASSERT_OK(sd_fiber_new(e, "socket-sendmsg-fd", socket_sendmsg_fd_fiber, args, /* destroy= */ NULL, &fs));
        ASSERT_OK(sd_future_set_priority(fs, 0));

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
        ASSERT_OK(sd_fiber_new(e, "blocking-recv", blocking_recv_fiber, INT_TO_PTR(sockfd[0]), /* destroy= */ NULL, &f));

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
        ASSERT_OK(sd_fiber_new(e, "accept", accept_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

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
        ASSERT_OK(sd_fiber_new(e, "accept-multiple", accept_multiple_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

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
        ASSERT_OK(sd_fiber_new(e, "accept-and-read", accept_and_read_fiber, INT_TO_PTR(listen_fd), /* destroy= */ NULL, &f));

        /* Connect and send data */
        _cleanup_close_ int connect_fd = -EBADF;
        ASSERT_OK(connect_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
        ASSERT_OK(connect(connect_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK_EQ_ERRNO(write(connect_fd, "hello", 5), 5);

        /* Run the event loop */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: poll with single fd ready immediately */
static int poll_immediate_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_poll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        /* Should have one fd ready */
        if (r != 1)
                return -EIO;

        if (!(fds[0].revents & POLLIN))
                return -EIO;

        return 0;
}

TEST(fiber_poll_immediate) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Write data before creating fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "X", 1), 1);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-immediate", poll_immediate_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: poll with fd that becomes ready after suspension */
static int poll_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_poll(fds, ELEMENTSOF(fds), USEC_INFINITY);
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

TEST(fiber_poll) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-suspend", poll_fiber, pipefd, /* destroy= */ NULL, &f));

        /* Run once - fiber will suspend on poll */
        ASSERT_OK_POSITIVE(sd_event_run(e, 0));

        /* Write data to wake it up */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "Y", 1), 1);

        /* Complete execution */
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: poll with multiple fds */
static int poll_multiple_fiber(void *userdata) {
        int (*pipes)[2] = userdata;
        struct pollfd fds[] = {
                { .fd = pipes[0][0], .events = POLLIN },
                { .fd = pipes[1][0], .events = POLLIN },
                { .fd = pipes[2][0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_poll(fds, ELEMENTSOF(fds), USEC_INFINITY);
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

TEST(fiber_poll_multiple) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create three pipes */
        int pipes[3][2];
        for (size_t i = 0; i < 3; i++)
                ASSERT_OK_ERRNO(pipe2(pipes[i], O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-multiple", poll_multiple_fiber, pipes, /* destroy= */ NULL, &f));

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

/* Test: poll with POLLOUT (write readiness) */
static int poll_pollout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[1], .events = POLLOUT },
        };
        int r;

        r = sd_fiber_poll(fds, ELEMENTSOF(fds), USEC_INFINITY);
        if (r < 0)
                return r;

        if (r != 1 || !(fds[0].revents & POLLOUT))
                return -EIO;

        /* Pipe should be writable */
        if (write(pipefd[1], "Z", 1) != 1)
                return -errno;

        return 0;
}

TEST(fiber_poll_pollout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-pollout", poll_pollout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));

        /* Verify data was written */
        char buf[1];
        ASSERT_OK_EQ_ERRNO(read(pipefd[0], buf, 1), 1);
        ASSERT_EQ(buf[0], 'Z');
}

/* Test: poll with timeout that expires */
static int poll_timeout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        /* Poll with 100ms timeout - no data will arrive */
        r = sd_fiber_poll(fds, ELEMENTSOF(fds), 100 * USEC_PER_MSEC);
        if (r < 0)
                return r;

        /* Should timeout with no fds ready */
        if (r != 0)
                return -EIO;

        return 0;
}

TEST(fiber_poll_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-timeout", poll_timeout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: poll with zero timeout (should not block) */
static int poll_zero_timeout_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        /* Poll with zero timeout - should return immediately */
        r = sd_fiber_poll(fds, ELEMENTSOF(fds), 0);
        if (r < 0)
                return r;

        /* No data available, so should return 0 */
        if (r != 0)
                return -EIO;

        /* Now write data */
        if (write(pipefd[1], "Q", 1) != 1)
                return -errno;

        /* Poll again with zero timeout - should see data */
        r = sd_fiber_poll(fds, ELEMENTSOF(fds), 0);
        if (r < 0)
                return r;

        if (r != 1 || !(fds[0].revents & POLLIN))
                return -EIO;

        return 0;
}

TEST(fiber_poll_zero_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-zero-timeout", poll_zero_timeout_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

/* Test: poll with zero fds and zero timeout (should return immediately) */
static int poll_zero_fds_fiber(void *userdata) {
        return sd_fiber_poll(NULL, 0, 0);
}

TEST(fiber_poll_zero_fds) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-zero-fds", poll_zero_fds_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_EQ(sd_future_result(f), 0);
}

/* Test: poll with zero fds and no timeout has no possible wakeup, must reject with -EINVAL */
static int poll_zero_fds_no_timeout_fiber(void *userdata) {
        return sd_fiber_poll(NULL, 0, USEC_INFINITY);
}

TEST(fiber_poll_zero_fds_no_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-zero-fds-no-timeout", poll_zero_fds_no_timeout_fiber, NULL, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_ERROR(sd_future_result(f), EINVAL);
}

/* Test: poll with negative fd (should be ignored) */
static int poll_negative_fd_fiber(void *userdata) {
        int *pipefd = userdata;
        struct pollfd fds[] = {
                { .fd = -1, .events = POLLIN },
                { .fd = pipefd[0], .events = POLLIN },
        };
        int r;

        r = sd_fiber_poll(fds, ELEMENTSOF(fds), USEC_INFINITY);
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

TEST(fiber_poll_negative_fd) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK));

        /* Write data before creating fiber */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "N", 1), 1);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "poll-negative-fd", poll_negative_fd_fiber, pipefd, /* destroy= */ NULL, &f));

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
        CLEANUP_ARRAY(fibers, n_fibers, sd_future_unref_array);
        SharedFdArgs args[3];
        int counter = 0;

        ASSERT_NOT_NULL(fibers = new0(sd_future*, n_fibers));
        for (size_t i = 0; i < 3; i++) {
                args[i].pipefd = pipefd[0];
                args[i].counter = &counter;
                ASSERT_OK(sd_fiber_new(e, "shared-fd-read", shared_fd_read_fiber, &args[i], /* destroy= */ NULL, &fibers[i]));
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

static int blocking_fd_preserve_fiber(void *userdata) {
        int *pipefd = ASSERT_PTR(userdata);
        char buf[8] = {};
        ssize_t n;

        /* The pipe has data pre-filled, so this should succeed immediately on the fast path.
         * This exercises the fd blocking state restore: fiber_io_operation() temporarily sets the fd
         * to nonblocking, and must restore it to blocking on the success path. */
        n = sd_fiber_read(pipefd[0], buf, sizeof(buf));
        if (n < 0)
                return (int) n;

        if ((size_t) n != sizeof(buf) || memcmp(buf, "blocking", sizeof(buf)) != 0)
                return -EIO;

        return 0;
}

TEST(fiber_io_blocking_fd_preserved) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create a blocking pipe (no O_NONBLOCK) */
        _cleanup_close_pair_ int pipefd[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(pipe2(pipefd, O_CLOEXEC));

        /* Pre-fill the pipe so the read will succeed immediately */
        ASSERT_OK_EQ_ERRNO(write(pipefd[1], "blocking", 8), 8);

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "blocking-fd-preserve", blocking_fd_preserve_fiber, pipefd, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));

        /* Verify the read end is still in blocking mode after the fiber completed */
        ASSERT_OK_ZERO(fd_nonblock(pipefd[0], false));
}

static int socket_connect_blocking_fiber(void *userdata) {
        struct sockaddr_un *addr = userdata;
        _cleanup_close_ int sockfd = -EBADF;

        /* Use a blocking socket (no SOCK_NONBLOCK). sd_fiber_connect() should temporarily set it
         * to nonblocking, handle the EINPROGRESS path with getsockopt(SO_ERROR), and restore
         * the blocking state. */
        sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (sockfd < 0)
                return -errno;

        int r = sd_fiber_connect(sockfd, (struct sockaddr*) addr, sizeof(*addr));
        if (r < 0)
                return r;

        /* Verify the socket is back in blocking mode */
        r = fd_nonblock(sockfd, false);
        if (r < 0)
                return r;
        if (r > 0)
                return -EBUSY; /* fd was nonblocking, but should have been restored to blocking */

        return 0;
}

TEST(fiber_io_connect_blocking) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* Create listening socket */
        _cleanup_close_ int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        ASSERT_OK(listen_fd);

        struct sockaddr_un addr = {
                .sun_family = AF_UNIX,
        };
        addr.sun_path[0] = '\0';
        snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "test-fiber-connect-blocking-%d", getpid());

        ASSERT_OK(bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr)));
        ASSERT_OK(listen(listen_fd, 1));

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        ASSERT_OK(sd_fiber_new(e, "connect-blocking", socket_connect_blocking_fiber, &addr, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK(sd_future_result(f));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
