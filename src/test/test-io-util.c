/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_sparse_write_one(int fd, const char *buffer, size_t n) {
        char check[n];

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_SET), 0);
        ASSERT_OK_ERRNO(ftruncate(fd, 0));
        ASSERT_OK_EQ(sparse_write(fd, buffer, n, 4), (ssize_t) n);

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_CUR), (off_t) n);
        ASSERT_OK_ERRNO(ftruncate(fd, n));

        ASSERT_OK_EQ_ERRNO(lseek(fd, 0, SEEK_SET), 0);
        ASSERT_OK_EQ_ERRNO(read(fd, check, n), (ssize_t) n);

        ASSERT_EQ(memcmp(buffer, check, n), 0);
}

TEST(sparse_write) {
        const char test_a[] = "test";
        const char test_b[] = "\0\0\0\0test\0\0\0\0";
        const char test_c[] = "\0\0test\0\0\0\0";
        const char test_d[] = "\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0test\0\0\0test\0\0\0\0test\0\0\0\0\0\0\0\0";
        const char test_e[] = "test\0\0\0\0test";
        _cleanup_close_ int fd = -EBADF;
        char fn[] = "/tmp/sparseXXXXXX";

        ASSERT_OK_ERRNO(fd = mkostemp(fn, O_CLOEXEC));
        (void) unlink(fn);

        test_sparse_write_one(fd, test_a, sizeof(test_a));
        test_sparse_write_one(fd, test_b, sizeof(test_b));
        test_sparse_write_one(fd, test_c, sizeof(test_c));
        test_sparse_write_one(fd, test_d, sizeof(test_d));
        test_sparse_write_one(fd, test_e, sizeof(test_e));
}

TEST(pwritev_full) {
        _cleanup_close_ int fd = -EBADF;
        struct iovec iovec[2 + 2 * IOV_MAX];
        char expected[3 + 2 * IOV_MAX], buf[sizeof(expected)];
        uint64_t written;
        size_t n = 0;

        ASSERT_OK(fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC));

        /* Nothing, or only empty iovecs, writes nothing */
        ASSERT_OK(pwritev_full(fd, NULL, 0, 0, &written));
        ASSERT_EQ(written, 0U);
        iovec[0] = (struct iovec) {};
        ASSERT_OK(pwritev_full(fd, iovec, 1, 0, &written));
        ASSERT_EQ(written, 0U);

        /* More iovecs than one pwritev() takes, some of them empty */
        iovec[n++] = IOVEC_MAKE_STRING("abc");
        iovec[n++] = (struct iovec) {};
        memcpy(expected, "abc", 3);
        for (size_t k = 0; k < 2 * IOV_MAX; k++) {
                expected[3 + k] = 'a' + k % 26;
                iovec[n++] = IOVEC_MAKE(expected + 3 + k, 1);
        }

        ASSERT_OK(pwritev_full(fd, iovec, n, 7, &written));
        ASSERT_EQ(written, sizeof(expected));
        ASSERT_EQ(pread(fd, buf, sizeof(buf), 7), (ssize_t) sizeof(buf));
        ASSERT_EQ(memcmp(buf, expected, sizeof(expected)), 0);

        /* Written iovecs are advanced past the data */
        FOREACH_ARRAY(i, iovec, n)
                ASSERT_FALSE(iovec_is_set(i));
}

TEST(pwrite_full) {
        _cleanup_close_ int fd = -EBADF;
        char buf[3];

        ASSERT_OK(fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC));

        ASSERT_OK(pwrite_full(fd, NULL, 0, 0));
        ASSERT_OK(pwrite_full(fd, "abc", 3, 5));
        ASSERT_EQ(pread(fd, buf, sizeof(buf), 5), (ssize_t) sizeof(buf));
        ASSERT_EQ(memcmp(buf, "abc", 3), 0);
}

/* The buffer is much larger than the send buffer of a socket, so a single send() can't send all of it. */
#define LOOP_SEND_SIZE (1024U * 1024U)

static uint8_t* loop_send_pattern(void) {
        uint8_t *buf = ASSERT_NOT_NULL(new(uint8_t, LOOP_SEND_SIZE));

        for (size_t i = 0; i < LOOP_SEND_SIZE; i++)
                buf[i] = (uint8_t) i;

        return buf;
}

TEST(loop_send) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_close_pair_ int sfd[2] = EBADF_PAIR;
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sfd));

        ASSERT_OK(r = pidref_safe_fork("(loop-send)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref));
        if (r == 0) {
                sfd[0] = safe_close(sfd[0]);

                _cleanup_free_ uint8_t *buf = loop_send_pattern();
                ASSERT_OK(loop_send(sfd[1], buf, LOOP_SEND_SIZE, MSG_NOSIGNAL));

                _exit(EXIT_SUCCESS);
        }

        sfd[1] = safe_close(sfd[1]);

        _cleanup_free_ uint8_t *expected = loop_send_pattern();
        _cleanup_free_ uint8_t *buf = ASSERT_NOT_NULL(new(uint8_t, LOOP_SEND_SIZE));
        ASSERT_OK(loop_read_exact(sfd[0], buf, LOOP_SEND_SIZE, /* do_poll= */ true));
        ASSERT_EQ(memcmp(buf, expected, LOOP_SEND_SIZE), 0);

        ASSERT_OK_EQ(pidref_wait_for_terminate_and_check("(loop-send)", &pidref, WAIT_LOG), EXIT_SUCCESS);
}

static int loop_send_fiber(void *userdata) {
        _cleanup_free_ uint8_t *buf = loop_send_pattern();

        return loop_send(PTR_TO_FD(userdata), buf, LOOP_SEND_SIZE, MSG_NOSIGNAL);
}

static int loop_send_receive_fiber(void *userdata) {
        _cleanup_free_ uint8_t *expected = loop_send_pattern();
        _cleanup_free_ uint8_t *buf = ASSERT_NOT_NULL(new(uint8_t, LOOP_SEND_SIZE));
        int r;

        r = loop_read_exact(PTR_TO_FD(userdata), buf, LOOP_SEND_SIZE, /* do_poll= */ true);
        if (r < 0)
                return r;

        return memcmp(buf, expected, LOOP_SEND_SIZE) == 0 ? 0 : -EBADMSG;
}

TEST(loop_send_fiber) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int sfd[2] = EBADF_PAIR;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        /* The sockets are blocking. If loop_send() blocked the thread, the receiving fiber would never run
         * and the test would hang. */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sfd));

        _cleanup_(sd_future_unrefp) sd_future *fs = NULL, *fr = NULL;
        ASSERT_OK(sd_fiber_new(e, "loop-send", loop_send_fiber, FD_TO_PTR(sfd[0]), &fs));
        ASSERT_OK(sd_fiber_new(e, "loop-send-receive", loop_send_receive_fiber, FD_TO_PTR(sfd[1]), &fr));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(fs));
        ASSERT_OK(sd_future_result(fr));
}

DEFINE_TEST_MAIN(LOG_INFO);
