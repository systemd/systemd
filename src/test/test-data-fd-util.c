/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "data-fd-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "memfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static void assert_equal_fd(int fd1, int fd2) {
        for (;;) {
                uint8_t a[4096], b[4096];
                ssize_t x, y;

                x = read(fd1, a, sizeof(a));
                assert_se(x >= 0);

                y = read(fd2, b, sizeof(b));
                assert_se(y >= 0);

                assert_se(x == y);

                if (x == 0)
                        break;

                assert_se(memcmp(a, b, x) == 0);
        }
}

TEST(copy_data_fd) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;
        _cleanup_close_pair_ int sfd[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        fd1 = open("/etc/fstab", O_RDONLY|O_CLOEXEC);
        if (fd1 >= 0) {

                fd2 = copy_data_fd(fd1);
                assert_se(fd2 >= 0);

                assert_se(lseek(fd1, 0, SEEK_SET) == 0);
                assert_equal_fd(fd1, fd2);
        }

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        fd1 = memfd_new_and_seal_string("data", "hallo");
        assert_se(fd1 >= 0);

        fd2 = copy_data_fd(fd1);
        assert_se(fd2 >= 0);

        safe_close(fd1);
        fd1 = memfd_new_and_seal_string("data", "hallo");
        assert_se(fd1 >= 0);

        assert_equal_fd(fd1, fd2);

        fd1 = safe_close(fd1);
        fd2 = safe_close(fd2);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, sfd) >= 0);

        r = pidref_safe_fork("(sd-pipe)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &pidref);
        assert_se(r >= 0);

        if (r == 0) {
                /* child */

                sfd[0] = safe_close(sfd[0]);

                for (uint64_t i = 0; i < 1536*1024 / sizeof(uint64_t); i++)
                        assert_se(write(sfd[1], &i, sizeof(i)) == sizeof(i));

                sfd[1] = safe_close(sfd[1]);

                _exit(EXIT_SUCCESS);
        }

        sfd[1] = safe_close(sfd[1]);

        fd2 = copy_data_fd(sfd[0]);
        assert_se(fd2 >= 0);

        uint64_t j;
        for (uint64_t i = 0; i < 1536*1024 / sizeof(uint64_t); i++) {
                assert_se(read(fd2, &j, sizeof(j)) == sizeof(j));
                assert_se(i == j);
        }

        assert_se(read(fd2, &j, sizeof(j)) == 0);
}

static int pipe_with_data(const uint8_t *data, size_t size, PidRef *ret_pidref) {
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        int r;

        assert(data);
        assert(ret_pidref);

        ASSERT_OK_ERRNO(pipe2(pfd, O_CLOEXEC));

        r = ASSERT_OK(pidref_safe_fork("(sd-pipe)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, ret_pidref));
        if (r == 0) {
                pfd[0] = safe_close(pfd[0]);

                /* The parent closes the read end when the data exceeds max_size. The kernel then kills
                 * the child with SIGPIPE on its next write(). */
                if (loop_write(pfd[1], data, size) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        return TAKE_FD(pfd[0]);
}

static void test_copy_data_fd_full_one(size_t size) {
        _cleanup_free_ uint8_t *data = NULL, *buf = NULL;

        log_debug("/* %s(%zu) */", __func__, size);

        data = ASSERT_NOT_NULL(new(uint8_t, size));
        for (size_t i = 0; i < size; i++)
                data[i] = i % 251;

        /* We read one byte more than we expect, so that we notice a copy that is too long. */
        buf = ASSERT_NOT_NULL(new(uint8_t, size + 1));

        FOREACH_ELEMENT(max_size, ((const uint64_t[]) { size, size - 1, UINT64_MAX })) {
                _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
                _cleanup_close_ int fd = -EBADF, copy_fd = -EBADF;

                fd = pipe_with_data(data, size, &pidref);

                if (*max_size < size) {
                        ASSERT_ERROR(copy_data_fd_full(fd, *max_size), EFBIG);
                        continue;
                }

                copy_fd = ASSERT_OK(copy_data_fd_full(fd, *max_size));

                ASSERT_EQ(loop_read(copy_fd, buf, size + 1, /* do_poll= */ false), (ssize_t) size);
                ASSERT_EQ(memcmp(buf, data, size), 0);
        }
}

TEST(copy_data_fd_full) {
        /* copy_data_fd_full() copies 5 bytes into a memfd, 100 KiB into a file in /tmp/, and 1.5 MiB into
         * a file in /var/tmp/. */
        test_copy_data_fd_full_one(5);
        test_copy_data_fd_full_one(100 * 1024);
        test_copy_data_fd_full_one(1536 * 1024);
}

static void assert_fd_contents(int fd, const char *contents) {
        struct stat st;
        char buf[64];

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ((size_t) st.st_size, strlen(contents));
        ASSERT_EQ(pread(fd, buf, sizeof(buf), 0), (ssize_t) strlen(contents));
        ASSERT_EQ(memcmp(buf, contents, strlen(contents)), 0);
}

TEST(open_seekable_data_fd) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int dir_fd = -EBADF, fd = -EBADF;
        struct stat st1, st2;

        dir_fd = ASSERT_OK(mkdtemp_open(NULL, O_PATH, &t));
        ASSERT_OK(write_string_file_at(dir_fd, "file", "hallo", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        fd = ASSERT_OK(open_seekable_data_fd(dir_fd, "file", /* max_size= */ 5));
        ASSERT_OK_ERRNO(fstatat(dir_fd, "file", &st1, 0));
        ASSERT_OK_ERRNO(fstat(fd, &st2));
        ASSERT_TRUE(stat_inode_same(&st1, &st2));
        fd = safe_close(fd);

        ASSERT_ERROR(open_seekable_data_fd(dir_fd, "file", /* max_size= */ 4), EFBIG);

        /* Files in /proc/ report a size of zero, so open_seekable_data_fd() copies their contents. */
        fd = ASSERT_OK(open_seekable_data_fd(AT_FDCWD, "/proc/self/comm", UINT64_MAX));
        ASSERT_OK_ERRNO(fstat(fd, &st2));
        ASSERT_GT(st2.st_size, 0);
        fd = safe_close(fd);

        /* The shell passes <(...) as a /proc/self/fd/ path to a pipe. */
        FOREACH_ELEMENT(max_size, ((const uint64_t[]) { 5, 4 })) {
                _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;

                ASSERT_OK_ERRNO(pipe2(pfd, O_CLOEXEC));
                ASSERT_EQ(write(pfd[1], "hallo", 5), 5);
                pfd[1] = safe_close(pfd[1]);

                if (*max_size < 5) {
                        ASSERT_ERROR(open_seekable_data_fd(AT_FDCWD, FORMAT_PROC_FD_PATH(pfd[0]), *max_size), EFBIG);
                        continue;
                }

                fd = ASSERT_OK(open_seekable_data_fd(AT_FDCWD, FORMAT_PROC_FD_PATH(pfd[0]), *max_size));
                assert_fd_contents(fd, "hallo");
                fd = safe_close(fd);
        }

        ASSERT_ERROR(open_seekable_data_fd(AT_FDCWD, t, UINT64_MAX), EISDIR);
        ASSERT_ERROR(open_seekable_data_fd(AT_FDCWD, "/dev/null", UINT64_MAX), EBADFD);
        ASSERT_ERROR(open_seekable_data_fd(dir_fd, "missing", UINT64_MAX), ENOENT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
