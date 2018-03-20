/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "string-util.h"
#include "util.h"

static void test_close_many(void) {
        int fds[3];
        char name0[] = "/tmp/test-close-many.XXXXXX";
        char name1[] = "/tmp/test-close-many.XXXXXX";
        char name2[] = "/tmp/test-close-many.XXXXXX";

        fds[0] = mkostemp_safe(name0);
        fds[1] = mkostemp_safe(name1);
        fds[2] = mkostemp_safe(name2);

        close_many(fds, 2);

        assert_se(fcntl(fds[0], F_GETFD) == -1);
        assert_se(fcntl(fds[1], F_GETFD) == -1);
        assert_se(fcntl(fds[2], F_GETFD) >= 0);

        safe_close(fds[2]);

        unlink(name0);
        unlink(name1);
        unlink(name2);
}

static void test_close_nointr(void) {
        char name[] = "/tmp/test-test-close_nointr.XXXXXX";
        int fd;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se(close_nointr(fd) >= 0);
        assert_se(close_nointr(fd) < 0);

        unlink(name);
}

static void test_same_fd(void) {
        _cleanup_close_pair_ int p[2] = { -1, -1 };
        _cleanup_close_ int a = -1, b = -1, c = -1;

        assert_se(pipe2(p, O_CLOEXEC) >= 0);
        assert_se((a = fcntl(p[0], F_DUPFD, 3)) >= 0);
        assert_se((b = open("/dev/null", O_RDONLY|O_CLOEXEC)) >= 0);
        assert_se((c = fcntl(a, F_DUPFD, 3)) >= 0);

        assert_se(same_fd(p[0], p[0]) > 0);
        assert_se(same_fd(p[1], p[1]) > 0);
        assert_se(same_fd(a, a) > 0);
        assert_se(same_fd(b, b) > 0);

        assert_se(same_fd(a, p[0]) > 0);
        assert_se(same_fd(p[0], a) > 0);
        assert_se(same_fd(c, p[0]) > 0);
        assert_se(same_fd(p[0], c) > 0);
        assert_se(same_fd(a, c) > 0);
        assert_se(same_fd(c, a) > 0);

        assert_se(same_fd(p[0], p[1]) == 0);
        assert_se(same_fd(p[1], p[0]) == 0);
        assert_se(same_fd(p[0], b) == 0);
        assert_se(same_fd(b, p[0]) == 0);
        assert_se(same_fd(p[1], a) == 0);
        assert_se(same_fd(a, p[1]) == 0);
        assert_se(same_fd(p[1], b) == 0);
        assert_se(same_fd(b, p[1]) == 0);

        assert_se(same_fd(a, b) == 0);
        assert_se(same_fd(b, a) == 0);
}

static void test_open_serialization_fd(void) {
        _cleanup_close_ int fd = -1;

        fd = open_serialization_fd("test");
        assert_se(fd >= 0);

        assert_se(write(fd, "test\n", 5) == 5);
}

static void test_acquire_data_fd_one(unsigned flags) {
        char wbuffer[196*1024 - 7];
        char rbuffer[sizeof(wbuffer)];
        int fd;

        fd = acquire_data_fd("foo", 3, flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == 3);
        assert_se(streq(rbuffer, "foo"));

        fd = safe_close(fd);

        fd = acquire_data_fd("", 0, flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == 0);
        assert_se(streq(rbuffer, ""));

        fd = safe_close(fd);

        random_bytes(wbuffer, sizeof(wbuffer));

        fd = acquire_data_fd(wbuffer, sizeof(wbuffer), flags);
        assert_se(fd >= 0);

        zero(rbuffer);
        assert_se(read(fd, rbuffer, sizeof(rbuffer)) == sizeof(rbuffer));
        assert_se(memcmp(rbuffer, wbuffer, sizeof(rbuffer)) == 0);

        fd = safe_close(fd);
}

static void test_acquire_data_fd(void) {

        test_acquire_data_fd_one(0);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL);
        test_acquire_data_fd_one(ACQUIRE_NO_MEMFD);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD);
        test_acquire_data_fd_one(ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE);
        test_acquire_data_fd_one(ACQUIRE_NO_DEV_NULL|ACQUIRE_NO_MEMFD|ACQUIRE_NO_PIPE|ACQUIRE_NO_TMPFILE);
}

static void test_fd_move_above_stdio(void) {
        int original_stdin, new_fd;

        original_stdin = fcntl(0, F_DUPFD, 3);
        assert_se(original_stdin >= 3);
        assert_se(close_nointr(0) != EBADF);

        new_fd = open("/dev/null", O_RDONLY);
        assert_se(new_fd == 0);

        new_fd = fd_move_above_stdio(new_fd);
        assert_se(new_fd >= 3);

        assert_se(dup(original_stdin) == 0);
        assert_se(close_nointr(original_stdin) != EBADF);
        assert_se(close_nointr(new_fd) != EBADF);
}

static void test_rearrange_stdio(void) {
        pid_t pid;
        int r;

        r = safe_fork("rearrange", FORK_WAIT|FORK_LOG, &pid);
        assert_se(r >= 0);

        if (r == 0) {
                _cleanup_free_ char *path = NULL;
                char buffer[10];

                /* Child */

                safe_close(STDERR_FILENO); /* Let's close an fd < 2, to make it more interesting */

                assert_se(rearrange_stdio(-1, -1, -1) >= 0);

                assert_se(fd_get_path(STDIN_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                assert_se(fd_get_path(STDOUT_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                assert_se(fd_get_path(STDOUT_FILENO, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                safe_close(STDIN_FILENO);
                safe_close(STDOUT_FILENO);
                safe_close(STDERR_FILENO);

                {
                        int pair[2];
                        assert_se(pipe(pair) >= 0);
                        assert_se(pair[0] == 0);
                        assert_se(pair[1] == 1);
                        assert_se(fd_move_above_stdio(0) == 3);
                }
                assert_se(open("/dev/full", O_WRONLY|O_CLOEXEC) == 0);
                assert_se(acquire_data_fd("foobar", 6, 0) == 2);

                assert_se(rearrange_stdio(2, 0, 1) >= 0);

                assert_se(write(1, "x", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "z", 1) == 1);
                assert_se(read(3, buffer, sizeof(buffer)) == 1);
                assert_se(buffer[0] == 'z');
                assert_se(read(0, buffer, sizeof(buffer)) == 6);
                assert_se(memcmp(buffer, "foobar", 6) == 0);

                assert_se(rearrange_stdio(-1, 1, 2) >= 0);
                assert_se(write(1, "a", 1) < 0 && errno == ENOSPC);
                assert_se(write(2, "y", 1) == 1);
                assert_se(read(3, buffer, sizeof(buffer)) == 1);
                assert_se(buffer[0] == 'y');

                assert_se(fd_get_path(0, &path) >= 0);
                assert_se(path_equal(path, "/dev/null"));
                path = mfree(path);

                _exit(EXIT_SUCCESS);
        }
}

int main(int argc, char *argv[]) {
        test_close_many();
        test_close_nointr();
        test_same_fd();
        test_open_serialization_fd();
        test_acquire_data_fd();
        test_fd_move_above_stdio();
        test_rearrange_stdio();

        return 0;
}
