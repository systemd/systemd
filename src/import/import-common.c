/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "btrfs-util.h"
#include "capability.h"
#include "import-common.h"

int import_make_read_only_fd(int fd) {
        int r;

        assert(fd >= 0);

        /* First, let's make this a read-only subvolume if it refers
         * to a subvolume */
        r = btrfs_subvol_set_read_only_fd(fd, true);
        if (r == -ENOTTY || r == -ENOTDIR || r == -EINVAL) {
                struct stat st;

                /* This doesn't refer to a subvolume, or the file
                 * system isn't even btrfs. In that, case fall back to
                 * chmod()ing */

                r = fstat(fd, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to stat temporary image: %m");

                /* Drop "w" flag */
                if (fchmod(fd, st.st_mode & 07555) < 0)
                        return log_error_errno(errno, "Failed to chmod() final image: %m");

                return 0;

        } else if (r < 0)
                return log_error_errno(r, "Failed to make subvolume read-only: %m");

        return 0;
}

int import_make_read_only(const char *path) {
        _cleanup_close_ int fd = 1;

        fd = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", path);

        return import_make_read_only_fd(fd);
}

int import_fork_tar_x(const char *path, pid_t *ret) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork off tar: %m");

        if (pid == 0) {
                int null_fd;
                uint64_t retain =
                        (1ULL << CAP_CHOWN) |
                        (1ULL << CAP_FOWNER) |
                        (1ULL << CAP_FSETID) |
                        (1ULL << CAP_MKNOD) |
                        (1ULL << CAP_SETFCAP) |
                        (1ULL << CAP_DAC_OVERRIDE);

                /* Child */

                reset_all_signal_handlers();
                reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                pipefd[1] = safe_close(pipefd[1]);

                if (dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (pipefd[0] != STDIN_FILENO)
                        pipefd[0] = safe_close(pipefd[0]);

                null_fd = open("/dev/null", O_WRONLY|O_NOCTTY);
                if (null_fd < 0) {
                        log_error_errno(errno, "Failed to open /dev/null: %m");
                        _exit(EXIT_FAILURE);
                }

                if (dup2(null_fd, STDOUT_FILENO) != STDOUT_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (null_fd != STDOUT_FILENO)
                        null_fd = safe_close(null_fd);

                fd_cloexec(STDIN_FILENO, false);
                fd_cloexec(STDOUT_FILENO, false);
                fd_cloexec(STDERR_FILENO, false);

                if (unshare(CLONE_NEWNET) < 0)
                        log_error_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(~retain, true);
                if (r < 0)
                        log_error_errno(r, "Failed to drop capabilities, ignoring: %m");

                execlp("tar", "tar", "--numeric-owner", "-C", path, "-px", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        pipefd[0] = safe_close(pipefd[0]);
        r = pipefd[1];
        pipefd[1] = -1;

        *ret = pid;

        return r;
}

int import_fork_tar_c(const char *path, pid_t *ret) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        pid_t pid;
        int r;

        assert(path);
        assert(ret);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork off tar: %m");

        if (pid == 0) {
                int null_fd;
                uint64_t retain = (1ULL << CAP_DAC_OVERRIDE);

                /* Child */

                reset_all_signal_handlers();
                reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                pipefd[0] = safe_close(pipefd[0]);

                if (dup2(pipefd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (pipefd[1] != STDOUT_FILENO)
                        pipefd[1] = safe_close(pipefd[1]);

                null_fd = open("/dev/null", O_RDONLY|O_NOCTTY);
                if (null_fd < 0) {
                        log_error_errno(errno, "Failed to open /dev/null: %m");
                        _exit(EXIT_FAILURE);
                }

                if (dup2(null_fd, STDIN_FILENO) != STDIN_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (null_fd != STDIN_FILENO)
                        null_fd = safe_close(null_fd);

                fd_cloexec(STDIN_FILENO, false);
                fd_cloexec(STDOUT_FILENO, false);
                fd_cloexec(STDERR_FILENO, false);

                if (unshare(CLONE_NEWNET) < 0)
                        log_error_errno(errno, "Failed to lock tar into network namespace, ignoring: %m");

                r = capability_bounding_set_drop(~retain, true);
                if (r < 0)
                        log_error_errno(r, "Failed to drop capabilities, ignoring: %m");

                execlp("tar", "tar", "--sparse", "-C", path, "-c", ".", NULL);
                log_error_errno(errno, "Failed to execute tar: %m");
                _exit(EXIT_FAILURE);
        }

        pipefd[1] = safe_close(pipefd[1]);
        r = pipefd[0];
        pipefd[0] = -1;

        *ret = pid;

        return r;
}
