/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"
#include "stdio-util.h"

/* maximum length of fdname */
#define FDNAME_MAX 255

/* Make sure we can distinguish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd)+1)
#define PTR_TO_FD(p) (PTR_TO_INT(p)-1)

/* Useful helpers for initializing pipe(), socketpair() or stdio fd arrays */
#define EBADF_PAIR { -EBADF, -EBADF }
#define EBADF_TRIPLET { -EBADF, -EBADF, -EBADF }

int close_nointr(int fd);
int safe_close(int fd);
void safe_close_pair(int p[static 2]);

static inline int safe_close_above_stdio(int fd) {
        if (fd < 3) /* Don't close stdin/stdout/stderr, but still invalidate the fd by returning -EBADF. */
                return -EBADF;

        return safe_close(fd);
}

void close_many(const int fds[], size_t n_fds);
void close_many_unset(int fds[], size_t n_fds);
void close_many_and_free(int *fds, size_t n_fds);

int fclose_nointr(FILE *f);
FILE* safe_fclose(FILE *f);
DIR* safe_closedir(DIR *f);

static inline void closep(int *fd) {
        safe_close(*fd);
}

static inline void close_pairp(int (*p)[2]) {
        safe_close_pair(*p);
}

static inline void fclosep(FILE **f) {
        safe_fclose(*f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, pclose, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(DIR*, closedir, NULL);

#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)
#define _cleanup_close_pair_ _cleanup_(close_pairp)

int fd_nonblock(int fd, bool nonblock);
int stdio_disable_nonblock(void);

int fd_cloexec(int fd, bool cloexec);
int fd_cloexec_many(const int fds[], size_t n_fds, bool cloexec);

int get_max_fd(void);

int close_all_fds(const int except[], size_t n_except);
int close_all_fds_without_malloc(const int except[], size_t n_except);

int same_fd(int a, int b);

void cmsg_close_all(struct msghdr *mh);

bool fdname_is_valid(const char *s);

int fd_get_path(int fd, char **ret);

int move_fd(int from, int to, int cloexec);

int fd_move_above_stdio(int fd);

int rearrange_stdio(int original_input_fd, int original_output_fd, int original_error_fd);

static inline int make_null_stdio(void) {
        return rearrange_stdio(-EBADF, -EBADF, -EBADF);
}

/* Like TAKE_PTR() but for file descriptors, resetting them to -EBADF */
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

/* Like free_and_replace(), but for file descriptors */
#define close_and_replace(a, b)                 \
        ({                                      \
                int *_fdp_ = &(a);              \
                safe_close(*_fdp_);             \
                *_fdp_ = TAKE_FD(b);            \
                0;                              \
        })

int fd_reopen(int fd, int flags);
int fd_reopen_condition(int fd, int flags, int mask, int *ret_new_fd);
int fd_is_opath(int fd);
int read_nr_open(void);
int fd_get_diskseq(int fd, uint64_t *ret);

int path_is_root_at(int dir_fd, const char *path);
static inline int path_is_root(const char *path) {
        return path_is_root_at(AT_FDCWD, path);
}
static inline int dir_fd_is_root(int dir_fd) {
        return path_is_root_at(dir_fd, NULL);
}
static inline int dir_fd_is_root_or_cwd(int dir_fd) {
        return dir_fd == AT_FDCWD ? true : path_is_root_at(dir_fd, NULL);
}

int fds_are_same_mount(int fd1, int fd2);

/* The maximum length a buffer for a /proc/self/fd/<fd> path needs */
#define PROC_FD_PATH_MAX \
        (STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int))

static inline char *format_proc_fd_path(char buf[static PROC_FD_PATH_MAX], int fd) {
        assert(buf);
        assert(fd >= 0);
        assert_se(snprintf_ok(buf, PROC_FD_PATH_MAX, "/proc/self/fd/%i", fd));
        return buf;
}

#define FORMAT_PROC_FD_PATH(fd) \
        format_proc_fd_path((char[PROC_FD_PATH_MAX]) {}, (fd))

/* The maximum length a buffer for a /proc/<pid>/fd/<fd> path needs */
#define PROC_PID_FD_PATH_MAX \
        (STRLEN("/proc//fd/") + DECIMAL_STR_MAX(pid_t) + DECIMAL_STR_MAX(int))

char *format_proc_pid_fd_path(char buf[static PROC_PID_FD_PATH_MAX], pid_t pid, int fd);

/* Kinda the same as FORMAT_PROC_FD_PATH(), but goes by PID rather than "self" symlink */
#define FORMAT_PROC_PID_FD_PATH(pid, fd)                                \
        format_proc_pid_fd_path((char[PROC_PID_FD_PATH_MAX]) {}, (pid), (fd))

const char *accmode_to_string(int flags);

/* Like ASSERT_PTR, but for fds */
#define ASSERT_FD(fd)                           \
        ({                                      \
                int _fd_ = (fd);                \
                assert(_fd_ >= 0);              \
                _fd_;                           \
        })
