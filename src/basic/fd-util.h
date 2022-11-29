/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
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

int close_nointr(int fd);
int safe_close(int fd);
void safe_close_pair(int p[static 2]);

static inline int safe_close_above_stdio(int fd) {
        if (fd < 3) /* Don't close stdin/stdout/stderr, but still invalidate the fd by returning -1 */
                return -1;

        return safe_close(fd);
}

void close_many(const int fds[], size_t n_fd);

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

enum {
        ACQUIRE_NO_DEV_NULL = 1 << 0,
        ACQUIRE_NO_MEMFD    = 1 << 1,
        ACQUIRE_NO_PIPE     = 1 << 2,
        ACQUIRE_NO_TMPFILE  = 1 << 3,
        ACQUIRE_NO_REGULAR  = 1 << 4,
};

int fd_move_above_stdio(int fd);

int rearrange_stdio(int original_input_fd, int original_output_fd, int original_error_fd);

static inline int make_null_stdio(void) {
        return rearrange_stdio(-1, -1, -1);
}

/* Like TAKE_PTR() but for file descriptors, resetting them to -1 */
#define TAKE_FD(fd)                             \
        ({                                      \
                int *_fd_ = &(fd);              \
                int _ret_ = *_fd_;              \
                *_fd_ = -1;                     \
                _ret_;                          \
        })

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
int read_nr_open(void);
int fd_get_diskseq(int fd, uint64_t *ret);

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
