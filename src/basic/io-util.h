/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int flush_fd(int fd);

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll);

int loop_write_full(int fd, const void *buf, size_t nbytes, usec_t timeout) _nonnull_if_nonzero_(2, 3);
static inline int loop_write(int fd, const void *buf, size_t nbytes) {
        return loop_write_full(fd, buf, nbytes, 0);
}

int pipe_eof(int fd);

int ppoll_usec_full(struct pollfd *fds, size_t n_fds, usec_t timeout, const sigset_t *ss) _nonnull_if_nonzero_(1, 2);
_nonnull_if_nonzero_(1, 2) static inline int ppoll_usec(struct pollfd *fds, size_t n_fds, usec_t timeout) {
        return ppoll_usec_full(fds, n_fds, timeout, NULL);
}

int fd_wait_for_event(int fd, int event, usec_t timeout);

ssize_t sparse_write(int fd, const void *p, size_t sz, size_t run_length);

static inline bool FILE_SIZE_VALID(uint64_t l) {
        /* ftruncate() and friends take an unsigned file size, but actually cannot deal with file sizes larger than
         * 2^63 since the kernel internally handles it as signed value. This call allows checking for this early. */

        return (l >> 63) == 0;
}

static inline bool FILE_SIZE_VALID_OR_INFINITY(uint64_t l) {

        /* Same as above, but allows one extra value: -1 as indication for infinity. */

        if (l == UINT64_MAX)
                return true;

        return FILE_SIZE_VALID(l);
}
