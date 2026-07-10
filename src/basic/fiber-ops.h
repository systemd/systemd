/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct sd_future sd_future;

/* Hooks installed on a fiber so that functions in src/basic can transparently defer to the suspending
 * variants in sd-future when invoked from a running fiber. Populated by sd_fiber_new() with pointers to the
 * implementations in fiber-ops.c. */
typedef struct FiberOps {
        int (*ppoll)(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask);
        ssize_t (*read)(int fd, void *buf, size_t count);
        ssize_t (*write)(int fd, const void *buf, size_t count);
        sd_future* (*timeout)(uint64_t timeout);
        sd_future* (*cancel_wait_unref)(sd_future *f);
} FiberOps;

bool fiber_ops_is_set(void);
void fiber_ops_set(const FiberOps *fiber_ops);

int fiber_ops_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask);
ssize_t fiber_ops_read(int fd, void *buf, size_t count);
ssize_t fiber_ops_write(int fd, const void *buf, size_t count);

/* Mirror of SD_FIBER_TIMEOUT() for code under src/basic that doesn't include sd-future.h: dispatches
 * through FiberOps so the actual sd_fiber_timeout() implementation lives in libsystemd. */
sd_future* fiber_ops_timeout(uint64_t timeout);
sd_future* fiber_ops_cancel_wait_unref(sd_future *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_future*, fiber_ops_cancel_wait_unref);

#define FIBER_OPS_TIMEOUT(timeout) _FIBER_OPS_TIMEOUT(UNIQ, (timeout))
#define _FIBER_OPS_TIMEOUT(uniq, timeout)                                                                                               \
        _unused_ _cleanup_(fiber_ops_cancel_wait_unrefp) sd_future *UNIQ_T(_fot_, uniq) = fiber_ops_timeout(timeout)
