/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-future.h"

#include "forward.h"

/* Cancellation is level-triggered. Once a fiber is cancelled, every suspension point returns -ECANCELED,
 * unless a shield hides the cancellation. Cancelling a fiber again makes the cancellation hard, and so does
 * the exit of the event loop. A shield hides the cancellations up to its level, and the timeouts of the
 * SD_FIBER_TIMEOUT() scopes that enclose it. A soft shield therefore still lets a second cancel end
 * cleanup code that takes too long. A full shield, at FIBER_CANCEL_HARD, hides every cancellation. A
 * hard cancellation that arrives while the fiber waits under a full shield cancels the future that the
 * fiber waits for instead. */
typedef enum FiberCancel {
        FIBER_CANCEL_NONE,
        FIBER_CANCEL_SOFT,
        FIBER_CANCEL_HARD,
} FiberCancel;

/* Hooks installed on a fiber so that functions in src/basic can transparently defer to the suspending
 * variants in sd-future when invoked from a running fiber. Populated by sd_fiber_new() with pointers to the
 * implementations in fiber-ops.c. */
typedef struct FiberOps {
        int (*ppoll)(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask);
        ssize_t (*read)(int fd, void *buf, size_t count);
        ssize_t (*write)(int fd, const void *buf, size_t count);
        sd_future* (*timeout)(uint64_t timeout);
        sd_future* (*timeout_unref)(sd_future *timer);
        sd_fiber_shield (*shield)(FiberCancel level);
        void (*unshield)(sd_fiber_shield *shield);
        bool (*exiting)(void);
} FiberOps;

bool fiber_ops_is_set(void);
void fiber_ops_set(const FiberOps *fiber_ops);

int fiber_ops_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask);
ssize_t fiber_ops_read(int fd, void *buf, size_t count);
ssize_t fiber_ops_write(int fd, const void *buf, size_t count);
/* Off a fiber, fiber_ops_shield() returns a shield that fiber_ops_unshield() ignores. */
sd_fiber_shield fiber_ops_shield(FiberCancel level);
void fiber_ops_unshield(sd_fiber_shield *shield);
/* Returns true if the event loop of the current fiber is exiting. A wait for a new event source then fails
 * with -ECANCELED right away, even under a shield, so the fiber can't wait for anything without
 * blocking. */
bool fiber_ops_exiting(void);

/* Mirror of SD_FIBER_TIMEOUT() for code under src/basic, which can't call into libsystemd: dispatches
 * through FiberOps so the actual sd_fiber_timeout() implementation lives in libsystemd. */
sd_future* fiber_ops_timeout(uint64_t timeout);
sd_future* fiber_ops_timeout_unref(sd_future *timer);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_future*, fiber_ops_timeout_unref);

#define FIBER_OPS_SHIELD(level) _FIBER_OPS_SHIELD(UNIQ, (level))
#define _FIBER_OPS_SHIELD(uniq, level)                                                                                                  \
        _unused_ _cleanup_(fiber_ops_unshield) sd_fiber_shield UNIQ_T(_fsh_, uniq) = fiber_ops_shield(level)

#define WITH_FIBER_OPS_SHIELD(level) _WITH_FIBER_OPS_SHIELD(UNIQ, (level))
#define _WITH_FIBER_OPS_SHIELD(uniq, level)                                                                                             \
        for (sd_fiber_shield UNIQ_T(_fsh_, uniq) _unused_ _cleanup_(fiber_ops_unshield) = fiber_ops_shield(level),                     \
                             *UNIQ_T(_fsh_b_, uniq) = &UNIQ_T(_fsh_, uniq);                                                             \
             UNIQ_T(_fsh_b_, uniq);                                                                                                     \
             UNIQ_T(_fsh_b_, uniq) = NULL)

#define FIBER_OPS_TIMEOUT(timeout) _FIBER_OPS_TIMEOUT(UNIQ, (timeout))
#define _FIBER_OPS_TIMEOUT(uniq, timeout)                                                                                               \
        _unused_ _cleanup_(fiber_ops_timeout_unrefp) sd_future *UNIQ_T(_fot_, uniq) = fiber_ops_timeout(timeout)
