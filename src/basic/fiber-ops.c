/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <poll.h>
#include <threads.h>
#include <unistd.h>

#include "errno-util.h"
#include "fiber-ops.h"

static thread_local const FiberOps *fiber_ops = NULL;

bool fiber_ops_is_set(void) {
        return fiber_ops != NULL;
}

void fiber_ops_set(const FiberOps *ops) {
        fiber_ops = ops;
}

int fiber_ops_ppoll(struct pollfd *fds, size_t n_fds, const struct timespec *timeout, const sigset_t *sigmask) {
        if (fiber_ops)
                return fiber_ops->ppoll(fds, n_fds, timeout, sigmask);

        return RET_NERRNO(ppoll(fds, n_fds, timeout, sigmask));
}

ssize_t fiber_ops_read(int fd, void *buf, size_t count) {
        if (fiber_ops)
                return fiber_ops->read(fd, buf, count);

        ssize_t n = read(fd, buf, count);
        return n < 0 ? -errno : n;
}

ssize_t fiber_ops_write(int fd, const void *buf, size_t count) {
        if (fiber_ops)
                return fiber_ops->write(fd, buf, count);

        return RET_NERRNO(write(fd, buf, count));
}

sd_fiber_shield fiber_ops_shield(FiberCancel level) {
        if (!fiber_ops)
                return (sd_fiber_shield) {};

        return fiber_ops->shield(level);
}

void fiber_ops_unshield(sd_fiber_shield *shield) {
        assert(shield);

        if (!shield->fiber)
                return;

        assert(fiber_ops);
        fiber_ops->unshield(shield);
}

bool fiber_ops_exiting(void) {
        return fiber_ops && fiber_ops->exiting();
}

sd_future* fiber_ops_timeout(uint64_t timeout) {
        assert(fiber_ops);

        return fiber_ops->timeout(timeout);
}

sd_future* fiber_ops_timeout_unref(sd_future *timer) {
        assert(fiber_ops);

        return fiber_ops->timeout_unref(timer);
}
