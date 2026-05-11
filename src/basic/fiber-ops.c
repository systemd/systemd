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

        return RET_NERRNO(read(fd, buf, count));
}

ssize_t fiber_ops_write(int fd, const void *buf, size_t count) {
        if (fiber_ops)
                return fiber_ops->write(fd, buf, count);

        return RET_NERRNO(write(fd, buf, count));
}

sd_future* fiber_ops_timeout(uint64_t timeout) {
        assert(fiber_ops);

        return fiber_ops->timeout(timeout);
}

sd_future* fiber_ops_cancel_wait_unref(sd_future *f) {
        assert(fiber_ops);

        return fiber_ops->cancel_wait_unref(f);
}
