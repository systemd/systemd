/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-future.h"
#include "fd-util.h"

typedef struct IoFuture {
        sd_event_source *source;
} IoFuture;

static void* io_future_alloc(void) {
        return new0(IoFuture, 1);
}

static void io_future_free(sd_future *f) {
        IoFuture *iof = sd_future_get_private(f);
        sd_event_source_unref(iof->source);
        free(iof);
}

static int io_future_cancel(sd_future *f) {
        IoFuture *iof = ASSERT_PTR(sd_future_get_private(f));
        int r = 0;

        RET_GATHER(r, sd_event_source_set_enabled(iof->source, SD_EVENT_OFF));
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int io_future_set_priority(sd_future *f, int64_t priority) {
        IoFuture *iof = ASSERT_PTR(sd_future_get_private(f));
        return sd_event_source_set_priority(iof->source, priority);
}

static const sd_future_ops io_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = io_future_alloc,
        .free = io_future_free,
        .cancel = io_future_cancel,
        .set_priority = io_future_set_priority,
};

static int io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        /* Resolve with the revents mask on success (matching io_uring poll_add's CQE convention) so
         * callers can read it directly off the future result. EPOLLERR is the one exception: surface
         * the actual socket error via SO_ERROR so callers like sd_fiber_connect() can return -errno
         * directly without re-querying. */
        if (FLAGS_SET(revents, EPOLLERR)) {
                int error = 0;
                socklen_t len = sizeof(error);

                int r = RET_NERRNO(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
                if (r == -ENOTSOCK)
                        return sd_future_resolve(f, (int) revents);
                if (r >= 0)
                        return sd_future_resolve(f, -error);
                /* On any other getsockopt() error fall through and resolve the future with that
                 * error so the waiting fiber wakes up rather than hanging forever. */
                return sd_future_resolve(f, r);
        }

        return sd_future_resolve(f, (int) revents);
}

int future_new_io(sd_event *e, int fd, uint32_t events, sd_future **ret) {
        int r;

        assert(e);
        assert(fd >= 0);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&io_future_ops, &f);
        if (r < 0)
                return r;

        IoFuture *iof = sd_future_get_private(f);

        /* Duplicate fd to avoid EEXIST from epoll when adding the same fd multiple times */
        _cleanup_close_ int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0)
                return -errno;

        r = sd_event_add_io(e, &iof->source, fd_copy, events, io_handler, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(iof->source, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(iof->source, true);
        if (r < 0)
                return r;

        TAKE_FD(fd_copy);

        if (sd_fiber_is_running()) {
                int64_t priority;

                r = sd_fiber_get_priority(&priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(iof->source, priority);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

typedef struct TimeFuture {
        sd_event_source *source;
        uint64_t usec;

        /* Result the future resolves with on natural expiry (vs. cancellation). 0 for normal sleep,
         * non-zero (e.g. -ETIMEDOUT) lets a fiber waiting on this future resume with that error. */
        int result;
} TimeFuture;

static void* time_future_alloc(void) {
        return new0(TimeFuture, 1);
}

static void time_future_free(sd_future *f) {
        TimeFuture *tf = sd_future_get_private(f);
        sd_event_source_unref(tf->source);
        free(tf);
}

static int time_future_cancel(sd_future *f) {
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(f));
        int r = sd_event_source_set_enabled(tf->source, SD_EVENT_OFF);
        RET_GATHER(r, sd_future_resolve(f, -ECANCELED));
        return r;
}

static int time_future_set_priority(sd_future *f, int64_t priority) {
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(f));
        return sd_event_source_set_priority(tf->source, priority);
}

static const sd_future_ops time_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = time_future_alloc,
        .free = time_future_free,
        .cancel = time_future_cancel,
        .set_priority = time_future_set_priority,
};

static int time_handler(sd_event_source *s, usec_t usec, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        TimeFuture *tf = ASSERT_PTR(sd_future_get_private(f));

        tf->usec = usec;
        return sd_future_resolve(f, tf->result);
}

int future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&time_future_ops, &f);
        if (r < 0)
                return r;

        TimeFuture *tf = sd_future_get_private(f);
        tf->result = result;

        r = sd_event_add_time(e, &tf->source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                int64_t priority;

                r = sd_fiber_get_priority(&priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(tf->source, priority);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, int result, sd_future **ret) {
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&time_future_ops, &f);
        if (r < 0)
                return r;

        TimeFuture *tf = sd_future_get_private(f);
        tf->result = result;

        r = sd_event_add_time_relative(e, &tf->source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                int64_t priority;

                r = sd_fiber_get_priority(&priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(tf->source, priority);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}
