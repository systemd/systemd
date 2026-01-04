/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fiber.h"
#include "future-internal.h"
#include "set.h"
#include "string-util.h"

int sd_future_resolve(sd_future *f, int result) {
        int r = 0;

        assert(f);

        if (f->state != SD_FUTURE_PENDING)
                return 0;

        f->state = SD_FUTURE_RESOLVED;
        f->result = result;

        if (f->callback)
                RET_GATHER(r, f->callback(f, f->userdata));

        sd_future *w;
        SET_FOREACH(w, f->waiters)
                RET_GATHER(r, sd_future_resolve(w, result));

        f->waiters = set_free(f->waiters);

        return r;
}

void sd_future_unref_many(sd_future **array, size_t n) {
        FOREACH_ARRAY(w, array, n)
                sd_future_unref(*w);

        free(array);
}

static sd_future* sd_future_free(sd_future *f) {
        if (!f)
                return NULL;

        if (f->state == SD_FUTURE_PENDING)
                (void) sd_future_resolve(f, -ECANCELED);

        set_free(f->waiters);

        switch (f->type) {
                case SD_FUTURE_IO:
                        sd_event_source_unref(f->io.source);
                        break;
                case SD_FUTURE_TIME:
                        sd_event_source_unref(f->time.source);
                        break;
                case SD_FUTURE_CHILD:
                        sd_event_source_unref(f->child.source);
                        break;
                case SD_FUTURE_WAIT:
                        set_remove(f->wait.target->waiters, f);
                        sd_future_unref(f->wait.target);
                        break;
                case SD_FUTURE_BUS:
                        sd_bus_slot_unref(f->bus.slot);
                        sd_bus_message_unref(f->bus.reply);
                        break;
                case SD_FUTURE_FIBER:
                        fiber_free(f->fiber.fiber);
                        break;
        }

        return mfree(f);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_future, sd_future, sd_future_free);

static int sd_future_new(int type, sd_future **ret) {
        assert(ret);

        _cleanup_free_ sd_future *f = new(sd_future, 1);
        if (!f)
                return -ENOMEM;

        *f = (sd_future) {
                .n_ref = 1,
                .type = type,
                .state = SD_FUTURE_PENDING,
        };

        *ret = TAKE_PTR(f);

        return 0;
}

int sd_future_state(sd_future *f) {
        assert(f);
        return f->state;
}

int sd_future_result(sd_future *f) {
        assert(f);
        assert(f->state == SD_FUTURE_RESOLVED);
        return f->result;
}

int sd_future_bus_reply(sd_future *f, sd_bus_message **ret) {
        assert(f);
        assert(f->type == SD_FUTURE_BUS);
        assert(f->state == SD_FUTURE_RESOLVED);
        assert(ret);

        *ret = f->bus.reply;
        return 0;
}

int sd_future_set_callback(sd_future *f, sd_future_func_t callback, void *userdata) {
        assert(f);

        f->callback = callback;
        f->userdata = userdata;
        return 0;
}

int sd_future_set_priority(sd_future *f, int64_t priority) {
        assert(f);
        assert(f->state == SD_FUTURE_PENDING);

        switch (f->type) {
                case SD_FUTURE_IO:
                        return sd_event_source_set_priority(f->io.source, priority);
                case SD_FUTURE_TIME:
                        return sd_event_source_set_priority(f->time.source, priority);
                case SD_FUTURE_CHILD:
                        return sd_event_source_set_priority(f->child.source, priority);
                case SD_FUTURE_FIBER:
                        return fiber_set_priority(f->fiber.fiber, priority);
                default:
                        assert_not_reached();
        }
}

int sd_future_cancel(sd_future *f) {
        int r = 0;

        assert(f);

        if (f->state == SD_FUTURE_RESOLVED)
                return 0;

        switch (f->type) {
                case SD_FUTURE_IO:
                        RET_GATHER(r, sd_event_source_set_enabled(f->io.source, SD_EVENT_OFF));
                        break;
                case SD_FUTURE_TIME:
                        RET_GATHER(r, sd_event_source_set_enabled(f->time.source, SD_EVENT_OFF));
                        break;
                case SD_FUTURE_CHILD:
                        RET_GATHER(r, sd_event_source_set_enabled(f->child.source, SD_EVENT_OFF));
                        break;
                case SD_FUTURE_WAIT:
                        set_remove(f->wait.target->waiters, f);
                        break;
                case SD_FUTURE_BUS:
                        sd_bus_slot_unref(f->bus.slot);
                        break;
                case SD_FUTURE_FIBER:
                        RET_GATHER(r, fiber_cancel(f->fiber.fiber));
                        break;
        }

        /* A fiber will resolve the future itself eventually when it is cancelled. */
        if (f->type != SD_FUTURE_FIBER)
                RET_GATHER(r, sd_future_resolve(f, -ECANCELED));

        return r;
}

static int io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        int r = 0;

        f->io.revents = revents;

        if (FLAGS_SET(revents, EPOLLERR)) {
                int error = 0;
                socklen_t len = sizeof(error);

                r = RET_NERRNO(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len));
                if (r < 0 && r != -ENOTSOCK)
                        return r;
                if (r >= 0)
                        r = -error;
        }

        return sd_future_resolve(f, r);
}

int sd_future_new_io(sd_event *e, int fd, uint32_t events, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(e);
        assert(fd >= 0);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_IO, &f);
        if (r < 0)
                return r;

        /* Duplicate fd to avoid EEXIST from epoll when adding the same fd multiple times */
        _cleanup_close_ int fd_copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd_copy < 0)
                return -errno;

        r = sd_event_add_io(e, &f->io.source, fd_copy, events, io_handler, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(f->io.source, SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        r = sd_event_source_set_io_fd_own(f->io.source, true);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(f->io.source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        TAKE_FD(fd_copy);

        *ret = TAKE_PTR(f);
        return 0;
}

static int time_handler(sd_event_source *s, usec_t usec, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        f->time.usec = usec;
        return sd_future_resolve(f, 0);
}

int sd_future_new_time(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(e);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_TIME, &f);
        if (r < 0)
                return r;

        r = sd_event_add_time(e, &f->time.source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(f->io.source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_future_new_time_relative(sd_event *e, clockid_t clock, uint64_t usec, uint64_t accuracy, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(e);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_TIME, &f);
        if (r < 0)
                return r;

        r = sd_event_add_time_relative(e, &f->time.source, clock, usec, accuracy, time_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(f->io.source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

static int child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        f->child.si = *si;
        return sd_future_resolve(f, 0);
}

int sd_future_new_child(sd_event *e, pid_t pid, int options, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_CHILD, &f);
        if (r < 0)
                return r;

        r = sd_event_add_child(e, &f->child.source, pid, options, child_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(f->io.source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_future_new_child_pidfd(sd_event *e, int pidfd, int options, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(e);
        assert(ret);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_CHILD, &f);
        if (r < 0)
                return r;

        r = sd_event_add_child_pidfd(e, &f->child.source, pidfd, options, child_handler, f);
        if (r < 0)
                return r;

        if (sd_fiber_is_running()) {
                r = sd_event_source_set_priority(f->io.source, sd_fiber_get_priority());
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_future_new_wait(sd_future *target, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(target);
        assert(ret);

        r = sd_future_new(SD_FUTURE_WAIT, &f);
        if (r < 0)
                return r;

        f->wait.target = sd_future_ref(target);

        r = set_ensure_put(&target->waiters, &trivial_hash_ops, f);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_future_new_fiber(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        r = sd_future_new(SD_FUTURE_FIBER, &f);
        if (r < 0)
                return r;

        r = fiber_new(e, name, func, userdata, destroy, f, &f->fiber.fiber);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}

int sd_future_get_child_pidfd_own(sd_future *f) {
        assert(f);
        assert(f->type == SD_FUTURE_CHILD);

        return sd_event_source_get_child_pidfd_own(f->child.source);
}

int sd_future_set_child_pidfd_own(sd_future *f, int own) {
        assert(f);
        assert(f->type == SD_FUTURE_CHILD);

        return sd_event_source_set_child_pidfd_own(f->child.source, own);
}

static int bus_handler(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        sd_future *f = ASSERT_PTR(userdata);
        int r = 0;

        if (sd_bus_message_is_method_error(m, NULL)) {
                const sd_bus_error *e = sd_bus_message_get_error(m);
                r = -sd_bus_error_get_errno(e);
        }

        f->bus.slot = sd_bus_slot_unref(f->bus.slot);
        f->bus.reply = sd_bus_message_ref(m);
        return sd_future_resolve(f, r);
}

int sd_bus_call_future(sd_bus *bus, sd_bus_message *m, uint64_t usec, sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(bus);
        assert(m);
        assert(ret);

        r = sd_future_new(SD_FUTURE_BUS, &f);
        if (r < 0)
                return r;

        r = sd_bus_call_async(bus, &f->bus.slot, m, bus_handler, f, usec);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);

        return 0;
}

int sd_bus_call_method_future(
                sd_bus *bus,
                sd_future **ret,
                const char *destination,
                const char *path,
                const char *interface,
                const char *member,
                const char *types,
                ...) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(ret);

        r = sd_bus_message_new_method_call(bus, &m, destination, path, interface, member);
        if (r < 0)
                return r;

        if (!isempty(types)) {
                va_list ap;

                va_start(ap, types);
                r = sd_bus_message_appendv(m, types, ap);
                va_end(ap);
                if (r < 0)
                        return r;
        }

        return sd_bus_call_future(bus, m, 0, ret);
}
