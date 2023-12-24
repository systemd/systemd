/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "env-util.h"
#include "event-source.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "list.h"
#include "logarithm.h"
#include "macro.h"
#include "mallinfo-util.h"
#include "memory-util.h"
#include "missing_magic.h"
#include "missing_syscall.h"
#include "missing_threads.h"
#include "origin-id.h"
#include "path-util.h"
#include "prioq.h"
#include "process-util.h"
#include "psi-util.h"
#include "set.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "time-util.h"

#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

static bool EVENT_SOURCE_WATCH_PIDFD(sd_event_source *s) {
        /* Returns true if this is a PID event source and can be implemented by watching EPOLLIN */
        return s &&
                s->type == SOURCE_CHILD &&
                s->child.pidfd >= 0 &&
                s->child.options == WEXITED;
}

static bool event_source_is_online(sd_event_source *s) {
        assert(s);
        return s->enabled != SD_EVENT_OFF && !s->ratelimited;
}

static bool event_source_is_offline(sd_event_source *s) {
        assert(s);
        return s->enabled == SD_EVENT_OFF || s->ratelimited;
}

static const char* const event_source_type_table[_SOURCE_EVENT_SOURCE_TYPE_MAX] = {
        [SOURCE_IO]                  = "io",
        [SOURCE_TIME_REALTIME]       = "realtime",
        [SOURCE_TIME_BOOTTIME]       = "boottime",
        [SOURCE_TIME_MONOTONIC]      = "monotonic",
        [SOURCE_TIME_REALTIME_ALARM] = "realtime-alarm",
        [SOURCE_TIME_BOOTTIME_ALARM] = "boottime-alarm",
        [SOURCE_SIGNAL]              = "signal",
        [SOURCE_CHILD]               = "child",
        [SOURCE_DEFER]               = "defer",
        [SOURCE_POST]                = "post",
        [SOURCE_EXIT]                = "exit",
        [SOURCE_WATCHDOG]            = "watchdog",
        [SOURCE_INOTIFY]             = "inotify",
        [SOURCE_MEMORY_PRESSURE]     = "memory-pressure",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(event_source_type, int);

#define EVENT_SOURCE_IS_TIME(t)                 \
        IN_SET((t),                             \
               SOURCE_TIME_REALTIME,            \
               SOURCE_TIME_BOOTTIME,            \
               SOURCE_TIME_MONOTONIC,           \
               SOURCE_TIME_REALTIME_ALARM,      \
               SOURCE_TIME_BOOTTIME_ALARM)

#define EVENT_SOURCE_CAN_RATE_LIMIT(t)          \
        IN_SET((t),                             \
               SOURCE_IO,                       \
               SOURCE_TIME_REALTIME,            \
               SOURCE_TIME_BOOTTIME,            \
               SOURCE_TIME_MONOTONIC,           \
               SOURCE_TIME_REALTIME_ALARM,      \
               SOURCE_TIME_BOOTTIME_ALARM,      \
               SOURCE_SIGNAL,                   \
               SOURCE_DEFER,                    \
               SOURCE_INOTIFY,                  \
               SOURCE_MEMORY_PRESSURE)

/* This is used to assert that we didn't pass an unexpected source type to event_source_time_prioq_put().
 * Time sources and ratelimited sources can be passed, so effectively this is the same as the
 * EVENT_SOURCE_CAN_RATE_LIMIT() macro. */
#define EVENT_SOURCE_USES_TIME_PRIOQ(t) EVENT_SOURCE_CAN_RATE_LIMIT(t)

struct sd_event {
        unsigned n_ref;

        int epoll_fd;
        int watchdog_fd;

        Prioq *pending;
        Prioq *prepare;

        /* timerfd_create() only supports these five clocks so far. We
         * can add support for more clocks when the kernel learns to
         * deal with them, too. */
        struct clock_data realtime;
        struct clock_data boottime;
        struct clock_data monotonic;
        struct clock_data realtime_alarm;
        struct clock_data boottime_alarm;

        usec_t perturb;

        sd_event_source **signal_sources; /* indexed by signal number */
        Hashmap *signal_data; /* indexed by priority */

        Hashmap *child_sources;
        unsigned n_online_child_sources;

        Set *post_sources;

        Prioq *exit;

        Hashmap *inotify_data; /* indexed by priority */

        /* A list of inode structures that still have an fd open, that we need to close before the next loop iteration */
        LIST_HEAD(struct inode_data, inode_data_to_close_list);

        /* A list of inotify objects that already have events buffered which aren't processed yet */
        LIST_HEAD(struct inotify_data, buffered_inotify_data_list);

        /* A list of memory pressure event sources that still need their subscription string written */
        LIST_HEAD(sd_event_source, memory_pressure_write_list);

        uint64_t origin_id;

        uint64_t iteration;
        triple_timestamp timestamp;
        int state;

        bool exit_requested:1;
        bool need_process_child:1;
        bool watchdog:1;
        bool profile_delays:1;

        int exit_code;

        pid_t tid;
        sd_event **default_event_ptr;

        usec_t watchdog_last, watchdog_period;

        unsigned n_sources;

        struct epoll_event *event_queue;

        LIST_HEAD(sd_event_source, sources);

        sd_event_source *sigint_event_source, *sigterm_event_source;

        usec_t last_run_usec, last_log_usec;
        unsigned delays[sizeof(usec_t) * 8];
};

DEFINE_PRIVATE_ORIGIN_ID_HELPERS(sd_event, event);

static thread_local sd_event *default_event = NULL;

static void source_disconnect(sd_event_source *s);
static void event_gc_inode_data(sd_event *e, struct inode_data *d);

static sd_event *event_resolve(sd_event *e) {
        return e == SD_EVENT_DEFAULT ? default_event : e;
}

static int pending_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;
        int r;

        assert(x->pending);
        assert(y->pending);

        /* Enabled ones first */
        r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
        if (r != 0)
                return r;

        /* Non rate-limited ones first. */
        r = CMP(!!x->ratelimited, !!y->ratelimited);
        if (r != 0)
                return r;

        /* Lower priority values first */
        r = CMP(x->priority, y->priority);
        if (r != 0)
                return r;

        /* Older entries first */
        return CMP(x->pending_iteration, y->pending_iteration);
}

static int prepare_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;
        int r;

        assert(x->prepare);
        assert(y->prepare);

        /* Enabled ones first */
        r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
        if (r != 0)
                return r;

        /* Non rate-limited ones first. */
        r = CMP(!!x->ratelimited, !!y->ratelimited);
        if (r != 0)
                return r;

        /* Move most recently prepared ones last, so that we can stop
         * preparing as soon as we hit one that has already been
         * prepared in the current iteration */
        r = CMP(x->prepare_iteration, y->prepare_iteration);
        if (r != 0)
                return r;

        /* Lower priority values first */
        return CMP(x->priority, y->priority);
}

static usec_t time_event_source_next(const sd_event_source *s) {
        assert(s);

        /* We have two kinds of event sources that have elapsation times associated with them: the actual
         * time based ones and the ones for which a ratelimit can be in effect (where we want to be notified
         * once the ratelimit time window ends). Let's return the next elapsing time depending on what we are
         * looking at here. */

        if (s->ratelimited) { /* If rate-limited the next elapsation is when the ratelimit time window ends */
                assert(s->rate_limit.begin != 0);
                assert(s->rate_limit.interval != 0);
                return usec_add(s->rate_limit.begin, s->rate_limit.interval);
        }

        /* Otherwise this must be a time event source, if not ratelimited */
        if (EVENT_SOURCE_IS_TIME(s->type))
                return s->time.next;

        return USEC_INFINITY;
}

static usec_t time_event_source_latest(const sd_event_source *s) {
        assert(s);

        if (s->ratelimited) { /* For ratelimited stuff the earliest and the latest time shall actually be the
                               * same, as we should avoid adding additional inaccuracy on an inaccuracy time
                               * window */
                assert(s->rate_limit.begin != 0);
                assert(s->rate_limit.interval != 0);
                return usec_add(s->rate_limit.begin, s->rate_limit.interval);
        }

        /* Must be a time event source, if not ratelimited */
        if (EVENT_SOURCE_IS_TIME(s->type))
                return usec_add(s->time.next, s->time.accuracy);

        return USEC_INFINITY;
}

static bool event_source_timer_candidate(const sd_event_source *s) {
        assert(s);

        /* Returns true for event sources that either are not pending yet (i.e. where it's worth to mark them pending)
         * or which are currently ratelimited (i.e. where it's worth leaving the ratelimited state) */
        return !s->pending || s->ratelimited;
}

static int time_prioq_compare(const void *a, const void *b, usec_t (*time_func)(const sd_event_source *s)) {
        const sd_event_source *x = a, *y = b;
        int r;

        /* Enabled ones first */
        r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
        if (r != 0)
                return r;

        /* Order "non-pending OR ratelimited" before "pending AND not-ratelimited" */
        r = CMP(!event_source_timer_candidate(x), !event_source_timer_candidate(y));
        if (r != 0)
                return r;

        /* Order by time */
        return CMP(time_func(x), time_func(y));
}

static int earliest_time_prioq_compare(const void *a, const void *b) {
        return time_prioq_compare(a, b, time_event_source_next);
}

static int latest_time_prioq_compare(const void *a, const void *b) {
        return time_prioq_compare(a, b, time_event_source_latest);
}

static int exit_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;
        int r;

        assert(x->type == SOURCE_EXIT);
        assert(y->type == SOURCE_EXIT);

        /* Enabled ones first */
        r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
        if (r != 0)
                return r;

        /* Lower priority values first */
        return CMP(x->priority, y->priority);
}

static void free_clock_data(struct clock_data *d) {
        assert(d);
        assert(d->wakeup == WAKEUP_CLOCK_DATA);

        safe_close(d->fd);
        prioq_free(d->earliest);
        prioq_free(d->latest);
}

static sd_event *event_free(sd_event *e) {
        sd_event_source *s;

        assert(e);

        e->sigterm_event_source = sd_event_source_unref(e->sigterm_event_source);
        e->sigint_event_source = sd_event_source_unref(e->sigint_event_source);

        while ((s = e->sources)) {
                assert(s->floating);
                source_disconnect(s);
                sd_event_source_unref(s);
        }

        assert(e->n_sources == 0);

        if (e->default_event_ptr)
                *(e->default_event_ptr) = NULL;

        safe_close(e->epoll_fd);
        safe_close(e->watchdog_fd);

        free_clock_data(&e->realtime);
        free_clock_data(&e->boottime);
        free_clock_data(&e->monotonic);
        free_clock_data(&e->realtime_alarm);
        free_clock_data(&e->boottime_alarm);

        prioq_free(e->pending);
        prioq_free(e->prepare);
        prioq_free(e->exit);

        free(e->signal_sources);
        hashmap_free(e->signal_data);

        hashmap_free(e->inotify_data);

        hashmap_free(e->child_sources);
        set_free(e->post_sources);

        free(e->event_queue);

        return mfree(e);
}

_public_ int sd_event_new(sd_event** ret) {
        sd_event *e;
        int r;

        assert_return(ret, -EINVAL);

        e = new(sd_event, 1);
        if (!e)
                return -ENOMEM;

        *e = (sd_event) {
                .n_ref = 1,
                .epoll_fd = -EBADF,
                .watchdog_fd = -EBADF,
                .realtime.wakeup = WAKEUP_CLOCK_DATA,
                .realtime.fd = -EBADF,
                .realtime.next = USEC_INFINITY,
                .boottime.wakeup = WAKEUP_CLOCK_DATA,
                .boottime.fd = -EBADF,
                .boottime.next = USEC_INFINITY,
                .monotonic.wakeup = WAKEUP_CLOCK_DATA,
                .monotonic.fd = -EBADF,
                .monotonic.next = USEC_INFINITY,
                .realtime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .realtime_alarm.fd = -EBADF,
                .realtime_alarm.next = USEC_INFINITY,
                .boottime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .boottime_alarm.fd = -EBADF,
                .boottime_alarm.next = USEC_INFINITY,
                .perturb = USEC_INFINITY,
                .origin_id = origin_id_query(),
        };

        r = prioq_ensure_allocated(&e->pending, pending_prioq_compare);
        if (r < 0)
                goto fail;

        e->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (e->epoll_fd < 0) {
                r = -errno;
                goto fail;
        }

        e->epoll_fd = fd_move_above_stdio(e->epoll_fd);

        if (secure_getenv("SD_EVENT_PROFILE_DELAYS")) {
                log_debug("Event loop profiling enabled. Logarithmic histogram of event loop iterations in the range 2^0 %s 2^63 us will be logged every 5s.",
                          special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                e->profile_delays = true;
        }

        *ret = e;
        return 0;

fail:
        event_free(e);
        return r;
}

/* Define manually so we can add the origin check */
_public_ sd_event *sd_event_ref(sd_event *e) {
        if (!e)
                return NULL;
        if (event_origin_changed(e))
                return NULL;

        e->n_ref++;

        return e;
}

_public_ sd_event* sd_event_unref(sd_event *e) {
        if (!e)
                return NULL;
        if (event_origin_changed(e))
                return NULL;

        assert(e->n_ref > 0);
        if (--e->n_ref > 0)
                return NULL;

        return event_free(e);
}

#define PROTECT_EVENT(e)                                                \
        _unused_ _cleanup_(sd_event_unrefp) sd_event *_ref = sd_event_ref(e);

_public_ sd_event_source* sd_event_source_disable_unref(sd_event_source *s) {
        if (s)
                (void) sd_event_source_set_enabled(s, SD_EVENT_OFF);
        return sd_event_source_unref(s);
}

static void source_io_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_IO);

        if (event_origin_changed(s->event))
                return;

        if (!s->io.registered)
                return;

        if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->io.fd, NULL) < 0)
                log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                strna(s->description), event_source_type_to_string(s->type));

        s->io.registered = false;
}

static int source_io_register(
                sd_event_source *s,
                int enabled,
                uint32_t events) {

        assert(s);
        assert(s->type == SOURCE_IO);
        assert(enabled != SD_EVENT_OFF);

        struct epoll_event ev = {
                .events = events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
                .data.ptr = s,
        };

        if (epoll_ctl(s->event->epoll_fd,
                      s->io.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                      s->io.fd, &ev) < 0)
                return -errno;

        s->io.registered = true;

        return 0;
}

static void source_child_pidfd_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_CHILD);

        if (event_origin_changed(s->event))
                return;

        if (!s->child.registered)
                return;

        if (EVENT_SOURCE_WATCH_PIDFD(s))
                if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->child.pidfd, NULL) < 0)
                        log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                        strna(s->description), event_source_type_to_string(s->type));

        s->child.registered = false;
}

static int source_child_pidfd_register(sd_event_source *s, int enabled) {
        assert(s);
        assert(s->type == SOURCE_CHILD);
        assert(enabled != SD_EVENT_OFF);

        if (EVENT_SOURCE_WATCH_PIDFD(s)) {
                struct epoll_event ev = {
                        .events = EPOLLIN | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
                        .data.ptr = s,
                };

                if (epoll_ctl(s->event->epoll_fd,
                              s->child.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                              s->child.pidfd, &ev) < 0)
                        return -errno;
        }

        s->child.registered = true;
        return 0;
}

static void source_memory_pressure_unregister(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (event_origin_changed(s->event))
                return;

        if (!s->memory_pressure.registered)
                return;

        if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->memory_pressure.fd, NULL) < 0)
                log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
                                strna(s->description), event_source_type_to_string(s->type));

        s->memory_pressure.registered = false;
}

static int source_memory_pressure_register(sd_event_source *s, int enabled) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);
        assert(enabled != SD_EVENT_OFF);

        struct epoll_event ev = {
                .events = s->memory_pressure.write_buffer_size > 0 ? EPOLLOUT :
                          (s->memory_pressure.events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0)),
                .data.ptr = s,
        };

        if (epoll_ctl(s->event->epoll_fd,
                      s->memory_pressure.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
                      s->memory_pressure.fd, &ev) < 0)
                return -errno;

        s->memory_pressure.registered = true;
        return 0;
}

static void source_memory_pressure_add_to_write_list(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (s->memory_pressure.in_write_list)
                return;

        LIST_PREPEND(memory_pressure.write_list, s->event->memory_pressure_write_list, s);
        s->memory_pressure.in_write_list = true;
}

static void source_memory_pressure_remove_from_write_list(sd_event_source *s) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (!s->memory_pressure.in_write_list)
                return;

        LIST_REMOVE(memory_pressure.write_list, s->event->memory_pressure_write_list, s);
        s->memory_pressure.in_write_list = false;
}

static clockid_t event_source_type_to_clock(EventSourceType t) {

        switch (t) {

        case SOURCE_TIME_REALTIME:
                return CLOCK_REALTIME;

        case SOURCE_TIME_BOOTTIME:
                return CLOCK_BOOTTIME;

        case SOURCE_TIME_MONOTONIC:
                return CLOCK_MONOTONIC;

        case SOURCE_TIME_REALTIME_ALARM:
                return CLOCK_REALTIME_ALARM;

        case SOURCE_TIME_BOOTTIME_ALARM:
                return CLOCK_BOOTTIME_ALARM;

        default:
                return (clockid_t) -1;
        }
}

static EventSourceType clock_to_event_source_type(clockid_t clock) {

        switch (clock) {

        case CLOCK_REALTIME:
                return SOURCE_TIME_REALTIME;

        case CLOCK_BOOTTIME:
                return SOURCE_TIME_BOOTTIME;

        case CLOCK_MONOTONIC:
                return SOURCE_TIME_MONOTONIC;

        case CLOCK_REALTIME_ALARM:
                return SOURCE_TIME_REALTIME_ALARM;

        case CLOCK_BOOTTIME_ALARM:
                return SOURCE_TIME_BOOTTIME_ALARM;

        default:
                return _SOURCE_EVENT_SOURCE_TYPE_INVALID;
        }
}

static struct clock_data* event_get_clock_data(sd_event *e, EventSourceType t) {
        assert(e);

        switch (t) {

        case SOURCE_TIME_REALTIME:
                return &e->realtime;

        case SOURCE_TIME_BOOTTIME:
                return &e->boottime;

        case SOURCE_TIME_MONOTONIC:
                return &e->monotonic;

        case SOURCE_TIME_REALTIME_ALARM:
                return &e->realtime_alarm;

        case SOURCE_TIME_BOOTTIME_ALARM:
                return &e->boottime_alarm;

        default:
                return NULL;
        }
}

static void event_free_signal_data(sd_event *e, struct signal_data *d) {
        assert(e);

        if (!d)
                return;

        hashmap_remove(e->signal_data, &d->priority);
        safe_close(d->fd);
        free(d);
}

static int event_make_signal_data(
                sd_event *e,
                int sig,
                struct signal_data **ret) {

        struct signal_data *d;
        bool added = false;
        sigset_t ss_copy;
        int64_t priority;
        int r;

        assert(e);

        if (event_origin_changed(e))
                return -ECHILD;

        if (e->signal_sources && e->signal_sources[sig])
                priority = e->signal_sources[sig]->priority;
        else
                priority = SD_EVENT_PRIORITY_NORMAL;

        d = hashmap_get(e->signal_data, &priority);
        if (d) {
                if (sigismember(&d->sigset, sig) > 0) {
                        if (ret)
                                *ret = d;
                        return 0;
                }
        } else {
                d = new(struct signal_data, 1);
                if (!d)
                        return -ENOMEM;

                *d = (struct signal_data) {
                        .wakeup = WAKEUP_SIGNAL_DATA,
                        .fd = -EBADF,
                        .priority = priority,
                };

                r = hashmap_ensure_put(&e->signal_data, &uint64_hash_ops, &d->priority, d);
                if (r < 0) {
                        free(d);
                        return r;
                }

                added = true;
        }

        ss_copy = d->sigset;
        assert_se(sigaddset(&ss_copy, sig) >= 0);

        r = signalfd(d->fd >= 0 ? d->fd : -1,   /* the first arg must be -1 or a valid signalfd */
                     &ss_copy,
                     SFD_NONBLOCK|SFD_CLOEXEC);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        d->sigset = ss_copy;

        if (d->fd >= 0) {
                if (ret)
                        *ret = d;
                return 0;
        }

        d->fd = fd_move_above_stdio(r);

        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, d->fd, &ev) < 0) {
                r = -errno;
                goto fail;
        }

        if (ret)
                *ret = d;

        return 0;

fail:
        if (added)
                event_free_signal_data(e, d);

        return r;
}

static void event_unmask_signal_data(sd_event *e, struct signal_data *d, int sig) {
        assert(e);
        assert(d);

        /* Turns off the specified signal in the signal data
         * object. If the signal mask of the object becomes empty that
         * way removes it. */

        if (sigismember(&d->sigset, sig) == 0)
                return;

        assert_se(sigdelset(&d->sigset, sig) >= 0);

        if (sigisemptyset(&d->sigset)) {
                /* If all the mask is all-zero we can get rid of the structure */
                event_free_signal_data(e, d);
                return;
        }

        if (event_origin_changed(e))
                return;

        assert(d->fd >= 0);

        if (signalfd(d->fd, &d->sigset, SFD_NONBLOCK|SFD_CLOEXEC) < 0)
                log_debug_errno(errno, "Failed to unset signal bit, ignoring: %m");
}

static void event_gc_signal_data(sd_event *e, const int64_t *priority, int sig) {
        struct signal_data *d;
        static const int64_t zero_priority = 0;

        assert(e);

        /* Rechecks if the specified signal is still something we are interested in. If not, we'll unmask it,
         * and possibly drop the signalfd for it. */

        if (sig == SIGCHLD &&
            e->n_online_child_sources > 0)
                return;

        if (e->signal_sources &&
            e->signal_sources[sig] &&
            event_source_is_online(e->signal_sources[sig]))
                return;

        /*
         * The specified signal might be enabled in three different queues:
         *
         * 1) the one that belongs to the priority passed (if it is non-NULL)
         * 2) the one that belongs to the priority of the event source of the signal (if there is one)
         * 3) the 0 priority (to cover the SIGCHLD case)
         *
         * Hence, let's remove it from all three here.
         */

        if (priority) {
                d = hashmap_get(e->signal_data, priority);
                if (d)
                        event_unmask_signal_data(e, d, sig);
        }

        if (e->signal_sources && e->signal_sources[sig]) {
                d = hashmap_get(e->signal_data, &e->signal_sources[sig]->priority);
                if (d)
                        event_unmask_signal_data(e, d, sig);
        }

        d = hashmap_get(e->signal_data, &zero_priority);
        if (d)
                event_unmask_signal_data(e, d, sig);
}

static void event_source_pp_prioq_reshuffle(sd_event_source *s) {
        assert(s);

        /* Reshuffles the pending + prepare prioqs. Called whenever the dispatch order changes, i.e. when
         * they are enabled/disabled or marked pending and such. */

        if (s->pending)
                prioq_reshuffle(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_reshuffle(s->event->prepare, s, &s->prepare_index);
}

static void event_source_time_prioq_reshuffle(sd_event_source *s) {
        struct clock_data *d;

        assert(s);

        /* Called whenever the event source's timer ordering properties changed, i.e. time, accuracy,
         * pending, enable state, and ratelimiting state. Makes sure the two prioq's are ordered
         * properly again. */

        if (s->ratelimited)
                d = &s->event->monotonic;
        else if (EVENT_SOURCE_IS_TIME(s->type))
                assert_se(d = event_get_clock_data(s->event, s->type));
        else
                return; /* no-op for an event source which is neither a timer nor ratelimited. */

        prioq_reshuffle(d->earliest, s, &s->earliest_index);
        prioq_reshuffle(d->latest, s, &s->latest_index);
        d->needs_rearm = true;
}

static void event_source_time_prioq_remove(
                sd_event_source *s,
                struct clock_data *d) {

        assert(s);
        assert(d);

        prioq_remove(d->earliest, s, &s->earliest_index);
        prioq_remove(d->latest, s, &s->latest_index);
        s->earliest_index = s->latest_index = PRIOQ_IDX_NULL;
        d->needs_rearm = true;
}

static void source_disconnect(sd_event_source *s) {
        sd_event *event;
        int r;

        assert(s);

        if (!s->event)
                return;

        assert(s->event->n_sources > 0);

        switch (s->type) {

        case SOURCE_IO:
                if (s->io.fd >= 0)
                        source_io_unregister(s);

                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
                /* Only remove this event source from the time event source here if it is not ratelimited. If
                 * it is ratelimited, we'll remove it below, separately. Why? Because the clock used might
                 * differ: ratelimiting always uses CLOCK_MONOTONIC, but timer events might use any clock */

                if (!s->ratelimited) {
                        struct clock_data *d;
                        assert_se(d = event_get_clock_data(s->event, s->type));
                        event_source_time_prioq_remove(s, d);
                }

                break;

        case SOURCE_SIGNAL:
                if (s->signal.sig > 0) {

                        if (s->event->signal_sources)
                                s->event->signal_sources[s->signal.sig] = NULL;

                        event_gc_signal_data(s->event, &s->priority, s->signal.sig);

                        if (s->signal.unblock) {
                                sigset_t new_ss;

                                if (sigemptyset(&new_ss) < 0)
                                        log_debug_errno(errno, "Failed to reset signal set, ignoring: %m");
                                else if (sigaddset(&new_ss, s->signal.sig) < 0)
                                        log_debug_errno(errno, "Failed to add signal %i to signal mask, ignoring: %m", s->signal.sig);
                                else {
                                        r = pthread_sigmask(SIG_UNBLOCK, &new_ss, NULL);
                                        if (r != 0)
                                                log_debug_errno(r, "Failed to unblock signal %i, ignoring: %m", s->signal.sig);
                                }
                        }
                }

                break;

        case SOURCE_CHILD:
                if (event_origin_changed(s->event))
                        s->child.process_owned = false;

                if (s->child.pid > 0) {
                        if (event_source_is_online(s)) {
                                assert(s->event->n_online_child_sources > 0);
                                s->event->n_online_child_sources--;
                        }

                        (void) hashmap_remove(s->event->child_sources, PID_TO_PTR(s->child.pid));
                }

                if (EVENT_SOURCE_WATCH_PIDFD(s))
                        source_child_pidfd_unregister(s);
                else
                        event_gc_signal_data(s->event, &s->priority, SIGCHLD);

                break;

        case SOURCE_DEFER:
                /* nothing */
                break;

        case SOURCE_POST:
                set_remove(s->event->post_sources, s);
                break;

        case SOURCE_EXIT:
                prioq_remove(s->event->exit, s, &s->exit.prioq_index);
                break;

        case SOURCE_INOTIFY: {
                struct inode_data *inode_data;

                inode_data = s->inotify.inode_data;
                if (inode_data) {
                        struct inotify_data *inotify_data;
                        assert_se(inotify_data = inode_data->inotify_data);

                        /* Detach this event source from the inode object */
                        LIST_REMOVE(inotify.by_inode_data, inode_data->event_sources, s);
                        s->inotify.inode_data = NULL;

                        if (s->pending) {
                                assert(inotify_data->n_pending > 0);
                                inotify_data->n_pending--;
                        }

                        /* Note that we don't reduce the inotify mask for the watch descriptor here if the inode is
                         * continued to being watched. That's because inotify doesn't really have an API for that: we
                         * can only change watch masks with access to the original inode either by fd or by path. But
                         * paths aren't stable, and keeping an O_PATH fd open all the time would mean wasting an fd
                         * continuously and keeping the mount busy which we can't really do. We could reconstruct the
                         * original inode from /proc/self/fdinfo/$INOTIFY_FD (as all watch descriptors are listed
                         * there), but given the need for open_by_handle_at() which is privileged and not universally
                         * available this would be quite an incomplete solution. Hence we go the other way, leave the
                         * mask set, even if it is not minimized now, and ignore all events we aren't interested in
                         * anymore after reception. Yes, this sucks, but … Linux … */

                        /* Maybe release the inode data (and its inotify) */
                        event_gc_inode_data(s->event, inode_data);
                }

                break;
        }

        case SOURCE_MEMORY_PRESSURE:
                source_memory_pressure_remove_from_write_list(s);
                source_memory_pressure_unregister(s);
                break;

        default:
                assert_not_reached();
        }

        if (s->pending)
                prioq_remove(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_remove(s->event->prepare, s, &s->prepare_index);

        if (s->ratelimited)
                event_source_time_prioq_remove(s, &s->event->monotonic);

        event = TAKE_PTR(s->event);
        LIST_REMOVE(sources, event->sources, s);
        event->n_sources--;

        /* Note that we don't invalidate the type here, since we still need it in order to close the fd or
         * pidfd associated with this event source, which we'll do only on source_free(). */

        if (!s->floating)
                sd_event_unref(event);
}

static sd_event_source* source_free(sd_event_source *s) {
        assert(s);

        source_disconnect(s);

        if (s->type == SOURCE_IO && s->io.owned)
                s->io.fd = safe_close(s->io.fd);

        if (s->type == SOURCE_CHILD) {
                /* Eventually the kernel will do this automatically for us, but for now let's emulate this (unreliably) in userspace. */

                if (s->child.process_owned) {

                        if (!s->child.exited) {
                                bool sent = false;

                                if (s->child.pidfd >= 0) {
                                        if (pidfd_send_signal(s->child.pidfd, SIGKILL, NULL, 0) < 0) {
                                                if (errno == ESRCH) /* Already dead */
                                                        sent = true;
                                                else if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                                        log_debug_errno(errno, "Failed to kill process " PID_FMT " via pidfd_send_signal(), re-trying via kill(): %m",
                                                                        s->child.pid);
                                        } else
                                                sent = true;
                                }

                                if (!sent)
                                        if (kill(s->child.pid, SIGKILL) < 0)
                                                if (errno != ESRCH) /* Already dead */
                                                        log_debug_errno(errno, "Failed to kill process " PID_FMT " via kill(), ignoring: %m",
                                                                        s->child.pid);
                        }

                        if (!s->child.waited) {
                                siginfo_t si = {};

                                /* Reap the child if we can */
                                (void) waitid(P_PID, s->child.pid, &si, WEXITED);
                        }
                }

                if (s->child.pidfd_owned)
                        s->child.pidfd = safe_close(s->child.pidfd);
        }

        if (s->type == SOURCE_MEMORY_PRESSURE) {
                s->memory_pressure.fd = safe_close(s->memory_pressure.fd);
                s->memory_pressure.write_buffer = mfree(s->memory_pressure.write_buffer);
        }

        if (s->destroy_callback)
                s->destroy_callback(s->userdata);

        free(s->description);
        return mfree(s);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_event_source*, source_free);

static int source_set_pending(sd_event_source *s, bool b) {
        int r;

        assert(s);
        assert(s->type != SOURCE_EXIT);

        if (s->pending == b)
                return 0;

        s->pending = b;

        if (b) {
                s->pending_iteration = s->event->iteration;

                r = prioq_put(s->event->pending, s, &s->pending_index);
                if (r < 0) {
                        s->pending = false;
                        return r;
                }
        } else
                assert_se(prioq_remove(s->event->pending, s, &s->pending_index));

        if (EVENT_SOURCE_IS_TIME(s->type))
                event_source_time_prioq_reshuffle(s);

        if (s->type == SOURCE_SIGNAL && !b) {
                struct signal_data *d;

                d = hashmap_get(s->event->signal_data, &s->priority);
                if (d && d->current == s)
                        d->current = NULL;
        }

        if (s->type == SOURCE_INOTIFY) {

                assert(s->inotify.inode_data);
                assert(s->inotify.inode_data->inotify_data);

                if (b)
                        s->inotify.inode_data->inotify_data->n_pending++;
                else {
                        assert(s->inotify.inode_data->inotify_data->n_pending > 0);
                        s->inotify.inode_data->inotify_data->n_pending--;
                }
        }

        return 1;
}

static sd_event_source *source_new(sd_event *e, bool floating, EventSourceType type) {

        /* Let's allocate exactly what we need. Note that the difference of the smallest event source
         * structure to the largest is 144 bytes on x86-64 at the time of writing, i.e. more than two cache
         * lines. */
        static const size_t size_table[_SOURCE_EVENT_SOURCE_TYPE_MAX] = {
                [SOURCE_IO]                  = endoffsetof_field(sd_event_source, io),
                [SOURCE_TIME_REALTIME]       = endoffsetof_field(sd_event_source, time),
                [SOURCE_TIME_BOOTTIME]       = endoffsetof_field(sd_event_source, time),
                [SOURCE_TIME_MONOTONIC]      = endoffsetof_field(sd_event_source, time),
                [SOURCE_TIME_REALTIME_ALARM] = endoffsetof_field(sd_event_source, time),
                [SOURCE_TIME_BOOTTIME_ALARM] = endoffsetof_field(sd_event_source, time),
                [SOURCE_SIGNAL]              = endoffsetof_field(sd_event_source, signal),
                [SOURCE_CHILD]               = endoffsetof_field(sd_event_source, child),
                [SOURCE_DEFER]               = endoffsetof_field(sd_event_source, defer),
                [SOURCE_POST]                = endoffsetof_field(sd_event_source, post),
                [SOURCE_EXIT]                = endoffsetof_field(sd_event_source, exit),
                [SOURCE_INOTIFY]             = endoffsetof_field(sd_event_source, inotify),
                [SOURCE_MEMORY_PRESSURE]     = endoffsetof_field(sd_event_source, memory_pressure),
        };

        sd_event_source *s;

        assert(e);
        assert(type >= 0);
        assert(type < _SOURCE_EVENT_SOURCE_TYPE_MAX);
        assert(size_table[type] > 0);

        s = malloc0(size_table[type]);
        if (!s)
                return NULL;
        /* We use expand_to_usable() here to tell gcc that it should consider this an object of the full
         * size, even if we only allocate the initial part we need. */
        s = expand_to_usable(s, sizeof(sd_event_source));

        /* Note: we cannot use compound initialization here, because sizeof(sd_event_source) is likely larger
         * than what we allocated here. */
        s->n_ref = 1;
        s->event = e;
        s->floating = floating;
        s->type = type;
        s->pending_index = PRIOQ_IDX_NULL;
        s->prepare_index = PRIOQ_IDX_NULL;

        if (!floating)
                sd_event_ref(e);

        LIST_PREPEND(sources, e->sources, s);
        e->n_sources++;

        return s;
}

static int io_exit_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

_public_ int sd_event_add_io(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t events,
                sd_event_io_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(fd >= 0, -EBADF);
        assert_return(!(events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP|EPOLLET)), -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = io_exit_callback;

        s = source_new(e, !ret, SOURCE_IO);
        if (!s)
                return -ENOMEM;

        s->wakeup = WAKEUP_EVENT_SOURCE;
        s->io.fd = fd;
        s->io.events = events;
        s->io.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        r = source_io_register(s, s->enabled, events);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

static void initialize_perturb(sd_event *e) {
        sd_id128_t id = {};

        /* When we sleep for longer, we try to realign the wakeup to the same time within each
         * minute/second/250ms, so that events all across the system can be coalesced into a single CPU
         * wakeup. However, let's take some system-specific randomness for this value, so that in a network
         * of systems with synced clocks timer events are distributed a bit. Here, we calculate a
         * perturbation usec offset from the boot ID (or machine ID if failed, e.g. /proc is not mounted). */

        if (_likely_(e->perturb != USEC_INFINITY))
                return;

        if (sd_id128_get_boot(&id) >= 0 || sd_id128_get_machine(&id) >= 0)
                e->perturb = (id.qwords[0] ^ id.qwords[1]) % USEC_PER_MINUTE;
        else
                e->perturb = 0; /* This is a super early process without /proc and /etc ?? */
}

static int event_setup_timer_fd(
                sd_event *e,
                struct clock_data *d,
                clockid_t clock) {

        assert(e);
        assert(d);

        if (_likely_(d->fd >= 0))
                return 0;

        _cleanup_close_ int fd = -EBADF;

        fd = timerfd_create(clock, TFD_NONBLOCK|TFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        fd = fd_move_above_stdio(fd);

        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                return -errno;

        d->fd = TAKE_FD(fd);
        return 0;
}

static int time_exit_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

static int setup_clock_data(sd_event *e, struct clock_data *d, clockid_t clock) {
        int r;

        assert(d);

        if (d->fd < 0) {
                r = event_setup_timer_fd(e, d, clock);
                if (r < 0)
                        return r;
        }

        r = prioq_ensure_allocated(&d->earliest, earliest_time_prioq_compare);
        if (r < 0)
                return r;

        r = prioq_ensure_allocated(&d->latest, latest_time_prioq_compare);
        if (r < 0)
                return r;

        return 0;
}

static int event_source_time_prioq_put(
                sd_event_source *s,
                struct clock_data *d) {

        int r;

        assert(s);
        assert(d);
        assert(EVENT_SOURCE_USES_TIME_PRIOQ(s->type));

        r = prioq_put(d->earliest, s, &s->earliest_index);
        if (r < 0)
                return r;

        r = prioq_put(d->latest, s, &s->latest_index);
        if (r < 0) {
                assert_se(prioq_remove(d->earliest, s, &s->earliest_index) > 0);
                s->earliest_index = PRIOQ_IDX_NULL;
                return r;
        }

        d->needs_rearm = true;
        return 0;
}

_public_ int sd_event_add_time(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata) {

        EventSourceType type;
        _cleanup_(source_freep) sd_event_source *s = NULL;
        struct clock_data *d;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(accuracy != UINT64_MAX, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!clock_supported(clock)) /* Checks whether the kernel supports the clock */
                return -EOPNOTSUPP;

        type = clock_to_event_source_type(clock); /* checks whether sd-event supports this clock */
        if (type < 0)
                return -EOPNOTSUPP;

        if (!callback)
                callback = time_exit_callback;

        assert_se(d = event_get_clock_data(e, type));

        r = setup_clock_data(e, d, clock);
        if (r < 0)
                return r;

        s = source_new(e, !ret, type);
        if (!s)
                return -ENOMEM;

        s->time.next = usec;
        s->time.accuracy = accuracy == 0 ? DEFAULT_ACCURACY_USEC : accuracy;
        s->time.callback = callback;
        s->earliest_index = s->latest_index = PRIOQ_IDX_NULL;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        r = event_source_time_prioq_put(s, d);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int sd_event_add_time_relative(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata) {

        usec_t t;
        int r;

        /* Same as sd_event_add_time() but operates relative to the event loop's current point in time, and
         * checks for overflow. */

        r = sd_event_now(e, clock, &t);
        if (r < 0)
                return r;

        if (usec >= USEC_INFINITY - t)
                return -EOVERFLOW;

        return sd_event_add_time(e, ret, clock, t + usec, accuracy, callback, userdata);
}

static int signal_exit_callback(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

_public_ int sd_event_add_signal(
                sd_event *e,
                sd_event_source **ret,
                int sig,
                sd_event_signal_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        struct signal_data *d;
        sigset_t new_ss;
        bool block_it;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        /* Let's make sure our special flag stays outside of the valid signal range */
        assert_cc(_NSIG < SD_EVENT_SIGNAL_PROCMASK);

        if (sig & SD_EVENT_SIGNAL_PROCMASK) {
                sig &= ~SD_EVENT_SIGNAL_PROCMASK;
                assert_return(SIGNAL_VALID(sig), -EINVAL);

                block_it = true;
        } else {
                assert_return(SIGNAL_VALID(sig), -EINVAL);

                r = signal_is_blocked(sig);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBUSY;

                block_it = false;
        }

        if (!callback)
                callback = signal_exit_callback;

        if (!e->signal_sources) {
                e->signal_sources = new0(sd_event_source*, _NSIG);
                if (!e->signal_sources)
                        return -ENOMEM;
        } else if (e->signal_sources[sig])
                return -EBUSY;

        s = source_new(e, !ret, SOURCE_SIGNAL);
        if (!s)
                return -ENOMEM;

        s->signal.sig = sig;
        s->signal.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        e->signal_sources[sig] = s;

        if (block_it) {
                sigset_t old_ss;

                if (sigemptyset(&new_ss) < 0)
                        return -errno;

                if (sigaddset(&new_ss, sig) < 0)
                        return -errno;

                r = pthread_sigmask(SIG_BLOCK, &new_ss, &old_ss);
                if (r != 0)
                        return -r;

                r = sigismember(&old_ss, sig);
                if (r < 0)
                        return -errno;

                s->signal.unblock = !r;
        } else
                s->signal.unblock = false;

        r = event_make_signal_data(e, sig, &d);
        if (r < 0) {
                if (s->signal.unblock)
                        (void) pthread_sigmask(SIG_UNBLOCK, &new_ss, NULL);

                return r;
        }

        /* Use the signal name as description for the event source by default */
        (void) sd_event_source_set_description(s, signal_to_string(sig));

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

static int child_exit_callback(sd_event_source *s, const siginfo_t *si, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

static bool shall_use_pidfd(void) {
        /* Mostly relevant for debugging, i.e. this is used in test-event.c to test the event loop once with and once without pidfd */
        return getenv_bool_secure("SYSTEMD_PIDFD") != 0;
}

_public_ int sd_event_add_child(
                sd_event *e,
                sd_event_source **ret,
                pid_t pid,
                int options,
                sd_event_child_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(pid > 1, -EINVAL);
        assert_return(!(options & ~(WEXITED|WSTOPPED|WCONTINUED)), -EINVAL);
        assert_return(options != 0, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = child_exit_callback;

        if (e->n_online_child_sources == 0) {
                /* Caller must block SIGCHLD before using us to watch children, even if pidfd is available,
                 * for compatibility with pre-pidfd and because we don't want the reap the child processes
                 * ourselves, i.e. call waitid(), and don't want Linux' default internal logic for that to
                 * take effect.
                 *
                 * (As an optimization we only do this check on the first child event source created.) */
                r = signal_is_blocked(SIGCHLD);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBUSY;
        }

        r = hashmap_ensure_allocated(&e->child_sources, NULL);
        if (r < 0)
                return r;

        if (hashmap_contains(e->child_sources, PID_TO_PTR(pid)))
                return -EBUSY;

        s = source_new(e, !ret, SOURCE_CHILD);
        if (!s)
                return -ENOMEM;

        s->wakeup = WAKEUP_EVENT_SOURCE;
        s->child.options = options;
        s->child.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        /* We always take a pidfd here if we can, even if we wait for anything else than WEXITED, so that we
         * pin the PID, and make regular waitid() handling race-free. */

        if (shall_use_pidfd()) {
                s->child.pidfd = pidfd_open(pid, 0);
                if (s->child.pidfd < 0) {
                        /* Propagate errors unless the syscall is not supported or blocked */
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                                return -errno;
                } else
                        s->child.pidfd_owned = true; /* If we allocate the pidfd we own it by default */
        } else
                s->child.pidfd = -EBADF;

        if (EVENT_SOURCE_WATCH_PIDFD(s)) {
                /* We have a pidfd and we only want to watch for exit */
                r = source_child_pidfd_register(s, s->enabled);
                if (r < 0)
                        return r;

        } else {
                /* We have no pidfd or we shall wait for some other event than WEXITED */
                r = event_make_signal_data(e, SIGCHLD, NULL);
                if (r < 0)
                        return r;

                e->need_process_child = true;
        }

        r = hashmap_put(e->child_sources, PID_TO_PTR(pid), s);
        if (r < 0)
                return r;

        /* These must be done after everything succeeds. */
        s->child.pid = pid;
        e->n_online_child_sources++;

        if (ret)
                *ret = s;
        TAKE_PTR(s);
        return 0;
}

_public_ int sd_event_add_child_pidfd(
                sd_event *e,
                sd_event_source **ret,
                int pidfd,
                int options,
                sd_event_child_handler_t callback,
                void *userdata) {


        _cleanup_(source_freep) sd_event_source *s = NULL;
        pid_t pid;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(pidfd >= 0, -EBADF);
        assert_return(!(options & ~(WEXITED|WSTOPPED|WCONTINUED)), -EINVAL);
        assert_return(options != 0, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = child_exit_callback;

        if (e->n_online_child_sources == 0) {
                r = signal_is_blocked(SIGCHLD);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EBUSY;
        }

        r = hashmap_ensure_allocated(&e->child_sources, NULL);
        if (r < 0)
                return r;

        r = pidfd_get_pid(pidfd, &pid);
        if (r < 0)
                return r;

        if (hashmap_contains(e->child_sources, PID_TO_PTR(pid)))
                return -EBUSY;

        s = source_new(e, !ret, SOURCE_CHILD);
        if (!s)
                return -ENOMEM;

        s->wakeup = WAKEUP_EVENT_SOURCE;
        s->child.pidfd = pidfd;
        s->child.pid = pid;
        s->child.options = options;
        s->child.callback = callback;
        s->child.pidfd_owned = false; /* If we got the pidfd passed in we don't own it by default (similar to the IO fd case) */
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        r = hashmap_put(e->child_sources, PID_TO_PTR(pid), s);
        if (r < 0)
                return r;

        if (EVENT_SOURCE_WATCH_PIDFD(s)) {
                /* We only want to watch for WEXITED */
                r = source_child_pidfd_register(s, s->enabled);
                if (r < 0)
                        return r;
        } else {
                /* We shall wait for some other event than WEXITED */
                r = event_make_signal_data(e, SIGCHLD, NULL);
                if (r < 0)
                        return r;

                e->need_process_child = true;
        }

        e->n_online_child_sources++;

        if (ret)
                *ret = s;
        TAKE_PTR(s);
        return 0;
}

static int generic_exit_callback(sd_event_source *s, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

_public_ int sd_event_add_defer(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = generic_exit_callback;

        s = source_new(e, !ret, SOURCE_DEFER);
        if (!s)
                return -ENOMEM;

        s->defer.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        r = source_set_pending(s, true);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int sd_event_add_post(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = generic_exit_callback;

        s = source_new(e, !ret, SOURCE_POST);
        if (!s)
                return -ENOMEM;

        s->post.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        r = set_ensure_put(&e->post_sources, NULL, s);
        if (r < 0)
                return r;
        assert(r > 0);

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int sd_event_add_exit(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        _cleanup_(source_freep) sd_event_source *s = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        r = prioq_ensure_allocated(&e->exit, exit_prioq_compare);
        if (r < 0)
                return r;

        s = source_new(e, !ret, SOURCE_EXIT);
        if (!s)
                return -ENOMEM;

        s->exit.callback = callback;
        s->userdata = userdata;
        s->exit.prioq_index = PRIOQ_IDX_NULL;
        s->enabled = SD_EVENT_ONESHOT;

        r = prioq_put(s->event->exit, s, &s->exit.prioq_index);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int sd_event_trim_memory(void) {
        int r;

        /* A default implementation of a memory pressure callback. Simply releases our own allocation caches
         * and glibc's. This is automatically used when people call sd_event_add_memory_pressure() with a
         * NULL callback parameter. */

        log_debug("Memory pressure event, trimming malloc() memory.");

#if HAVE_GENERIC_MALLINFO
        generic_mallinfo before_mallinfo = generic_mallinfo_get();
#endif

        usec_t before_timestamp = now(CLOCK_MONOTONIC);
        hashmap_trim_pools();
        r = malloc_trim(0);
        usec_t after_timestamp = now(CLOCK_MONOTONIC);

        if (r > 0)
                log_debug("Successfully trimmed some memory.");
        else
                log_debug("Couldn't trim any memory.");

        usec_t period = after_timestamp - before_timestamp;

#if HAVE_GENERIC_MALLINFO
        generic_mallinfo after_mallinfo = generic_mallinfo_get();
        size_t l = LESS_BY((size_t) before_mallinfo.hblkhd, (size_t) after_mallinfo.hblkhd) +
                LESS_BY((size_t) before_mallinfo.arena, (size_t) after_mallinfo.arena);
        log_struct(LOG_DEBUG,
                   LOG_MESSAGE("Memory trimming took %s, returned %s to OS.",
                               FORMAT_TIMESPAN(period, 0),
                               FORMAT_BYTES(l)),
                   "MESSAGE_ID=" SD_MESSAGE_MEMORY_TRIM_STR,
                   "TRIMMED_BYTES=%zu", l,
                   "TRIMMED_USEC=" USEC_FMT, period);
#else
        log_struct(LOG_DEBUG,
                   LOG_MESSAGE("Memory trimming took %s.",
                               FORMAT_TIMESPAN(period, 0)),
                   "MESSAGE_ID=" SD_MESSAGE_MEMORY_TRIM_STR,
                   "TRIMMED_USEC=" USEC_FMT, period);
#endif

        return 0;
}

static int memory_pressure_callback(sd_event_source *s, void *userdata) {
        assert(s);

        sd_event_trim_memory();
        return 0;
}

_public_ int sd_event_add_memory_pressure(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        _cleanup_free_ char *w = NULL;
        _cleanup_(source_freep) sd_event_source *s = NULL;
        _cleanup_close_ int path_fd = -EBADF, fd = -EBADF;
        _cleanup_free_ void *write_buffer = NULL;
        const char *watch, *watch_fallback = NULL, *env;
        size_t write_buffer_size = 0;
        struct stat st;
        uint32_t events;
        bool locked;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = memory_pressure_callback;

        s = source_new(e, !ret, SOURCE_MEMORY_PRESSURE);
        if (!s)
                return -ENOMEM;

        s->wakeup = WAKEUP_EVENT_SOURCE;
        s->memory_pressure.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;
        s->memory_pressure.fd = -EBADF;

        env = secure_getenv("MEMORY_PRESSURE_WATCH");
        if (env) {
                if (isempty(env) || path_equal(env, "/dev/null"))
                        return log_debug_errno(SYNTHETIC_ERRNO(EHOSTDOWN),
                                               "Memory pressure logic is explicitly disabled via $MEMORY_PRESSURE_WATCH.");

                if (!path_is_absolute(env) || !path_is_normalized(env))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "$MEMORY_PRESSURE_WATCH set to invalid path: %s", env);

                watch = env;

                env = secure_getenv("MEMORY_PRESSURE_WRITE");
                if (env) {
                        r = unbase64mem(env, SIZE_MAX, &write_buffer, &write_buffer_size);
                        if (r < 0)
                                return r;
                }

                locked = true;
        } else {

                r = is_pressure_supported();
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EOPNOTSUPP;

                /* By default we want to watch memory pressure on the local cgroup, but we'll fall back on
                 * the system wide pressure if for some reason we cannot (which could be: memory controller
                 * not delegated to us, or PSI simply not available in the kernel). On legacy cgroupv1 we'll
                 * only use the system-wide logic. */
                r = cg_all_unified();
                if (r < 0)
                        return r;
                if (r == 0)
                        watch = "/proc/pressure/memory";
                else {
                        _cleanup_free_ char *cg = NULL;

                        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cg);
                        if (r < 0)
                                return r;

                        w = path_join("/sys/fs/cgroup", cg, "memory.pressure");
                        if (!w)
                                return -ENOMEM;

                        watch = w;
                        watch_fallback = "/proc/pressure/memory";
                }

                /* Android uses three levels in its userspace low memory killer logic:
                 *     some  70000 1000000
                 *     some 100000 1000000
                 *     full  70000 1000000
                 *
                 * GNOME's low memory monitor uses:
                 *     some  70000 1000000
                 *     some 100000 1000000
                 *     full 100000 1000000
                 *
                 * We'll default to the middle level that both agree on. Except we do it on a 2s window
                 * (i.e. 200ms per 2s, rather than 100ms per 1s), because that's the window duration the
                 * kernel will allow us to do unprivileged, also in the future. */
                if (asprintf((char**) &write_buffer,
                             "%s " USEC_FMT " " USEC_FMT,
                             MEMORY_PRESSURE_DEFAULT_TYPE,
                             MEMORY_PRESSURE_DEFAULT_THRESHOLD_USEC,
                             MEMORY_PRESSURE_DEFAULT_WINDOW_USEC) < 0)
                        return -ENOMEM;

                write_buffer_size = strlen(write_buffer) + 1;
                locked = false;
        }

        path_fd = open(watch, O_PATH|O_CLOEXEC);
        if (path_fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* We got ENOENT. Three options now: try the fallback if we have one, or return the error as
                 * is (if based on user/env config), or return -EOPNOTSUPP (because we picked the path, and
                 * the PSI service apparently is not supported) */
                if (!watch_fallback)
                        return locked ? -ENOENT : -EOPNOTSUPP;

                path_fd = open(watch_fallback, O_PATH|O_CLOEXEC);
                if (path_fd < 0) {
                        if (errno == ENOENT) /* PSI is not available in the kernel even under the fallback path? */
                                return -EOPNOTSUPP;
                        return -errno;
                }
        }

        if (fstat(path_fd, &st) < 0)
                return -errno;

        if (S_ISSOCK(st.st_mode)) {
                fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (fd < 0)
                        return -errno;

                r = connect_unix_path(fd, path_fd, NULL);
                if (r < 0)
                        return r;

                events = EPOLLIN;

        } else if (S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode)) {
                fd = fd_reopen(path_fd, (write_buffer_size > 0 ? O_RDWR : O_RDONLY) |O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                if (fd < 0)
                        return fd;

                if (S_ISREG(st.st_mode)) {
                        struct statfs sfs;

                        /* If this is a regular file validate this is a procfs or cgroupfs file, where we look for EPOLLPRI */

                        if (fstatfs(fd, &sfs) < 0)
                                return -errno;

                        if (!is_fs_type(&sfs, PROC_SUPER_MAGIC) &&
                            !is_fs_type(&sfs, CGROUP2_SUPER_MAGIC))
                                return -ENOTTY;

                        events = EPOLLPRI;
                } else
                        /* For fifos and char devices just watch for EPOLLIN */
                        events = EPOLLIN;

        } else if (S_ISDIR(st.st_mode))
                return -EISDIR;
        else
                return -EBADF;

        s->memory_pressure.fd = TAKE_FD(fd);
        s->memory_pressure.write_buffer = TAKE_PTR(write_buffer);
        s->memory_pressure.write_buffer_size = write_buffer_size;
        s->memory_pressure.events = events;
        s->memory_pressure.locked = locked;

        /* So here's the thing: if we are talking to PSI we need to write the watch string before adding the
         * fd to epoll (if we ignore this, then the watch won't work). Hence we'll not actually register the
         * fd with the epoll right-away. Instead, we just add the event source to a list of memory pressure
         * event sources on which writes must be executed before the first event loop iteration is
         * executed. (We could also write the data here, right away, but we want to give the caller the
         * freedom to call sd_event_source_set_memory_pressure_type() and
         * sd_event_source_set_memory_pressure_rate() before we write it. */

        if (s->memory_pressure.write_buffer_size > 0)
                source_memory_pressure_add_to_write_list(s);
        else {
                r = source_memory_pressure_register(s, s->enabled);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

static void event_free_inotify_data(sd_event *e, struct inotify_data *d) {
        assert(e);

        if (!d)
                return;

        assert(hashmap_isempty(d->inodes));
        assert(hashmap_isempty(d->wd));

        if (d->buffer_filled > 0)
                LIST_REMOVE(buffered, e->buffered_inotify_data_list, d);

        hashmap_free(d->inodes);
        hashmap_free(d->wd);

        assert_se(hashmap_remove(e->inotify_data, &d->priority) == d);

        if (d->fd >= 0) {
                if (!event_origin_changed(e) &&
                    epoll_ctl(e->epoll_fd, EPOLL_CTL_DEL, d->fd, NULL) < 0)
                        log_debug_errno(errno, "Failed to remove inotify fd from epoll, ignoring: %m");

                safe_close(d->fd);
        }
        free(d);
}

static int event_make_inotify_data(
                sd_event *e,
                int64_t priority,
                struct inotify_data **ret) {

        _cleanup_close_ int fd = -EBADF;
        struct inotify_data *d;
        int r;

        assert(e);

        d = hashmap_get(e->inotify_data, &priority);
        if (d) {
                if (ret)
                        *ret = d;
                return 0;
        }

        fd = inotify_init1(IN_NONBLOCK|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        fd = fd_move_above_stdio(fd);

        d = new(struct inotify_data, 1);
        if (!d)
                return -ENOMEM;

        *d = (struct inotify_data) {
                .wakeup = WAKEUP_INOTIFY_DATA,
                .fd = TAKE_FD(fd),
                .priority = priority,
        };

        r = hashmap_ensure_put(&e->inotify_data, &uint64_hash_ops, &d->priority, d);
        if (r < 0) {
                d->fd = safe_close(d->fd);
                free(d);
                return r;
        }

        struct epoll_event ev = {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, d->fd, &ev) < 0) {
                r = -errno;
                d->fd = safe_close(d->fd); /* let's close this ourselves, as event_free_inotify_data() would otherwise
                                            * remove the fd from the epoll first, which we don't want as we couldn't
                                            * add it in the first place. */
                event_free_inotify_data(e, d);
                return r;
        }

        if (ret)
                *ret = d;

        return 1;
}

static int inode_data_compare(const struct inode_data *x, const struct inode_data *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->dev, y->dev);
        if (r != 0)
                return r;

        return CMP(x->ino, y->ino);
}

static void inode_data_hash_func(const struct inode_data *d, struct siphash *state) {
        assert(d);

        siphash24_compress(&d->dev, sizeof(d->dev), state);
        siphash24_compress(&d->ino, sizeof(d->ino), state);
}

DEFINE_PRIVATE_HASH_OPS(inode_data_hash_ops, struct inode_data, inode_data_hash_func, inode_data_compare);

static void event_free_inode_data(
                sd_event *e,
                struct inode_data *d) {

        assert(e);

        if (!d)
                return;

        assert(!d->event_sources);

        if (d->fd >= 0) {
                LIST_REMOVE(to_close, e->inode_data_to_close_list, d);
                safe_close(d->fd);
        }

        if (d->inotify_data) {

                if (d->wd >= 0) {
                        if (d->inotify_data->fd >= 0 && !event_origin_changed(e)) {
                                /* So here's a problem. At the time this runs the watch descriptor might already be
                                 * invalidated, because an IN_IGNORED event might be queued right the moment we enter
                                 * the syscall. Hence, whenever we get EINVAL, ignore it entirely, since it's a very
                                 * likely case to happen. */

                                if (inotify_rm_watch(d->inotify_data->fd, d->wd) < 0 && errno != EINVAL)
                                        log_debug_errno(errno, "Failed to remove watch descriptor %i from inotify, ignoring: %m", d->wd);
                        }

                        assert_se(hashmap_remove(d->inotify_data->wd, INT_TO_PTR(d->wd)) == d);
                }

                assert_se(hashmap_remove(d->inotify_data->inodes, d) == d);
        }

        free(d);
}

static void event_gc_inotify_data(
                sd_event *e,
                struct inotify_data *d) {

        assert(e);

        /* GCs the inotify data object if we don't need it anymore. That's the case if we don't want to watch
         * any inode with it anymore, which in turn happens if no event source of this priority is interested
         * in any inode any longer. That said, we maintain an extra busy counter: if non-zero we'll delay GC
         * (under the expectation that the GC is called again once the counter is decremented). */

        if (!d)
                return;

        if (!hashmap_isempty(d->inodes))
                return;

        if (d->n_busy > 0)
                return;

        event_free_inotify_data(e, d);
}

static void event_gc_inode_data(
                sd_event *e,
                struct inode_data *d) {

        struct inotify_data *inotify_data;

        assert(e);

        if (!d)
                return;

        if (d->event_sources)
                return;

        inotify_data = d->inotify_data;
        event_free_inode_data(e, d);

        event_gc_inotify_data(e, inotify_data);
}

static int event_make_inode_data(
                sd_event *e,
                struct inotify_data *inotify_data,
                dev_t dev,
                ino_t ino,
                struct inode_data **ret) {

        struct inode_data *d, key;
        int r;

        assert(e);
        assert(inotify_data);

        key = (struct inode_data) {
                .ino = ino,
                .dev = dev,
        };

        d = hashmap_get(inotify_data->inodes, &key);
        if (d) {
                if (ret)
                        *ret = d;

                return 0;
        }

        r = hashmap_ensure_allocated(&inotify_data->inodes, &inode_data_hash_ops);
        if (r < 0)
                return r;

        d = new(struct inode_data, 1);
        if (!d)
                return -ENOMEM;

        *d = (struct inode_data) {
                .dev = dev,
                .ino = ino,
                .wd = -1,
                .fd = -EBADF,
                .inotify_data = inotify_data,
        };

        r = hashmap_put(inotify_data->inodes, d, d);
        if (r < 0) {
                free(d);
                return r;
        }

        if (ret)
                *ret = d;

        return 1;
}

static uint32_t inode_data_determine_mask(struct inode_data *d) {
        bool excl_unlink = true;
        uint32_t combined = 0;

        assert(d);

        /* Combines the watch masks of all event sources watching this inode. We generally just OR them together, but
         * the IN_EXCL_UNLINK flag is ANDed instead.
         *
         * Note that we add all sources to the mask here, regardless whether enabled, disabled or oneshot. That's
         * because we cannot change the mask anymore after the event source was created once, since the kernel has no
         * API for that. Hence we need to subscribe to the maximum mask we ever might be interested in, and suppress
         * events we don't care for client-side. */

        LIST_FOREACH(inotify.by_inode_data, s, d->event_sources) {

                if ((s->inotify.mask & IN_EXCL_UNLINK) == 0)
                        excl_unlink = false;

                combined |= s->inotify.mask;
        }

        return (combined & ~(IN_ONESHOT|IN_DONT_FOLLOW|IN_ONLYDIR|IN_EXCL_UNLINK)) | (excl_unlink ? IN_EXCL_UNLINK : 0);
}

static int inode_data_realize_watch(sd_event *e, struct inode_data *d) {
        uint32_t combined_mask;
        int wd, r;

        assert(d);
        assert(d->fd >= 0);

        combined_mask = inode_data_determine_mask(d);

        if (d->wd >= 0 && combined_mask == d->combined_mask)
                return 0;

        r = hashmap_ensure_allocated(&d->inotify_data->wd, NULL);
        if (r < 0)
                return r;

        wd = inotify_add_watch_fd(d->inotify_data->fd, d->fd, combined_mask);
        if (wd < 0)
                return -errno;

        if (d->wd < 0) {
                r = hashmap_put(d->inotify_data->wd, INT_TO_PTR(wd), d);
                if (r < 0) {
                        (void) inotify_rm_watch(d->inotify_data->fd, wd);
                        return r;
                }

                d->wd = wd;

        } else if (d->wd != wd) {

                log_debug("Weird, the watch descriptor we already knew for this inode changed?");
                (void) inotify_rm_watch(d->fd, wd);
                return -EINVAL;
        }

        d->combined_mask = combined_mask;
        return 1;
}

static int inotify_exit_callback(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

static int event_add_inotify_fd_internal(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                bool donate,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {

        _cleanup_close_ int donated_fd = donate ? fd : -EBADF;
        _cleanup_(source_freep) sd_event_source *s = NULL;
        struct inotify_data *inotify_data = NULL;
        struct inode_data *inode_data = NULL;
        struct stat st;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(fd >= 0, -EBADF);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!callback)
                callback = inotify_exit_callback;

        /* Refuse IN_MASK_ADD since we coalesce watches on the same inode, and hence really don't want to merge
         * masks. Or in other words, this whole code exists only to manage IN_MASK_ADD type operations for you, hence
         * the user can't use them for us. */
        if (mask & IN_MASK_ADD)
                return -EINVAL;

        if (fstat(fd, &st) < 0)
                return -errno;

        s = source_new(e, !ret, SOURCE_INOTIFY);
        if (!s)
                return -ENOMEM;

        s->enabled = mask & IN_ONESHOT ? SD_EVENT_ONESHOT : SD_EVENT_ON;
        s->inotify.mask = mask;
        s->inotify.callback = callback;
        s->userdata = userdata;

        /* Allocate an inotify object for this priority, and an inode object within it */
        r = event_make_inotify_data(e, SD_EVENT_PRIORITY_NORMAL, &inotify_data);
        if (r < 0)
                return r;

        r = event_make_inode_data(e, inotify_data, st.st_dev, st.st_ino, &inode_data);
        if (r < 0) {
                event_gc_inotify_data(e, inotify_data);
                return r;
        }

        /* Keep the O_PATH fd around until the first iteration of the loop, so that we can still change the priority of
         * the event source, until then, for which we need the original inode. */
        if (inode_data->fd < 0) {
                if (donated_fd >= 0)
                        inode_data->fd = TAKE_FD(donated_fd);
                else {
                        inode_data->fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
                        if (inode_data->fd < 0) {
                                r = -errno;
                                event_gc_inode_data(e, inode_data);
                                return r;
                        }
                }

                LIST_PREPEND(to_close, e->inode_data_to_close_list, inode_data);
        }

        /* Link our event source to the inode data object */
        LIST_PREPEND(inotify.by_inode_data, inode_data->event_sources, s);
        s->inotify.inode_data = inode_data;

        /* Actually realize the watch now */
        r = inode_data_realize_watch(e, inode_data);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
}

_public_ int sd_event_add_inotify_fd(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {

        return event_add_inotify_fd_internal(e, ret, fd, /* donate= */ false, mask, callback, userdata);
}

_public_ int sd_event_add_inotify(
                sd_event *e,
                sd_event_source **ret,
                const char *path,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {

        sd_event_source *s = NULL; /* avoid false maybe-uninitialized warning */
        int fd, r;

        assert_return(path, -EINVAL);

        fd = open(path, O_PATH | O_CLOEXEC |
                        (mask & IN_ONLYDIR ? O_DIRECTORY : 0) |
                        (mask & IN_DONT_FOLLOW ? O_NOFOLLOW : 0));
        if (fd < 0)
                return -errno;

        r = event_add_inotify_fd_internal(e, &s, fd, /* donate= */ true, mask, callback, userdata);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, path);

        if (ret)
                *ret = s;

        return r;
}

static sd_event_source* event_source_free(sd_event_source *s) {
        if (!s)
                return NULL;

        /* Here's a special hack: when we are called from a
         * dispatch handler we won't free the event source
         * immediately, but we will detach the fd from the
         * epoll. This way it is safe for the caller to unref
         * the event source and immediately close the fd, but
         * we still retain a valid event source object after
         * the callback. */

        if (s->dispatching)
                source_disconnect(s);
        else
                source_free(s);

        return NULL;
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_event_source, sd_event_source, event_source_free);

_public_ int sd_event_source_set_description(sd_event_source *s, const char *description) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return free_and_strdup(&s->description, description);
}

_public_ int sd_event_source_get_description(sd_event_source *s, const char **description) {
        assert_return(s, -EINVAL);
        assert_return(description, -EINVAL);

        if (!s->description)
                return -ENXIO;

        *description = s->description;
        return 0;
}

_public_ sd_event *sd_event_source_get_event(sd_event_source *s) {
        assert_return(s, NULL);
        assert_return(!event_origin_changed(s->event), NULL);

        return s->event;
}

_public_ int sd_event_source_get_pending(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->pending;
}

_public_ int sd_event_source_get_io_fd(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->io.fd;
}

_public_ int sd_event_source_set_io_fd(sd_event_source *s, int fd) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->io.fd == fd)
                return 0;

        if (event_source_is_offline(s)) {
                s->io.fd = fd;
                s->io.registered = false;
        } else {
                int saved_fd;

                saved_fd = s->io.fd;
                assert(s->io.registered);

                s->io.fd = fd;
                s->io.registered = false;

                r = source_io_register(s, s->enabled, s->io.events);
                if (r < 0) {
                        s->io.fd = saved_fd;
                        s->io.registered = true;
                        return r;
                }

                (void) epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, saved_fd, NULL);
        }

        return 0;
}

_public_ int sd_event_source_get_io_fd_own(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->io.owned;
}

_public_ int sd_event_source_set_io_fd_own(sd_event_source *s, int own) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        s->io.owned = own;
        return 0;
}

_public_ int sd_event_source_get_io_events(sd_event_source *s, uint32_t* events) {
        assert_return(s, -EINVAL);
        assert_return(events, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *events = s->io.events;
        return 0;
}

_public_ int sd_event_source_set_io_events(sd_event_source *s, uint32_t events) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!(events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP|EPOLLET)), -EINVAL);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        /* edge-triggered updates are never skipped, so we can reset edges */
        if (s->io.events == events && !(events & EPOLLET))
                return 0;

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        if (event_source_is_online(s)) {
                r = source_io_register(s, s->enabled, events);
                if (r < 0)
                        return r;
        }

        s->io.events = events;

        return 0;
}

_public_ int sd_event_source_get_io_revents(sd_event_source *s, uint32_t* revents) {
        assert_return(s, -EINVAL);
        assert_return(revents, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(s->pending, -ENODATA);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *revents = s->io.revents;
        return 0;
}

_public_ int sd_event_source_get_signal(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_SIGNAL, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->signal.sig;
}

_public_ int sd_event_source_get_priority(sd_event_source *s, int64_t *priority) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *priority = s->priority;
        return 0;
}

_public_ int sd_event_source_set_priority(sd_event_source *s, int64_t priority) {
        bool rm_inotify = false, rm_inode = false;
        struct inotify_data *new_inotify_data = NULL;
        struct inode_data *new_inode_data = NULL;
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->priority == priority)
                return 0;

        if (s->type == SOURCE_INOTIFY) {
                struct inode_data *old_inode_data;

                assert(s->inotify.inode_data);
                old_inode_data = s->inotify.inode_data;

                /* We need the original fd to change the priority. If we don't have it we can't change the priority,
                 * anymore. Note that we close any fds when entering the next event loop iteration, i.e. for inotify
                 * events we allow priority changes only until the first following iteration. */
                if (old_inode_data->fd < 0)
                        return -EOPNOTSUPP;

                r = event_make_inotify_data(s->event, priority, &new_inotify_data);
                if (r < 0)
                        return r;
                rm_inotify = r > 0;

                r = event_make_inode_data(s->event, new_inotify_data, old_inode_data->dev, old_inode_data->ino, &new_inode_data);
                if (r < 0)
                        goto fail;
                rm_inode = r > 0;

                if (new_inode_data->fd < 0) {
                        /* Duplicate the fd for the new inode object if we don't have any yet */
                        new_inode_data->fd = fcntl(old_inode_data->fd, F_DUPFD_CLOEXEC, 3);
                        if (new_inode_data->fd < 0) {
                                r = -errno;
                                goto fail;
                        }

                        LIST_PREPEND(to_close, s->event->inode_data_to_close_list, new_inode_data);
                }

                /* Move the event source to the new inode data structure */
                LIST_REMOVE(inotify.by_inode_data, old_inode_data->event_sources, s);
                LIST_PREPEND(inotify.by_inode_data, new_inode_data->event_sources, s);
                s->inotify.inode_data = new_inode_data;

                /* Now create the new watch */
                r = inode_data_realize_watch(s->event, new_inode_data);
                if (r < 0) {
                        /* Move it back */
                        LIST_REMOVE(inotify.by_inode_data, new_inode_data->event_sources, s);
                        LIST_PREPEND(inotify.by_inode_data, old_inode_data->event_sources, s);
                        s->inotify.inode_data = old_inode_data;
                        goto fail;
                }

                s->priority = priority;

                event_gc_inode_data(s->event, old_inode_data);

        } else if (s->type == SOURCE_SIGNAL && event_source_is_online(s)) {
                struct signal_data *old, *d;

                /* Move us from the signalfd belonging to the old
                 * priority to the signalfd of the new priority */

                assert_se(old = hashmap_get(s->event->signal_data, &s->priority));

                s->priority = priority;

                r = event_make_signal_data(s->event, s->signal.sig, &d);
                if (r < 0) {
                        s->priority = old->priority;
                        return r;
                }

                event_unmask_signal_data(s->event, old, s->signal.sig);
        } else
                s->priority = priority;

        event_source_pp_prioq_reshuffle(s);

        if (s->type == SOURCE_EXIT)
                prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);

        return 0;

fail:
        if (rm_inode)
                event_free_inode_data(s->event, new_inode_data);

        if (rm_inotify)
                event_free_inotify_data(s->event, new_inotify_data);

        return r;
}

_public_ int sd_event_source_get_enabled(sd_event_source *s, int *ret) {
        /* Quick mode: the event source doesn't exist and we only want to query boolean enablement state. */
        if (!s && !ret)
                return false;

        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (ret)
                *ret = s->enabled;

        return s->enabled != SD_EVENT_OFF;
}

static int event_source_offline(
                sd_event_source *s,
                int enabled,
                bool ratelimited) {

        bool was_offline;
        int r;

        assert(s);
        assert(enabled == SD_EVENT_OFF || ratelimited);

        /* Unset the pending flag when this event source is disabled */
        if (s->enabled != SD_EVENT_OFF &&
            enabled == SD_EVENT_OFF &&
            !IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        was_offline = event_source_is_offline(s);
        s->enabled = enabled;
        s->ratelimited = ratelimited;

        switch (s->type) {

        case SOURCE_IO:
                source_io_unregister(s);
                break;

        case SOURCE_SIGNAL:
                event_gc_signal_data(s->event, &s->priority, s->signal.sig);
                break;

        case SOURCE_CHILD:
                if (!was_offline) {
                        assert(s->event->n_online_child_sources > 0);
                        s->event->n_online_child_sources--;
                }

                if (EVENT_SOURCE_WATCH_PIDFD(s))
                        source_child_pidfd_unregister(s);
                else
                        event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                break;

        case SOURCE_EXIT:
                prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);
                break;

        case SOURCE_MEMORY_PRESSURE:
                source_memory_pressure_unregister(s);
                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
        case SOURCE_DEFER:
        case SOURCE_POST:
        case SOURCE_INOTIFY:
                break;

        default:
                assert_not_reached();
        }

        /* Always reshuffle time prioq, as the ratelimited flag may be changed. */
        event_source_time_prioq_reshuffle(s);

        return 1;
}

static int event_source_online(
                sd_event_source *s,
                int enabled,
                bool ratelimited) {

        bool was_online;
        int r;

        assert(s);
        assert(enabled != SD_EVENT_OFF || !ratelimited);

        /* Unset the pending flag when this event source is enabled */
        if (s->enabled == SD_EVENT_OFF &&
            enabled != SD_EVENT_OFF &&
            !IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        /* Are we really ready for onlining? */
        if (enabled == SD_EVENT_OFF || ratelimited) {
                /* Nope, we are not ready for onlining, then just update the precise state and exit */
                s->enabled = enabled;
                s->ratelimited = ratelimited;
                return 0;
        }

        was_online = event_source_is_online(s);

        switch (s->type) {
        case SOURCE_IO:
                r = source_io_register(s, enabled, s->io.events);
                if (r < 0)
                        return r;
                break;

        case SOURCE_SIGNAL:
                r = event_make_signal_data(s->event, s->signal.sig, NULL);
                if (r < 0) {
                        event_gc_signal_data(s->event, &s->priority, s->signal.sig);
                        return r;
                }

                break;

        case SOURCE_CHILD:
                if (EVENT_SOURCE_WATCH_PIDFD(s)) {
                        /* yes, we have pidfd */

                        r = source_child_pidfd_register(s, enabled);
                        if (r < 0)
                                return r;
                } else {
                        /* no pidfd, or something other to watch for than WEXITED */

                        r = event_make_signal_data(s->event, SIGCHLD, NULL);
                        if (r < 0) {
                                event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                                return r;
                        }
                }

                if (!was_online)
                        s->event->n_online_child_sources++;
                break;

        case SOURCE_MEMORY_PRESSURE:
                r = source_memory_pressure_register(s, enabled);
                if (r < 0)
                        return r;

                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
        case SOURCE_EXIT:
        case SOURCE_DEFER:
        case SOURCE_POST:
        case SOURCE_INOTIFY:
                break;

        default:
                assert_not_reached();
        }

        s->enabled = enabled;
        s->ratelimited = ratelimited;

        /* Non-failing operations below */
        if (s->type == SOURCE_EXIT)
                prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);

        /* Always reshuffle time prioq, as the ratelimited flag may be changed. */
        event_source_time_prioq_reshuffle(s);

        return 1;
}

_public_ int sd_event_source_set_enabled(sd_event_source *s, int m) {
        int r;

        assert_return(IN_SET(m, SD_EVENT_OFF, SD_EVENT_ON, SD_EVENT_ONESHOT), -EINVAL);

        /* Quick mode: if the source doesn't exist, SD_EVENT_OFF is a noop. */
        if (m == SD_EVENT_OFF && !s)
                return 0;

        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        /* If we are dead anyway, we are fine with turning off sources, but everything else needs to fail. */
        if (s->event->state == SD_EVENT_FINISHED)
                return m == SD_EVENT_OFF ? 0 : -ESTALE;

        if (s->enabled == m) /* No change? */
                return 0;

        if (m == SD_EVENT_OFF)
                r = event_source_offline(s, m, s->ratelimited);
        else {
                if (s->enabled != SD_EVENT_OFF) {
                        /* Switching from "on" to "oneshot" or back? If that's the case, we can take a shortcut, the
                         * event source is already enabled after all. */
                        s->enabled = m;
                        return 0;
                }

                r = event_source_online(s, m, s->ratelimited);
        }
        if (r < 0)
                return r;

        event_source_pp_prioq_reshuffle(s);
        return 0;
}

_public_ int sd_event_source_get_time(sd_event_source *s, uint64_t *usec) {
        assert_return(s, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *usec = s->time.next;
        return 0;
}

_public_ int sd_event_source_set_time(sd_event_source *s, uint64_t usec) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        s->time.next = usec;

        event_source_time_prioq_reshuffle(s);
        return 0;
}

_public_ int sd_event_source_set_time_relative(sd_event_source *s, uint64_t usec) {
        usec_t t;
        int r;

        assert_return(s, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (usec == USEC_INFINITY)
                return sd_event_source_set_time(s, USEC_INFINITY);

        r = sd_event_now(s->event, event_source_type_to_clock(s->type), &t);
        if (r < 0)
                return r;

        usec = usec_add(t, usec);
        if (usec == USEC_INFINITY)
                return -EOVERFLOW;

        return sd_event_source_set_time(s, usec);
}

_public_ int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec) {
        assert_return(s, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *usec = s->time.accuracy;
        return 0;
}

_public_ int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(usec != UINT64_MAX, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        if (usec == 0)
                usec = DEFAULT_ACCURACY_USEC;

        s->time.accuracy = usec;

        event_source_time_prioq_reshuffle(s);
        return 0;
}

_public_ int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *clock) {
        assert_return(s, -EINVAL);
        assert_return(clock, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *clock = event_source_type_to_clock(s->type);
        return 0;
}

_public_ int sd_event_source_get_child_pid(sd_event_source *s, pid_t *pid) {
        assert_return(s, -EINVAL);
        assert_return(pid, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *pid = s->child.pid;
        return 0;
}

_public_ int sd_event_source_get_child_pidfd(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->child.pidfd < 0)
                return -EOPNOTSUPP;

        return s->child.pidfd;
}

_public_ int sd_event_source_send_child_signal(sd_event_source *s, int sig, const siginfo_t *si, unsigned flags) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);
        assert_return(SIGNAL_VALID(sig), -EINVAL);

        /* If we already have seen indication the process exited refuse sending a signal early. This way we
         * can be sure we don't accidentally kill the wrong process on PID reuse when pidfds are not
         * available. */
        if (s->child.exited)
                return -ESRCH;

        if (s->child.pidfd >= 0) {
                siginfo_t copy;

                /* pidfd_send_signal() changes the siginfo_t argument. This is weird, let's hence copy the
                 * structure here */
                if (si)
                        copy = *si;

                if (pidfd_send_signal(s->child.pidfd, sig, si ? &copy : NULL, 0) < 0) {
                        /* Let's propagate the error only if the system call is not implemented or prohibited */
                        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                                return -errno;
                } else
                        return 0;
        }

        /* Flags are only supported for pidfd_send_signal(), not for rt_sigqueueinfo(), hence let's refuse
         * this here. */
        if (flags != 0)
                return -EOPNOTSUPP;

        if (si) {
                /* We use rt_sigqueueinfo() only if siginfo_t is specified. */
                siginfo_t copy = *si;

                if (rt_sigqueueinfo(s->child.pid, sig, &copy) < 0)
                        return -errno;
        } else if (kill(s->child.pid, sig) < 0)
                return -errno;

        return 0;
}

_public_ int sd_event_source_get_child_pidfd_own(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->child.pidfd < 0)
                return -EOPNOTSUPP;

        return s->child.pidfd_owned;
}

_public_ int sd_event_source_set_child_pidfd_own(sd_event_source *s, int own) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->child.pidfd < 0)
                return -EOPNOTSUPP;

        s->child.pidfd_owned = own;
        return 0;
}

_public_ int sd_event_source_get_child_process_own(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->child.process_owned;
}

_public_ int sd_event_source_set_child_process_own(sd_event_source *s, int own) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        s->child.process_owned = own;
        return 0;
}

_public_ int sd_event_source_get_inotify_mask(sd_event_source *s, uint32_t *mask) {
        assert_return(s, -EINVAL);
        assert_return(mask, -EINVAL);
        assert_return(s->type == SOURCE_INOTIFY, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        *mask = s->inotify.mask;
        return 0;
}

_public_ int sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->prepare == callback)
                return 0;

        if (callback && s->prepare) {
                s->prepare = callback;
                return 0;
        }

        r = prioq_ensure_allocated(&s->event->prepare, prepare_prioq_compare);
        if (r < 0)
                return r;

        s->prepare = callback;

        if (callback) {
                r = prioq_put(s->event->prepare, s, &s->prepare_index);
                if (r < 0)
                        return r;
        } else
                prioq_remove(s->event->prepare, s, &s->prepare_index);

        return 0;
}

_public_ void* sd_event_source_get_userdata(sd_event_source *s) {
        assert_return(s, NULL);
        assert_return(!event_origin_changed(s->event), NULL);

        return s->userdata;
}

_public_ void *sd_event_source_set_userdata(sd_event_source *s, void *userdata) {
        void *ret;

        assert_return(s, NULL);
        assert_return(!event_origin_changed(s->event), NULL);

        ret = s->userdata;
        s->userdata = userdata;

        return ret;
}

static int event_source_enter_ratelimited(sd_event_source *s) {
        int r;

        assert(s);

        /* When an event source becomes ratelimited, we place it in the CLOCK_MONOTONIC priority queue, with
         * the end of the rate limit time window, much as if it was a timer event source. */

        if (s->ratelimited)
                return 0; /* Already ratelimited, this is a NOP hence */

        /* Make sure we can install a CLOCK_MONOTONIC event further down. */
        r = setup_clock_data(s->event, &s->event->monotonic, CLOCK_MONOTONIC);
        if (r < 0)
                return r;

        /* Timer event sources are already using the earliest/latest queues for the timer scheduling. Let's
         * first remove them from the prioq appropriate for their own clock, so that we can use the prioq
         * fields of the event source then for adding it to the CLOCK_MONOTONIC prioq instead. */
        if (EVENT_SOURCE_IS_TIME(s->type))
                event_source_time_prioq_remove(s, event_get_clock_data(s->event, s->type));

        /* Now, let's add the event source to the monotonic clock instead */
        r = event_source_time_prioq_put(s, &s->event->monotonic);
        if (r < 0)
                goto fail;

        /* And let's take the event source officially offline */
        r = event_source_offline(s, s->enabled, /* ratelimited= */ true);
        if (r < 0) {
                event_source_time_prioq_remove(s, &s->event->monotonic);
                goto fail;
        }

        event_source_pp_prioq_reshuffle(s);

        log_debug("Event source %p (%s) entered rate limit state.", s, strna(s->description));
        return 0;

fail:
        /* Reinstall time event sources in the priority queue as before. This shouldn't fail, since the queue
         * space for it should already be allocated. */
        if (EVENT_SOURCE_IS_TIME(s->type))
                assert_se(event_source_time_prioq_put(s, event_get_clock_data(s->event, s->type)) >= 0);

        return r;
}

static int event_source_leave_ratelimit(sd_event_source *s, bool run_callback) {
        int r;

        assert(s);

        if (!s->ratelimited)
                return 0;

        /* Let's take the event source out of the monotonic prioq first. */
        event_source_time_prioq_remove(s, &s->event->monotonic);

        /* Let's then add the event source to its native clock prioq again — if this is a timer event source */
        if (EVENT_SOURCE_IS_TIME(s->type)) {
                r = event_source_time_prioq_put(s, event_get_clock_data(s->event, s->type));
                if (r < 0)
                        goto fail;
        }

        /* Let's try to take it online again.  */
        r = event_source_online(s, s->enabled, /* ratelimited= */ false);
        if (r < 0) {
                /* Do something roughly sensible when this failed: undo the two prioq ops above */
                if (EVENT_SOURCE_IS_TIME(s->type))
                        event_source_time_prioq_remove(s, event_get_clock_data(s->event, s->type));

                goto fail;
        }

        event_source_pp_prioq_reshuffle(s);
        ratelimit_reset(&s->rate_limit);

        log_debug("Event source %p (%s) left rate limit state.", s, strna(s->description));

        if (run_callback && s->ratelimit_expire_callback) {
                s->dispatching = true;
                r = s->ratelimit_expire_callback(s, s->userdata);
                s->dispatching = false;

                if (r < 0) {
                        log_debug_errno(r, "Ratelimit expiry callback of event source %s (type %s) returned error, %s: %m",
                                        strna(s->description),
                                        event_source_type_to_string(s->type),
                                        s->exit_on_failure ? "exiting" : "disabling");

                        if (s->exit_on_failure)
                                (void) sd_event_exit(s->event, r);
                }

                if (s->n_ref == 0)
                        source_free(s);
                else if (r < 0)
                        assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);

                return 1;
        }

        return 0;

fail:
        /* Do something somewhat reasonable when we cannot move an event sources out of ratelimited mode:
         * simply put it back in it, maybe we can then process it more successfully next iteration. */
        assert_se(event_source_time_prioq_put(s, &s->event->monotonic) >= 0);

        return r;
}

static usec_t sleep_between(sd_event *e, usec_t a, usec_t b) {
        usec_t c;
        assert(e);
        assert(a <= b);

        if (a <= 0)
                return 0;
        if (a >= USEC_INFINITY)
                return USEC_INFINITY;

        if (b <= a + 1)
                return a;

        initialize_perturb(e);

        /*
          Find a good time to wake up again between times a and b. We
          have two goals here:

          a) We want to wake up as seldom as possible, hence prefer
             later times over earlier times.

          b) But if we have to wake up, then let's make sure to
             dispatch as much as possible on the entire system.

          We implement this by waking up everywhere at the same time
          within any given minute if we can, synchronised via the
          perturbation value determined from the boot ID. If we can't,
          then we try to find the same spot in every 10s, then 1s and
          then 250ms step. Otherwise, we pick the last possible time
          to wake up.
        */

        c = (b / USEC_PER_MINUTE) * USEC_PER_MINUTE + e->perturb;
        if (c >= b) {
                if (_unlikely_(c < USEC_PER_MINUTE))
                        return b;

                c -= USEC_PER_MINUTE;
        }

        if (c >= a)
                return c;

        c = (b / (USEC_PER_SEC*10)) * (USEC_PER_SEC*10) + (e->perturb % (USEC_PER_SEC*10));
        if (c >= b) {
                if (_unlikely_(c < USEC_PER_SEC*10))
                        return b;

                c -= USEC_PER_SEC*10;
        }

        if (c >= a)
                return c;

        c = (b / USEC_PER_SEC) * USEC_PER_SEC + (e->perturb % USEC_PER_SEC);
        if (c >= b) {
                if (_unlikely_(c < USEC_PER_SEC))
                        return b;

                c -= USEC_PER_SEC;
        }

        if (c >= a)
                return c;

        c = (b / (USEC_PER_MSEC*250)) * (USEC_PER_MSEC*250) + (e->perturb % (USEC_PER_MSEC*250));
        if (c >= b) {
                if (_unlikely_(c < USEC_PER_MSEC*250))
                        return b;

                c -= USEC_PER_MSEC*250;
        }

        if (c >= a)
                return c;

        return b;
}

static int event_arm_timer(
                sd_event *e,
                struct clock_data *d) {

        struct itimerspec its = {};
        sd_event_source *a, *b;
        usec_t t;

        assert(e);
        assert(d);

        if (!d->needs_rearm)
                return 0;

        d->needs_rearm = false;

        a = prioq_peek(d->earliest);
        assert(!a || EVENT_SOURCE_USES_TIME_PRIOQ(a->type));
        if (!a || a->enabled == SD_EVENT_OFF || time_event_source_next(a) == USEC_INFINITY) {

                if (d->fd < 0)
                        return 0;

                if (d->next == USEC_INFINITY)
                        return 0;

                /* disarm */
                if (timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
                        return -errno;

                d->next = USEC_INFINITY;
                return 0;
        }

        b = prioq_peek(d->latest);
        assert(!b || EVENT_SOURCE_USES_TIME_PRIOQ(b->type));
        assert(b && b->enabled != SD_EVENT_OFF);

        t = sleep_between(e, time_event_source_next(a), time_event_source_latest(b));
        if (d->next == t)
                return 0;

        assert_se(d->fd >= 0);

        if (t == 0) {
                /* We don't want to disarm here, just mean some time looooong ago. */
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;
        } else
                timespec_store(&its.it_value, t);

        if (timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL) < 0)
                return -errno;

        d->next = t;
        return 0;
}

static int process_io(sd_event *e, sd_event_source *s, uint32_t revents) {
        assert(e);
        assert(s);
        assert(s->type == SOURCE_IO);

        /* If the event source was already pending, we just OR in the
         * new revents, otherwise we reset the value. The ORing is
         * necessary to handle EPOLLONESHOT events properly where
         * readability might happen independently of writability, and
         * we need to keep track of both */

        if (s->pending)
                s->io.revents |= revents;
        else
                s->io.revents = revents;

        return source_set_pending(s, true);
}

static int flush_timer(sd_event *e, int fd, uint32_t events, usec_t *next) {
        uint64_t x;
        ssize_t ss;

        assert(e);
        assert(fd >= 0);

        assert_return(events == EPOLLIN, -EIO);

        ss = read(fd, &x, sizeof(x));
        if (ss < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return -errno;
        }

        if (_unlikely_(ss != sizeof(x)))
                return -EIO;

        if (next)
                *next = USEC_INFINITY;

        return 0;
}

static int process_timer(
                sd_event *e,
                usec_t n,
                struct clock_data *d) {

        sd_event_source *s;
        bool callback_invoked = false;
        int r;

        assert(e);
        assert(d);

        for (;;) {
                s = prioq_peek(d->earliest);
                assert(!s || EVENT_SOURCE_USES_TIME_PRIOQ(s->type));

                if (!s || time_event_source_next(s) > n)
                        break;

                if (s->ratelimited) {
                        /* This is an event sources whose ratelimit window has ended. Let's turn it on
                         * again. */
                        assert(s->ratelimited);

                        r = event_source_leave_ratelimit(s, /* run_callback */ true);
                        if (r < 0)
                                return r;
                        else if (r == 1)
                                callback_invoked = true;

                        continue;
                }

                if (s->enabled == SD_EVENT_OFF || s->pending)
                        break;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;

                event_source_time_prioq_reshuffle(s);
        }

        return callback_invoked;
}

static int process_child(sd_event *e, int64_t threshold, int64_t *ret_min_priority) {
        int64_t min_priority = threshold;
        bool something_new = false;
        sd_event_source *s;
        int r;

        assert(e);
        assert(ret_min_priority);

        if (!e->need_process_child) {
                *ret_min_priority = min_priority;
                return 0;
        }

        e->need_process_child = false;

        /* So, this is ugly. We iteratively invoke waitid() with P_PID + WNOHANG for each PID we wait
         * for, instead of using P_ALL. This is because we only want to get child information of very
         * specific child processes, and not all of them. We might not have processed the SIGCHLD event
         * of a previous invocation and we don't want to maintain a unbounded *per-child* event queue,
         * hence we really don't want anything flushed out of the kernel's queue that we don't care
         * about. Since this is O(n) this means that if you have a lot of processes you probably want
         * to handle SIGCHLD yourself.
         *
         * We do not reap the children here (by using WNOWAIT), this is only done after the event
         * source is dispatched so that the callback still sees the process as a zombie. */

        HASHMAP_FOREACH(s, e->child_sources) {
                assert(s->type == SOURCE_CHILD);

                if (s->priority > threshold)
                        continue;

                if (s->pending)
                        continue;

                if (event_source_is_offline(s))
                        continue;

                if (s->child.exited)
                        continue;

                if (EVENT_SOURCE_WATCH_PIDFD(s))
                        /* There's a usable pidfd known for this event source? Then don't waitid() for
                         * it here */
                        continue;

                zero(s->child.siginfo);
                if (waitid(P_PID, s->child.pid, &s->child.siginfo,
                           WNOHANG | (s->child.options & WEXITED ? WNOWAIT : 0) | s->child.options) < 0)
                        return negative_errno();

                if (s->child.siginfo.si_pid != 0) {
                        bool zombie = IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED);

                        if (zombie)
                                s->child.exited = true;

                        if (!zombie && (s->child.options & WEXITED)) {
                                /* If the child isn't dead then let's immediately remove the state
                                 * change from the queue, since there's no benefit in leaving it
                                 * queued. */

                                assert(s->child.options & (WSTOPPED|WCONTINUED));
                                (void) waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|(s->child.options & (WSTOPPED|WCONTINUED)));
                        }

                        r = source_set_pending(s, true);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                something_new = true;
                                min_priority = MIN(min_priority, s->priority);
                        }
                }
        }

        *ret_min_priority = min_priority;
        return something_new;
}

static int process_pidfd(sd_event *e, sd_event_source *s, uint32_t revents) {
        assert(e);
        assert(s);
        assert(s->type == SOURCE_CHILD);

        if (s->pending)
                return 0;

        if (event_source_is_offline(s))
                return 0;

        if (!EVENT_SOURCE_WATCH_PIDFD(s))
                return 0;

        zero(s->child.siginfo);
        if (waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG | WNOWAIT | s->child.options) < 0)
                return -errno;

        if (s->child.siginfo.si_pid == 0)
                return 0;

        if (IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED))
                s->child.exited = true;

        return source_set_pending(s, true);
}

static int process_signal(sd_event *e, struct signal_data *d, uint32_t events, int64_t *min_priority) {
        int r;

        assert(e);
        assert(d);
        assert_return(events == EPOLLIN, -EIO);
        assert(min_priority);

        /* If there's a signal queued on this priority and SIGCHLD is on this priority too, then make
         * sure to recheck the children we watch. This is because we only ever dequeue the first signal
         * per priority, and if we dequeue one, and SIGCHLD might be enqueued later we wouldn't know,
         * but we might have higher priority children we care about hence we need to check that
         * explicitly. */

        if (sigismember(&d->sigset, SIGCHLD))
                e->need_process_child = true;

        /* If there's already an event source pending for this priority we don't read another */
        if (d->current)
                return 0;

        for (;;) {
                struct signalfd_siginfo si;
                ssize_t n;
                sd_event_source *s = NULL;

                n = read(d->fd, &si, sizeof(si));
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                return 0;

                        return -errno;
                }

                if (_unlikely_(n != sizeof(si)))
                        return -EIO;

                assert(SIGNAL_VALID(si.ssi_signo));

                if (e->signal_sources)
                        s = e->signal_sources[si.ssi_signo];
                if (!s)
                        continue;
                if (s->pending)
                        continue;

                s->signal.siginfo = si;
                d->current = s;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;
                if (r > 0 && *min_priority >= s->priority) {
                        *min_priority = s->priority;
                        return 1; /* an event source with smaller priority is queued. */
                }

                return 0;
        }
}

static int event_inotify_data_read(sd_event *e, struct inotify_data *d, uint32_t revents, int64_t threshold) {
        ssize_t n;

        assert(e);
        assert(d);

        assert_return(revents == EPOLLIN, -EIO);

        /* If there's already an event source pending for this priority, don't read another */
        if (d->n_pending > 0)
                return 0;

        /* Is the read buffer non-empty? If so, let's not read more */
        if (d->buffer_filled > 0)
                return 0;

        if (d->priority > threshold)
                return 0;

        n = read(d->fd, &d->buffer, sizeof(d->buffer));
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return -errno;
        }

        assert(n > 0);
        d->buffer_filled = (size_t) n;
        LIST_PREPEND(buffered, e->buffered_inotify_data_list, d);

        return 1;
}

static void event_inotify_data_drop(sd_event *e, struct inotify_data *d, size_t sz) {
        assert(e);
        assert(d);
        assert(sz <= d->buffer_filled);

        if (sz == 0)
                return;

        /* Move the rest to the buffer to the front, in order to get things properly aligned again */
        memmove(d->buffer.raw, d->buffer.raw + sz, d->buffer_filled - sz);
        d->buffer_filled -= sz;

        if (d->buffer_filled == 0)
                LIST_REMOVE(buffered, e->buffered_inotify_data_list, d);
}

static int event_inotify_data_process(sd_event *e, struct inotify_data *d) {
        int r;

        assert(e);
        assert(d);

        /* If there's already an event source pending for this priority, don't read another */
        if (d->n_pending > 0)
                return 0;

        while (d->buffer_filled > 0) {
                size_t sz;

                /* Let's validate that the event structures are complete */
                if (d->buffer_filled < offsetof(struct inotify_event, name))
                        return -EIO;

                sz = offsetof(struct inotify_event, name) + d->buffer.ev.len;
                if (d->buffer_filled < sz)
                        return -EIO;

                if (d->buffer.ev.mask & IN_Q_OVERFLOW) {
                        struct inode_data *inode_data;

                        /* The queue overran, let's pass this event to all event sources connected to this inotify
                         * object */

                        HASHMAP_FOREACH(inode_data, d->inodes)
                                LIST_FOREACH(inotify.by_inode_data, s, inode_data->event_sources) {

                                        if (event_source_is_offline(s))
                                                continue;

                                        r = source_set_pending(s, true);
                                        if (r < 0)
                                                return r;
                                }
                } else {
                        struct inode_data *inode_data;

                        /* Find the inode object for this watch descriptor. If IN_IGNORED is set we also remove it from
                         * our watch descriptor table. */
                        if (d->buffer.ev.mask & IN_IGNORED) {

                                inode_data = hashmap_remove(d->wd, INT_TO_PTR(d->buffer.ev.wd));
                                if (!inode_data) {
                                        event_inotify_data_drop(e, d, sz);
                                        continue;
                                }

                                /* The watch descriptor was removed by the kernel, let's drop it here too */
                                inode_data->wd = -1;
                        } else {
                                inode_data = hashmap_get(d->wd, INT_TO_PTR(d->buffer.ev.wd));
                                if (!inode_data) {
                                        event_inotify_data_drop(e, d, sz);
                                        continue;
                                }
                        }

                        /* Trigger all event sources that are interested in these events. Also trigger all event
                         * sources if IN_IGNORED or IN_UNMOUNT is set. */
                        LIST_FOREACH(inotify.by_inode_data, s, inode_data->event_sources) {

                                if (event_source_is_offline(s))
                                        continue;

                                if ((d->buffer.ev.mask & (IN_IGNORED|IN_UNMOUNT)) == 0 &&
                                    (s->inotify.mask & d->buffer.ev.mask & IN_ALL_EVENTS) == 0)
                                        continue;

                                r = source_set_pending(s, true);
                                if (r < 0)
                                        return r;
                        }
                }

                /* Something pending now? If so, let's finish, otherwise let's read more. */
                if (d->n_pending > 0)
                        return 1;
        }

        return 0;
}

static int process_inotify(sd_event *e) {
        int r, done = 0;

        assert(e);

        LIST_FOREACH(buffered, d, e->buffered_inotify_data_list) {
                r = event_inotify_data_process(e, d);
                if (r < 0)
                        return r;
                if (r > 0)
                        done++;
        }

        return done;
}

static int process_memory_pressure(sd_event_source *s, uint32_t revents) {
        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        if (s->pending)
                s->memory_pressure.revents |= revents;
        else
                s->memory_pressure.revents = revents;

        return source_set_pending(s, true);
}

static int source_memory_pressure_write(sd_event_source *s) {
        ssize_t n;
        int r;

        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        /* once we start writing, the buffer is locked, we allow no further changes. */
        s->memory_pressure.locked = true;

        if (s->memory_pressure.write_buffer_size > 0) {
                n = write(s->memory_pressure.fd, s->memory_pressure.write_buffer, s->memory_pressure.write_buffer_size);
                if (n < 0) {
                        if (!ERRNO_IS_TRANSIENT(errno)) {
                                /* If kernel is built with CONFIG_PSI_DEFAULT_DISABLED it will expose PSI
                                 * files, but then generates EOPNOSUPP on read() and write() (instead of on
                                 * open()!). This sucks hard, since we can only detect this kind of failure
                                 * so late. Let's make the best of it, and turn off the event source like we
                                 * do for failed event source handlers. */

                                log_debug_errno(errno, "Writing memory pressure settings to kernel failed, disabling memory pressure event source: %m");
                                assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);
                                return 0;
                        }

                        n = 0;
                }
        } else
                n = 0;

        assert(n >= 0);

        if ((size_t) n == s->memory_pressure.write_buffer_size) {
                s->memory_pressure.write_buffer = mfree(s->memory_pressure.write_buffer);

                if (n > 0) {
                        s->memory_pressure.write_buffer_size = 0;

                        /* Update epoll events mask, since we have now written everything and don't care for EPOLLOUT anymore */
                        r = source_memory_pressure_register(s, s->enabled);
                        if (r < 0)
                                return r;
                }
        } else if (n > 0) {
                _cleanup_free_ void *c = NULL;

                assert((size_t) n < s->memory_pressure.write_buffer_size);

                c = memdup((uint8_t*) s->memory_pressure.write_buffer + n, s->memory_pressure.write_buffer_size - n);
                if (!c)
                        return -ENOMEM;

                free_and_replace(s->memory_pressure.write_buffer, c);
                s->memory_pressure.write_buffer_size -= n;
                return 1;
        }

        return 0;
}

static int source_memory_pressure_initiate_dispatch(sd_event_source *s) {
        int r;

        assert(s);
        assert(s->type == SOURCE_MEMORY_PRESSURE);

        r = source_memory_pressure_write(s);
        if (r < 0)
                return r;
        if (r > 0)
                return 1; /* if we wrote something, then don't continue with dispatching user dispatch
                           * function. Instead, shortcut it so that we wait for next EPOLLOUT immediately. */

        /* No pending incoming IO? Then let's not continue further */
        if ((s->memory_pressure.revents & (EPOLLIN|EPOLLPRI)) == 0) {

                /* Treat IO errors on the notifier the same ways errors returned from a callback */
                if ((s->memory_pressure.revents & (EPOLLHUP|EPOLLERR|EPOLLRDHUP)) != 0)
                        return -EIO;

                return 1; /* leave dispatch, we already processed everything */
        }

        if (s->memory_pressure.revents & EPOLLIN) {
                uint8_t pipe_buf[PIPE_BUF];
                ssize_t n;

                /* If the fd is readable, then flush out anything that might be queued */

                n = read(s->memory_pressure.fd, pipe_buf, sizeof(pipe_buf));
                if (n < 0 && !ERRNO_IS_TRANSIENT(errno))
                        return -errno;
        }

        return 0; /* go on, dispatch to user callback */
}

static int source_dispatch(sd_event_source *s) {
        EventSourceType saved_type;
        sd_event *saved_event;
        int r = 0;

        assert(s);
        assert(s->pending || s->type == SOURCE_EXIT);

        /* Save the event source type, here, so that we still know it after the event callback which might
         * invalidate the event. */
        saved_type = s->type;

        /* Similarly, store a reference to the event loop object, so that we can still access it after the
         * callback might have invalidated/disconnected the event source. */
        saved_event = s->event;
        PROTECT_EVENT(saved_event);

        /* Check if we hit the ratelimit for this event source, and if so, let's disable it. */
        assert(!s->ratelimited);
        if (!ratelimit_below(&s->rate_limit)) {
                r = event_source_enter_ratelimited(s);
                if (r < 0)
                        return r;

                return 1;
        }

        if (!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        if (s->type != SOURCE_POST) {
                sd_event_source *z;

                /* If we execute a non-post source, let's mark all post sources as pending. */

                SET_FOREACH(z, s->event->post_sources) {
                        if (event_source_is_offline(z))
                                continue;

                        r = source_set_pending(z, true);
                        if (r < 0)
                                return r;
                }
        }

        if (s->type == SOURCE_MEMORY_PRESSURE) {
                r = source_memory_pressure_initiate_dispatch(s);
                if (r == -EIO) /* handle EIO errors similar to callback errors */
                        goto finish;
                if (r < 0)
                        return r;
                if (r > 0) /* already handled */
                        return 1;
        }

        if (s->enabled == SD_EVENT_ONESHOT) {
                r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
                if (r < 0)
                        return r;
        }

        s->dispatching = true;

        switch (s->type) {

        case SOURCE_IO:
                r = s->io.callback(s, s->io.fd, s->io.revents, s->userdata);
                break;

        case SOURCE_TIME_REALTIME:
        case SOURCE_TIME_BOOTTIME:
        case SOURCE_TIME_MONOTONIC:
        case SOURCE_TIME_REALTIME_ALARM:
        case SOURCE_TIME_BOOTTIME_ALARM:
                r = s->time.callback(s, s->time.next, s->userdata);
                break;

        case SOURCE_SIGNAL:
                r = s->signal.callback(s, &s->signal.siginfo, s->userdata);
                break;

        case SOURCE_CHILD: {
                bool zombie;

                zombie = IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED);

                r = s->child.callback(s, &s->child.siginfo, s->userdata);

                /* Now, reap the PID for good. */
                if (zombie) {
                        (void) waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|WEXITED);
                        s->child.waited = true;
                }

                break;
        }

        case SOURCE_DEFER:
                r = s->defer.callback(s, s->userdata);
                break;

        case SOURCE_POST:
                r = s->post.callback(s, s->userdata);
                break;

        case SOURCE_EXIT:
                r = s->exit.callback(s, s->userdata);
                break;

        case SOURCE_INOTIFY: {
                struct sd_event *e = s->event;
                struct inotify_data *d;
                size_t sz;

                assert(s->inotify.inode_data);
                assert_se(d = s->inotify.inode_data->inotify_data);

                assert(d->buffer_filled >= offsetof(struct inotify_event, name));
                sz = offsetof(struct inotify_event, name) + d->buffer.ev.len;
                assert(d->buffer_filled >= sz);

                /* If the inotify callback destroys the event source then this likely means we don't need to
                 * watch the inode anymore, and thus also won't need the inotify object anymore. But if we'd
                 * free it immediately, then we couldn't drop the event from the inotify event queue without
                 * memory corruption anymore, as below. Hence, let's not free it immediately, but mark it
                 * "busy" with a counter (which will ensure it's not GC'ed away prematurely). Let's then
                 * explicitly GC it after we are done dropping the inotify event from the buffer. */
                d->n_busy++;
                r = s->inotify.callback(s, &d->buffer.ev, s->userdata);
                d->n_busy--;

                /* When no event is pending anymore on this inotify object, then let's drop the event from
                 * the inotify event queue buffer. */
                if (d->n_pending == 0)
                        event_inotify_data_drop(e, d, sz);

                /* Now we don't want to access 'd' anymore, it's OK to GC now. */
                event_gc_inotify_data(e, d);
                break;
        }

        case SOURCE_MEMORY_PRESSURE:
                r = s->memory_pressure.callback(s, s->userdata);
                break;

        case SOURCE_WATCHDOG:
        case _SOURCE_EVENT_SOURCE_TYPE_MAX:
        case _SOURCE_EVENT_SOURCE_TYPE_INVALID:
                assert_not_reached();
        }

        s->dispatching = false;

finish:
        if (r < 0) {
                log_debug_errno(r, "Event source %s (type %s) returned error, %s: %m",
                                strna(s->description),
                                event_source_type_to_string(saved_type),
                                s->exit_on_failure ? "exiting" : "disabling");

                if (s->exit_on_failure)
                        (void) sd_event_exit(saved_event, r);
        }

        if (s->n_ref == 0)
                source_free(s);
        else if (r < 0)
                assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);

        return 1;
}

static int event_prepare(sd_event *e) {
        int r;

        assert(e);

        for (;;) {
                sd_event_source *s;

                s = prioq_peek(e->prepare);
                if (!s || s->prepare_iteration == e->iteration || event_source_is_offline(s))
                        break;

                s->prepare_iteration = e->iteration;
                prioq_reshuffle(e->prepare, s, &s->prepare_index);

                assert(s->prepare);
                s->dispatching = true;
                r = s->prepare(s, s->userdata);
                s->dispatching = false;

                if (r < 0) {
                        log_debug_errno(r, "Prepare callback of event source %s (type %s) returned error, %s: %m",
                                        strna(s->description),
                                        event_source_type_to_string(s->type),
                                        s->exit_on_failure ? "exiting" : "disabling");

                        if (s->exit_on_failure)
                                (void) sd_event_exit(e, r);
                }

                if (s->n_ref == 0)
                        source_free(s);
                else if (r < 0)
                        assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);
        }

        return 0;
}

static int dispatch_exit(sd_event *e) {
        sd_event_source *p;
        int r;

        assert(e);

        p = prioq_peek(e->exit);
        assert(!p || p->type == SOURCE_EXIT);

        if (!p || event_source_is_offline(p)) {
                e->state = SD_EVENT_FINISHED;
                return 0;
        }

        PROTECT_EVENT(e);
        e->iteration++;
        e->state = SD_EVENT_EXITING;
        r = source_dispatch(p);
        e->state = SD_EVENT_INITIAL;
        return r;
}

static sd_event_source* event_next_pending(sd_event *e) {
        sd_event_source *p;

        assert(e);

        p = prioq_peek(e->pending);
        if (!p)
                return NULL;

        if (event_source_is_offline(p))
                return NULL;

        return p;
}

static int arm_watchdog(sd_event *e) {
        struct itimerspec its = {};
        usec_t t;

        assert(e);
        assert(e->watchdog_fd >= 0);

        t = sleep_between(e,
                          usec_add(e->watchdog_last, (e->watchdog_period / 2)),
                          usec_add(e->watchdog_last, (e->watchdog_period * 3 / 4)));

        timespec_store(&its.it_value, t);

        /* Make sure we never set the watchdog to 0, which tells the
         * kernel to disable it. */
        if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
                its.it_value.tv_nsec = 1;

        return RET_NERRNO(timerfd_settime(e->watchdog_fd, TFD_TIMER_ABSTIME, &its, NULL));
}

static int process_watchdog(sd_event *e) {
        assert(e);

        if (!e->watchdog)
                return 0;

        /* Don't notify watchdog too often */
        if (e->watchdog_last + e->watchdog_period / 4 > e->timestamp.monotonic)
                return 0;

        sd_notify(false, "WATCHDOG=1");
        e->watchdog_last = e->timestamp.monotonic;

        return arm_watchdog(e);
}

static void event_close_inode_data_fds(sd_event *e) {
        struct inode_data *d;

        assert(e);

        /* Close the fds pointing to the inodes to watch now. We need to close them as they might otherwise pin
         * filesystems. But we can't close them right-away as we need them as long as the user still wants to make
         * adjustments to the event source, such as changing the priority (which requires us to remove and re-add a watch
         * for the inode). Hence, let's close them when entering the first iteration after they were added, as a
         * compromise. */

        while ((d = e->inode_data_to_close_list)) {
                assert(d->fd >= 0);
                d->fd = safe_close(d->fd);

                LIST_REMOVE(to_close, e->inode_data_to_close_list, d);
        }
}

static int event_memory_pressure_write_list(sd_event *e) {
        int r;

        assert(e);

        for (;;) {
                sd_event_source *s;

                s = LIST_POP(memory_pressure.write_list, e->memory_pressure_write_list);
                if (!s)
                        break;

                assert(s->type == SOURCE_MEMORY_PRESSURE);
                assert(s->memory_pressure.write_buffer_size > 0);
                s->memory_pressure.in_write_list = false;

                r = source_memory_pressure_write(s);
                if (r < 0)
                        return r;
        }

        return 0;
}

_public_ int sd_event_prepare(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        /* Let's check that if we are a default event loop we are executed in the correct thread. We only do
         * this check here once, since gettid() is typically not cached, and thus want to minimize
         * syscalls */
        assert_return(!e->default_event_ptr || e->tid == gettid(), -EREMOTEIO);

        /* Make sure that none of the preparation callbacks ends up freeing the event source under our feet */
        PROTECT_EVENT(e);

        if (e->exit_requested)
                goto pending;

        e->iteration++;

        e->state = SD_EVENT_PREPARING;
        r = event_prepare(e);
        e->state = SD_EVENT_INITIAL;
        if (r < 0)
                return r;

        r = event_memory_pressure_write_list(e);
        if (r < 0)
                return r;

        r = event_arm_timer(e, &e->realtime);
        if (r < 0)
                return r;

        r = event_arm_timer(e, &e->boottime);
        if (r < 0)
                return r;

        r = event_arm_timer(e, &e->monotonic);
        if (r < 0)
                return r;

        r = event_arm_timer(e, &e->realtime_alarm);
        if (r < 0)
                return r;

        r = event_arm_timer(e, &e->boottime_alarm);
        if (r < 0)
                return r;

        event_close_inode_data_fds(e);

        if (event_next_pending(e) || e->need_process_child || e->buffered_inotify_data_list)
                goto pending;

        e->state = SD_EVENT_ARMED;

        return 0;

pending:
        e->state = SD_EVENT_ARMED;
        r = sd_event_wait(e, 0);
        if (r == 0)
                e->state = SD_EVENT_ARMED;

        return r;
}

static int epoll_wait_usec(
                int fd,
                struct epoll_event *events,
                int maxevents,
                usec_t timeout) {

        int msec;
        /* A wrapper that uses epoll_pwait2() if available, and falls back to epoll_wait() if not. */

#if HAVE_EPOLL_PWAIT2
        static bool epoll_pwait2_absent = false;
        int r;

        /* epoll_pwait2() was added to Linux 5.11 (2021-02-14) and to glibc in 2.35 (2022-02-03). In contrast
         * to other syscalls we don't bother with our own fallback syscall wrappers on old libcs, since this
         * is not that obvious to implement given the libc and kernel definitions differ in the last
         * argument. Moreover, the only reason to use it is the more accurate time-outs (which is not a
         * biggie), let's hence rely on glibc's definitions, and fallback to epoll_pwait() when that's
         * missing. */

        if (!epoll_pwait2_absent && timeout != USEC_INFINITY) {
                r = epoll_pwait2(fd,
                                 events,
                                 maxevents,
                                 TIMESPEC_STORE(timeout),
                                 NULL);
                if (r >= 0)
                        return r;
                if (!ERRNO_IS_NOT_SUPPORTED(errno) && !ERRNO_IS_PRIVILEGE(errno))
                        return -errno; /* Only fallback to old epoll_wait() if the syscall is masked or not
                                        * supported. */

                epoll_pwait2_absent = true;
        }
#endif

        if (timeout == USEC_INFINITY)
                msec = -1;
        else {
                usec_t k;

                k = DIV_ROUND_UP(timeout, USEC_PER_MSEC);
                if (k >= INT_MAX)
                        msec = INT_MAX; /* Saturate */
                else
                        msec = (int) k;
        }

        return RET_NERRNO(epoll_wait(fd, events, maxevents, msec));
}

static int process_epoll(sd_event *e, usec_t timeout, int64_t threshold, int64_t *ret_min_priority) {
        size_t n_event_queue, m, n_event_max;
        int64_t min_priority = threshold;
        bool something_new = false;
        int r;

        assert(e);
        assert(ret_min_priority);

        n_event_queue = MAX(e->n_sources, 1u);
        if (!GREEDY_REALLOC(e->event_queue, n_event_queue))
                return -ENOMEM;

        n_event_max = MALLOC_ELEMENTSOF(e->event_queue);

        /* If we still have inotify data buffered, then query the other fds, but don't wait on it */
        if (e->buffered_inotify_data_list)
                timeout = 0;

        for (;;) {
                r = epoll_wait_usec(
                                e->epoll_fd,
                                e->event_queue,
                                n_event_max,
                                timeout);
                if (r < 0)
                        return r;

                m = (size_t) r;

                if (m < n_event_max)
                        break;

                if (n_event_max >= n_event_queue * 10)
                        break;

                if (!GREEDY_REALLOC(e->event_queue, n_event_max + n_event_queue))
                        return -ENOMEM;

                n_event_max = MALLOC_ELEMENTSOF(e->event_queue);
                timeout = 0;
        }

        /* Set timestamp only when this is called first time. */
        if (threshold == INT64_MAX)
                triple_timestamp_now(&e->timestamp);

        for (size_t i = 0; i < m; i++) {

                if (e->event_queue[i].data.ptr == INT_TO_PTR(SOURCE_WATCHDOG))
                        r = flush_timer(e, e->watchdog_fd, e->event_queue[i].events, NULL);
                else {
                        WakeupType *t = e->event_queue[i].data.ptr;

                        switch (*t) {

                        case WAKEUP_EVENT_SOURCE: {
                                sd_event_source *s = e->event_queue[i].data.ptr;

                                assert(s);

                                if (s->priority > threshold)
                                        continue;

                                min_priority = MIN(min_priority, s->priority);

                                switch (s->type) {

                                case SOURCE_IO:
                                        r = process_io(e, s, e->event_queue[i].events);
                                        break;

                                case SOURCE_CHILD:
                                        r = process_pidfd(e, s, e->event_queue[i].events);
                                        break;

                                case SOURCE_MEMORY_PRESSURE:
                                        r = process_memory_pressure(s, e->event_queue[i].events);
                                        break;

                                default:
                                        assert_not_reached();
                                }

                                break;
                        }

                        case WAKEUP_CLOCK_DATA: {
                                struct clock_data *d = e->event_queue[i].data.ptr;

                                assert(d);

                                r = flush_timer(e, d->fd, e->event_queue[i].events, &d->next);
                                break;
                        }

                        case WAKEUP_SIGNAL_DATA:
                                r = process_signal(e, e->event_queue[i].data.ptr, e->event_queue[i].events, &min_priority);
                                break;

                        case WAKEUP_INOTIFY_DATA:
                                r = event_inotify_data_read(e, e->event_queue[i].data.ptr, e->event_queue[i].events, threshold);
                                break;

                        default:
                                assert_not_reached();
                        }
                }
                if (r < 0)
                        return r;
                if (r > 0)
                        something_new = true;
        }

        *ret_min_priority = min_priority;
        return something_new;
}

_public_ int sd_event_wait(sd_event *e, uint64_t timeout) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_ARMED, -EBUSY);

        if (e->exit_requested) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        for (int64_t threshold = INT64_MAX; ; threshold--) {
                int64_t epoll_min_priority, child_min_priority;

                /* There may be a possibility that new epoll (especially IO) and child events are
                 * triggered just after process_epoll() call but before process_child(), and the new IO
                 * events may have higher priority than the child events. To salvage these events,
                 * let's call epoll_wait() again, but accepts only events with higher priority than the
                 * previous. See issue https://github.com/systemd/systemd/issues/18190 and comments
                 * https://github.com/systemd/systemd/pull/18750#issuecomment-785801085
                 * https://github.com/systemd/systemd/pull/18922#issuecomment-792825226 */

                r = process_epoll(e, timeout, threshold, &epoll_min_priority);
                if (r == -EINTR) {
                        e->state = SD_EVENT_PENDING;
                        return 1;
                }
                if (r < 0)
                        goto finish;
                if (r == 0 && threshold < INT64_MAX)
                        /* No new epoll event. */
                        break;

                r = process_child(e, threshold, &child_min_priority);
                if (r < 0)
                        goto finish;
                if (r == 0)
                        /* No new child event. */
                        break;

                threshold = MIN(epoll_min_priority, child_min_priority);
                if (threshold == INT64_MIN)
                        break;

                timeout = 0;
        }

        r = process_watchdog(e);
        if (r < 0)
                goto finish;

        r = process_inotify(e);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.monotonic, &e->monotonic);
        if (r < 0)
                goto finish;
        else if (r == 1) {
                /* Ratelimit expiry callback was called. Let's postpone processing pending sources and
                 * put loop in the initial state in order to evaluate (in the next iteration) also sources
                 * there were potentially re-enabled by the callback.
                 *
                 * Wondering why we treat only this invocation of process_timer() differently? Once event
                 * source is ratelimited we essentially transform it into CLOCK_MONOTONIC timer hence
                 * ratelimit expiry callback is never called for any other timer type. */
                r = 0;
                goto finish;
        }

        if (event_next_pending(e)) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        r = 0;

finish:
        e->state = SD_EVENT_INITIAL;

        return r;
}

_public_ int sd_event_dispatch(sd_event *e) {
        sd_event_source *p;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_PENDING, -EBUSY);

        if (e->exit_requested)
                return dispatch_exit(e);

        p = event_next_pending(e);
        if (p) {
                PROTECT_EVENT(e);

                e->state = SD_EVENT_RUNNING;
                r = source_dispatch(p);
                e->state = SD_EVENT_INITIAL;
                return r;
        }

        e->state = SD_EVENT_INITIAL;

        return 1;
}

static void event_log_delays(sd_event *e) {
        char b[ELEMENTSOF(e->delays) * DECIMAL_STR_MAX(unsigned) + 1], *p;
        size_t l, i;

        p = b;
        l = sizeof(b);
        for (i = 0; i < ELEMENTSOF(e->delays); i++) {
                l = strpcpyf(&p, l, "%u ", e->delays[i]);
                e->delays[i] = 0;
        }
        log_debug("Event loop iterations: %s", b);
}

_public_ int sd_event_run(sd_event *e, uint64_t timeout) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        if (e->profile_delays && e->last_run_usec != 0) {
                usec_t this_run;
                unsigned l;

                this_run = now(CLOCK_MONOTONIC);

                l = log2u64(this_run - e->last_run_usec);
                assert(l < ELEMENTSOF(e->delays));
                e->delays[l]++;

                if (this_run - e->last_log_usec >= 5*USEC_PER_SEC) {
                        event_log_delays(e);
                        e->last_log_usec = this_run;
                }
        }

        /* Make sure that none of the preparation callbacks ends up freeing the event source under our feet */
        PROTECT_EVENT(e);

        r = sd_event_prepare(e);
        if (r == 0)
                /* There was nothing? Then wait... */
                r = sd_event_wait(e, timeout);

        if (e->profile_delays)
                e->last_run_usec = now(CLOCK_MONOTONIC);

        if (r > 0) {
                /* There's something now, then let's dispatch it */
                r = sd_event_dispatch(e);
                if (r < 0)
                        return r;

                return 1;
        }

        return r;
}

_public_ int sd_event_loop(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);


        PROTECT_EVENT(e);

        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, UINT64_MAX);
                if (r < 0)
                        return r;
        }

        return e->exit_code;
}

_public_ int sd_event_get_fd(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->epoll_fd;
}

_public_ int sd_event_get_state(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->state;
}

_public_ int sd_event_get_exit_code(sd_event *e, int *code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(code, -EINVAL);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!e->exit_requested)
                return -ENODATA;

        *code = e->exit_code;
        return 0;
}

_public_ int sd_event_exit(sd_event *e, int code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_origin_changed(e), -ECHILD);

        e->exit_requested = true;
        e->exit_code = code;

        return 0;
}

_public_ int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(usec, -EINVAL);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (!TRIPLE_TIMESTAMP_HAS_CLOCK(clock))
                return -EOPNOTSUPP;

        if (!triple_timestamp_is_set(&e->timestamp)) {
                /* Implicitly fall back to now() if we never ran before and thus have no cached time. */
                *usec = now(clock);
                return 1;
        }

        *usec = triple_timestamp_by_clock(&e->timestamp, clock);
        return 0;
}

_public_ int sd_event_default(sd_event **ret) {
        sd_event *e = NULL;
        int r;

        if (!ret)
                return !!default_event;

        if (default_event) {
                *ret = sd_event_ref(default_event);
                return 0;
        }

        r = sd_event_new(&e);
        if (r < 0)
                return r;

        e->default_event_ptr = &default_event;
        e->tid = gettid();
        default_event = e;

        *ret = e;
        return 1;
}

_public_ int sd_event_get_tid(sd_event *e, pid_t *tid) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(tid, -EINVAL);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (e->tid != 0) {
                *tid = e->tid;
                return 0;
        }

        return -ENXIO;
}

_public_ int sd_event_set_watchdog(sd_event *e, int b) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        if (e->watchdog == !!b)
                return e->watchdog;

        if (b) {
                r = sd_watchdog_enabled(false, &e->watchdog_period);
                if (r <= 0)
                        return r;

                /* Issue first ping immediately */
                sd_notify(false, "WATCHDOG=1");
                e->watchdog_last = now(CLOCK_MONOTONIC);

                e->watchdog_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
                if (e->watchdog_fd < 0)
                        return -errno;

                r = arm_watchdog(e);
                if (r < 0)
                        goto fail;

                struct epoll_event ev = {
                        .events = EPOLLIN,
                        .data.ptr = INT_TO_PTR(SOURCE_WATCHDOG),
                };

                if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, e->watchdog_fd, &ev) < 0) {
                        r = -errno;
                        goto fail;
                }

        } else {
                if (e->watchdog_fd >= 0) {
                        (void) epoll_ctl(e->epoll_fd, EPOLL_CTL_DEL, e->watchdog_fd, NULL);
                        e->watchdog_fd = safe_close(e->watchdog_fd);
                }
        }

        e->watchdog = !!b;
        return e->watchdog;

fail:
        e->watchdog_fd = safe_close(e->watchdog_fd);
        return r;
}

_public_ int sd_event_get_watchdog(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        return e->watchdog;
}

_public_ int sd_event_get_iteration(sd_event *e, uint64_t *ret) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_origin_changed(e), -ECHILD);

        *ret = e->iteration;
        return 0;
}

_public_ int sd_event_source_set_destroy_callback(sd_event_source *s, sd_event_destroy_t callback) {
        assert_return(s, -EINVAL);
        assert_return(s->event, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        s->destroy_callback = callback;
        return 0;
}

_public_ int sd_event_source_get_destroy_callback(sd_event_source *s, sd_event_destroy_t *ret) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (ret)
                *ret = s->destroy_callback;

        return !!s->destroy_callback;
}

_public_ int sd_event_source_get_floating(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->floating;
}

_public_ int sd_event_source_set_floating(sd_event_source *s, int b) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->floating == !!b)
                return 0;

        if (!s->event) /* Already disconnected */
                return -ESTALE;

        s->floating = b;

        if (b) {
                sd_event_source_ref(s);
                sd_event_unref(s->event);
        } else {
                sd_event_ref(s->event);
                sd_event_source_unref(s);
        }

        return 1;
}

_public_ int sd_event_source_get_exit_on_failure(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        return s->exit_on_failure;
}

_public_ int sd_event_source_set_exit_on_failure(sd_event_source *s, int b) {
        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (s->exit_on_failure == !!b)
                return 0;

        s->exit_on_failure = b;
        return 1;
}

_public_ int sd_event_source_set_ratelimit(sd_event_source *s, uint64_t interval, unsigned burst) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        /* Turning on ratelimiting on event source types that don't support it, is a loggable offense. Doing
         * so is a programming error. */
        assert_return(EVENT_SOURCE_CAN_RATE_LIMIT(s->type), -EDOM);

        /* When ratelimiting is configured we'll always reset the rate limit state first and start fresh,
         * non-ratelimited. */
        r = event_source_leave_ratelimit(s, /* run_callback */ false);
        if (r < 0)
                return r;

        s->rate_limit = (RateLimit) { interval, burst };
        return 0;
}

_public_ int sd_event_source_set_ratelimit_expire_callback(sd_event_source *s, sd_event_handler_t callback) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        s->ratelimit_expire_callback = callback;
        return 0;
}

_public_ int sd_event_source_get_ratelimit(sd_event_source *s, uint64_t *ret_interval, unsigned *ret_burst) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        /* Querying whether an event source has ratelimiting configured is not a loggable offense, hence
         * don't use assert_return(). Unlike turning on ratelimiting it's not really a programming error. */
        if (!EVENT_SOURCE_CAN_RATE_LIMIT(s->type))
                return -EDOM;

        if (!ratelimit_configured(&s->rate_limit))
                return -ENOEXEC;

        if (ret_interval)
                *ret_interval = s->rate_limit.interval;
        if (ret_burst)
                *ret_burst = s->rate_limit.burst;

        return 0;
}

_public_ int sd_event_source_is_ratelimited(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (!EVENT_SOURCE_CAN_RATE_LIMIT(s->type))
                return false;

        if (!ratelimit_configured(&s->rate_limit))
                return false;

        return s->ratelimited;
}

_public_ int sd_event_source_leave_ratelimit(sd_event_source *s) {
        int r;

        assert_return(s, -EINVAL);

        if (!EVENT_SOURCE_CAN_RATE_LIMIT(s->type))
                return 0;

        if (!ratelimit_configured(&s->rate_limit))
                return 0;

        if (!s->ratelimited)
                return 0;

        r = event_source_leave_ratelimit(s, /* run_callback */ false);
        if (r < 0)
                return r;

        return 1; /* tell caller that we indeed just left the ratelimit state */
}

_public_ int sd_event_set_signal_exit(sd_event *e, int b) {
        bool change = false;
        int r;

        assert_return(e, -EINVAL);

        if (b) {
                /* We want to maintain pointers to these event sources, so that we can destroy them when told
                 * so. But we also don't want them to pin the event loop itself. Hence we mark them as
                 * floating after creation (and undo this before deleting them again). */

                if (!e->sigint_event_source) {
                        r = sd_event_add_signal(e, &e->sigint_event_source, SIGINT | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL);
                        if (r < 0)
                                return r;

                        assert(sd_event_source_set_floating(e->sigint_event_source, true) >= 0);
                        change = true;
                }

                if (!e->sigterm_event_source) {
                        r = sd_event_add_signal(e, &e->sigterm_event_source, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, NULL);
                        if (r < 0) {
                                if (change) {
                                        assert(sd_event_source_set_floating(e->sigint_event_source, false) >= 0);
                                        e->sigint_event_source = sd_event_source_unref(e->sigint_event_source);
                                }

                                return r;
                        }

                        assert(sd_event_source_set_floating(e->sigterm_event_source, true) >= 0);
                        change = true;
                }

        } else {
                if (e->sigint_event_source) {
                        assert(sd_event_source_set_floating(e->sigint_event_source, false) >= 0);
                        e->sigint_event_source = sd_event_source_unref(e->sigint_event_source);
                        change = true;
                }

                if (e->sigterm_event_source) {
                        assert(sd_event_source_set_floating(e->sigterm_event_source, false) >= 0);
                        e->sigterm_event_source = sd_event_source_unref(e->sigterm_event_source);
                        change = true;
                }
        }

        return change;
}

_public_ int sd_event_source_set_memory_pressure_type(sd_event_source *s, const char *ty) {
        _cleanup_free_ char *b = NULL;
        _cleanup_free_ void *w = NULL;

        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_MEMORY_PRESSURE, -EDOM);
        assert_return(ty, -EINVAL);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (!STR_IN_SET(ty, "some", "full"))
                return -EINVAL;

        if (s->memory_pressure.locked) /* Refuse adjusting parameters, if caller told us how to watch for events */
                return -EBUSY;

        char* space = memchr(s->memory_pressure.write_buffer, ' ', s->memory_pressure.write_buffer_size);
        if (!space)
                return -EINVAL;

        size_t l = (char*) space - (char*) s->memory_pressure.write_buffer;
        b = memdup_suffix0(s->memory_pressure.write_buffer, l);
        if (!b)
                return -ENOMEM;
        if (!STR_IN_SET(b, "some", "full"))
                return -EINVAL;

        if (streq(b, ty))
                return 0;

        size_t nl = strlen(ty) + (s->memory_pressure.write_buffer_size - l);
        w = new(char, nl);
        if (!w)
                return -ENOMEM;

        memcpy(stpcpy(w, ty), space, (s->memory_pressure.write_buffer_size - l));

        free_and_replace(s->memory_pressure.write_buffer, w);
        s->memory_pressure.write_buffer_size = nl;
        s->memory_pressure.locked = false;

        return 1;
}

_public_ int sd_event_source_set_memory_pressure_period(sd_event_source *s, uint64_t threshold_usec, uint64_t window_usec) {
        _cleanup_free_ char *b = NULL;
        _cleanup_free_ void *w = NULL;

        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_MEMORY_PRESSURE, -EDOM);
        assert_return(!event_origin_changed(s->event), -ECHILD);

        if (threshold_usec <= 0 || threshold_usec >= UINT64_MAX)
                return -ERANGE;
        if (window_usec <= 0 || window_usec >= UINT64_MAX)
                return -ERANGE;
        if (threshold_usec > window_usec)
                return -EINVAL;

        if (s->memory_pressure.locked) /* Refuse adjusting parameters, if caller told us how to watch for events */
                return -EBUSY;

        char* space = memchr(s->memory_pressure.write_buffer, ' ', s->memory_pressure.write_buffer_size);
        if (!space)
                return -EINVAL;

        size_t l = (char*) space - (char*) s->memory_pressure.write_buffer;
        b = memdup_suffix0(s->memory_pressure.write_buffer, l);
        if (!b)
                return -ENOMEM;
        if (!STR_IN_SET(b, "some", "full"))
                return -EINVAL;

        if (asprintf((char**) &w,
                     "%s " USEC_FMT " " USEC_FMT "",
                     b,
                     threshold_usec,
                     window_usec) < 0)
                return -EINVAL;

        l = strlen(w) + 1;
        if (memcmp_nn(s->memory_pressure.write_buffer, s->memory_pressure.write_buffer_size, w, l) == 0)
                return 0;

        free_and_replace(s->memory_pressure.write_buffer, w);
        s->memory_pressure.write_buffer_size = l;
        s->memory_pressure.locked = false;

        return 1;
}
