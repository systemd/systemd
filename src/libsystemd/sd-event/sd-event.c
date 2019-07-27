/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "event-source.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "memory-util.h"
#include "missing.h"
#include "prioq.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "time-util.h"

#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

static const char* const event_source_type_table[_SOURCE_EVENT_SOURCE_TYPE_MAX] = {
        [SOURCE_IO] = "io",
        [SOURCE_TIME_REALTIME] = "realtime",
        [SOURCE_TIME_BOOTTIME] = "bootime",
        [SOURCE_TIME_MONOTONIC] = "monotonic",
        [SOURCE_TIME_REALTIME_ALARM] = "realtime-alarm",
        [SOURCE_TIME_BOOTTIME_ALARM] = "boottime-alarm",
        [SOURCE_SIGNAL] = "signal",
        [SOURCE_CHILD] = "child",
        [SOURCE_DEFER] = "defer",
        [SOURCE_POST] = "post",
        [SOURCE_EXIT] = "exit",
        [SOURCE_WATCHDOG] = "watchdog",
        [SOURCE_INOTIFY] = "inotify",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(event_source_type, int);

#define EVENT_SOURCE_IS_TIME(t) IN_SET((t), SOURCE_TIME_REALTIME, SOURCE_TIME_BOOTTIME, SOURCE_TIME_MONOTONIC, SOURCE_TIME_REALTIME_ALARM, SOURCE_TIME_BOOTTIME_ALARM)

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
        unsigned n_enabled_child_sources;

        Set *post_sources;

        Prioq *exit;

        Hashmap *inotify_data; /* indexed by priority */

        /* A list of inode structures that still have an fd open, that we need to close before the next loop iteration */
        LIST_HEAD(struct inode_data, inode_data_to_close);

        /* A list of inotify objects that already have events buffered which aren't processed yet */
        LIST_HEAD(struct inotify_data, inotify_data_buffered);

        pid_t original_pid;

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

        LIST_HEAD(sd_event_source, sources);

        usec_t last_run, last_log;
        unsigned delays[sizeof(usec_t) * 8];
};

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
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

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
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

        /* Move most recently prepared ones last, so that we can stop
         * preparing as soon as we hit one that has already been
         * prepared in the current iteration */
        r = CMP(x->prepare_iteration, y->prepare_iteration);
        if (r != 0)
                return r;

        /* Lower priority values first */
        return CMP(x->priority, y->priority);
}

static int earliest_time_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(EVENT_SOURCE_IS_TIME(x->type));
        assert(x->type == y->type);

        /* Enabled ones first */
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

        /* Move the pending ones to the end */
        if (!x->pending && y->pending)
                return -1;
        if (x->pending && !y->pending)
                return 1;

        /* Order by time */
        return CMP(x->time.next, y->time.next);
}

static usec_t time_event_source_latest(const sd_event_source *s) {
        return usec_add(s->time.next, s->time.accuracy);
}

static int latest_time_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(EVENT_SOURCE_IS_TIME(x->type));
        assert(x->type == y->type);

        /* Enabled ones first */
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

        /* Move the pending ones to the end */
        if (!x->pending && y->pending)
                return -1;
        if (x->pending && !y->pending)
                return 1;

        /* Order by time */
        return CMP(time_event_source_latest(x), time_event_source_latest(y));
}

static int exit_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->type == SOURCE_EXIT);
        assert(y->type == SOURCE_EXIT);

        /* Enabled ones first */
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

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
                .epoll_fd = -1,
                .watchdog_fd = -1,
                .realtime.wakeup = WAKEUP_CLOCK_DATA,
                .realtime.fd = -1,
                .realtime.next = USEC_INFINITY,
                .boottime.wakeup = WAKEUP_CLOCK_DATA,
                .boottime.fd = -1,
                .boottime.next = USEC_INFINITY,
                .monotonic.wakeup = WAKEUP_CLOCK_DATA,
                .monotonic.fd = -1,
                .monotonic.next = USEC_INFINITY,
                .realtime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .realtime_alarm.fd = -1,
                .realtime_alarm.next = USEC_INFINITY,
                .boottime_alarm.wakeup = WAKEUP_CLOCK_DATA,
                .boottime_alarm.fd = -1,
                .boottime_alarm.next = USEC_INFINITY,
                .perturb = USEC_INFINITY,
                .original_pid = getpid_cached(),
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
                log_debug("Event loop profiling enabled. Logarithmic histogram of event loop iterations in the range 2^0 ... 2^63 us will be logged every 5s.");
                e->profile_delays = true;
        }

        *ret = e;
        return 0;

fail:
        event_free(e);
        return r;
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_event, sd_event, event_free);

_public_ sd_event_source* sd_event_source_disable_unref(sd_event_source *s) {
        if (s)
                (void) sd_event_source_set_enabled(s, SD_EVENT_OFF);
        return sd_event_source_unref(s);
}

static bool event_pid_changed(sd_event *e) {
        assert(e);

        /* We don't support people creating an event loop and keeping
         * it around over a fork(). Let's complain. */

        return e->original_pid != getpid_cached();
}

static void source_io_unregister(sd_event_source *s) {
        int r;

        assert(s);
        assert(s->type == SOURCE_IO);

        if (event_pid_changed(s->event))
                return;

        if (!s->io.registered)
                return;

        r = epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->io.fd, NULL);
        if (r < 0)
                log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll: %m",
                                strna(s->description), event_source_type_to_string(s->type));

        s->io.registered = false;
}

static int source_io_register(
                sd_event_source *s,
                int enabled,
                uint32_t events) {

        struct epoll_event ev;
        int r;

        assert(s);
        assert(s->type == SOURCE_IO);
        assert(enabled != SD_EVENT_OFF);

        ev = (struct epoll_event) {
                .events = events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
                .data.ptr = s,
        };

        if (s->io.registered)
                r = epoll_ctl(s->event->epoll_fd, EPOLL_CTL_MOD, s->io.fd, &ev);
        else
                r = epoll_ctl(s->event->epoll_fd, EPOLL_CTL_ADD, s->io.fd, &ev);
        if (r < 0)
                return -errno;

        s->io.registered = true;

        return 0;
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

        struct epoll_event ev;
        struct signal_data *d;
        bool added = false;
        sigset_t ss_copy;
        int64_t priority;
        int r;

        assert(e);

        if (event_pid_changed(e))
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
                r = hashmap_ensure_allocated(&e->signal_data, &uint64_hash_ops);
                if (r < 0)
                        return r;

                d = new(struct signal_data, 1);
                if (!d)
                        return -ENOMEM;

                *d = (struct signal_data) {
                        .wakeup = WAKEUP_SIGNAL_DATA,
                        .fd = -1,
                        .priority = priority,
                };

                r = hashmap_put(e->signal_data, &d->priority, d);
                if (r < 0) {
                        free(d);
                        return r;
                }

                added = true;
        }

        ss_copy = d->sigset;
        assert_se(sigaddset(&ss_copy, sig) >= 0);

        r = signalfd(d->fd, &ss_copy, SFD_NONBLOCK|SFD_CLOEXEC);
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

        ev = (struct epoll_event) {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, d->fd, &ev);
        if (r < 0)  {
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

        assert(d->fd >= 0);

        if (signalfd(d->fd, &d->sigset, SFD_NONBLOCK|SFD_CLOEXEC) < 0)
                log_debug_errno(errno, "Failed to unset signal bit, ignoring: %m");
}

static void event_gc_signal_data(sd_event *e, const int64_t *priority, int sig) {
        struct signal_data *d;
        static const int64_t zero_priority = 0;

        assert(e);

        /* Rechecks if the specified signal is still something we are
         * interested in. If not, we'll unmask it, and possibly drop
         * the signalfd for it. */

        if (sig == SIGCHLD &&
            e->n_enabled_child_sources > 0)
                return;

        if (e->signal_sources &&
            e->signal_sources[sig] &&
            e->signal_sources[sig]->enabled != SD_EVENT_OFF)
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

static void source_disconnect(sd_event_source *s) {
        sd_event *event;

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
        case SOURCE_TIME_BOOTTIME_ALARM: {
                struct clock_data *d;

                d = event_get_clock_data(s->event, s->type);
                assert(d);

                prioq_remove(d->earliest, s, &s->time.earliest_index);
                prioq_remove(d->latest, s, &s->time.latest_index);
                d->needs_rearm = true;
                break;
        }

        case SOURCE_SIGNAL:
                if (s->signal.sig > 0) {

                        if (s->event->signal_sources)
                                s->event->signal_sources[s->signal.sig] = NULL;

                        event_gc_signal_data(s->event, &s->priority, s->signal.sig);
                }

                break;

        case SOURCE_CHILD:
                if (s->child.pid > 0) {
                        if (s->enabled != SD_EVENT_OFF) {
                                assert(s->event->n_enabled_child_sources > 0);
                                s->event->n_enabled_child_sources--;
                        }

                        (void) hashmap_remove(s->event->child_sources, PID_TO_PTR(s->child.pid));
                        event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                }

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

        default:
                assert_not_reached("Wut? I shouldn't exist.");
        }

        if (s->pending)
                prioq_remove(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_remove(s->event->prepare, s, &s->prepare_index);

        event = s->event;

        s->type = _SOURCE_EVENT_SOURCE_TYPE_INVALID;
        s->event = NULL;
        LIST_REMOVE(sources, event->sources, s);
        event->n_sources--;

        if (!s->floating)
                sd_event_unref(event);
}

static void source_free(sd_event_source *s) {
        assert(s);

        source_disconnect(s);

        if (s->type == SOURCE_IO && s->io.owned)
                s->io.fd = safe_close(s->io.fd);

        if (s->destroy_callback)
                s->destroy_callback(s->userdata);

        free(s->description);
        free(s);
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

        if (EVENT_SOURCE_IS_TIME(s->type)) {
                struct clock_data *d;

                d = event_get_clock_data(s->event, s->type);
                assert(d);

                prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
                prioq_reshuffle(d->latest, s, &s->time.latest_index);
                d->needs_rearm = true;
        }

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
                        s->inotify.inode_data->inotify_data->n_pending ++;
                else {
                        assert(s->inotify.inode_data->inotify_data->n_pending > 0);
                        s->inotify.inode_data->inotify_data->n_pending --;
                }
        }

        return 0;
}

static sd_event_source *source_new(sd_event *e, bool floating, EventSourceType type) {
        sd_event_source *s;

        assert(e);

        s = new(sd_event_source, 1);
        if (!s)
                return NULL;

        *s = (struct sd_event_source) {
                .n_ref = 1,
                .event = e,
                .floating = floating,
                .type = type,
                .pending_index = PRIOQ_IDX_NULL,
                .prepare_index = PRIOQ_IDX_NULL,
        };

        if (!floating)
                sd_event_ref(e);

        LIST_PREPEND(sources, e->sources, s);
        e->n_sources++;

        return s;
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
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

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
        sd_id128_t bootid = {};

        /* When we sleep for longer, we try to realign the wakeup to
           the same time within each minute/second/250ms, so that
           events all across the system can be coalesced into a single
           CPU wakeup. However, let's take some system-specific
           randomness for this value, so that in a network of systems
           with synced clocks timer events are distributed a
           bit. Here, we calculate a perturbation usec offset from the
           boot ID. */

        if (_likely_(e->perturb != USEC_INFINITY))
                return;

        if (sd_id128_get_boot(&bootid) >= 0)
                e->perturb = (bootid.qwords[0] ^ bootid.qwords[1]) % USEC_PER_MINUTE;
}

static int event_setup_timer_fd(
                sd_event *e,
                struct clock_data *d,
                clockid_t clock) {

        struct epoll_event ev;
        int r, fd;

        assert(e);
        assert(d);

        if (_likely_(d->fd >= 0))
                return 0;

        fd = timerfd_create(clock, TFD_NONBLOCK|TFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        fd = fd_move_above_stdio(fd);

        ev = (struct epoll_event) {
                .events = EPOLLIN,
                .data.ptr = d,
        };

        r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0) {
                safe_close(fd);
                return -errno;
        }

        d->fd = fd;
        return 0;
}

static int time_exit_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        assert(s);

        return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
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
        assert_return(accuracy != (uint64_t) -1, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!clock_supported(clock)) /* Checks whether the kernel supports the clock */
                return -EOPNOTSUPP;

        type = clock_to_event_source_type(clock); /* checks whether sd-event supports this clock */
        if (type < 0)
                return -EOPNOTSUPP;

        if (!callback)
                callback = time_exit_callback;

        d = event_get_clock_data(e, type);
        assert(d);

        r = prioq_ensure_allocated(&d->earliest, earliest_time_prioq_compare);
        if (r < 0)
                return r;

        r = prioq_ensure_allocated(&d->latest, latest_time_prioq_compare);
        if (r < 0)
                return r;

        if (d->fd < 0) {
                r = event_setup_timer_fd(e, d, clock);
                if (r < 0)
                        return r;
        }

        s = source_new(e, !ret, type);
        if (!s)
                return -ENOMEM;

        s->time.next = usec;
        s->time.accuracy = accuracy == 0 ? DEFAULT_ACCURACY_USEC : accuracy;
        s->time.callback = callback;
        s->time.earliest_index = s->time.latest_index = PRIOQ_IDX_NULL;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        d->needs_rearm = true;

        r = prioq_put(d->earliest, s, &s->time.earliest_index);
        if (r < 0)
                return r;

        r = prioq_put(d->latest, s, &s->time.latest_index);
        if (r < 0)
                return r;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
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
        sigset_t ss;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(SIGNAL_VALID(sig), -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!callback)
                callback = signal_exit_callback;

        r = pthread_sigmask(SIG_SETMASK, NULL, &ss);
        if (r != 0)
                return -r;

        if (!sigismember(&ss, sig))
                return -EBUSY;

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

        r = event_make_signal_data(e, sig, &d);
        if (r < 0)
                return r;

        /* Use the signal name as description for the event source by default */
        (void) sd_event_source_set_description(s, signal_to_string(sig));

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
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
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        r = hashmap_ensure_allocated(&e->child_sources, NULL);
        if (r < 0)
                return r;

        if (hashmap_contains(e->child_sources, PID_TO_PTR(pid)))
                return -EBUSY;

        s = source_new(e, !ret, SOURCE_CHILD);
        if (!s)
                return -ENOMEM;

        s->child.pid = pid;
        s->child.options = options;
        s->child.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ONESHOT;

        r = hashmap_put(e->child_sources, PID_TO_PTR(pid), s);
        if (r < 0)
                return r;

        e->n_enabled_child_sources++;

        r = event_make_signal_data(e, SIGCHLD, NULL);
        if (r < 0) {
                e->n_enabled_child_sources--;
                return r;
        }

        e->need_process_child = true;

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
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
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

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
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        r = set_ensure_allocated(&e->post_sources, NULL);
        if (r < 0)
                return r;

        s = source_new(e, !ret, SOURCE_POST);
        if (!s)
                return -ENOMEM;

        s->post.callback = callback;
        s->userdata = userdata;
        s->enabled = SD_EVENT_ON;

        r = set_put(e->post_sources, s);
        if (r < 0)
                return r;

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
        assert_return(!event_pid_changed(e), -ECHILD);

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

static void event_free_inotify_data(sd_event *e, struct inotify_data *d) {
        assert(e);

        if (!d)
                return;

        assert(hashmap_isempty(d->inodes));
        assert(hashmap_isempty(d->wd));

        if (d->buffer_filled > 0)
                LIST_REMOVE(buffered, e->inotify_data_buffered, d);

        hashmap_free(d->inodes);
        hashmap_free(d->wd);

        assert_se(hashmap_remove(e->inotify_data, &d->priority) == d);

        if (d->fd >= 0) {
                if (epoll_ctl(e->epoll_fd, EPOLL_CTL_DEL, d->fd, NULL) < 0)
                        log_debug_errno(errno, "Failed to remove inotify fd from epoll, ignoring: %m");

                safe_close(d->fd);
        }
        free(d);
}

static int event_make_inotify_data(
                sd_event *e,
                int64_t priority,
                struct inotify_data **ret) {

        _cleanup_close_ int fd = -1;
        struct inotify_data *d;
        struct epoll_event ev;
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

        r = hashmap_ensure_allocated(&e->inotify_data, &uint64_hash_ops);
        if (r < 0)
                return r;

        d = new(struct inotify_data, 1);
        if (!d)
                return -ENOMEM;

        *d = (struct inotify_data) {
                .wakeup = WAKEUP_INOTIFY_DATA,
                .fd = TAKE_FD(fd),
                .priority = priority,
        };

        r = hashmap_put(e->inotify_data, &d->priority, d);
        if (r < 0) {
                d->fd = safe_close(d->fd);
                free(d);
                return r;
        }

        ev = (struct epoll_event) {
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
                LIST_REMOVE(to_close, e->inode_data_to_close, d);
                safe_close(d->fd);
        }

        if (d->inotify_data) {

                if (d->wd >= 0) {
                        if (d->inotify_data->fd >= 0) {
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

        if (inotify_data && hashmap_isempty(inotify_data->inodes))
                event_free_inotify_data(e, inotify_data);
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
                .fd = -1,
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
        sd_event_source *s;

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

_public_ int sd_event_add_inotify(
                sd_event *e,
                sd_event_source **ret,
                const char *path,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {

        struct inotify_data *inotify_data = NULL;
        struct inode_data *inode_data = NULL;
        _cleanup_close_ int fd = -1;
        _cleanup_(source_freep) sd_event_source *s = NULL;
        struct stat st;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(path, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        /* Refuse IN_MASK_ADD since we coalesce watches on the same inode, and hence really don't want to merge
         * masks. Or in other words, this whole code exists only to manage IN_MASK_ADD type operations for you, hence
         * the user can't use them for us. */
        if (mask & IN_MASK_ADD)
                return -EINVAL;

        fd = open(path, O_PATH|O_CLOEXEC|
                  (mask & IN_ONLYDIR ? O_DIRECTORY : 0)|
                  (mask & IN_DONT_FOLLOW ? O_NOFOLLOW : 0));
        if (fd < 0)
                return -errno;

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
                event_free_inotify_data(e, inotify_data);
                return r;
        }

        /* Keep the O_PATH fd around until the first iteration of the loop, so that we can still change the priority of
         * the event source, until then, for which we need the original inode. */
        if (inode_data->fd < 0) {
                inode_data->fd = TAKE_FD(fd);
                LIST_PREPEND(to_close, e->inode_data_to_close, inode_data);
        }

        /* Link our event source to the inode data object */
        LIST_PREPEND(inotify.by_inode_data, inode_data->event_sources, s);
        s->inotify.inode_data = inode_data;

        /* Actually realize the watch now */
        r = inode_data_realize_watch(e, inode_data);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(s, path);

        if (ret)
                *ret = s;
        TAKE_PTR(s);

        return 0;
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

        if (s->dispatching) {
                if (s->type == SOURCE_IO)
                        source_io_unregister(s);

                source_disconnect(s);
        } else
                source_free(s);

        return NULL;
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_event_source, sd_event_source, event_source_free);

_public_ int sd_event_source_set_description(sd_event_source *s, const char *description) {
        assert_return(s, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        return free_and_strdup(&s->description, description);
}

_public_ int sd_event_source_get_description(sd_event_source *s, const char **description) {
        assert_return(s, -EINVAL);
        assert_return(description, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        if (!s->description)
                return -ENXIO;

        *description = s->description;
        return 0;
}

_public_ sd_event *sd_event_source_get_event(sd_event_source *s) {
        assert_return(s, NULL);

        return s->event;
}

_public_ int sd_event_source_get_pending(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        return s->pending;
}

_public_ int sd_event_source_get_io_fd(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        return s->io.fd;
}

_public_ int sd_event_source_set_io_fd(sd_event_source *s, int fd) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        if (s->io.fd == fd)
                return 0;

        if (s->enabled == SD_EVENT_OFF) {
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

                epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, saved_fd, NULL);
        }

        return 0;
}

_public_ int sd_event_source_get_io_fd_own(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);

        return s->io.owned;
}

_public_ int sd_event_source_set_io_fd_own(sd_event_source *s, int own) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);

        s->io.owned = own;
        return 0;
}

_public_ int sd_event_source_get_io_events(sd_event_source *s, uint32_t* events) {
        assert_return(s, -EINVAL);
        assert_return(events, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *events = s->io.events;
        return 0;
}

_public_ int sd_event_source_set_io_events(sd_event_source *s, uint32_t events) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_IO, -EDOM);
        assert_return(!(events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP|EPOLLET)), -EINVAL);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        /* edge-triggered updates are never skipped, so we can reset edges */
        if (s->io.events == events && !(events & EPOLLET))
                return 0;

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        if (s->enabled != SD_EVENT_OFF) {
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
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *revents = s->io.revents;
        return 0;
}

_public_ int sd_event_source_get_signal(sd_event_source *s) {
        assert_return(s, -EINVAL);
        assert_return(s->type == SOURCE_SIGNAL, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        return s->signal.sig;
}

_public_ int sd_event_source_get_priority(sd_event_source *s, int64_t *priority) {
        assert_return(s, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

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
        assert_return(!event_pid_changed(s->event), -ECHILD);

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

                        LIST_PREPEND(to_close, s->event->inode_data_to_close, new_inode_data);
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

        } else if (s->type == SOURCE_SIGNAL && s->enabled != SD_EVENT_OFF) {
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

        if (s->pending)
                prioq_reshuffle(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

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

_public_ int sd_event_source_get_enabled(sd_event_source *s, int *m) {
        assert_return(s, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        if (m)
                *m = s->enabled;
        return s->enabled != SD_EVENT_OFF;
}

_public_ int sd_event_source_set_enabled(sd_event_source *s, int m) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(IN_SET(m, SD_EVENT_OFF, SD_EVENT_ON, SD_EVENT_ONESHOT), -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        /* If we are dead anyway, we are fine with turning off
         * sources, but everything else needs to fail. */
        if (s->event->state == SD_EVENT_FINISHED)
                return m == SD_EVENT_OFF ? 0 : -ESTALE;

        if (s->enabled == m)
                return 0;

        if (m == SD_EVENT_OFF) {

                /* Unset the pending flag when this event source is disabled */
                if (!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                        r = source_set_pending(s, false);
                        if (r < 0)
                                return r;
                }

                switch (s->type) {

                case SOURCE_IO:
                        source_io_unregister(s);
                        s->enabled = m;
                        break;

                case SOURCE_TIME_REALTIME:
                case SOURCE_TIME_BOOTTIME:
                case SOURCE_TIME_MONOTONIC:
                case SOURCE_TIME_REALTIME_ALARM:
                case SOURCE_TIME_BOOTTIME_ALARM: {
                        struct clock_data *d;

                        s->enabled = m;
                        d = event_get_clock_data(s->event, s->type);
                        assert(d);

                        prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(d->latest, s, &s->time.latest_index);
                        d->needs_rearm = true;
                        break;
                }

                case SOURCE_SIGNAL:
                        s->enabled = m;

                        event_gc_signal_data(s->event, &s->priority, s->signal.sig);
                        break;

                case SOURCE_CHILD:
                        s->enabled = m;

                        assert(s->event->n_enabled_child_sources > 0);
                        s->event->n_enabled_child_sources--;

                        event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                        break;

                case SOURCE_EXIT:
                        s->enabled = m;
                        prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);
                        break;

                case SOURCE_DEFER:
                case SOURCE_POST:
                case SOURCE_INOTIFY:
                        s->enabled = m;
                        break;

                default:
                        assert_not_reached("Wut? I shouldn't exist.");
                }

        } else {

                /* Unset the pending flag when this event source is enabled */
                if (s->enabled == SD_EVENT_OFF && !IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                        r = source_set_pending(s, false);
                        if (r < 0)
                                return r;
                }

                switch (s->type) {

                case SOURCE_IO:
                        r = source_io_register(s, m, s->io.events);
                        if (r < 0)
                                return r;

                        s->enabled = m;
                        break;

                case SOURCE_TIME_REALTIME:
                case SOURCE_TIME_BOOTTIME:
                case SOURCE_TIME_MONOTONIC:
                case SOURCE_TIME_REALTIME_ALARM:
                case SOURCE_TIME_BOOTTIME_ALARM: {
                        struct clock_data *d;

                        s->enabled = m;
                        d = event_get_clock_data(s->event, s->type);
                        assert(d);

                        prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(d->latest, s, &s->time.latest_index);
                        d->needs_rearm = true;
                        break;
                }

                case SOURCE_SIGNAL:

                        s->enabled = m;

                        r = event_make_signal_data(s->event, s->signal.sig, NULL);
                        if (r < 0) {
                                s->enabled = SD_EVENT_OFF;
                                event_gc_signal_data(s->event, &s->priority, s->signal.sig);
                                return r;
                        }

                        break;

                case SOURCE_CHILD:

                        if (s->enabled == SD_EVENT_OFF)
                                s->event->n_enabled_child_sources++;

                        s->enabled = m;

                        r = event_make_signal_data(s->event, SIGCHLD, NULL);
                        if (r < 0) {
                                s->enabled = SD_EVENT_OFF;
                                s->event->n_enabled_child_sources--;
                                event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                                return r;
                        }

                        break;

                case SOURCE_EXIT:
                        s->enabled = m;
                        prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);
                        break;

                case SOURCE_DEFER:
                case SOURCE_POST:
                case SOURCE_INOTIFY:
                        s->enabled = m;
                        break;

                default:
                        assert_not_reached("Wut? I shouldn't exist.");
                }
        }

        if (s->pending)
                prioq_reshuffle(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

        return 0;
}

_public_ int sd_event_source_get_time(sd_event_source *s, uint64_t *usec) {
        assert_return(s, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *usec = s->time.next;
        return 0;
}

_public_ int sd_event_source_set_time(sd_event_source *s, uint64_t usec) {
        struct clock_data *d;
        int r;

        assert_return(s, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        s->time.next = usec;

        d = event_get_clock_data(s->event, s->type);
        assert(d);

        prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
        prioq_reshuffle(d->latest, s, &s->time.latest_index);
        d->needs_rearm = true;

        return 0;
}

_public_ int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec) {
        assert_return(s, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *usec = s->time.accuracy;
        return 0;
}

_public_ int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec) {
        struct clock_data *d;
        int r;

        assert_return(s, -EINVAL);
        assert_return(usec != (uint64_t) -1, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        r = source_set_pending(s, false);
        if (r < 0)
                return r;

        if (usec == 0)
                usec = DEFAULT_ACCURACY_USEC;

        s->time.accuracy = usec;

        d = event_get_clock_data(s->event, s->type);
        assert(d);

        prioq_reshuffle(d->latest, s, &s->time.latest_index);
        d->needs_rearm = true;

        return 0;
}

_public_ int sd_event_source_get_time_clock(sd_event_source *s, clockid_t *clock) {
        assert_return(s, -EINVAL);
        assert_return(clock, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *clock = event_source_type_to_clock(s->type);
        return 0;
}

_public_ int sd_event_source_get_child_pid(sd_event_source *s, pid_t *pid) {
        assert_return(s, -EINVAL);
        assert_return(pid, -EINVAL);
        assert_return(s->type == SOURCE_CHILD, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *pid = s->child.pid;
        return 0;
}

_public_ int sd_event_source_get_inotify_mask(sd_event_source *s, uint32_t *mask) {
        assert_return(s, -EINVAL);
        assert_return(mask, -EINVAL);
        assert_return(s->type == SOURCE_INOTIFY, -EDOM);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *mask = s->inotify.mask;
        return 0;
}

_public_ int sd_event_source_set_prepare(sd_event_source *s, sd_event_handler_t callback) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_EXIT, -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

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

        return s->userdata;
}

_public_ void *sd_event_source_set_userdata(sd_event_source *s, void *userdata) {
        void *ret;

        assert_return(s, NULL);

        ret = s->userdata;
        s->userdata = userdata;

        return ret;
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
        int r;

        assert(e);
        assert(d);

        if (!d->needs_rearm)
                return 0;
        else
                d->needs_rearm = false;

        a = prioq_peek(d->earliest);
        if (!a || a->enabled == SD_EVENT_OFF || a->time.next == USEC_INFINITY) {

                if (d->fd < 0)
                        return 0;

                if (d->next == USEC_INFINITY)
                        return 0;

                /* disarm */
                r = timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL);
                if (r < 0)
                        return r;

                d->next = USEC_INFINITY;
                return 0;
        }

        b = prioq_peek(d->latest);
        assert_se(b && b->enabled != SD_EVENT_OFF);

        t = sleep_between(e, a->time.next, time_event_source_latest(b));
        if (d->next == t)
                return 0;

        assert_se(d->fd >= 0);

        if (t == 0) {
                /* We don' want to disarm here, just mean some time looooong ago. */
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;
        } else
                timespec_store(&its.it_value, t);

        r = timerfd_settime(d->fd, TFD_TIMER_ABSTIME, &its, NULL);
        if (r < 0)
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
                if (IN_SET(errno, EAGAIN, EINTR))
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
        int r;

        assert(e);
        assert(d);

        for (;;) {
                s = prioq_peek(d->earliest);
                if (!s ||
                    s->time.next > n ||
                    s->enabled == SD_EVENT_OFF ||
                    s->pending)
                        break;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;

                prioq_reshuffle(d->earliest, s, &s->time.earliest_index);
                prioq_reshuffle(d->latest, s, &s->time.latest_index);
                d->needs_rearm = true;
        }

        return 0;
}

static int process_child(sd_event *e) {
        sd_event_source *s;
        Iterator i;
        int r;

        assert(e);

        e->need_process_child = false;

        /*
           So, this is ugly. We iteratively invoke waitid() with P_PID
           + WNOHANG for each PID we wait for, instead of using
           P_ALL. This is because we only want to get child
           information of very specific child processes, and not all
           of them. We might not have processed the SIGCHLD even of a
           previous invocation and we don't want to maintain a
           unbounded *per-child* event queue, hence we really don't
           want anything flushed out of the kernel's queue that we
           don't care about. Since this is O(n) this means that if you
           have a lot of processes you probably want to handle SIGCHLD
           yourself.

           We do not reap the children here (by using WNOWAIT), this
           is only done after the event source is dispatched so that
           the callback still sees the process as a zombie.
        */

        HASHMAP_FOREACH(s, e->child_sources, i) {
                assert(s->type == SOURCE_CHILD);

                if (s->pending)
                        continue;

                if (s->enabled == SD_EVENT_OFF)
                        continue;

                zero(s->child.siginfo);
                r = waitid(P_PID, s->child.pid, &s->child.siginfo,
                           WNOHANG | (s->child.options & WEXITED ? WNOWAIT : 0) | s->child.options);
                if (r < 0)
                        return -errno;

                if (s->child.siginfo.si_pid != 0) {
                        bool zombie = IN_SET(s->child.siginfo.si_code, CLD_EXITED, CLD_KILLED, CLD_DUMPED);

                        if (!zombie && (s->child.options & WEXITED)) {
                                /* If the child isn't dead then let's
                                 * immediately remove the state change
                                 * from the queue, since there's no
                                 * benefit in leaving it queued */

                                assert(s->child.options & (WSTOPPED|WCONTINUED));
                                waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|(s->child.options & (WSTOPPED|WCONTINUED)));
                        }

                        r = source_set_pending(s, true);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int process_signal(sd_event *e, struct signal_data *d, uint32_t events) {
        bool read_one = false;
        int r;

        assert(e);
        assert(d);
        assert_return(events == EPOLLIN, -EIO);

        /* If there's a signal queued on this priority and SIGCHLD is
           on this priority too, then make sure to recheck the
           children we watch. This is because we only ever dequeue
           the first signal per priority, and if we dequeue one, and
           SIGCHLD might be enqueued later we wouldn't know, but we
           might have higher priority children we care about hence we
           need to check that explicitly. */

        if (sigismember(&d->sigset, SIGCHLD))
                e->need_process_child = true;

        /* If there's already an event source pending for this
         * priority we don't read another */
        if (d->current)
                return 0;

        for (;;) {
                struct signalfd_siginfo si;
                ssize_t n;
                sd_event_source *s = NULL;

                n = read(d->fd, &si, sizeof(si));
                if (n < 0) {
                        if (IN_SET(errno, EAGAIN, EINTR))
                                return read_one;

                        return -errno;
                }

                if (_unlikely_(n != sizeof(si)))
                        return -EIO;

                assert(SIGNAL_VALID(si.ssi_signo));

                read_one = true;

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

                return 1;
        }
}

static int event_inotify_data_read(sd_event *e, struct inotify_data *d, uint32_t revents) {
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

        n = read(d->fd, &d->buffer, sizeof(d->buffer));
        if (n < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return -errno;
        }

        assert(n > 0);
        d->buffer_filled = (size_t) n;
        LIST_PREPEND(buffered, e->inotify_data_buffered, d);

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
                LIST_REMOVE(buffered, e->inotify_data_buffered, d);
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
                        Iterator i;

                        /* The queue overran, let's pass this event to all event sources connected to this inotify
                         * object */

                        HASHMAP_FOREACH(inode_data, d->inodes, i) {
                                sd_event_source *s;

                                LIST_FOREACH(inotify.by_inode_data, s, inode_data->event_sources) {

                                        if (s->enabled == SD_EVENT_OFF)
                                                continue;

                                        r = source_set_pending(s, true);
                                        if (r < 0)
                                                return r;
                                }
                        }
                } else {
                        struct inode_data *inode_data;
                        sd_event_source *s;

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

                                if (s->enabled == SD_EVENT_OFF)
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
        struct inotify_data *d;
        int r, done = 0;

        assert(e);

        LIST_FOREACH(buffered, d, e->inotify_data_buffered) {
                r = event_inotify_data_process(e, d);
                if (r < 0)
                        return r;
                if (r > 0)
                        done ++;
        }

        return done;
}

static int source_dispatch(sd_event_source *s) {
        EventSourceType saved_type;
        int r = 0;

        assert(s);
        assert(s->pending || s->type == SOURCE_EXIT);

        /* Save the event source type, here, so that we still know it after the event callback which might invalidate
         * the event. */
        saved_type = s->type;

        if (!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        if (s->type != SOURCE_POST) {
                sd_event_source *z;
                Iterator i;

                /* If we execute a non-post source, let's mark all
                 * post sources as pending */

                SET_FOREACH(z, s->event->post_sources, i) {
                        if (z->enabled == SD_EVENT_OFF)
                                continue;

                        r = source_set_pending(z, true);
                        if (r < 0)
                                return r;
                }
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
                if (zombie)
                        (void) waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|WEXITED);

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

                r = s->inotify.callback(s, &d->buffer.ev, s->userdata);

                /* When no event is pending anymore on this inotify object, then let's drop the event from the
                 * buffer. */
                if (d->n_pending == 0)
                        event_inotify_data_drop(e, d, sz);

                break;
        }

        case SOURCE_WATCHDOG:
        case _SOURCE_EVENT_SOURCE_TYPE_MAX:
        case _SOURCE_EVENT_SOURCE_TYPE_INVALID:
                assert_not_reached("Wut? I shouldn't exist.");
        }

        s->dispatching = false;

        if (r < 0)
                log_debug_errno(r, "Event source %s (type %s) returned error, disabling: %m",
                                strna(s->description), event_source_type_to_string(saved_type));

        if (s->n_ref == 0)
                source_free(s);
        else if (r < 0)
                sd_event_source_set_enabled(s, SD_EVENT_OFF);

        return 1;
}

static int event_prepare(sd_event *e) {
        int r;

        assert(e);

        for (;;) {
                sd_event_source *s;

                s = prioq_peek(e->prepare);
                if (!s || s->prepare_iteration == e->iteration || s->enabled == SD_EVENT_OFF)
                        break;

                s->prepare_iteration = e->iteration;
                r = prioq_reshuffle(e->prepare, s, &s->prepare_index);
                if (r < 0)
                        return r;

                assert(s->prepare);

                s->dispatching = true;
                r = s->prepare(s, s->userdata);
                s->dispatching = false;

                if (r < 0)
                        log_debug_errno(r, "Prepare callback of event source %s (type %s) returned error, disabling: %m",
                                        strna(s->description), event_source_type_to_string(s->type));

                if (s->n_ref == 0)
                        source_free(s);
                else if (r < 0)
                        sd_event_source_set_enabled(s, SD_EVENT_OFF);
        }

        return 0;
}

static int dispatch_exit(sd_event *e) {
        sd_event_source *p;
        _cleanup_(sd_event_unrefp) sd_event *ref = NULL;
        int r;

        assert(e);

        p = prioq_peek(e->exit);
        if (!p || p->enabled == SD_EVENT_OFF) {
                e->state = SD_EVENT_FINISHED;
                return 0;
        }

        ref = sd_event_ref(e);
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

        if (p->enabled == SD_EVENT_OFF)
                return NULL;

        return p;
}

static int arm_watchdog(sd_event *e) {
        struct itimerspec its = {};
        usec_t t;
        int r;

        assert(e);
        assert(e->watchdog_fd >= 0);

        t = sleep_between(e,
                          e->watchdog_last + (e->watchdog_period / 2),
                          e->watchdog_last + (e->watchdog_period * 3 / 4));

        timespec_store(&its.it_value, t);

        /* Make sure we never set the watchdog to 0, which tells the
         * kernel to disable it. */
        if (its.it_value.tv_sec == 0 && its.it_value.tv_nsec == 0)
                its.it_value.tv_nsec = 1;

        r = timerfd_settime(e->watchdog_fd, TFD_TIMER_ABSTIME, &its, NULL);
        if (r < 0)
                return -errno;

        return 0;
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
         * adjustments to the even source, such as changing the priority (which requires us to remove and re-add a watch
         * for the inode). Hence, let's close them when entering the first iteration after they were added, as a
         * compromise. */

        while ((d = e->inode_data_to_close)) {
                assert(d->fd >= 0);
                d->fd = safe_close(d->fd);

                LIST_REMOVE(to_close, e->inode_data_to_close, d);
        }
}

_public_ int sd_event_prepare(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        if (e->exit_requested)
                goto pending;

        e->iteration++;

        e->state = SD_EVENT_PREPARING;
        r = event_prepare(e);
        e->state = SD_EVENT_INITIAL;
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

        if (event_next_pending(e) || e->need_process_child)
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

_public_ int sd_event_wait(sd_event *e, uint64_t timeout) {
        struct epoll_event *ev_queue;
        unsigned ev_queue_max;
        int r, m, i;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_ARMED, -EBUSY);

        if (e->exit_requested) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        ev_queue_max = MAX(e->n_sources, 1u);
        ev_queue = newa(struct epoll_event, ev_queue_max);

        /* If we still have inotify data buffered, then query the other fds, but don't wait on it */
        if (e->inotify_data_buffered)
                timeout = 0;

        m = epoll_wait(e->epoll_fd, ev_queue, ev_queue_max,
                       timeout == (uint64_t) -1 ? -1 : (int) DIV_ROUND_UP(timeout, USEC_PER_MSEC));
        if (m < 0) {
                if (errno == EINTR) {
                        e->state = SD_EVENT_PENDING;
                        return 1;
                }

                r = -errno;
                goto finish;
        }

        triple_timestamp_get(&e->timestamp);

        for (i = 0; i < m; i++) {

                if (ev_queue[i].data.ptr == INT_TO_PTR(SOURCE_WATCHDOG))
                        r = flush_timer(e, e->watchdog_fd, ev_queue[i].events, NULL);
                else {
                        WakeupType *t = ev_queue[i].data.ptr;

                        switch (*t) {

                        case WAKEUP_EVENT_SOURCE:
                                r = process_io(e, ev_queue[i].data.ptr, ev_queue[i].events);
                                break;

                        case WAKEUP_CLOCK_DATA: {
                                struct clock_data *d = ev_queue[i].data.ptr;
                                r = flush_timer(e, d->fd, ev_queue[i].events, &d->next);
                                break;
                        }

                        case WAKEUP_SIGNAL_DATA:
                                r = process_signal(e, ev_queue[i].data.ptr, ev_queue[i].events);
                                break;

                        case WAKEUP_INOTIFY_DATA:
                                r = event_inotify_data_read(e, ev_queue[i].data.ptr, ev_queue[i].events);
                                break;

                        default:
                                assert_not_reached("Invalid wake-up pointer");
                        }
                }
                if (r < 0)
                        goto finish;
        }

        r = process_watchdog(e);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.monotonic, &e->monotonic);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.boottime, &e->boottime_alarm);
        if (r < 0)
                goto finish;

        if (e->need_process_child) {
                r = process_child(e);
                if (r < 0)
                        goto finish;
        }

        r = process_inotify(e);
        if (r < 0)
                goto finish;

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
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_PENDING, -EBUSY);

        if (e->exit_requested)
                return dispatch_exit(e);

        p = event_next_pending(e);
        if (p) {
                _cleanup_(sd_event_unrefp) sd_event *ref = NULL;

                ref = sd_event_ref(e);
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
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        if (e->profile_delays && e->last_run) {
                usec_t this_run;
                unsigned l;

                this_run = now(CLOCK_MONOTONIC);

                l = u64log2(this_run - e->last_run);
                assert(l < sizeof(e->delays));
                e->delays[l]++;

                if (this_run - e->last_log >= 5*USEC_PER_SEC) {
                        event_log_delays(e);
                        e->last_log = this_run;
                }
        }

        r = sd_event_prepare(e);
        if (r == 0)
                /* There was nothing? Then wait... */
                r = sd_event_wait(e, timeout);

        if (e->profile_delays)
                e->last_run = now(CLOCK_MONOTONIC);

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
        _cleanup_(sd_event_unrefp) sd_event *ref = NULL;
        int r;

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        ref = sd_event_ref(e);

        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, (uint64_t) -1);
                if (r < 0)
                        return r;
        }

        return e->exit_code;
}

_public_ int sd_event_get_fd(sd_event *e) {

        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->epoll_fd;
}

_public_ int sd_event_get_state(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->state;
}

_public_ int sd_event_get_exit_code(sd_event *e, int *code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(code, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!e->exit_requested)
                return -ENODATA;

        *code = e->exit_code;
        return 0;
}

_public_ int sd_event_exit(sd_event *e, int code) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        e->exit_requested = true;
        e->exit_code = code;

        return 0;
}

_public_ int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(usec, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!TRIPLE_TIMESTAMP_HAS_CLOCK(clock))
                return -EOPNOTSUPP;

        /* Generate a clean error in case CLOCK_BOOTTIME is not available. Note that don't use clock_supported() here,
         * for a reason: there are systems where CLOCK_BOOTTIME is supported, but CLOCK_BOOTTIME_ALARM is not, but for
         * the purpose of getting the time this doesn't matter. */
        if (IN_SET(clock, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM) && !clock_boottime_supported())
                return -EOPNOTSUPP;

        if (!triple_timestamp_is_set(&e->timestamp)) {
                /* Implicitly fall back to now() if we never ran
                 * before and thus have no cached time. */
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
        assert_return(!event_pid_changed(e), -ECHILD);

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
        assert_return(!event_pid_changed(e), -ECHILD);

        if (e->watchdog == !!b)
                return e->watchdog;

        if (b) {
                struct epoll_event ev;

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

                ev = (struct epoll_event) {
                        .events = EPOLLIN,
                        .data.ptr = INT_TO_PTR(SOURCE_WATCHDOG),
                };

                r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, e->watchdog_fd, &ev);
                if (r < 0) {
                        r = -errno;
                        goto fail;
                }

        } else {
                if (e->watchdog_fd >= 0) {
                        epoll_ctl(e->epoll_fd, EPOLL_CTL_DEL, e->watchdog_fd, NULL);
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
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->watchdog;
}

_public_ int sd_event_get_iteration(sd_event *e, uint64_t *ret) {
        assert_return(e, -EINVAL);
        assert_return(e = event_resolve(e), -ENOPKG);
        assert_return(!event_pid_changed(e), -ECHILD);

        *ret = e->iteration;
        return 0;
}

_public_ int sd_event_source_set_destroy_callback(sd_event_source *s, sd_event_destroy_t callback) {
        assert_return(s, -EINVAL);

        s->destroy_callback = callback;
        return 0;
}

_public_ int sd_event_source_get_destroy_callback(sd_event_source *s, sd_event_destroy_t *ret) {
        assert_return(s, -EINVAL);

        if (ret)
                *ret = s->destroy_callback;

        return !!s->destroy_callback;
}

_public_ int sd_event_source_get_floating(sd_event_source *s) {
        assert_return(s, -EINVAL);

        return s->floating;
}

_public_ int sd_event_source_set_floating(sd_event_source *s, int b) {
        assert_return(s, -EINVAL);

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
