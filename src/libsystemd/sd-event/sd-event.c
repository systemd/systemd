/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "missing.h"
#include "prioq.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "string-util.h"
#include "time-util.h"
#include "util.h"

#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

typedef enum EventSourceType {
        SOURCE_IO,
        SOURCE_TIME_REALTIME,
        SOURCE_TIME_BOOTTIME,
        SOURCE_TIME_MONOTONIC,
        SOURCE_TIME_REALTIME_ALARM,
        SOURCE_TIME_BOOTTIME_ALARM,
        SOURCE_SIGNAL,
        SOURCE_CHILD,
        SOURCE_DEFER,
        SOURCE_POST,
        SOURCE_EXIT,
        SOURCE_WATCHDOG,
        _SOURCE_EVENT_SOURCE_TYPE_MAX,
        _SOURCE_EVENT_SOURCE_TYPE_INVALID = -1
} EventSourceType;

/* All objects we use in epoll events start with this value, so that
 * we know how to dispatch it */
typedef enum WakeupType {
        WAKEUP_NONE,
        WAKEUP_EVENT_SOURCE,
        WAKEUP_CLOCK_DATA,
        WAKEUP_SIGNAL_DATA,
        _WAKEUP_TYPE_MAX,
        _WAKEUP_TYPE_INVALID = -1,
} WakeupType;

#define EVENT_SOURCE_IS_TIME(t) IN_SET((t), SOURCE_TIME_REALTIME, SOURCE_TIME_BOOTTIME, SOURCE_TIME_MONOTONIC, SOURCE_TIME_REALTIME_ALARM, SOURCE_TIME_BOOTTIME_ALARM)

struct sd_event_source {
        WakeupType wakeup;

        unsigned n_ref;

        sd_event *event;
        void *userdata;
        sd_event_handler_t prepare;

        char *description;

        EventSourceType type:5;
        int enabled:3;
        bool pending:1;
        bool dispatching:1;
        bool floating:1;

        int64_t priority;
        unsigned pending_index;
        unsigned prepare_index;
        unsigned pending_iteration;
        unsigned prepare_iteration;

        LIST_FIELDS(sd_event_source, sources);

        union {
                struct {
                        sd_event_io_handler_t callback;
                        int fd;
                        uint32_t events;
                        uint32_t revents;
                        bool registered:1;
                } io;
                struct {
                        sd_event_time_handler_t callback;
                        usec_t next, accuracy;
                        unsigned earliest_index;
                        unsigned latest_index;
                } time;
                struct {
                        sd_event_signal_handler_t callback;
                        struct signalfd_siginfo siginfo;
                        int sig;
                } signal;
                struct {
                        sd_event_child_handler_t callback;
                        siginfo_t siginfo;
                        pid_t pid;
                        int options;
                } child;
                struct {
                        sd_event_handler_t callback;
                } defer;
                struct {
                        sd_event_handler_t callback;
                } post;
                struct {
                        sd_event_handler_t callback;
                        unsigned prioq_index;
                } exit;
        };
};

struct clock_data {
        WakeupType wakeup;
        int fd;

        /* For all clocks we maintain two priority queues each, one
         * ordered for the earliest times the events may be
         * dispatched, and one ordered by the latest times they must
         * have been dispatched. The range between the top entries in
         * the two prioqs is the time window we can freely schedule
         * wakeups in */

        Prioq *earliest;
        Prioq *latest;
        usec_t next;

        bool needs_rearm:1;
};

struct signal_data {
        WakeupType wakeup;

        /* For each priority we maintain one signal fd, so that we
         * only have to dequeue a single event per priority at a
         * time. */

        int fd;
        int64_t priority;
        sigset_t sigset;
        sd_event_source *current;
};

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

        pid_t original_pid;

        unsigned iteration;
        dual_timestamp timestamp;
        usec_t timestamp_boottime;
        int state;

        bool exit_requested:1;
        bool need_process_child:1;
        bool watchdog:1;

        int exit_code;

        pid_t tid;
        sd_event **default_event_ptr;

        usec_t watchdog_last, watchdog_period;

        unsigned n_sources;

        LIST_HEAD(sd_event_source, sources);
};

static void source_disconnect(sd_event_source *s);

static int pending_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->pending);
        assert(y->pending);

        /* Enabled ones first */
        if (x->enabled != SD_EVENT_OFF && y->enabled == SD_EVENT_OFF)
                return -1;
        if (x->enabled == SD_EVENT_OFF && y->enabled != SD_EVENT_OFF)
                return 1;

        /* Lower priority values first */
        if (x->priority < y->priority)
                return -1;
        if (x->priority > y->priority)
                return 1;

        /* Older entries first */
        if (x->pending_iteration < y->pending_iteration)
                return -1;
        if (x->pending_iteration > y->pending_iteration)
                return 1;

        return 0;
}

static int prepare_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

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
        if (x->prepare_iteration < y->prepare_iteration)
                return -1;
        if (x->prepare_iteration > y->prepare_iteration)
                return 1;

        /* Lower priority values first */
        if (x->priority < y->priority)
                return -1;
        if (x->priority > y->priority)
                return 1;

        return 0;
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
        if (x->time.next < y->time.next)
                return -1;
        if (x->time.next > y->time.next)
                return 1;

        return 0;
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
        if (x->time.next + x->time.accuracy < y->time.next + y->time.accuracy)
                return -1;
        if (x->time.next + x->time.accuracy > y->time.next + y->time.accuracy)
                return 1;

        return 0;
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
        if (x->priority < y->priority)
                return -1;
        if (x->priority > y->priority)
                return 1;

        return 0;
}

static void free_clock_data(struct clock_data *d) {
        assert(d);
        assert(d->wakeup == WAKEUP_CLOCK_DATA);

        safe_close(d->fd);
        prioq_free(d->earliest);
        prioq_free(d->latest);
}

static void event_free(sd_event *e) {
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

        hashmap_free(e->child_sources);
        set_free(e->post_sources);
        free(e);
}

_public_ int sd_event_new(sd_event** ret) {
        sd_event *e;
        int r;

        assert_return(ret, -EINVAL);

        e = new0(sd_event, 1);
        if (!e)
                return -ENOMEM;

        e->n_ref = 1;
        e->watchdog_fd = e->epoll_fd = e->realtime.fd = e->boottime.fd = e->monotonic.fd = e->realtime_alarm.fd = e->boottime_alarm.fd = -1;
        e->realtime.next = e->boottime.next = e->monotonic.next = e->realtime_alarm.next = e->boottime_alarm.next = USEC_INFINITY;
        e->realtime.wakeup = e->boottime.wakeup = e->monotonic.wakeup = e->realtime_alarm.wakeup = e->boottime_alarm.wakeup = WAKEUP_CLOCK_DATA;
        e->original_pid = getpid();
        e->perturb = USEC_INFINITY;

        e->pending = prioq_new(pending_prioq_compare);
        if (!e->pending) {
                r = -ENOMEM;
                goto fail;
        }

        e->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (e->epoll_fd < 0) {
                r = -errno;
                goto fail;
        }

        *ret = e;
        return 0;

fail:
        event_free(e);
        return r;
}

_public_ sd_event* sd_event_ref(sd_event *e) {
        assert_return(e, NULL);

        assert(e->n_ref >= 1);
        e->n_ref++;

        return e;
}

_public_ sd_event* sd_event_unref(sd_event *e) {

        if (!e)
                return NULL;

        assert(e->n_ref >= 1);
        e->n_ref--;

        if (e->n_ref <= 0)
                event_free(e);

        return NULL;
}

static bool event_pid_changed(sd_event *e) {
        assert(e);

        /* We don't support people creating an event loop and keeping
         * it around over a fork(). Let's complain. */

        return e->original_pid != getpid();
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
                log_debug_errno(errno, "Failed to remove source %s from epoll: %m", strna(s->description));

        s->io.registered = false;
}

static int source_io_register(
                sd_event_source *s,
                int enabled,
                uint32_t events) {

        struct epoll_event ev = {};
        int r;

        assert(s);
        assert(s->type == SOURCE_IO);
        assert(enabled != SD_EVENT_OFF);

        ev.events = events;
        ev.data.ptr = s;

        if (enabled == SD_EVENT_ONESHOT)
                ev.events |= EPOLLONESHOT;

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

static int event_make_signal_data(
                sd_event *e,
                int sig,
                struct signal_data **ret) {

        struct epoll_event ev = {};
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
                priority = 0;

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

                d = new0(struct signal_data, 1);
                if (!d)
                        return -ENOMEM;

                d->wakeup = WAKEUP_SIGNAL_DATA;
                d->fd  = -1;
                d->priority = priority;

                r = hashmap_put(e->signal_data, &d->priority, d);
                if (r < 0)
                        return r;

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

        d->fd = r;

        ev.events = EPOLLIN;
        ev.data.ptr = d;

        r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, d->fd, &ev);
        if (r < 0)  {
                r = -errno;
                goto fail;
        }

        if (ret)
                *ret = d;

        return 0;

fail:
        if (added) {
                d->fd = safe_close(d->fd);
                hashmap_remove(e->signal_data, &d->priority);
                free(d);
        }

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
                hashmap_remove(e->signal_data, &d->priority);
                assert(!d->current);
                safe_close(d->fd);
                free(d);
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
        free(s->description);
        free(s);
}

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

        return 0;
}

static sd_event_source *source_new(sd_event *e, bool floating, EventSourceType type) {
        sd_event_source *s;

        assert(e);

        s = new0(sd_event_source, 1);
        if (!s)
                return NULL;

        s->n_ref = 1;
        s->event = e;
        s->floating = floating;
        s->type = type;
        s->pending_index = s->prepare_index = PRIOQ_IDX_NULL;

        if (!floating)
                sd_event_ref(e);

        LIST_PREPEND(sources, e->sources, s);
        e->n_sources ++;

        return s;
}

_public_ int sd_event_add_io(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t events,
                sd_event_io_handler_t callback,
                void *userdata) {

        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
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
        if (r < 0) {
                source_free(s);
                return r;
        }

        if (ret)
                *ret = s;

        return 0;
}

static void initialize_perturb(sd_event *e) {
        sd_id128_t bootid = {};

        /* When we sleep for longer, we try to realign the wakeup to
           the same time wihtin each minute/second/250ms, so that
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

        struct epoll_event ev = {};
        int r, fd;

        assert(e);
        assert(d);

        if (_likely_(d->fd >= 0))
                return 0;

        fd = timerfd_create(clock, TFD_NONBLOCK|TFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        ev.events = EPOLLIN;
        ev.data.ptr = d;

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
        sd_event_source *s;
        struct clock_data *d;
        int r;

        assert_return(e, -EINVAL);
        assert_return(usec != (uint64_t) -1, -EINVAL);
        assert_return(accuracy != (uint64_t) -1, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!callback)
                callback = time_exit_callback;

        type = clock_to_event_source_type(clock);
        assert_return(type >= 0, -EOPNOTSUPP);

        d = event_get_clock_data(e, type);
        assert(d);

        if (!d->earliest) {
                d->earliest = prioq_new(earliest_time_prioq_compare);
                if (!d->earliest)
                        return -ENOMEM;
        }

        if (!d->latest) {
                d->latest = prioq_new(latest_time_prioq_compare);
                if (!d->latest)
                        return -ENOMEM;
        }

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
                goto fail;

        r = prioq_put(d->latest, s, &s->time.latest_index);
        if (r < 0)
                goto fail;

        if (ret)
                *ret = s;

        return 0;

fail:
        source_free(s);
        return r;
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

        sd_event_source *s;
        struct signal_data *d;
        sigset_t ss;
        int r;

        assert_return(e, -EINVAL);
        assert_return(sig > 0, -EINVAL);
        assert_return(sig < _NSIG, -EINVAL);
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
        if (r < 0) {
                source_free(s);
                return r;
        }

        /* Use the signal name as description for the event source by default */
        (void) sd_event_source_set_description(s, signal_to_string(sig));

        if (ret)
                *ret = s;

        return 0;
}

_public_ int sd_event_add_child(
                sd_event *e,
                sd_event_source **ret,
                pid_t pid,
                int options,
                sd_event_child_handler_t callback,
                void *userdata) {

        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
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
        if (r < 0) {
                source_free(s);
                return r;
        }

        e->n_enabled_child_sources ++;

        r = event_make_signal_data(e, SIGCHLD, NULL);
        if (r < 0) {
                e->n_enabled_child_sources--;
                source_free(s);
                return r;
        }

        e->need_process_child = true;

        if (ret)
                *ret = s;

        return 0;
}

_public_ int sd_event_add_defer(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
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
        if (r < 0) {
                source_free(s);
                return r;
        }

        if (ret)
                *ret = s;

        return 0;
}

_public_ int sd_event_add_post(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
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
        if (r < 0) {
                source_free(s);
                return r;
        }

        if (ret)
                *ret = s;

        return 0;
}

_public_ int sd_event_add_exit(
                sd_event *e,
                sd_event_source **ret,
                sd_event_handler_t callback,
                void *userdata) {

        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!e->exit) {
                e->exit = prioq_new(exit_prioq_compare);
                if (!e->exit)
                        return -ENOMEM;
        }

        s = source_new(e, !ret, SOURCE_EXIT);
        if (!s)
                return -ENOMEM;

        s->exit.callback = callback;
        s->userdata = userdata;
        s->exit.prioq_index = PRIOQ_IDX_NULL;
        s->enabled = SD_EVENT_ONESHOT;

        r = prioq_put(s->event->exit, s, &s->exit.prioq_index);
        if (r < 0) {
                source_free(s);
                return r;
        }

        if (ret)
                *ret = s;

        return 0;
}

_public_ sd_event_source* sd_event_source_ref(sd_event_source *s) {
        assert_return(s, NULL);

        assert(s->n_ref >= 1);
        s->n_ref++;

        return s;
}

_public_ sd_event_source* sd_event_source_unref(sd_event_source *s) {

        if (!s)
                return NULL;

        assert(s->n_ref >= 1);
        s->n_ref--;

        if (s->n_ref <= 0) {
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
        }

        return NULL;
}

_public_ int sd_event_source_set_description(sd_event_source *s, const char *description) {
        assert_return(s, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        return free_and_strdup(&s->description, description);
}

_public_ int sd_event_source_get_description(sd_event_source *s, const char **description) {
        assert_return(s, -EINVAL);
        assert_return(description, -EINVAL);
        assert_return(s->description, -ENXIO);
        assert_return(!event_pid_changed(s->event), -ECHILD);

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

        if (s->enabled != SD_EVENT_OFF) {
                r = source_io_register(s, s->enabled, events);
                if (r < 0)
                        return r;
        }

        s->io.events = events;
        source_set_pending(s, false);

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

        return s->priority;
}

_public_ int sd_event_source_set_priority(sd_event_source *s, int64_t priority) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        if (s->priority == priority)
                return 0;

        if (s->type == SOURCE_SIGNAL && s->enabled != SD_EVENT_OFF) {
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
}

_public_ int sd_event_source_get_enabled(sd_event_source *s, int *m) {
        assert_return(s, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        *m = s->enabled;
        return 0;
}

_public_ int sd_event_source_set_enabled(sd_event_source *s, int m) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(m == SD_EVENT_OFF || m == SD_EVENT_ON || m == SD_EVENT_ONESHOT, -EINVAL);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        /* If we are dead anyway, we are fine with turning off
         * sources, but everything else needs to fail. */
        if (s->event->state == SD_EVENT_FINISHED)
                return m == SD_EVENT_OFF ? 0 : -ESTALE;

        if (s->enabled == m)
                return 0;

        if (m == SD_EVENT_OFF) {

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
                        s->enabled = m;
                        break;

                default:
                        assert_not_reached("Wut? I shouldn't exist.");
                }

        } else {
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

        assert_return(s, -EINVAL);
        assert_return(usec != (uint64_t) -1, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        s->time.next = usec;

        source_set_pending(s, false);

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

        assert_return(s, -EINVAL);
        assert_return(usec != (uint64_t) -1, -EINVAL);
        assert_return(EVENT_SOURCE_IS_TIME(s->type), -EDOM);
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(s->event), -ECHILD);

        if (usec == 0)
                usec = DEFAULT_ACCURACY_USEC;

        s->time.accuracy = usec;

        source_set_pending(s, false);

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
        if (!a || a->enabled == SD_EVENT_OFF) {

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

        t = sleep_between(e, a->time.next, b->time.next + b->time.accuracy);
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
                if (errno == EAGAIN || errno == EINTR)
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
                        bool zombie =
                                s->child.siginfo.si_code == CLD_EXITED ||
                                s->child.siginfo.si_code == CLD_KILLED ||
                                s->child.siginfo.si_code == CLD_DUMPED;

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
                        if (errno == EAGAIN || errno == EINTR)
                                return read_one;

                        return -errno;
                }

                if (_unlikely_(n != sizeof(si)))
                        return -EIO;

                assert(si.ssi_signo < _NSIG);

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

static int source_dispatch(sd_event_source *s) {
        int r = 0;

        assert(s);
        assert(s->pending || s->type == SOURCE_EXIT);

        if (s->type != SOURCE_DEFER && s->type != SOURCE_EXIT) {
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

                zombie = s->child.siginfo.si_code == CLD_EXITED ||
                         s->child.siginfo.si_code == CLD_KILLED ||
                         s->child.siginfo.si_code == CLD_DUMPED;

                r = s->child.callback(s, &s->child.siginfo, s->userdata);

                /* Now, reap the PID for good. */
                if (zombie)
                        waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|WEXITED);

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

        case SOURCE_WATCHDOG:
        case _SOURCE_EVENT_SOURCE_TYPE_MAX:
        case _SOURCE_EVENT_SOURCE_TYPE_INVALID:
                assert_not_reached("Wut? I shouldn't exist.");
        }

        s->dispatching = false;

        if (r < 0) {
                if (s->description)
                        log_debug_errno(r, "Event source '%s' returned error, disabling: %m", s->description);
                else
                        log_debug_errno(r, "Event source %p returned error, disabling: %m", s);
        }

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

                if (r < 0) {
                        if (s->description)
                                log_debug_errno(r, "Prepare callback of event source '%s' returned error, disabling: %m", s->description);
                        else
                                log_debug_errno(r, "Prepare callback of event source %p returned error, disabling: %m", s);
                }

                if (s->n_ref == 0)
                        source_free(s);
                else if (r < 0)
                        sd_event_source_set_enabled(s, SD_EVENT_OFF);
        }

        return 0;
}

static int dispatch_exit(sd_event *e) {
        sd_event_source *p;
        int r;

        assert(e);

        p = prioq_peek(e->exit);
        if (!p || p->enabled == SD_EVENT_OFF) {
                e->state = SD_EVENT_FINISHED;
                return 0;
        }

        sd_event_ref(e);
        e->iteration++;
        e->state = SD_EVENT_EXITING;

        r = source_dispatch(p);

        e->state = SD_EVENT_INITIAL;
        sd_event_unref(e);

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

_public_ int sd_event_prepare(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        if (e->exit_requested)
                goto pending;

        e->iteration++;

        r = event_prepare(e);
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
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_ARMED, -EBUSY);

        if (e->exit_requested) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        ev_queue_max = MAX(e->n_sources, 1u);
        ev_queue = newa(struct epoll_event, ev_queue_max);

        m = epoll_wait(e->epoll_fd, ev_queue, ev_queue_max,
                       timeout == (uint64_t) -1 ? -1 : (int) ((timeout + USEC_PER_MSEC - 1) / USEC_PER_MSEC));
        if (m < 0) {
                if (errno == EINTR) {
                        e->state = SD_EVENT_PENDING;
                        return 1;
                }

                r = -errno;
                goto finish;
        }

        dual_timestamp_get(&e->timestamp);
        e->timestamp_boottime = now(CLOCK_BOOTTIME);

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

        r = process_timer(e, e->timestamp_boottime, &e->boottime);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.monotonic, &e->monotonic);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp.realtime, &e->realtime_alarm);
        if (r < 0)
                goto finish;

        r = process_timer(e, e->timestamp_boottime, &e->boottime_alarm);
        if (r < 0)
                goto finish;

        if (e->need_process_child) {
                r = process_child(e);
                if (r < 0)
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
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_PENDING, -EBUSY);

        if (e->exit_requested)
                return dispatch_exit(e);

        p = event_next_pending(e);
        if (p) {
                sd_event_ref(e);

                e->state = SD_EVENT_RUNNING;
                r = source_dispatch(p);
                e->state = SD_EVENT_INITIAL;

                sd_event_unref(e);

                return r;
        }

        e->state = SD_EVENT_INITIAL;

        return 1;
}

_public_ int sd_event_run(sd_event *e, uint64_t timeout) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        r = sd_event_prepare(e);
        if (r == 0)
                /* There was nothing? Then wait... */
                r = sd_event_wait(e, timeout);

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
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state == SD_EVENT_INITIAL, -EBUSY);

        sd_event_ref(e);

        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, (uint64_t) -1);
                if (r < 0)
                        goto finish;
        }

        r = e->exit_code;

finish:
        sd_event_unref(e);
        return r;
}

_public_ int sd_event_get_fd(sd_event *e) {

        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->epoll_fd;
}

_public_ int sd_event_get_state(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->state;
}

_public_ int sd_event_get_exit_code(sd_event *e, int *code) {
        assert_return(e, -EINVAL);
        assert_return(code, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!e->exit_requested)
                return -ENODATA;

        *code = e->exit_code;
        return 0;
}

_public_ int sd_event_exit(sd_event *e, int code) {
        assert_return(e, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        e->exit_requested = true;
        e->exit_code = code;

        return 0;
}

_public_ int sd_event_now(sd_event *e, clockid_t clock, uint64_t *usec) {
        assert_return(e, -EINVAL);
        assert_return(usec, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!dual_timestamp_is_set(&e->timestamp)) {
                /* Implicitly fall back to now() if we never ran
                 * before and thus have no cached time. */
                *usec = now(clock);
                return 1;
        }

        switch (clock) {

        case CLOCK_REALTIME:
        case CLOCK_REALTIME_ALARM:
                *usec = e->timestamp.realtime;
                break;

        case CLOCK_MONOTONIC:
                *usec = e->timestamp.monotonic;
                break;

        case CLOCK_BOOTTIME:
        case CLOCK_BOOTTIME_ALARM:
                *usec = e->timestamp_boottime;
                break;
        }

        return 0;
}

_public_ int sd_event_default(sd_event **ret) {

        static thread_local sd_event *default_event = NULL;
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
        assert_return(!event_pid_changed(e), -ECHILD);

        if (e->watchdog == !!b)
                return e->watchdog;

        if (b) {
                struct epoll_event ev = {};

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

                ev.events = EPOLLIN;
                ev.data.ptr = INT_TO_PTR(SOURCE_WATCHDOG);

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
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->watchdog;
}
