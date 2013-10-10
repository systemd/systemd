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

#include "macro.h"
#include "prioq.h"
#include "hashmap.h"
#include "util.h"
#include "time-util.h"
#include "sd-id128.h"

#include "sd-event.h"

#define EPOLL_QUEUE_MAX 64
#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

typedef enum EventSourceType {
        SOURCE_IO,
        SOURCE_MONOTONIC,
        SOURCE_REALTIME,
        SOURCE_SIGNAL,
        SOURCE_CHILD,
        SOURCE_DEFER,
        SOURCE_QUIT
} EventSourceType;

struct sd_event_source {
        unsigned n_ref;

        sd_event *event;
        void *userdata;
        sd_prepare_handler_t prepare;

        EventSourceType type:4;
        int mute:3;
        bool pending:1;

        int priority;
        unsigned pending_index;
        unsigned prepare_index;
        unsigned pending_iteration;
        unsigned prepare_iteration;

        union {
                struct {
                        sd_io_handler_t callback;
                        int fd;
                        uint32_t events;
                        uint32_t revents;
                        bool registered:1;
                } io;
                struct {
                        sd_time_handler_t callback;
                        usec_t next, accuracy;
                        unsigned earliest_index;
                        unsigned latest_index;
                } time;
                struct {
                        sd_signal_handler_t callback;
                        struct signalfd_siginfo siginfo;
                        int sig;
                } signal;
                struct {
                        sd_child_handler_t callback;
                        siginfo_t siginfo;
                        pid_t pid;
                        int options;
                } child;
                struct {
                        sd_defer_handler_t callback;
                } defer;
                struct {
                        sd_quit_handler_t callback;
                        unsigned prioq_index;
                } quit;
        };
};

struct sd_event {
        unsigned n_ref;

        int epoll_fd;
        int signal_fd;
        int realtime_fd;
        int monotonic_fd;

        Prioq *pending;
        Prioq *prepare;

        /* For both clocks we maintain two priority queues each, one
         * ordered for the earliest times the events may be
         * dispatched, and one ordered by the latest times they must
         * have been dispatched. The range between the top entries in
         * the two prioqs is the time window we can freely schedule
         * wakeups in */
        Prioq *monotonic_earliest;
        Prioq *monotonic_latest;
        Prioq *realtime_earliest;
        Prioq *realtime_latest;

        usec_t realtime_next, monotonic_next;
        usec_t perturb;

        sigset_t sigset;
        sd_event_source **signal_sources;

        Hashmap *child_sources;
        unsigned n_unmuted_child_sources;

        Prioq *quit;

        pid_t original_pid;

        unsigned iteration;
        int state;

        bool quit_requested:1;
        bool need_process_child:1;
};

static int pending_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->pending);
        assert(y->pending);

        /* Unmuted ones first */
        if (x->mute != SD_EVENT_MUTED && y->mute == SD_EVENT_MUTED)
                return -1;
        if (x->mute == SD_EVENT_MUTED && y->mute != SD_EVENT_MUTED)
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

        /* Stability for the rest */
        if (x < y)
                return -1;
        if (x > y)
                return 1;

        return 0;
}

static int prepare_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->prepare);
        assert(y->prepare);

        /* Move most recently prepared ones last, so that we can stop
         * preparing as soon as we hit one that has already been
         * prepared in the current iteration */
        if (x->prepare_iteration < y->prepare_iteration)
                return -1;
        if (x->prepare_iteration > y->prepare_iteration)
                return 1;

        /* Unmuted ones first */
        if (x->mute != SD_EVENT_MUTED && y->mute == SD_EVENT_MUTED)
                return -1;
        if (x->mute == SD_EVENT_MUTED && y->mute != SD_EVENT_MUTED)
                return 1;

        /* Lower priority values first */
        if (x->priority < y->priority)
                return -1;
        if (x->priority > y->priority)
                return 1;

        /* Stability for the rest */
        if (x < y)
                return -1;
        if (x > y)
                return 1;

        return 0;
}

static int earliest_time_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->type == SOURCE_MONOTONIC || x->type == SOURCE_REALTIME);
        assert(y->type == SOURCE_MONOTONIC || y->type == SOURCE_REALTIME);

        /* Unmuted ones first */
        if (x->mute != SD_EVENT_MUTED && y->mute == SD_EVENT_MUTED)
                return -1;
        if (x->mute == SD_EVENT_MUTED && y->mute != SD_EVENT_MUTED)
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
                return -1;

        /* Stability for the rest */
        if (x < y)
                return -1;
        if (x > y)
                return 1;

        return 0;
}

static int latest_time_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert((x->type == SOURCE_MONOTONIC && y->type == SOURCE_MONOTONIC) ||
               (x->type == SOURCE_REALTIME && y->type == SOURCE_REALTIME));

        /* Unmuted ones first */
        if (x->mute != SD_EVENT_MUTED && y->mute == SD_EVENT_MUTED)
                return -1;
        if (x->mute == SD_EVENT_MUTED && y->mute != SD_EVENT_MUTED)
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
                return -1;

        /* Stability for the rest */
        if (x < y)
                return -1;
        if (x > y)
                return 1;

        return 0;
}

static int quit_prioq_compare(const void *a, const void *b) {
        const sd_event_source *x = a, *y = b;

        assert(x->type == SOURCE_QUIT);
        assert(y->type == SOURCE_QUIT);

        /* Unmuted ones first */
        if (x->mute != SD_EVENT_MUTED && y->mute == SD_EVENT_MUTED)
                return -1;
        if (x->mute == SD_EVENT_MUTED && y->mute != SD_EVENT_MUTED)
                return 1;

        /* Lower priority values first */
        if (x->priority < y->priority)
                return -1;
        if (x->priority > y->priority)
                return 1;

        /* Stability for the rest */
        if (x < y)
                return -1;
        if (x > y)
                return 1;

        return 0;
}

static void event_free(sd_event *e) {
        assert(e);

        if (e->epoll_fd >= 0)
                close_nointr_nofail(e->epoll_fd);

        if (e->signal_fd >= 0)
                close_nointr_nofail(e->signal_fd);

        if (e->realtime_fd >= 0)
                close_nointr_nofail(e->realtime_fd);

        if (e->monotonic_fd >= 0)
                close_nointr_nofail(e->monotonic_fd);

        prioq_free(e->pending);
        prioq_free(e->prepare);
        prioq_free(e->monotonic_earliest);
        prioq_free(e->monotonic_latest);
        prioq_free(e->realtime_earliest);
        prioq_free(e->realtime_latest);
        prioq_free(e->quit);

        free(e->signal_sources);

        hashmap_free(e->child_sources);
        free(e);
}

int sd_event_new(sd_event** ret) {
        sd_event *e;
        int r;

        if (!ret)
                return -EINVAL;

        e = new0(sd_event, 1);
        if (!e)
                return -ENOMEM;

        e->n_ref = 1;
        e->signal_fd = e->realtime_fd = e->monotonic_fd = e->epoll_fd = -1;
        e->realtime_next = e->monotonic_next = (usec_t) -1;
        e->original_pid = getpid();

        assert_se(sigemptyset(&e->sigset) == 0);

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

sd_event* sd_event_ref(sd_event *e) {
        if (!e)
                return NULL;

        assert(e->n_ref >= 1);
        e->n_ref++;

        return e;
}

sd_event* sd_event_unref(sd_event *e) {
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

        /* We don't support people creating am event loop and keeping
         * it around over a fork(). Let's complain. */

        return e->original_pid != getpid();
}

static int source_io_unregister(sd_event_source *s) {
        int r;

        assert(s);
        assert(s->type == SOURCE_IO);

        if (!s->io.registered)
                return 0;

        r = epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->io.fd, NULL);
        if (r < 0)
                return -errno;

        s->io.registered = false;
        return 0;
}

static int source_io_register(sd_event_source *s, int mute, uint32_t events) {
        struct epoll_event ev = {};
        int r;

        assert(s);
        assert(s->type == SOURCE_IO);
        assert(mute != SD_EVENT_MUTED);

        ev.events = events;
        ev.data.ptr = s;

        if (mute == SD_EVENT_ONESHOT)
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

static void source_free(sd_event_source *s) {
        assert(s);

        if (s->event) {
                switch (s->type) {

                case SOURCE_IO:
                        if (s->io.fd >= 0)
                                source_io_unregister(s);

                        break;

                case SOURCE_MONOTONIC:
                        prioq_remove(s->event->monotonic_earliest, s, &s->time.earliest_index);
                        prioq_remove(s->event->monotonic_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_REALTIME:
                        prioq_remove(s->event->realtime_earliest, s, &s->time.earliest_index);
                        prioq_remove(s->event->realtime_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_SIGNAL:
                        if (s->signal.sig > 0) {
                                if (s->signal.sig != SIGCHLD || s->event->n_unmuted_child_sources == 0)
                                        assert_se(sigdelset(&s->event->sigset, s->signal.sig) == 0);

                                if (s->event->signal_sources)
                                        s->event->signal_sources[s->signal.sig] = NULL;
                        }

                        break;

                case SOURCE_CHILD:
                        if (s->child.pid > 0) {
                                if (s->mute != SD_EVENT_MUTED) {
                                        assert(s->event->n_unmuted_child_sources > 0);
                                        s->event->n_unmuted_child_sources--;
                                }

                                if (!s->event->signal_sources || !s->event->signal_sources[SIGCHLD])
                                        assert_se(sigdelset(&s->event->sigset, SIGCHLD) == 0);

                                hashmap_remove(s->event->child_sources, INT_TO_PTR(s->child.pid));
                        }

                        break;

                case SOURCE_QUIT:
                        prioq_remove(s->event->quit, s, &s->quit.prioq_index);
                        break;
                }

                if (s->pending)
                        prioq_remove(s->event->pending, s, &s->pending_index);

                if (s->prepare)
                        prioq_remove(s->event->prepare, s, &s->prepare_index);

                sd_event_unref(s->event);
        }

        free(s);
}

static int source_set_pending(sd_event_source *s, bool b) {
        int r;

        assert(s);
        assert(s->type != SOURCE_QUIT);

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

        return 0;
}

static sd_event_source *source_new(sd_event *e, EventSourceType type) {
        sd_event_source *s;

        assert(e);

        s = new0(sd_event_source, 1);
        if (!s)
                return NULL;

        s->n_ref = 1;
        s->event = sd_event_ref(e);
        s->type = type;
        s->pending_index = s->prepare_index = PRIOQ_IDX_NULL;

        return s;
}

int sd_event_add_io(
                sd_event *e,
                int fd,
                uint32_t events,
                sd_io_handler_t callback,
                void *userdata,
                sd_event_source **ret) {

        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        if (fd < 0)
                return -EINVAL;
        if (events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP))
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(e))
                return -ECHILD;

        s = source_new(e, SOURCE_IO);
        if (!s)
                return -ENOMEM;

        s->io.fd = fd;
        s->io.events = events;
        s->io.callback = callback;
        s->userdata = userdata;
        s->mute = SD_EVENT_UNMUTED;

        r = source_io_register(s, s->mute, events);
        if (r < 0) {
                source_free(s);
                return -errno;
        }

        *ret = s;
        return 0;
}

static int event_setup_timer_fd(
                sd_event *e,
                EventSourceType type,
                int *timer_fd,
                clockid_t id) {

        struct epoll_event ev = {};
        int r, fd;
        sd_id128_t bootid;

        assert(e);
        assert(timer_fd);

        if (_likely_(*timer_fd >= 0))
                return 0;

        fd = timerfd_create(id, TFD_NONBLOCK|TFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        ev.events = EPOLLIN;
        ev.data.ptr = INT_TO_PTR(type);

        r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0) {
                close_nointr_nofail(fd);
                return -errno;
        }

        /* When we sleep for longer, we try to realign the wakeup to
           the same time wihtin each second, so that events all across
           the system can be coalesced into a single CPU
           wakeup. However, let's take some system-specific randomness
           for this value, so that in a network of systems with synced
           clocks timer events are distributed a bit. Here, we
           calculate a perturbation usec offset from the boot ID. */

        if (sd_id128_get_boot(&bootid) >= 0)
                e->perturb = (bootid.qwords[0] ^ bootid.qwords[1]) % USEC_PER_SEC;

        *timer_fd = fd;
        return 0;
}

static int event_add_time_internal(
                sd_event *e,
                EventSourceType type,
                int *timer_fd,
                clockid_t id,
                Prioq **earliest,
                Prioq **latest,
                uint64_t usec,
                uint64_t accuracy,
                sd_time_handler_t callback,
                void *userdata,
                sd_event_source **ret) {

        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        if (usec == (uint64_t) -1)
                return -EINVAL;
        if (accuracy == (uint64_t) -1)
                return -EINVAL;
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(e))
                return -ECHILD;

        assert(timer_fd);
        assert(earliest);
        assert(latest);

        if (!*earliest) {
                *earliest = prioq_new(earliest_time_prioq_compare);
                if (!*earliest)
                        return -ENOMEM;
        }

        if (!*latest) {
                *latest = prioq_new(latest_time_prioq_compare);
                if (!*latest)
                        return -ENOMEM;
        }

        if (*timer_fd < 0) {
                r = event_setup_timer_fd(e, type, timer_fd, id);
                if (r < 0)
                        return r;
        }

        s = source_new(e, type);
        if (!s)
                return -ENOMEM;

        s->time.next = usec;
        s->time.accuracy = accuracy == 0 ? DEFAULT_ACCURACY_USEC : accuracy;
        s->time.callback = callback;
        s->time.earliest_index = s->time.latest_index = PRIOQ_IDX_NULL;
        s->userdata = userdata;
        s->mute = SD_EVENT_ONESHOT;

        r = prioq_put(*earliest, s, &s->time.earliest_index);
        if (r < 0)
                goto fail;

        r = prioq_put(*latest, s, &s->time.latest_index);
        if (r < 0)
                goto fail;

        *ret = s;
        return 0;

fail:
        source_free(s);
        return r;
}

int sd_event_add_monotonic(sd_event *e, uint64_t usec, uint64_t accuracy, sd_time_handler_t callback, void *userdata, sd_event_source **ret) {
        return event_add_time_internal(e, SOURCE_MONOTONIC, &e->monotonic_fd, CLOCK_MONOTONIC, &e->monotonic_earliest, &e->monotonic_latest, usec, accuracy, callback, userdata, ret);
}

int sd_event_add_realtime(sd_event *e, uint64_t usec, uint64_t accuracy, sd_time_handler_t callback, void *userdata, sd_event_source **ret) {
        return event_add_time_internal(e, SOURCE_REALTIME, &e->realtime_fd, CLOCK_REALTIME, &e->realtime_earliest, &e->monotonic_latest, usec, accuracy, callback, userdata, ret);
}

static int event_update_signal_fd(sd_event *e) {
        struct epoll_event ev = {};
        bool add_to_epoll;
        int r;

        assert(e);

        add_to_epoll = e->signal_fd < 0;

        r = signalfd(e->signal_fd, &e->sigset, SFD_NONBLOCK|SFD_CLOEXEC);
        if (r < 0)
                return -errno;

        e->signal_fd = r;

        if (!add_to_epoll)
                return 0;

        ev.events = EPOLLIN;
        ev.data.ptr = INT_TO_PTR(SOURCE_SIGNAL);

        r = epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, e->signal_fd, &ev);
        if (r < 0) {
                close_nointr_nofail(e->signal_fd);
                e->signal_fd = -1;

                return -errno;
        }

        return 0;
}

int sd_event_add_signal(sd_event *e, int sig, sd_signal_handler_t callback, void *userdata, sd_event_source **ret) {
        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        if (sig <= 0)
                return -EINVAL;
        if (sig >= _NSIG)
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(e))
                return -ECHILD;

        if (!e->signal_sources) {
                e->signal_sources = new0(sd_event_source*, _NSIG);
                if (!e->signal_sources)
                        return -ENOMEM;
        } else if (e->signal_sources[sig])
                return -EBUSY;

        s = source_new(e, SOURCE_SIGNAL);
        if (!s)
                return -ENOMEM;

        s->signal.sig = sig;
        s->signal.callback = callback;
        s->userdata = userdata;
        s->mute = SD_EVENT_UNMUTED;

        e->signal_sources[sig] = s;
        assert_se(sigaddset(&e->sigset, sig) == 0);

        if (sig != SIGCHLD || e->n_unmuted_child_sources == 0) {
                r = event_update_signal_fd(e);
                if (r < 0) {
                        source_free(s);
                        return r;
                }
        }

        *ret = s;
        return 0;
}

int sd_event_add_child(sd_event *e, pid_t pid, int options, sd_child_handler_t callback, void *userdata, sd_event_source **ret) {
        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        if (pid <= 1)
                return -EINVAL;
        if (options & ~(WEXITED|WSTOPPED|WCONTINUED))
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(e))
                return -ECHILD;

        r = hashmap_ensure_allocated(&e->child_sources, trivial_hash_func, trivial_compare_func);
        if (r < 0)
                return r;

        if (hashmap_contains(e->child_sources, INT_TO_PTR(pid)))
                return -EBUSY;

        s = source_new(e, SOURCE_CHILD);
        if (!s)
                return -ENOMEM;

        s->child.pid = pid;
        s->child.options = options;
        s->child.callback = callback;
        s->userdata = userdata;
        s->mute = SD_EVENT_ONESHOT;

        r = hashmap_put(e->child_sources, INT_TO_PTR(pid), s);
        if (r < 0) {
                source_free(s);
                return r;
        }

        e->n_unmuted_child_sources ++;

        assert_se(sigaddset(&e->sigset, SIGCHLD) == 0);

        if (!e->signal_sources || !e->signal_sources[SIGCHLD]) {
                r = event_update_signal_fd(e);
                if (r < 0) {
                        source_free(s);
                        return -errno;
                }
        }

        e->need_process_child = true;

        *ret = s;
        return 0;
}

int sd_event_add_defer(sd_event *e, sd_defer_handler_t callback, void *userdata, sd_event_source **ret) {
        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        if (!ret)
                return -EINVAL;
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(e))
                return -ECHILD;

        s = source_new(e, SOURCE_DEFER);
        if (!s)
                return -ENOMEM;

        s->defer.callback = callback;
        s->userdata = userdata;
        s->mute = SD_EVENT_ONESHOT;

        r = source_set_pending(s, true);
        if (r < 0) {
                source_free(s);
                return r;
        }

        *ret = s;
        return 0;
}

int sd_event_add_quit(sd_event *e, sd_quit_handler_t callback, void *userdata, sd_event_source **ret) {
        sd_event_source *s;
        int r;

        assert_return(e, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        if (!e->quit) {
                e->quit = prioq_new(quit_prioq_compare);
                if (!e->quit)
                        return -ENOMEM;
        }

        s = source_new(e, SOURCE_QUIT);
        if (!s)
                return -ENOMEM;

        s->quit.callback = callback;
        s->userdata = userdata;
        s->quit.prioq_index = PRIOQ_IDX_NULL;
        s->mute = SD_EVENT_ONESHOT;

        r = prioq_put(s->event->quit, s, &s->quit.prioq_index);
        if (r < 0) {
                source_free(s);
                return r;
        }

        *ret = s;
        return 0;
}

sd_event_source* sd_event_source_ref(sd_event_source *s) {
        assert_return(s, NULL);

        assert(s->n_ref >= 1);
        s->n_ref++;

        return s;
}

sd_event_source* sd_event_source_unref(sd_event_source *s) {
        assert_return(s, NULL);

        assert(s->n_ref >= 1);
        s->n_ref--;

        if (s->n_ref <= 0)
                source_free(s);

        return NULL;
}

sd_event *sd_event_get(sd_event_source *s) {
        if (!s)
                return NULL;

        return s->event;
}

int sd_event_source_get_pending(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        return s->pending;
}

int sd_event_source_get_io_fd(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (event_pid_changed(s->event))
                return -ECHILD;

        return s->io.fd;
}

int sd_event_source_get_io_events(sd_event_source *s, uint32_t* events) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (!events)
                return -EINVAL;
        if (event_pid_changed(s->event))
                return -ECHILD;

        *events = s->io.events;
        return 0;
}

int sd_event_source_set_io_events(sd_event_source *s, uint32_t events) {
        int r;

        if (!s)
                return -EINVAL;
        if (!s->type != SOURCE_IO)
                return -EDOM;
        if (events & ~(EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLERR|EPOLLHUP))
                return -EINVAL;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        if (s->io.events == events)
                return 0;

        if (s->mute != SD_EVENT_MUTED) {
                r = source_io_register(s, s->io.events, events);
                if (r < 0)
                        return r;
        }

        s->io.events = events;

        return 0;
}

int sd_event_source_get_io_revents(sd_event_source *s, uint32_t* revents) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_IO)
                return -EDOM;
        if (!revents)
                return -EINVAL;
        if (!s->pending)
                return -ENODATA;
        if (event_pid_changed(s->event))
                return -ECHILD;

        *revents = s->io.revents;
        return 0;
}

int sd_event_source_get_signal(sd_event_source *s) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_SIGNAL)
                return -EDOM;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        return s->signal.sig;
}

int sd_event_source_get_priority(sd_event_source *s, int *priority) {
        if (!s)
                return -EINVAL;
        if (event_pid_changed(s->event))
                return -ECHILD;

        return s->priority;
}

int sd_event_source_set_priority(sd_event_source *s, int priority) {
        if (!s)
                return -EINVAL;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        if (s->priority == priority)
                return 0;

        s->priority = priority;

        if (s->pending)
                prioq_reshuffle(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

        return 0;
}

int sd_event_source_get_mute(sd_event_source *s, int *m) {
        if (!s)
                return -EINVAL;
        if (!m)
                return -EINVAL;
        if (event_pid_changed(s->event))
                return -ECHILD;

        *m = s->mute;
        return 0;
}

int sd_event_source_set_mute(sd_event_source *s, int m) {
        int r;

        if (!s)
                return -EINVAL;
        if (m != SD_EVENT_MUTED && m != SD_EVENT_UNMUTED && !SD_EVENT_ONESHOT)
                return -EINVAL;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        if (s->mute == m)
                return 0;

        if (m == SD_EVENT_MUTED) {

                switch (s->type) {

                case SOURCE_IO:
                        r = source_io_unregister(s);
                        if (r < 0)
                                return r;

                        s->mute = m;
                        break;

                case SOURCE_MONOTONIC:
                        s->mute = m;
                        prioq_reshuffle(s->event->monotonic_earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(s->event->monotonic_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_REALTIME:
                        s->mute = m;
                        prioq_reshuffle(s->event->realtime_earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(s->event->realtime_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_SIGNAL:
                        s->mute = m;
                        if (s->signal.sig != SIGCHLD || s->event->n_unmuted_child_sources == 0) {
                                assert_se(sigdelset(&s->event->sigset, s->signal.sig) == 0);
                                event_update_signal_fd(s->event);
                        }

                        break;

                case SOURCE_CHILD:
                        s->mute = m;

                        assert(s->event->n_unmuted_child_sources > 0);
                        s->event->n_unmuted_child_sources--;

                        if (!s->event->signal_sources || !s->event->signal_sources[SIGCHLD]) {
                                assert_se(sigdelset(&s->event->sigset, SIGCHLD) == 0);
                                event_update_signal_fd(s->event);
                        }

                        break;

                case SOURCE_DEFER:
                case SOURCE_QUIT:
                        s->mute = m;
                        break;
                }

        } else {
                switch (s->type) {

                case SOURCE_IO:
                        r = source_io_register(s, m, s->io.events);
                        if (r < 0)
                                return r;

                        s->mute = m;
                        break;

                case SOURCE_MONOTONIC:
                        s->mute = m;
                        prioq_reshuffle(s->event->monotonic_earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(s->event->monotonic_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_REALTIME:
                        s->mute = m;
                        prioq_reshuffle(s->event->realtime_earliest, s, &s->time.earliest_index);
                        prioq_reshuffle(s->event->realtime_latest, s, &s->time.latest_index);
                        break;

                case SOURCE_SIGNAL:
                        s->mute = m;

                        if (s->signal.sig != SIGCHLD || s->event->n_unmuted_child_sources == 0)  {
                                assert_se(sigaddset(&s->event->sigset, s->signal.sig) == 0);
                                event_update_signal_fd(s->event);
                        }
                        break;

                case SOURCE_CHILD:
                        s->mute = m;

                        if (s->mute == SD_EVENT_MUTED) {
                                s->event->n_unmuted_child_sources++;

                                if (!s->event->signal_sources || !s->event->signal_sources[SIGCHLD]) {
                                        assert_se(sigaddset(&s->event->sigset, SIGCHLD) == 0);
                                        event_update_signal_fd(s->event);
                                }
                        }
                        break;

                case SOURCE_DEFER:
                case SOURCE_QUIT:
                        s->mute = m;
                        break;
                }
        }

        if (s->pending)
                prioq_reshuffle(s->event->pending, s, &s->pending_index);

        if (s->prepare)
                prioq_reshuffle(s->event->prepare, s, &s->prepare_index);

        return 0;
}

int sd_event_source_get_time(sd_event_source *s, uint64_t *usec) {
        if (!s)
                return -EINVAL;
        if (!usec)
                return -EINVAL;
        if (s->type != SOURCE_REALTIME && s->type != SOURCE_MONOTONIC)
                return -EDOM;
        if (event_pid_changed(s->event))
                return -ECHILD;

        *usec = s->time.next;
        return 0;
}

int sd_event_source_set_time(sd_event_source *s, uint64_t usec) {
        if (!s)
                return -EINVAL;
        if (usec == (uint64_t) -1)
                return -EINVAL;
        if (s->type != SOURCE_REALTIME && s->type != SOURCE_MONOTONIC)
                return -EDOM;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        if (s->time.next == usec)
                return 0;

        s->time.next = usec;

        if (s->type == SOURCE_REALTIME) {
                prioq_reshuffle(s->event->realtime_earliest, s, &s->time.earliest_index);
                prioq_reshuffle(s->event->realtime_latest, s, &s->time.latest_index);
        } else {
                prioq_reshuffle(s->event->monotonic_earliest, s, &s->time.earliest_index);
                prioq_reshuffle(s->event->monotonic_latest, s, &s->time.latest_index);
        }

        return 0;
}

int sd_event_source_set_time_accuracy(sd_event_source *s, uint64_t usec) {
        if (!s)
                return -EINVAL;
        if (s->type != SOURCE_MONOTONIC && s->type != SOURCE_REALTIME)
                return -EDOM;
        assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
        if (event_pid_changed(s->event))
                return -ECHILD;

        if (usec == 0)
                usec = DEFAULT_ACCURACY_USEC;

        if (s->time.accuracy == usec)
                return 0;

        s->time.accuracy = usec;

        if (s->type == SOURCE_REALTIME)
                prioq_reshuffle(s->event->realtime_latest, s, &s->time.latest_index);
        else
                prioq_reshuffle(s->event->monotonic_latest, s, &s->time.latest_index);

        return 0;
}

int sd_event_source_get_time_accuracy(sd_event_source *s, uint64_t *usec) {
        if (!s)
                return -EINVAL;
        if (!usec)
                return -EINVAL;
        if (s->type != SOURCE_MONOTONIC && s->type != SOURCE_REALTIME)
                return -EDOM;
        if (event_pid_changed(s->event))
                return -ECHILD;

        *usec = s->time.accuracy;
        return 0;
}

int sd_event_source_set_prepare(sd_event_source *s, sd_prepare_handler_t callback) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(s->type != SOURCE_QUIT, -EDOM);
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

void* sd_event_source_get_userdata(sd_event_source *s) {
        assert_return(s, NULL);

        return s->userdata;
}

static usec_t sleep_between(sd_event *e, usec_t a, usec_t b) {
        usec_t c;
        assert(e);
        assert(a <= b);

        if (a <= 0)
                return 0;

        if (b <= a + 1)
                return a;

        /*
          Find a good time to wake up again between times a and b. We
          have two goals here:

          a) We want to wake up as seldom as possible, hence prefer
             later times over earlier times.

          b) But if we have to wake up, then let's make sure to
             dispatch as much as possible on the entire system.

          We implement this by waking up everywhere at the same time
          within any given second if we can, synchronised via the
          perturbation value determined from the boot ID. If we can't,
          then we try to find the same spot in every a 250ms
          step. Otherwise, we pick the last possible time to wake up.
        */

        c = (b / USEC_PER_SEC) * USEC_PER_SEC + e->perturb;
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
                int timer_fd,
                Prioq *earliest,
                Prioq *latest,
                usec_t *next) {

        struct itimerspec its = {};
        sd_event_source *a, *b;
        usec_t t;
        int r;

        assert_se(e);
        assert_se(next);

        a = prioq_peek(earliest);
        if (!a || a->mute == SD_EVENT_MUTED)
                return 0;

        b = prioq_peek(latest);
        assert_se(b && b->mute != SD_EVENT_MUTED);

        t = sleep_between(e, a->time.next, b->time.next + b->time.accuracy);
        if (*next == t)
                return 0;

        assert_se(timer_fd >= 0);

        if (t == 0) {
                /* We don' want to disarm here, just mean some time looooong ago. */
                its.it_value.tv_sec = 0;
                its.it_value.tv_nsec = 1;
        } else
                timespec_store(&its.it_value, t);

        r = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
        if (r < 0)
                return r;

        *next = t;
        return 0;
}

static int process_io(sd_event *e, sd_event_source *s, uint32_t events) {
        assert(e);
        assert(s);
        assert(s->type == SOURCE_IO);

        s->io.revents = events;

        /*
           If this is a oneshot event source, then we added it to the
           epoll with EPOLLONESHOT, hence we know it's not registered
           anymore. We can save a syscall here...
        */

        if (s->mute == SD_EVENT_ONESHOT)
                s->io.registered = false;

        return source_set_pending(s, true);
}

static int flush_timer(sd_event *e, int fd, uint32_t events) {
        uint64_t x;
        ssize_t ss;

        assert(e);
        assert(fd >= 0);

        if (events != EPOLLIN)
                return -EIO;

        ss = read(fd, &x, sizeof(x));
        if (ss < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        if (ss != sizeof(x))
                return -EIO;

        return 0;
}

static int process_timer(sd_event *e, usec_t n, Prioq *earliest, Prioq *latest) {
        sd_event_source *s;
        int r;

        assert(e);

        for (;;) {
                s = prioq_peek(earliest);
                if (!s ||
                    s->time.next > n ||
                    s->mute == SD_EVENT_MUTED ||
                    s->pending)
                        break;

                r = source_set_pending(s, true);
                if (r < 0)
                        return r;

                prioq_reshuffle(earliest, s, &s->time.earliest_index);
                prioq_reshuffle(latest, s, &s->time.latest_index);
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
        */

        HASHMAP_FOREACH(s, e->child_sources, i) {
                assert(s->type == SOURCE_CHILD);

                if (s->pending)
                        continue;

                if (s->mute == SD_EVENT_MUTED)
                        continue;

                zero(s->child.siginfo);
                r = waitid(P_PID, s->child.pid, &s->child.siginfo, WNOHANG|s->child.options);
                if (r < 0)
                        return -errno;

                if (s->child.siginfo.si_pid != 0) {
                        r = source_set_pending(s, true);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int process_signal(sd_event *e, uint32_t events) {
        struct signalfd_siginfo si;
        bool read_one = false;
        ssize_t ss;
        int r;

        assert(e);

        if (events != EPOLLIN)
                return -EIO;

        for (;;) {
                sd_event_source *s;

                ss = read(e->signal_fd, &si, sizeof(si));
                if (ss < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                return read_one;

                        return -errno;
                }

                if (ss != sizeof(si))
                        return -EIO;

                read_one = true;

                if (si.ssi_signo == SIGCHLD) {
                        r = process_child(e);
                        if (r < 0)
                                return r;
                        if (r > 0 || !e->signal_sources[si.ssi_signo])
                                continue;
                } else {
                        s = e->signal_sources[si.ssi_signo];
                        if (!s)
                                return -EIO;
                }

                s->signal.siginfo = si;
                r = source_set_pending(s, true);
                if (r < 0)
                        return r;
        }


        return 0;
}

static int source_dispatch(sd_event_source *s) {
        int r;

        assert(s);
        assert(s->pending || s->type == SOURCE_QUIT);

        if (s->type != SOURCE_DEFER && s->type != SOURCE_QUIT) {
                r = source_set_pending(s, false);
                if (r < 0)
                        return r;
        }

        if (s->mute == SD_EVENT_ONESHOT) {
                r = sd_event_source_set_mute(s, SD_EVENT_MUTED);
                if (r < 0)
                        return r;
        }

        switch (s->type) {

        case SOURCE_IO:
                r = s->io.callback(s, s->io.fd, s->io.revents, s->userdata);
                break;

        case SOURCE_MONOTONIC:
                r = s->time.callback(s, s->time.next, s->userdata);
                break;

        case SOURCE_REALTIME:
                r = s->time.callback(s, s->time.next, s->userdata);
                break;

        case SOURCE_SIGNAL:
                r = s->signal.callback(s, &s->signal.siginfo, s->userdata);
                break;

        case SOURCE_CHILD:
                r = s->child.callback(s, &s->child.siginfo, s->userdata);
                break;

        case SOURCE_DEFER:
                r = s->defer.callback(s, s->userdata);
                break;

        case SOURCE_QUIT:
                r = s->quit.callback(s, s->userdata);
                break;
        }

        return r;
}

static int event_prepare(sd_event *e) {
        int r;

        assert(e);

        for (;;) {
                sd_event_source *s;

                s = prioq_peek(e->prepare);
                if (!s || s->prepare_iteration == e->iteration || s->mute == SD_EVENT_MUTED)
                        break;

                s->prepare_iteration = e->iteration;
                r = prioq_reshuffle(e->prepare, s, &s->prepare_index);
                if (r < 0)
                        return r;

                assert(s->prepare);
                r = s->prepare(s, s->userdata);
                if (r < 0)
                        return r;

        }

        return 0;
}

static int dispatch_quit(sd_event *e) {
        sd_event_source *p;
        int r;

        assert(e);

        p = prioq_peek(e->quit);
        if (!p || p->mute == SD_EVENT_MUTED) {
                e->state = SD_EVENT_FINISHED;
                return 0;
        }

        sd_event_ref(e);
        e->iteration++;
        e->state = SD_EVENT_QUITTING;

        r = source_dispatch(p);

        e->state = SD_EVENT_PASSIVE;
        sd_event_unref(e);

        return r;
}

static sd_event_source* event_next_pending(sd_event *e) {
        sd_event_source *p;

        assert(e);

        p = prioq_peek(e->pending);
        if (!p)
                return NULL;

        if (p->mute == SD_EVENT_MUTED)
                return NULL;

        return p;
}

int sd_event_run(sd_event *e, uint64_t timeout) {
        struct epoll_event ev_queue[EPOLL_QUEUE_MAX];
        sd_event_source *p;
        int r, i, m;
        dual_timestamp n;

        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(e->state == SD_EVENT_PASSIVE, -EBUSY);

        if (e->quit_requested)
                return dispatch_quit(e);

        sd_event_ref(e);
        e->iteration++;
        e->state = SD_EVENT_RUNNING;

        r = event_prepare(e);
        if (r < 0)
                goto finish;

        if (event_next_pending(e) || e->need_process_child)
                timeout = 0;

        if (timeout > 0) {
                r = event_arm_timer(e, e->monotonic_fd, e->monotonic_earliest, e->monotonic_latest, &e->monotonic_next);
                if (r < 0)
                        goto finish;

                r = event_arm_timer(e, e->realtime_fd, e->realtime_earliest, e->realtime_latest, &e->realtime_next);
                if (r < 0)
                        goto finish;
        }

        m = epoll_wait(e->epoll_fd, ev_queue, EPOLL_QUEUE_MAX,
                       timeout == (uint64_t) -1 ? -1 : (int) ((timeout + USEC_PER_MSEC - 1) / USEC_PER_MSEC));
        if (m < 0) {
                r = m;
                goto finish;
        }

        dual_timestamp_get(&n);

        for (i = 0; i < m; i++) {

                if (ev_queue[i].data.ptr == INT_TO_PTR(SOURCE_MONOTONIC))
                        r = flush_timer(e, e->monotonic_fd, ev_queue[i].events);
                else if (ev_queue[i].data.ptr == INT_TO_PTR(SOURCE_REALTIME))
                        r = flush_timer(e, e->realtime_fd, ev_queue[i].events);
                else if (ev_queue[i].data.ptr == INT_TO_PTR(SOURCE_SIGNAL))
                        r = process_signal(e, ev_queue[i].events);
                else
                        r = process_io(e, ev_queue[i].data.ptr, ev_queue[i].events);

                if (r < 0)
                        goto finish;
        }

        r = process_timer(e, n.monotonic, e->monotonic_earliest, e->monotonic_latest);
        if (r < 0)
                goto finish;

        r = process_timer(e, n.realtime, e->realtime_earliest, e->realtime_latest);
        if (r < 0)
                goto finish;

        if (e->need_process_child) {
                r = process_child(e);
                if (r < 0)
                        goto finish;
        }

        p = event_next_pending(e);
        if (!p) {
                r = 0;
                goto finish;
        }

        r = source_dispatch(p);

finish:
        e->state = SD_EVENT_PASSIVE;
        sd_event_unref(e);

        return r;
}

int sd_event_loop(sd_event *e) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);
        assert_return(e->state == SD_EVENT_PASSIVE, -EBUSY);

        sd_event_ref(e);

        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, (uint64_t) -1);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        sd_event_unref(e);
        return r;
}

int sd_event_get_state(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->state;
}

int sd_event_get_quit(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(!event_pid_changed(e), -ECHILD);

        return e->quit_requested;
}

int sd_event_request_quit(sd_event *e) {
        assert_return(e, -EINVAL);
        assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
        assert_return(!event_pid_changed(e), -ECHILD);

        e->quit_requested = true;
        return 0;
}
