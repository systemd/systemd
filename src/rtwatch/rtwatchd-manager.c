/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-messages.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "event-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "log.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rtwatchd-manager.h"
#include "rtwatchd-varlink.h"
#include "set.h"
#include "stdio-util.h"
#include "user-util.h"

Manager* manager_lock(Manager *m) {
        assert(m);
        assert_se(pthread_mutex_lock(&m->mutex) == 0);
        return m;
}

void manager_unlockp(Manager **m) {
        assert(m);

        if (*m)
                assert_se(pthread_mutex_unlock(&(*m)->mutex) == 0);
}

static TrackedThread* tracked_thread_free(TrackedThread *t) {
        if (!t)
                return NULL;

        if (t->process) {
                TrackedUser *u = ASSERT_PTR(t->process->user);
                Manager *m = ASSERT_PTR(u->manager);

                LIST_REMOVE(threads, t->process->threads, t);

                assert(u->n_threads > 0);
                u->n_threads--;

                assert(m->n_threads > 0);
                m->n_threads--;
        }

        sd_event_source_disable_unref(t->exit_event_source);
        threadref_done(&t->thread);
        return mfree(t);
}

static TrackedProcess* tracked_process_free(TrackedProcess *p) {
        if (!p)
                return NULL;

        while (p->threads)
                tracked_thread_free(p->threads);

        if (p->user) {
                Manager *m = ASSERT_PTR(p->user->manager);

                LIST_REMOVE(processes, p->user->processes, p);

                assert(p->user->n_processes > 0);
                p->user->n_processes--;

                assert(m->n_processes > 0);
                m->n_processes--;
        }

        sd_event_source_disable_unref(p->exit_event_source);
        pidref_done(&p->pid);
        return mfree(p);
}

static TrackedUser* tracked_user_free(TrackedUser *u) {
        if (!u)
                return NULL;

        while (u->processes)
                tracked_process_free(u->processes);

        if (u->manager)
                hashmap_remove(u->manager->users, UID_TO_PTR(u->uid));

        return mfree(u);
}

static usec_t manager_now(Manager *m) {
        usec_t t;

        assert(m);

        /* Must only be called from the main thread */
        assert_se(sd_event_now(m->event, CLOCK_MONOTONIC, &t) >= 0);
        return t;
}

static bool user_in_burst(TrackedUser *u) {
        assert(u);

        return manager_now(u->manager) < usec_add(u->burst_start, u->manager->settings.actions_burst);
}

static bool user_verify_burst(TrackedUser *u) {
        assert(u);

        if (!user_in_burst(u)) {
                /* Restart burst phase */
                u->burst_start = manager_now(u->manager);
                u->n_actions = 0;
                return true;
        }

        if (u->n_actions >= u->manager->settings.actions_per_burst_max) {
                log_warning("Reached burst limit for user " UID_FMT ", denying request.", u->uid);
                return false;
        }

        u->n_actions++;
        return true;
}

static int manager_acquire_user(Manager *m, uid_t uid, TrackedUser **ret) {
        TrackedUser *u;
        int r;

        assert(m);
        assert(uid_is_valid(uid));
        assert(ret);

        u = hashmap_get(m->users, UID_TO_PTR(uid));
        if (u) {
                *ret = u;
                return 0;
        }

        if (hashmap_size(m->users) >= m->settings.users_max)
                return log_warning_errno(SYNTHETIC_ERRNO(EUSERS),
                                         "Reached maximum concurrent user limit, denying request.");

        u = new(TrackedUser, 1);
        if (!u)
                return log_oom();

        *u = (TrackedUser) {
                .uid = uid,
                .burst_start = manager_now(m),
        };

        r = hashmap_ensure_put(&m->users, &trivial_hash_ops, UID_TO_PTR(uid), u);
        if (r < 0) {
                free(u);
                return log_oom();
        }

        u->manager = m;

        *ret = u;
        return 0;
}

static int on_process_exit(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        TrackedProcess *p = ASSERT_PTR(userdata);
        Manager *m = ASSERT_PTR(p->user->manager);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        log_debug("Process " PID_FMT " exited, forgetting it.", p->pid.pid);
        tracked_process_free(p);

        manager_notify_status(m);
        return 0;
}

static int on_thread_exit(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        TrackedThread *t = ASSERT_PTR(userdata);
        TrackedProcess *p = ASSERT_PTR(t->process);
        Manager *m = ASSERT_PTR(p->user->manager);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        log_debug("Thread " PID_FMT " of process " PID_FMT " exited, forgetting it.", t->thread.thread_id, p->pid.pid);
        tracked_thread_free(t);

        /* We only track processes for the sake of their threads, hence forget about the process too, if
         * this was the last thread */
        if (!p->threads)
                tracked_process_free(p);

        manager_notify_status(m);
        return 0;
}

static int manager_watch_exit(
                Manager *m,
                int pidfd,
                sd_event_io_handler_t handler,
                void *userdata,
                const char *description,
                sd_event_source **ret) {

        int r;

        assert(m);
        assert(handler);
        assert(ret);

        /* If we have a pidfd, get notified when the process/thread exits, so that we can forget about it
         * right away. If we have none, manager_gc() will clean up eventually. */

        if (pidfd < 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_event_add_io(m->event, ret, pidfd, EPOLLIN, handler, userdata);
        if (r < 0)
                return log_error_errno(r, "Failed to watch pidfd: %m");

        (void) sd_event_source_set_description(*ret, description);
        return 0;
}

static int user_acquire_process(TrackedUser *u, PidRef *pid, TrackedProcess **ret) {
        _cleanup_(pidref_done) PidRef copy = PIDREF_NULL;
        TrackedProcess *p;
        int r;

        assert(u);
        assert(pidref_is_set(pid));
        assert(ret);

        LIST_FOREACH(processes, i, u->processes)
                if (pidref_equal(&i->pid, pid)) {
                        *ret = i;
                        return 0;
                }

        if (u->n_processes >= u->manager->settings.processes_per_user_max)
                return log_warning_errno(SYNTHETIC_ERRNO(EUSERS),
                                         "Reached maximum concurrent process limit for user " UID_FMT ", denying request.",
                                         u->uid);

        r = pidref_copy(pid, &copy);
        if (r < 0)
                return log_error_errno(r, "Failed to copy PID reference: %m");

        p = new(TrackedProcess, 1);
        if (!p)
                return log_oom();

        *p = (TrackedProcess) {
                .pid = TAKE_PIDREF(copy),
        };

        r = manager_watch_exit(u->manager, p->pid.fd, on_process_exit, p, "process-exit", &p->exit_event_source);
        if (r < 0) {
                tracked_process_free(p);
                return r;
        }

        p->user = u;
        LIST_PREPEND(processes, u->processes, p);
        u->n_processes++;
        u->manager->n_processes++;

        *ret = p;
        return 0;
}

static int process_acquire_thread(TrackedProcess *p, ThreadRef *thread, TrackedThread **ret) {
        TrackedUser *u;
        TrackedThread *t;
        int r;

        assert(p);
        assert(threadref_is_set(thread));
        assert(ret);

        /* Takes possession of the ThreadRef if a new thread object is allocated */

        LIST_FOREACH(threads, i, p->threads)
                if (threadref_equal(&i->thread, thread)) {
                        *ret = i;
                        return 0;
                }

        u = ASSERT_PTR(p->user);
        if (u->n_threads >= u->manager->settings.threads_per_user_max)
                return log_warning_errno(SYNTHETIC_ERRNO(EUSERS),
                                         "Reached maximum concurrent threads limit for user " UID_FMT ", denying request.",
                                         u->uid);

        t = new(TrackedThread, 1);
        if (!t)
                return log_oom();

        *t = (TrackedThread) {
                .thread = TAKE_THREADREF(*thread),
                .realtime_priority = -1,
        };

        r = manager_watch_exit(u->manager, t->thread.thread_pidfd, on_thread_exit, t, "thread-exit", &t->exit_event_source);
        if (r < 0) {
                tracked_thread_free(t);
                return r;
        }

        t->process = p;
        LIST_PREPEND(threads, p->threads, t);
        u->n_threads++;
        u->manager->n_threads++;

        *ret = t;
        return 0;
}

static bool thread_relevant(TrackedThread *t, bool reset) {
        int r;

        assert(t);

        /* This checks if a thread still matters to us, i.e. if its TID still refers to the same thread and
         * if it is still high priority or realtime */

        /* Did the thread die, or did its TID get recycled? */
        r = threadref_verify(&t->thread);
        if (r < 0) {
                if (!IN_SET(r, -ESRCH, -ENXIO))
                        log_warning_errno(r, "Failed to verify thread " PID_FMT ", forgetting it: %m", t->thread.thread_id);
                return false;
        }

        /* If suspended, don't verify scheduling unless it's a reset. */
        if (t->process->user->manager->suspended && !reset)
                return true;

        int policy = sched_getscheduler(t->thread.thread_id);
        if (policy < 0) {
                /* Maybe it died right now? */
                if (errno != ESRCH)
                        log_warning_errno(errno, "Failed to read scheduling policy of thread " PID_FMT ", forgetting it: %m", t->thread.thread_id);
                return false;
        }

        /* Make sure the TID wasn't recycled before we use the policy we just read */
        if (threadref_verify(&t->thread) < 0)
                return false;

        /* Is this a realtime thread? */
        if (IN_SET(policy & ~SCHED_RESET_ON_FORK, SCHED_RR, SCHED_FIFO))
                return true;

        errno = 0;
        int nice_level = getpriority(PRIO_PROCESS, t->thread.thread_id);
        if (errno != 0) {
                if (errno != ESRCH)
                        log_warning_errno(errno, "Failed to read nice level of thread " PID_FMT ", forgetting it: %m", t->thread.thread_id);
                return false;
        }

        /* Same here */
        if (threadref_verify(&t->thread) < 0)
                return false;

        /* Is this a high priority thread? */
        return nice_level < 0;
}

void manager_gc(Manager *m, bool reset) {
        TrackedUser *u;

        assert(m);

        /* Clean up all users, processes, threads we don't need to keep track of anymore */

        HASHMAP_FOREACH(u, m->users) {
                LIST_FOREACH(processes, p, u->processes) {
                        LIST_FOREACH(threads, t, p->threads)
                                if (!thread_relevant(t, reset))
                                        tracked_thread_free(t);

                        if (!p->threads)
                                tracked_process_free(p);
                }

                if (!u->processes && !user_in_burst(u))
                        tracked_user_free(u);
        }
}

static int self_set_realtime(int policy, int priority) {
        if (sched_setscheduler(/* pid= */ 0, policy|SCHED_RESET_ON_FORK, &(const struct sched_param) { .sched_priority = priority }) < 0)
                return log_error_errno(errno, "Failed to make ourselves realtime: %m");

        return 0;
}

void self_drop_realtime(int nice_level) {
        if (sched_setscheduler(/* pid= */ 0, SCHED_OTHER, &(const struct sched_param) {}) < 0)
                log_warning_errno(errno, "Failed to reset scheduling policy to SCHED_OTHER, ignoring: %m");

        if (setpriority(PRIO_PROCESS, /* who= */ 0, nice_level) < 0)
                log_warning_errno(errno, "Failed to reset nice level to %i, ignoring: %m", nice_level);
}

static int pidref_get_owner(const PidRef *pid, uid_t *ret) {
        char path[STRLEN("/proc/") + DECIMAL_STR_MAX(pid_t)];
        struct stat st;
        int r;

        assert(pidref_is_set(pid));
        assert(ret);

        /* Returns the effective UID of the process, since that's what we compare the caller's (effective)
         * UID with. Uses PIDFD_GET_INFO if available, and falls back to the owner of /proc/$PID/ otherwise
         * (which is the effective UID too, except for non-dumpable processes, for which it is root). */

        if (pid->fd >= 0) {
                struct pidfd_info info = { .mask = PIDFD_INFO_CREDS };

                r = pidfd_get_info(pid->fd, &info);
                if (r >= 0) {
                        assert(FLAGS_SET(info.mask, PIDFD_INFO_CREDS));
                        *ret = info.euid;
                        return 0;
                }
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return r;
        }

        xsprintf(path, "/proc/" PID_FMT, pid->pid);
        if (stat(path, &st) < 0)
                return errno == ENOENT ? -ESRCH : -errno;

        /* Make sure the PID wasn't recycled before we use the owner we just read */
        r = pidref_verify(pid);
        if (r < 0)
                return r;

        *ret = st.st_uid;
        return 0;
}

static int process_verify_user(TrackedProcess *p) {
        uid_t uid;
        int r;

        assert(p);

        r = pidref_get_owner(&p->pid, &uid);
        if (r < 0) {
                if (r != -ESRCH)
                        log_warning_errno(r, "Failed to determine owner of process " PID_FMT ": %m", p->pid.pid);
                return r;
        }

        return uid == p->user->uid ? 0 : -EPERM;
}

static int process_verify_rttime(TrackedProcess *p) {
        struct rlimit rl;
        int r;

        assert(p);

        /* Verifies that RLIMIT_RTTIME is set for the specified process */

        r = pidref_getrlimit(&p->pid, RLIMIT_RTTIME, &rl);
        if (r == -ESRCH)
                return r;
        if (r < 0)
                return log_error_errno(r, "Failed to read RLIMIT_RTTIME of process " PID_FMT ": %m", p->pid.pid);

        if (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > p->user->manager->settings.rttime_max)
                return -ERANGE;

        return 0;
}

static int thread_verify(TrackedThread *t, bool check_rttime) {
        int r;

        assert(t);

        r = process_verify_user(t->process);
        if (r < 0)
                return r;

        if (check_rttime) {
                r = process_verify_rttime(t->process);
                if (r < 0)
                        return r;
        }

        /* Finally, make sure neither the PID nor the TID were recycled while we were looking at them */
        return threadref_verify(&t->thread);
}

static int thread_reset(pid_t tid) {
        int r = 0;

        // FIXME: We'd much prefer to do this via a thread pidfd, but the kernel provides no pidfd based
        // equivalent of sched_setscheduler() and setpriority(), hence we have to address the thread by TID.
        // Callers validate the TID via threadref_verify() before (and possibly after) calling us, but the TID
        // might still be recycled in between, in which case we'd reset some other thread. (Since we only
        // ever demote here that's not too bad, but still.)
        if (sched_setscheduler(tid, SCHED_OTHER, &(const struct sched_param) {}) < 0) {
                if (errno != ESRCH)
                        log_warning_errno(errno, "Failed to reset scheduling policy of thread " PID_FMT " to SCHED_OTHER: %m", tid);
                RET_GATHER(r, -errno);
        }

        if (setpriority(PRIO_PROCESS, tid, /* prio= */ 0) < 0) {
                if (errno != ESRCH)
                        log_warning_errno(errno, "Failed to reset nice level of thread " PID_FMT " to 0: %m", tid);
                RET_GATHER(r, -errno);
        }

        return r;
}

static void log_thread_demoted(uid_t uid, pid_t pid, pid_t tid) {
        log_struct(LOG_NOTICE,
                   LOG_MESSAGE_ID(SD_MESSAGE_RTWATCH_DEMOTED_STR),
                   LOG_MESSAGE("Demoted thread " PID_FMT " of process " PID_FMT " owned by UID " UID_FMT ".", tid, pid, uid),
                   LOG_ITEM("OBJECT_PID=" PID_FMT, pid),
                   LOG_ITEM("RTWATCH_UID=" UID_FMT, uid),
                   LOG_ITEM("RTWATCH_PID=" PID_FMT, pid),
                   LOG_ITEM("RTWATCH_TID=" PID_FMT, tid));
}

static int thread_set_realtime_internal(TrackedThread *t, int priority) {
        int r;

        assert(t);

        /* Let's make sure that everything is alright before we make the thread realtime */
        r = thread_verify(t, /* check_rttime= */ true);
        if (r < 0)
                return r;

        /* Ok, everything seems to be in order, now, let's do it */
        // FIXME: We'd much prefer to do this via the thread pidfd, but the kernel provides no pidfd based
        // equivalent of sched_setscheduler(), hence we have to address the thread by TID. We validate it via
        // threadref_verify() before and after, and undo things if the latter fails, but there's a window
        // during which the TID might be recycled and some other thread is made realtime.
        if (sched_setscheduler(t->thread.thread_id,
                               t->process->user->manager->settings.sched_policy|SCHED_RESET_ON_FORK,
                               &(const struct sched_param) { .sched_priority = priority }) < 0)
                return log_error_errno(errno, "Failed to make thread " PID_FMT " realtime: %m", t->thread.thread_id);

        /* We do some sanity checks afterwards, to verify that the caller didn't play games with us and
         * replaced the process behind the PID */
        r = thread_verify(t, /* check_rttime= */ true);
        if (r < 0) {
                (void) thread_reset(t->thread.thread_id);
                return r;
        }

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_RTWATCH_REALTIME_STR),
                   LOG_MESSAGE("Made thread " PID_FMT " of process " PID_FMT " owned by UID " UID_FMT " realtime at priority %i.",
                               t->thread.thread_id, t->process->pid.pid, t->process->user->uid, priority),
                   LOG_ITEM("OBJECT_PID=" PID_FMT, t->process->pid.pid),
                   LOG_ITEM("RTWATCH_UID=" UID_FMT, t->process->user->uid),
                   LOG_ITEM("RTWATCH_PID=" PID_FMT, t->process->pid.pid),
                   LOG_ITEM("RTWATCH_TID=" PID_FMT, t->thread.thread_id),
                   LOG_ITEM("RTWATCH_PRIORITY=%i", priority));
        return 0;
}

static int thread_set_realtime(TrackedThread *t, int priority) {
        int r;

        assert(t);

        const Settings *s = &t->process->user->manager->settings;

        if (!sched_priority_is_valid(s->sched_policy, priority))
                return -EINVAL;

        /* We always want to be able to get a higher RT priority than the client */
        if (priority >= s->our_realtime_priority ||
            priority > s->max_realtime_priority)
                return -EPERM;

        /* Temporarily become a realtime process. We do this to make sure that our verification code is not
         * preempted by an evil client's code which might have gotten RT through us. */
        r = self_set_realtime(s->sched_policy, s->our_realtime_priority);
        if (r < 0)
                return r;

        r = thread_set_realtime_internal(t, priority);
        self_drop_realtime(s->our_nice_level);
        return r;
}

static int thread_set_high_priority_internal(TrackedThread *t, int nice_level) {
        int r;

        assert(t);

        /* Let's make sure that everything is alright before we make the thread high priority */
        r = thread_verify(t, /* check_rttime= */ false);
        if (r < 0)
                return r;

        /* Ok, everything seems to be in order, now, let's do it */
        // FIXME: We'd much prefer to do this via the thread pidfd, but the kernel provides no pidfd based
        // equivalent of sched_setscheduler() and setpriority(), hence we have to address the thread by TID.
        // We validate it via threadref_verify() before and after, and undo things if the latter fails, but
        // there's a window during which the TID might be recycled and some other thread is made high
        // priority.
        if (sched_setscheduler(t->thread.thread_id, SCHED_OTHER|SCHED_RESET_ON_FORK, &(const struct sched_param) {}) < 0)
                return log_error_errno(errno, "Failed to make thread " PID_FMT " SCHED_OTHER: %m", t->thread.thread_id);

        if (setpriority(PRIO_PROCESS, t->thread.thread_id, nice_level) < 0)
                return log_error_errno(errno, "Failed to set nice level of thread " PID_FMT " to %i: %m", t->thread.thread_id, nice_level);

        r = thread_verify(t, /* check_rttime= */ false);
        if (r < 0) {
                (void) thread_reset(t->thread.thread_id);
                return r;
        }

        log_struct(LOG_INFO,
                   LOG_MESSAGE_ID(SD_MESSAGE_RTWATCH_HIGH_PRIORITY_STR),
                   LOG_MESSAGE("Made thread " PID_FMT " of process " PID_FMT " owned by UID " UID_FMT " high priority at nice level %i.",
                               t->thread.thread_id, t->process->pid.pid, t->process->user->uid, nice_level),
                   LOG_ITEM("OBJECT_PID=" PID_FMT, t->process->pid.pid),
                   LOG_ITEM("RTWATCH_UID=" UID_FMT, t->process->user->uid),
                   LOG_ITEM("RTWATCH_PID=" PID_FMT, t->process->pid.pid),
                   LOG_ITEM("RTWATCH_TID=" PID_FMT, t->thread.thread_id),
                   LOG_ITEM("RTWATCH_NICE_LEVEL=%i", nice_level));
        return 0;
}

static int thread_set_high_priority(TrackedThread *t, int nice_level) {
        int r;

        assert(t);

        const Settings *s = &t->process->user->manager->settings;

        if (!nice_is_valid(nice_level))
                return -EINVAL;

        if (nice_level < s->min_nice_level)
                return -EPERM;

        /* Temporarily become a realtime process, see above */
        r = self_set_realtime(s->sched_policy, s->our_realtime_priority);
        if (r < 0)
                return r;

        r = thread_set_high_priority_internal(t, nice_level);
        self_drop_realtime(s->our_nice_level);
        return r;
}

static int thread_resume(TrackedThread *t) {
        assert(t);

        if (t->realtime_priority >= 0)
                return thread_set_realtime(t, t->realtime_priority);

        return thread_set_high_priority(t, t->nice_level);
}

static int manager_verify_canary_refusal(Manager *m) {
        assert(m);

        if (manager_now(m) < m->refuse_until)
                return log_warning_errno(SYNTHETIC_ERRNO(EOWNERDEAD),
                                         "Recovering from system lockup, not allowing further realtime threads.");

        return 0;
}

static int manager_lookup_client(Manager *m, uid_t uid, const ThreadRef *thread, TrackedThread **ret) {
        _cleanup_(threadref_done) ThreadRef copy = THREADREF_NULL;
        TrackedUser *u;
        TrackedProcess *p;
        int r;

        assert(m);
        assert(threadref_is_set(thread));
        assert(ret);

        /* Find or create user structure */
        r = manager_acquire_user(m, uid, &u);
        if (r < 0)
                return r;

        r = threadref_copy(thread, &copy);
        if (r < 0)
                return log_error_errno(r, "Failed to copy thread reference: %m");

        /* Find or create process structure */
        r = user_acquire_process(u, &copy.process, &p);
        if (r < 0)
                return r;

        /* Find or create thread structure */
        return process_acquire_thread(p, &copy, ret);
}

int manager_make_thread_realtime(Manager *m, uid_t uid, const ThreadRef *thread, uint32_t priority) {
        TrackedThread *t;
        int r;

        assert(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        /* We garbage collect on every call */
        manager_gc(m, /* reset= */ false);

        r = manager_verify_canary_refusal(m);
        if (r < 0)
                return r;

        if (priority > INT_MAX)
                return -EINVAL;

        r = manager_lookup_client(m, uid, thread, &t);
        if (r < 0)
                return r;

        /* Make sure users don't flood us with requests */
        if (!user_verify_burst(t->process->user))
                return -EBUSY;

        if (m->suspended)
                return -EAGAIN;

        r = thread_set_realtime(t, (int) priority);
        if (r < 0)
                return r;

        t->realtime_priority = (int) priority;
        t->nice_level = 0;

        manager_send_thread_event(m, WATCH_EVENT_REALTIME, t);
        return 0;
}

int manager_make_thread_high_priority(Manager *m, uid_t uid, const ThreadRef *thread, int32_t nice_level) {
        TrackedThread *t;
        int r;

        assert(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        manager_gc(m, /* reset= */ false);

        r = manager_verify_canary_refusal(m);
        if (r < 0)
                return r;

        r = manager_lookup_client(m, uid, thread, &t);
        if (r < 0)
                return r;

        if (!user_verify_burst(t->process->user))
                return -EBUSY;

        if (m->suspended)
                return -EAGAIN;

        r = thread_set_high_priority(t, nice_level);
        if (r < 0)
                return r;

        t->realtime_priority = -1; /* thread_set_high_priority() switched it to SCHED_OTHER */
        t->nice_level = nice_level;

        manager_send_thread_event(m, WATCH_EVENT_HIGH_PRIORITY, t);
        return 0;
}

static unsigned manager_reset_known_unlocked(Manager *m) {
        TrackedUser *u;
        unsigned n_demoted = 0;

        assert(m);

        log_info("Demoting known realtime threads.");

        HASHMAP_FOREACH(u, m->users)
                LIST_FOREACH(processes, p, u->processes)
                        LIST_FOREACH(threads, t, p->threads) {
                                if (thread_verify(t, /* check_rttime= */ false) < 0)
                                        continue;

                                if (thread_reset(t->thread.thread_id) < 0)
                                        continue;

                                log_thread_demoted(u->uid, p->pid.pid, t->thread.thread_id);
                                n_demoted++;
                        }

        log_notice("Demoted %u threads.", n_demoted);
        return n_demoted;
}

static int process_reset_all_threads(uid_t uid, const PidRef *pid, unsigned *n_demoted) {
        char path[STRLEN("/proc//task") + DECIMAL_STR_MAX(pid_t)];
        _cleanup_closedir_ DIR *d = NULL;
        int ret = 0, r;

        assert(pidref_is_set(pid));
        assert(n_demoted);

        /* Demotes all realtime threads of the specified process. Returns -ESRCH if the process went away.
         * Failures to handle individual threads are gathered and returned, but don't stop us from
         * processing the remaining threads. */

        xsprintf(path, "/proc/" PID_FMT "/task", pid->pid);
        d = opendir(path);
        if (!d) {
                r = -errno;
                if (r == -ENOENT)
                        return -ESRCH;

                return log_debug_errno(r, "Failed to open '%s': %m", path);
        }

        FOREACH_DIRENT(de, d, return -errno) {
                pid_t tid;
                int policy;

                if (!IN_SET(de->d_type, DT_DIR, DT_UNKNOWN))
                        continue;

                if (parse_pid(de->d_name, &tid) < 0)
                        continue;

                _cleanup_(threadref_done) ThreadRef thread = THREADREF_NULL;
                r = threadref_set(&thread, pid, tid);
                if (r == -ENXIO) /* Thread went away, that's fine */
                        continue;
                if (r == -ESRCH) /* Process went away, no point in looking further */
                        return r;
                if (r < 0) {
                        RET_GATHER(ret, log_debug_errno(r, "Failed to pin thread " PID_FMT ": %m", tid));
                        continue;
                }

                policy = RET_NERRNO(sched_getscheduler(tid));
                if (policy == -ESRCH) /* Thread went away */
                        continue;
                if (policy < 0) {
                        RET_GATHER(ret, log_debug_errno(policy, "Failed to read scheduling policy of thread " PID_FMT ": %m", tid));
                        continue;
                }

                /* Make sure the TID wasn't recycled before we act on the policy we just read */
                r = threadref_verify(&thread);
                if (r == -ENXIO)
                        continue;
                if (r == -ESRCH)
                        return r;
                if (r < 0) {
                        RET_GATHER(ret, r);
                        continue;
                }

                if (!IN_SET(policy & ~SCHED_RESET_ON_FORK, SCHED_FIFO, SCHED_RR))
                        continue;

                r = thread_reset(tid);
                if (r < 0) {
                        if (r != -ESRCH) /* thread_reset() already logged about anything but ESRCH */
                                RET_GATHER(ret, r);
                        continue;
                }

                log_thread_demoted(uid, pid->pid, tid);
                (*n_demoted)++;
        }

        return ret;
}

static int manager_reset_all_unlocked(Manager *m, unsigned *ret_n_demoted) {
        _cleanup_closedir_ DIR *d = NULL;
        unsigned n_demoted = 0;
        int ret = 0, r;

        assert(m);
        assert(ret_n_demoted);

        /* Goes through /proc/ and demotes *all* realtime threads to SCHED_OTHER. Unexpected errors are
         * collected and the first one returned, but don't stop us from processing the remaining
         * processes. The number of demoted threads is returned in either case. */

        log_info("Demoting known and unknown realtime threads.");

        r = proc_dir_open(&d);
        if (r < 0)
                return log_error_errno(r, "Failed to open /proc/: %m");

        for (;;) {
                pid_t pid;
                uid_t uid;

                r = proc_dir_read(d, &pid);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to enumerate processes: %m"));
                        break;
                }
                if (r == 0)
                        break;

                if (pid == getpid_cached() || pid == 1)
                        continue;

                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = pidref_set_pid(&pidref, pid);
                if (r == -ESRCH)
                        continue;
                if (r < 0) {
                        RET_GATHER(ret, log_warning_errno(r, "Failed to pin process " PID_FMT ": %m", pid));
                        continue;
                }

                r = pidref_get_owner(&pidref, &uid);
                if (r == -ESRCH)
                        continue;
                if (r < 0) {
                        RET_GATHER(ret, log_warning_errno(r, "Failed to determine owner of process " PID_FMT ": %m", pid));
                        continue;
                }

                if (!m->settings.canary_demote_root && uid == 0) {
                        log_debug("Process " PID_FMT " is owned by root, not demoting.", pid);
                        continue;
                }

                r = process_reset_all_threads(uid, &pidref, &n_demoted);
                if (r < 0 && r != -ESRCH)
                        RET_GATHER(ret, log_warning_errno(r, "Failed to demote all realtime threads of process " PID_FMT ": %m", pid));
        }

        log_notice("Demoted %u threads.", n_demoted);

        *ret_n_demoted = n_demoted;
        return ret;
}

void manager_reset_known(Manager *m) {
        unsigned n_demoted;

        assert(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        n_demoted = manager_reset_known_unlocked(m);
        manager_gc(m, /* reset= */ true);

        manager_send_event(m, WATCH_EVENT_RESET_KNOWN, n_demoted);
}

int manager_reset_all(Manager *m) {
        unsigned n_demoted = 0;
        int r;

        assert(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        r = manager_reset_all_unlocked(m, &n_demoted);
        manager_gc(m, /* reset= */ true);

        /* Even if we failed for some processes, let watchers know about the threads we did demote */
        manager_send_event(m, WATCH_EVENT_RESET_ALL, n_demoted);
        return r;
}

static void watchdog_take_action(Manager *m, usec_t n) {
        assert(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        m->refuse_until = usec_add(n, m->settings.canary_refuse);

        if (m->settings.canary_demote_unknown)
                (void) manager_reset_all_unlocked(m, &m->watchdog_n_demoted);
        else
                m->watchdog_n_demoted = manager_reset_known_unlocked(m);

        log_struct(LOG_WARNING,
                   LOG_MESSAGE_ID(SD_MESSAGE_RTWATCH_CANARY_STARVING_STR),
                   LOG_MESSAGE("Realtime threads are starving the system, demoted %u threads, refusing further requests for %s.",
                               m->watchdog_n_demoted, FORMAT_TIMESPAN(m->settings.canary_refuse, USEC_PER_SEC)),
                   LOG_ITEM("RTWATCH_DEMOTED_THREADS=%u", m->watchdog_n_demoted),
                   LOG_ITEM("RTWATCH_REFUSE_USEC=" USEC_FMT, m->settings.canary_refuse));

        /* We may not talk to Varlink clients from this thread, hence let the main thread know */
        if (eventfd_write(m->watchdog_action_fd, /* value= */ 1) < 0)
                log_warning_errno(errno, "Failed to write to watchdog action eventfd, ignoring: %m");
}

static void* watchdog_thread(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        /* The watchdog runs at a very high realtime priority, and checks if the main loop (which runs at
         * SCHED_OTHER) still gets CPU time. If it does not it demotes the realtime threads we know of (or
         * all of them). Note that this function runs in a separate thread, hence be careful with accessing
         * shared state: everything that is changed by the main thread must be accessed only with the
         * mutex taken. Settings are only written before the thread is started, hence are fine to access
         * without the lock. */

        (void) self_set_realtime(m->settings.sched_policy, WATCHDOG_REALTIME_PRIORITY);

        log_debug("Watchdog thread running.");

        usec_t last_cheep = now(CLOCK_MONOTONIC);
        for (;;) {
                enum {
                        POLLFD_CANARY,
                        POLLFD_QUIT,
                        _POLLFD_MAX,
                };

                struct pollfd pollfd[_POLLFD_MAX] = {
                        [POLLFD_CANARY] = { .fd = m->canary_fd,        .events = POLLIN },
                        [POLLFD_QUIT]   = { .fd = m->watchdog_quit_fd, .events = POLLIN },
                };

                usec_t deadline = usec_add(last_cheep, m->settings.canary_watchdog);

                r = ppoll_usec(pollfd, ELEMENTSOF(pollfd), usec_sub_unsigned(deadline, now(CLOCK_MONOTONIC)));
                if (r == -EINTR)
                        continue;
                if (r < 0) {
                        log_error_errno(r, "Failed to wait for canary: %m");
                        break;
                }

                usec_t n = now(CLOCK_MONOTONIC);

                if (pollfd[POLLFD_QUIT].revents != 0) {
                        log_debug("Exiting watchdog thread.");
                        break;
                }

                if (pollfd[POLLFD_CANARY].revents != 0) {
                        eventfd_t value;

                        if (eventfd_read(m->canary_fd, &value) < 0) {
                                log_error_errno(errno, "Failed to read from canary eventfd: %m");
                                break;
                        }

                        last_cheep = n;
                        continue;
                }

                if (n < deadline)
                        continue;

                last_cheep = n;
                watchdog_take_action(m, n);
        }

        return NULL;
}

static int on_canary_cheep(sd_event_source *s, uint64_t usec, void *userdata);

static int manager_arm_canary_timer(Manager *m) {
        assert(m);

        return event_reset_time_relative(
                        m->event,
                        &m->canary_event_source,
                        CLOCK_MONOTONIC,
                        m->settings.canary_cheep,
                        /* accuracy= */ (m->settings.canary_watchdog - m->settings.canary_cheep) / 2,
                        on_canary_cheep,
                        m,
                        /* priority= */ SD_EVENT_PRIORITY_NORMAL,
                        "canary-cheep",
                        /* force_reset= */ true);
}

static int on_canary_cheep(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (eventfd_write(m->canary_fd, /* value= */ 1) < 0)
                log_warning_errno(errno, "Failed to write to canary eventfd, ignoring: %m");

        r = manager_arm_canary_timer(m);
        if (r < 0)
                return log_error_errno(r, "Failed to rearm canary timer: %m");

        return 0;
}

static int on_watchdog_action(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        unsigned n_demoted;
        eventfd_t value;

        if (eventfd_read(fd, &value) < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read from watchdog action eventfd: %m");
        }

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        n_demoted = m->watchdog_n_demoted;
        manager_send_event(m, WATCH_EVENT_STARVING, n_demoted);
        return 0;
}

static void manager_stop_canary(Manager *m) {
        int r;

        assert(m);

        (void) event_source_disable(m->canary_event_source);

        if (m->watchdog_thread_running) {
                if (eventfd_write(m->watchdog_quit_fd, /* value= */ 1) < 0)
                        log_warning_errno(errno, "Failed to write to watchdog quit eventfd, ignoring: %m");

                r = pthread_join(m->watchdog_thread, /* retval= */ NULL);
                if (r != 0)
                        log_warning_errno(r, "Failed to join watchdog thread, ignoring: %m");

                m->watchdog_thread_running = false;
        }

        m->canary_fd = safe_close(m->canary_fd);
        m->watchdog_quit_fd = safe_close(m->watchdog_quit_fd);
}

static int manager_start_canary(Manager *m) {
        int r;

        assert(m);

        if (!m->settings.canary || m->watchdog_thread_running)
                return 0;

        m->canary_fd = eventfd(/* initval= */ 0, EFD_NONBLOCK|EFD_CLOEXEC);
        if (m->canary_fd < 0)
                return log_error_errno(errno, "Failed to allocate canary eventfd: %m");

        m->watchdog_quit_fd = eventfd(/* initval= */ 0, EFD_NONBLOCK|EFD_CLOEXEC);
        if (m->watchdog_quit_fd < 0) {
                r = log_error_errno(errno, "Failed to allocate watchdog quit eventfd: %m");
                goto fail;
        }

        r = manager_arm_canary_timer(m);
        if (r < 0) {
                log_error_errno(r, "Failed to set up canary timer: %m");
                goto fail;
        }

        /* Make sure the watchdog thread is not disturbed by any signal: start it with all signals blocked */
        sigset_t ss, saved_ss;
        assert_se(sigfillset(&ss) >= 0);

        r = pthread_sigmask(SIG_BLOCK, &ss, &saved_ss);
        if (r != 0) {
                r = log_error_errno(r, "Failed to block signals: %m");
                goto fail;
        }

        r = pthread_create(&m->watchdog_thread, /* attr= */ NULL, watchdog_thread, m);
        assert_se(pthread_sigmask(SIG_SETMASK, &saved_ss, /* oldset= */ NULL) == 0);
        if (r != 0) {
                r = log_error_errno(r, "Failed to start watchdog thread: %m");
                goto fail;
        }

        m->watchdog_thread_running = true;
        return 0;

fail:
        manager_stop_canary(m);
        return r;
}

void manager_suspend(Manager *m) {
        assert(m);

        if (m->suspended)
                return;

        /* Note: this must be called without the lock taken, since the watchdog thread might be waiting for
         * it, and we join it here. */
        manager_stop_canary(m);

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        m->suspended = true;
        manager_send_event(m, WATCH_EVENT_SUSPENDED, manager_reset_known_unlocked(m));
}

static void manager_resume_threads(Manager *m) {
        TrackedUser *u;
        unsigned n_resumed = 0;

        assert(m);

        log_info("Resuming known realtime threads.");

        /* It is not possible for there to be more resumable processes and threads than user limits, as
         * suspended processes and threads can only be created when non-suspended, subject to normal
         * enforcement. */

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        usec_t n = manager_now(m);
        HASHMAP_FOREACH(u, m->users) {
                /* Force restart burst phase, extending time window. */
                u->burst_start = n;

                LIST_FOREACH(processes, p, u->processes)
                        LIST_FOREACH(threads, t, p->threads)
                                if (thread_resume(t) >= 0)
                                        n_resumed++;
        }

        log_notice("Resumed scheduling of %u threads.", n_resumed);

        m->suspended = false;
        manager_send_event(m, WATCH_EVENT_RESUMED, n_resumed);
}

void manager_resume(Manager *m) {
        assert(m);

        if (!m->suspended)
                return;

        manager_resume_threads(m);

        /* Start the watchdog thread only after we released the lock again */
        (void) manager_start_canary(m);
}

void manager_notify_status(Manager *m) {
        assert(m);

        /* The counters are only ever modified from the main thread, hence no need to take the lock here */

        log_debug("Supervising %u threads of %u processes of %u users.",
                  m->n_threads, m->n_processes, hashmap_size(m->users));

        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=Supervising %u threads of %u processes of %u users.",
                          m->n_threads, m->n_processes, hashmap_size(m->users));
}

int manager_new(const Settings *settings, Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        pthread_mutexattr_t attr;
        int r;

        assert(settings);
        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return log_oom();

        *m = (Manager) {
                .settings = *settings,
                .canary_fd = -EBADF,
                .watchdog_quit_fd = -EBADF,
                .watchdog_action_fd = -EBADF,
                .inhibit_fd = -EBADF,
        };

        /* Use a priority inheriting mutex, so that the watchdog thread (which runs at a very high RT
         * priority) temporarily lifts the main thread's priority while it holds the lock. */
        r = pthread_mutexattr_init(&attr);
        if (r != 0)
                return log_error_errno(r, "Failed to initialize mutex attributes: %m");

        r = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
        if (r == 0)
                r = pthread_mutex_init(&m->mutex, &attr);
        assert_se(pthread_mutexattr_destroy(&attr) == 0);
        if (r != 0)
                return log_error_errno(r, "Failed to initialize mutex: %m");

        m->mutex_initialized = true;

        r = sd_event_default(&m->event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        (void) sd_event_set_watchdog(m->event, /* b= */ true);

        r = sd_event_set_signal_exit(m->event, /* b= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT/SIGTERM handlers: %m");

        m->watchdog_action_fd = eventfd(/* initval= */ 0, EFD_NONBLOCK|EFD_CLOEXEC);
        if (m->watchdog_action_fd < 0)
                return log_error_errno(errno, "Failed to allocate watchdog action eventfd: %m");

        r = sd_event_add_io(m->event, &m->watchdog_action_event_source, m->watchdog_action_fd, EPOLLIN, on_watchdog_action, m);
        if (r < 0)
                return log_error_errno(r, "Failed to watch watchdog action eventfd: %m");

        (void) sd_event_source_set_description(m->watchdog_action_event_source, "watchdog-action");

        *ret = TAKE_PTR(m);
        return 0;
}

Manager* manager_free(Manager *m) {
        TrackedUser *u;

        if (!m)
                return NULL;

        manager_stop_canary(m);

        while ((u = hashmap_first(m->users)))
                tracked_user_free(u);
        hashmap_free(m->users);

        sd_event_source_unref(m->canary_event_source);
        sd_event_source_unref(m->watchdog_action_event_source);
        safe_close(m->watchdog_action_fd);

        sd_bus_slot_unref(m->inhibit_slot);
        sd_bus_slot_unref(m->prepare_for_sleep_slot);
        safe_close(m->inhibit_fd);

        set_free(m->watch_links);
        sd_varlink_server_unref(m->varlink_server);
        hashmap_free(m->polkit_registry);
        sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        if (m->mutex_initialized)
                assert_se(pthread_mutex_destroy(&m->mutex) == 0);

        return mfree(m);
}

static void self_limit_resources(Manager *m) {
        struct rlimit rl;

        assert(m);

        /* Do as I say AND do as I do: since we temporarily make ourselves realtime too, enforce the same
         * RLIMIT_RTTIME on ourselves as on our clients. */

        if (getrlimit(RLIMIT_RTTIME, &rl) < 0) {
                log_warning_errno(errno, "Failed to query RLIMIT_RTTIME, ignoring: %m");
                return;
        }

        if (rl.rlim_max < m->settings.rttime_max)
                return;

        rl.rlim_cur = rl.rlim_max = m->settings.rttime_max;
        if (setrlimit(RLIMIT_RTTIME, &rl) < 0)
                log_warning_errno(errno, "Failed to set RLIMIT_RTTIME, ignoring: %m");
}

int manager_startup(Manager *m) {
        assert(m);

        /* Raise our timer slack, we don't really need to be woken up on time. Note that this is inherited
         * by the watchdog thread, as long as we do this before we start it. */
        if (prctl(PR_SET_TIMERSLACK, (m->settings.canary_watchdog - m->settings.canary_cheep) / 2 * NSEC_PER_USEC) < 0)
                log_warning_errno(errno, "Failed to set timer slack, ignoring: %m");

        self_drop_realtime(m->settings.our_nice_level);
        self_limit_resources(m);

        return manager_start_canary(m);
}
