/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sched.h>

#include "forward.h"
#include "list.h"
#include "pidref.h"
#include "threadref.h"
#include "time-util.h"

/* The realtime priority the watchdog thread runs at */
#define WATCHDOG_REALTIME_PRIORITY 99

typedef struct Settings {
        int sched_policy;               /* SCHED_RR or SCHED_FIFO */
        int our_realtime_priority;      /* While we process a request we temporarily run at this RT priority */
        int our_nice_level;             /* Otherwise we run at this nice level */
        int max_realtime_priority;      /* The maximum RT priority to hand out */
        int min_nice_level;             /* The minimum nice level to hand out */
        usec_t rttime_max;              /* Clients must have RLIMIT_RTTIME set to a value <= this */
        unsigned users_max;             /* How many users we supervise at max */
        unsigned processes_per_user_max;
        unsigned threads_per_user_max;
        usec_t actions_burst;           /* Refuse further requests if a user issues more than … */
        unsigned actions_per_burst_max; /* … this many requests in this time */
        bool canary;                    /* Run a canary based watchdog */
        usec_t canary_cheep;            /* Canary cheep interval */
        usec_t canary_watchdog;         /* Watchdog interval */
        usec_t canary_refuse;           /* How long to refuse further RT requests after the canary died */
        bool canary_demote_root;        /* Demote root processes when the canary died? */
        bool canary_demote_unknown;     /* Demote unknown processes when the canary died? */
} Settings;

#define SETTINGS_DEFAULT                                                \
        (Settings) {                                                    \
                .sched_policy = SCHED_RR,                               \
                .our_realtime_priority = 21,                            \
                .our_nice_level = 1,                                    \
                .max_realtime_priority = 20,                            \
                .min_nice_level = -15,                                  \
                .rttime_max = 200 * USEC_PER_MSEC,                      \
                .users_max = 2048,                                      \
                .processes_per_user_max = 15,                           \
                .threads_per_user_max = 25,                             \
                .actions_burst = 20 * USEC_PER_SEC,                     \
                .actions_per_burst_max = 25,                            \
                .canary = true,                                         \
                .canary_cheep = 5 * USEC_PER_SEC,                       \
                .canary_watchdog = 10 * USEC_PER_SEC,                   \
                .canary_refuse = 5 * USEC_PER_MINUTE,                   \
        }

typedef struct Manager Manager;
typedef struct TrackedUser TrackedUser;
typedef struct TrackedProcess TrackedProcess;
typedef struct TrackedThread TrackedThread;

struct TrackedThread {
        TrackedProcess *process;

        /* We pin the thread via a ThreadRef, i.e. via a thread pidfd (if supported), so that we can detect
         * TID reuse, and get notified when the thread exits. */
        ThreadRef thread;
        sd_event_source *exit_event_source;

        int realtime_priority;          /* ≥ 0 if we made it realtime, -1 if we made it high priority */
        int nice_level;                 /* the nice level we set, if realtime_priority is -1 */

        LIST_FIELDS(TrackedThread, threads);
};

struct TrackedProcess {
        TrackedUser *user;

        /* We pin the process via a PidRef, i.e. via a pidfd (if supported), so that we can detect PID
         * reuse, and get notified when the process exits. */
        PidRef pid;
        sd_event_source *exit_event_source;

        LIST_HEAD(TrackedThread, threads);
        LIST_FIELDS(TrackedProcess, processes);
};

struct TrackedUser {
        Manager *manager;

        uid_t uid;

        usec_t burst_start;
        unsigned n_actions;

        LIST_HEAD(TrackedProcess, processes);
        unsigned n_processes;
        unsigned n_threads;
};

struct Manager {
        Settings settings;

        sd_event *event;
        sd_bus *bus;
        sd_varlink_server *varlink_server;
        Set *watch_links;               /* Varlink connections subscribed via Watch() */
        Hashmap *polkit_registry;

        /* All fields below are protected by 'mutex', since they are accessed both from the main thread and
         * the watchdog thread. Note that the mutex uses priority inheritance, so that the watchdog thread
         * (which runs at high RT priority) is not blocked on the main thread (which normally does not run
         * at RT priority) for long. */
        pthread_mutex_t mutex;
        bool mutex_initialized;

        Hashmap *users;                 /* uid_t → TrackedUser */
        unsigned n_processes;
        unsigned n_threads;

        bool suspended;
        usec_t refuse_until;            /* CLOCK_MONOTONIC */
        unsigned watchdog_n_demoted;    /* How many threads the watchdog demoted the last time it took action */

        /* The main loop is the canary: it cheeps into canary_fd in regular intervals. The watchdog thread
         * listens for these cheeps, and if they don't come in time takes action. */
        sd_event_source *canary_event_source;
        int canary_fd;
        int watchdog_quit_fd;
        pthread_t watchdog_thread;
        bool watchdog_thread_running;

        /* The watchdog thread pings this after it took action, so that the main thread can tell
         * subscribers about it. (We never talk to Varlink clients from the watchdog thread.) */
        int watchdog_action_fd;
        sd_event_source *watchdog_action_event_source;

        /* Logind sleep inhibitor */
        int inhibit_fd;
        sd_bus_slot *inhibit_slot;
        sd_bus_slot *prepare_for_sleep_slot;
};

int manager_new(const Settings *settings, Manager **ret);
Manager* manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

int manager_startup(Manager *m);

/* Take the lock protecting the users/processes/threads, which are also accessed by the watchdog thread */
Manager* manager_lock(Manager *m);
void manager_unlockp(Manager **m);

/* Forgets about threads that are gone or not realtime/high priority anymore. Must be called with the lock
 * taken, from the main thread. */
void manager_gc(Manager *m, bool reset);

/* These two take the thread to operate on, pinned via threadref_set() by the IPC layer as early as
 * possible, and return the following errors, which are propagated to clients:
 *
 *   -ESRCH      → the process does not exist (anymore)
 *   -ENXIO      → the thread does not exist (anymore)
 *   -EINVAL     → priority/nice level out of range
 *   -EPERM      → not permitted (process not owned by caller, identity changed, priority above limit)
 *   -ERANGE     → RLIMIT_RTTIME not set or too high
 *   -EUSERS     → maximum number of supervised users/processes/threads reached
 *   -EBUSY      → too many requests from this user in the rate limit window
 *   -EAGAIN     → we are currently suspended
 *   -EOWNERDEAD → the canary died recently, we refuse further requests for a while
 */
int manager_make_thread_realtime(Manager *m, uid_t uid, const ThreadRef *thread, uint32_t priority);
int manager_make_thread_high_priority(Manager *m, uid_t uid, const ThreadRef *thread, int32_t nice_level);

void manager_reset_known(Manager *m);
int manager_reset_all(Manager *m);
void manager_suspend(Manager *m);
void manager_resume(Manager *m);

void manager_notify_status(Manager *m);

void self_drop_realtime(int nice_level);
