#pragma once
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#include "sd-event.h"

#include "hashmap.h"
#include "inotify-util.h"
#include "list.h"
#include "prioq.h"
#include "ratelimit.h"

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
        SOURCE_INOTIFY,
        _SOURCE_EVENT_SOURCE_TYPE_MAX,
        _SOURCE_EVENT_SOURCE_TYPE_INVALID = -EINVAL,
} EventSourceType;

/* All objects we use in epoll events start with this value, so that
 * we know how to dispatch it */
typedef enum WakeupType {
        WAKEUP_NONE,
        WAKEUP_EVENT_SOURCE, /* either I/O or pidfd wakeup */
        WAKEUP_CLOCK_DATA,
        WAKEUP_SIGNAL_DATA,
        WAKEUP_INOTIFY_DATA,
        _WAKEUP_TYPE_MAX,
        _WAKEUP_TYPE_INVALID = -EINVAL,
} WakeupType;

struct inode_data;

struct sd_event_source {
        WakeupType wakeup;

        unsigned n_ref;

        sd_event *event;
        void *userdata;
        sd_event_handler_t prepare;

        char *description;

        EventSourceType type;
        signed int enabled:3;
        bool pending:1;
        bool dispatching:1;
        bool floating:1;
        bool exit_on_failure:1;
        bool ratelimited:1;

        int64_t priority;
        unsigned pending_index;
        unsigned prepare_index;
        uint64_t pending_iteration;
        uint64_t prepare_iteration;

        sd_event_destroy_t destroy_callback;
        sd_event_handler_t ratelimit_expire_callback;

        LIST_FIELDS(sd_event_source, sources);

        RateLimit rate_limit;

        /* These are primarily fields relevant for time event sources, but since any event source can
         * effectively become one when rate-limited, this is part of the common fields. */
        unsigned earliest_index;
        unsigned latest_index;

        union {
                struct {
                        sd_event_io_handler_t callback;
                        int fd;
                        uint32_t events;
                        uint32_t revents;
                        bool registered:1;
                        bool owned:1;
                } io;
                struct {
                        sd_event_time_handler_t callback;
                        usec_t next, accuracy;
                } time;
                struct {
                        sd_event_signal_handler_t callback;
                        struct signalfd_siginfo siginfo;
                        int sig;
                        bool unblock;
                } signal;
                struct {
                        sd_event_child_handler_t callback;
                        siginfo_t siginfo;
                        pid_t pid;
                        int options;
                        int pidfd;
                        bool registered:1; /* whether the pidfd is registered in the epoll */
                        bool pidfd_owned:1; /* close pidfd when event source is freed */
                        bool process_owned:1; /* kill+reap process when event source is freed */
                        bool exited:1; /* true if process exited (i.e. if there's value in SIGKILLing it if we want to get rid of it) */
                        bool waited:1; /* true if process was waited for (i.e. if there's value in waitid(P_PID)'ing it if we want to get rid of it) */
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
                struct {
                        sd_event_inotify_handler_t callback;
                        uint32_t mask;
                        struct inode_data *inode_data;
                        LIST_FIELDS(sd_event_source, by_inode_data);
                } inotify;
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

/* A structure listing all event sources currently watching a specific inode */
struct inode_data {
        /* The identifier for the inode, the combination of the .st_dev + .st_ino fields of the file */
        ino_t ino;
        dev_t dev;

        /* An fd of the inode to watch. The fd is kept open until the next iteration of the loop, so that we can
         * rearrange the priority still until then, as we need the original inode to change the priority as we need to
         * add a watch descriptor to the right inotify for the priority which we can only do if we have a handle to the
         * original inode. We keep a list of all inode_data objects with an open fd in the to_close list (see below) of
         * the sd-event object, so that it is efficient to close everything, before entering the next event loop
         * iteration. */
        int fd;

        /* The inotify "watch descriptor" */
        int wd;

        /* The combination of the mask of all inotify watches on this inode we manage. This is also the mask that has
         * most recently been set on the watch descriptor. */
        uint32_t combined_mask;

        /* All event sources subscribed to this inode */
        LIST_HEAD(sd_event_source, event_sources);

        /* The inotify object we watch this inode with */
        struct inotify_data *inotify_data;

        /* A linked list of all inode data objects with fds to close (see above) */
        LIST_FIELDS(struct inode_data, to_close);
};

/* A structure encapsulating an inotify fd */
struct inotify_data {
        WakeupType wakeup;

        /* For each priority we maintain one inotify fd, so that we only have to dequeue a single event per priority at
         * a time */

        int fd;
        int64_t priority;

        Hashmap *inodes; /* The inode_data structures keyed by dev+ino */
        Hashmap *wd;     /* The inode_data structures keyed by the watch descriptor for each */

        /* The buffer we read inotify events into */
        union inotify_event_buffer buffer;
        size_t buffer_filled; /* fill level of the buffer */

        /* How many event sources are currently marked pending for this inotify. We won't read new events off the
         * inotify fd as long as there are still pending events on the inotify (because we have no strategy of queuing
         * the events locally if they can't be coalesced). */
        unsigned n_pending;

        /* If this counter is non-zero, don't GC the inotify data object even if not used to watch any inode
         * anymore. This is useful to pin the object for a bit longer, after the last event source needing it
         * is gone. */
        unsigned n_busy;

        /* A linked list of all inotify objects with data already read, that still need processing. We keep this list
         * to make it efficient to figure out what inotify objects to process data on next. */
        LIST_FIELDS(struct inotify_data, buffered);
};
