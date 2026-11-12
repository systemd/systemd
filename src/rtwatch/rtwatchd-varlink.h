/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct Manager Manager;
typedef struct TrackedThread TrackedThread;

typedef enum WatchEvent {
        WATCH_EVENT_READY,
        WATCH_EVENT_REALTIME,
        WATCH_EVENT_HIGH_PRIORITY,
        WATCH_EVENT_RESET_KNOWN,
        WATCH_EVENT_RESET_ALL,
        WATCH_EVENT_SUSPENDED,
        WATCH_EVENT_RESUMED,
        WATCH_EVENT_STARVING,
        _WATCH_EVENT_MAX,
        _WATCH_EVENT_INVALID = -EINVAL,
} WatchEvent;

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(watch_event, WatchEvent);

int manager_connect_varlink(Manager *m);

/* Notify subscribers of Watch() about events. Must be called from the main thread only. */
void manager_send_thread_event(Manager *m, WatchEvent event, TrackedThread *t);
void manager_send_event(Manager *m, WatchEvent event, unsigned n_threads);
