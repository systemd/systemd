/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/ucontext.h>

#include "basic-forward.h"
#include "list.h"

/* We need to be able to get the current fiber and access its log context and log prefix from log.c and
 * log-context.c, so the definition of Fiber lives here instead of in libsystemd. */

typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;
typedef struct sd_future sd_future;

typedef enum FiberState {
        FIBER_STATE_READY,
        FIBER_STATE_SUSPENDED,
        FIBER_STATE_CANCELLED,
        FIBER_STATE_COMPLETED,
        _FIBER_STATE_MAX,
        _FIBER_STATE_INVALID = -EINVAL,
} FiberState;

typedef struct Fiber {
        void *stack;
        size_t stack_size;
        ucontext_t context;

        FiberState state;
        int result;                     /* Either resume error code or final return value */

        sd_event *event;
        sd_event_source *defer_event_source;
        sd_event_source *exit_event_source;

        char *name;
        int64_t priority;
        FiberFunc func;
        void *userdata;
        FiberDestroy destroy;
        sd_future *future;

        LIST_HEAD(LogContext, log_context);
        size_t log_context_num_fields;
        const char *log_prefix;

#if HAVE_VALGRIND_VALGRIND_H
        unsigned stack_id;
#endif
} Fiber;

const char *fiber_state_to_string(FiberState s);
FiberState fiber_state_from_string(const char *s);

Fiber *fiber_get_current(void);
void fiber_set_current(Fiber *f);
