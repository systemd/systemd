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
typedef struct sd_promise sd_promise;
typedef int (*sd_fiber_func_t)(void *userdata);
typedef void (*sd_fiber_destroy_t)(void *userdata);

typedef enum FiberState {
        FIBER_STATE_INITIAL,
        FIBER_STATE_READY,
        FIBER_STATE_SUSPENDED,
        FIBER_STATE_CANCELLED,
        FIBER_STATE_COMPLETED,
        _FIBER_STATE_MAX,
        _FIBER_STATE_INVALID = -EINVAL,
} FiberState;

typedef struct Fiber {
        sd_promise *promise;            /* must be first: set by sd_future_new() via the impl convention */

        void *stack;
        size_t stack_size;
        ucontext_t context;
        ucontext_t resume_context;      /* Where to jump back to when the fiber yields or completes. */

        FiberState state;
        int result;                     /* Either resume error code or final return value */

        sd_future *floating;            /* Self-ref held while the fiber is floating; dropped on resolve. */

        sd_event *event;
        sd_event_source *defer_event_source;
        sd_event_source *exit_event_source;

        char *name;
        int64_t priority;
        sd_fiber_func_t func;
        void *userdata;
        sd_fiber_destroy_t destroy;

        LIST_HEAD(LogContext, log_context);
        size_t log_context_num_fields;
        const char *log_prefix;

#if HAVE_VALGRIND_VALGRIND_H
        unsigned stack_id;
#endif
} Fiber;

DECLARE_STRING_TABLE_LOOKUP(fiber_state, FiberState);

Fiber* fiber_get_current(void);
void fiber_set_current(Fiber *f);
