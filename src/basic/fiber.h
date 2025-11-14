/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/ucontext.h>

#include "basic-forward.h"
#include "list.h"

/* We need to be able to get the current fiber and access its log context and log prefix from log.c and
 * log-context.c, so the definition of sd_fiber lives here instead of in sd-fiber.c. */

typedef int (*sd_fiber_func_t)(void *userdata);
typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;

typedef enum sd_fiber_state_t {
        SD_FIBER_STATE_READY,
        SD_FIBER_STATE_SUSPENDED,
        SD_FIBER_STATE_CANCELLED,
        SD_FIBER_STATE_COMPLETED,
        _SD_FIBER_STATE_MAX,
        _SD_FIBER_STATE_INVALID = -EINVAL,
} sd_fiber_state_t;

typedef struct sd_fiber {
        unsigned n_ref;

        void *stack;
        size_t stack_size;
        ucontext_t context;

        sd_fiber_state_t state;
        int result;                     /* Either resume error code or final return value */

        sd_event *event;
        sd_event_source *defer_event_source;
        sd_event_source *exit_event_source;

        char *name;
        int64_t priority;
        sd_fiber_func_t func;
        void *userdata;

        LIST_HEAD(LogContext, log_context);
        size_t log_context_num_fields;
        const char *log_prefix;
} sd_fiber;

const char *sd_fiber_state_to_string(sd_fiber_state_t s);
sd_fiber_state_t sd_fiber_state_from_string(const char *s);

DISABLE_WARNING_REDUNDANT_DECLS;
sd_fiber *sd_fiber_current(void);
REENABLE_WARNING;

void sd_fiber_set_current(sd_fiber *f);
