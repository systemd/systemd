/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/ucontext.h>

#include "basic-forward.h"
#include "list.h"
#include "macro-fundamental.h"

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

/* Hooks installed on a fiber so that functions in src/basic can transparently defer to the suspending
 * variants in sd-future when invoked from a running fiber. Populated by sd_fiber_new() with pointers to the
 * implementations in fiber-ops.c. */
typedef struct FiberOps {
        int (*ppoll)(struct pollfd *fds, size_t n_fds, usec_t timeout);
        ssize_t (*read)(int fd, void *buf, size_t count);
        ssize_t (*write)(int fd, const void *buf, size_t count);
        sd_future* (*timeout)(uint64_t timeout);
        sd_future* (*timeout_done)(sd_future *timer);
} FiberOps;

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

        const FiberOps *ops;

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

typedef struct FiberOpsRestore {
        Fiber *fiber;
        const FiberOps *ops;
} FiberOpsRestore;

static inline void fiber_ops_restore(FiberOpsRestore *s) {
        if (s->fiber)
                s->fiber->ops = s->ops;
}

/* Forward the call to the fiber op (if we're on a fiber with ops installed), otherwise fall through to the
 * caller's fallback body. Clears and restores ops around the call so the op's implementation can call back
 * into the non-redirected basic functions without infinite recursion. The restore runs via cleanup, so ops
 * is reinstated regardless of how the scope exits. */
#define FIBER_OPS_FORWARD(func, ...)                                    \
        do {                                                            \
                Fiber *_f = fiber_get_current();                        \
                if (_f && _f->ops && _f->ops->func) {                   \
                        _unused_ _cleanup_(fiber_ops_restore) FiberOpsRestore _r = { .fiber = _f, .ops = _f->ops }; \
                        const FiberOps *_o = _f->ops;                   \
                        _f->ops = NULL;                                 \
                        return _o->func(__VA_ARGS__);                   \
                }                                                       \
        } while (0)

/* Mirror of SD_FIBER_TIMEOUT() for code under src/basic that doesn't include sd-future.h: dispatches
 * through FiberOps so the actual sd_fiber_timeout() implementation lives in libsystemd. */
static inline sd_future* fiber_ops_timeout(uint64_t timeout) {
        Fiber *f = fiber_get_current();
        if (f && f->ops)
                return f->ops->timeout(timeout);
        return NULL;
}

static inline void fiber_ops_timeout_done(sd_future **timer) {
        if (!*timer)
                return;

        Fiber *f = ASSERT_PTR(fiber_get_current());
        *timer = f->ops->timeout_done(*timer);
}

#define FIBER_OPS_TIMEOUT(timeout) _FIBER_OPS_TIMEOUT(UNIQ, (timeout))
#define _FIBER_OPS_TIMEOUT(uniq, timeout)                                                                                               \
        _unused_ _cleanup_(fiber_ops_timeout_done) sd_future *UNIQ_T(_fot_, uniq) = fiber_ops_timeout(timeout)
