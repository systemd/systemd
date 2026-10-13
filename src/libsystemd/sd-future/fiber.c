/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <threads.h>
#include <ucontext.h>
#include <unistd.h>

#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "architecture.h"
#include "errno-util.h"
#include "event-future.h"
#include "event-util.h"
#include "fiber-ops.h"
#include "future-internal.h"
#include "log-context.h"
#include "log.h"
#include "memory-util.h"
#include "pthread-util.h"
#include "time-util.h"

#if HAS_FEATURE_ADDRESS_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

/* glibc's _FORTIFY_SOURCE wraps siglongjmp() with __longjmp_chk, which asserts that the target SP is below
 * the current SP. That assumption is incompatible with fiber switching, where the target SP lives on a
 * separately-mmap'd stack and can be at any address relative to the caller. The fortify redirect happens
 * in <setjmp.h>'s declaration of siglongjmp; we sidestep it by declaring our own alias that links
 * directly to the unchecked "siglongjmp" symbol. musl doesn't fortify setjmp.h, so the alias is a plain
 * synonym there. */
_noreturn_ extern void siglongjmp_unchecked(sigjmp_buf env, int val) __asm__("siglongjmp");

static thread_local sd_future *current_fiber = NULL;

typedef enum FiberState {
        FIBER_STATE_INITIAL,
        FIBER_STATE_READY,
        FIBER_STATE_RUNNING,
        FIBER_STATE_SUSPENDED,
        FIBER_STATE_COMPLETED,
        _FIBER_STATE_MAX,
        _FIBER_STATE_INVALID = -EINVAL,
} FiberState;

typedef struct Fiber {
        struct iovec stack;
        sigjmp_buf context;             /* Where to jump to when entering or resuming the fiber. */
        sigjmp_buf resume_context;      /* Where to jump back to when the fiber yields or completes. */

        /* Stack range we were entered from, recorded by finish_switch_stack() on each entry (the
         * entering side may be the thread's original stack or another fiber's), so the fiber's
         * siglongjmp back out (in fiber_swap() or the trampoline's terminate path) can hand
         * AddressSanitizer the destination stack info. With ucontext this comes for free via
         * uc_link/uc_stack; sigjmp_buf is opaque and doesn't carry it. */
        struct iovec resume_stack;

        FiberState state;
        int result;                     /* Either resume value or final return value */
        bool result_pending;            /* sd_fiber_resume() stashed a value that fiber_swap() hasn't consumed yet */

        FiberCancel cancel;             /* How hard the fiber was cancelled. Never decreases. */
        FiberCancel shield;             /* The strongest cancellation that the active shields hide. */
        /* The target's cancel callback can cancel this fiber again, so we must prevent recursive forwarding. */
        bool forwarding_cancel;

        sd_future *floating;            /* Self-ref held while the fiber is floating; dropped on resolve. */
        FutureWaiter wait;

        /* The timers of the SD_FIBER_TIMEOUT() scopes the fiber is in, innermost last. The scopes own the
         * timers. A shield hides the first n_shielded_timeouts timers because their scopes enclose the shield. */
        sd_future **timeouts;
        size_t n_timeouts;
        size_t n_shielded_timeouts;

        sd_event_source *defer_event_source;
        sd_event_source *exit_event_source;

        char *name;
        int64_t priority;
        sd_fiber_func_t func;
        void *userdata;
        sd_fiber_destroy_t destroy;

        /* Storage for the swap performed in fiber_run(): while the fiber is suspended these hold the
         * fiber's own log state; while it is running they hold the caller's log state. The active state
         * always lives in the thread-locals in log.c / log-context.c. */
        LIST_HEAD(LogContext, log_context);
        size_t log_context_num_fields;
        const char *log_prefix;

#if HAVE_VALGRIND_VALGRIND_H
        unsigned stack_id;
#endif
} Fiber;

static Fiber* fiber_get(sd_future *f) {
        return ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
}

static void fiber_set_current(sd_future *f) {
        current_fiber = f;
}

static int fiber_allocate_stack(size_t size, void **ret) {
        void *stack = NULL;
        int r;

        /* The effective stack size is one page less than the given size, because we have to use
         * one page as the guard page for the stack. */

        assert(size > 0 && size % page_size() == 0);
        assert(ret);

        /* Do not pass -EBADF as fd here, otherwise valgrind fails. */
        stack = mmap(/* addr= */ NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                     /* fd= */ -1, /* offset= */ 0);
        if (stack == MAP_FAILED)
                return -errno;

        /* Place the guard page where stack overflow will hit it: the high end on architectures
         * where the stack grows up (PA-RISC), the low end everywhere else. fiber_stack_usable()
         * mirrors this with the inverse offset. */
        void *guard = STACK_GROWS_UP ? (uint8_t*) stack + size - page_size() : stack;

        /* Prefer MADV_GUARD_INSTALL (Linux 6.13+): unlike mprotect(PROT_NONE) it doesn't split
         * the VMA, so guard installation skips the mmap-lock contention and per-guard VMA cost.
         * Fall back to mprotect on older kernels, which return EINVAL for unknown advice.
         * FIXME: delete when baseline above 6.13. */
        r = RET_NERRNO(madvise(guard, page_size(), MADV_GUARD_INSTALL));
        if (r == -EINVAL)
                r = RET_NERRNO(mprotect(guard, page_size(), PROT_NONE));
        if (r < 0) {
                munmap_safe(stack, size);
                return r;
        }

        *ret = TAKE_PTR(stack);
        return 0;
}

/* Usable stack range of a fiber: the full mmap region minus the guard page. Single source of
 * truth for the layout assumed by fiber_allocate_stack(); every consumer (ucontext ss_sp,
 * ASAN handoff iovecs, Valgrind stack registration) goes through here.
 *
 * iov_base is the lowest usable byte regardless of growth direction — that matches POSIX's
 * definition of stack_t.ss_sp, so libc's makecontext() handles the direction for us. Only the
 * guard page placement (and hence iov_base's offset within the mapping) varies. */
static struct iovec fiber_stack_usable(const struct iovec *stack) {
        assert(stack);
        assert(stack->iov_len > page_size());
        return (struct iovec) {
                .iov_base = STACK_GROWS_UP ? stack->iov_base : (uint8_t*) stack->iov_base + page_size(),
                .iov_len = stack->iov_len - page_size(),
        };
}

static inline void start_switch_stack(void **fake_stack_save, const struct iovec *dest) {
#if HAS_FEATURE_ADDRESS_SANITIZER
        __sanitizer_start_switch_fiber(fake_stack_save,
                                       dest ? dest->iov_base : NULL,
                                       dest ? dest->iov_len : 0);
#endif
}

static inline void finish_switch_stack(void *fake_stack_save, struct iovec *ret_old) {

        /* ret_old, if not NULL, is set to the stack range we just switched away from, as ASAN knows it.
         * Fibers use this to remember where to switch back to. Asking ASAN, rather than deriving the range
         * ourselves, also covers the thread's original stack, whose bounds we don't otherwise know. Passing
         * NULL/0 as the destination of start_switch_stack() instead makes ASAN forget the bounds of the
         * stack we return to, after which it complains in __asan_handle_no_return() on every siglongjmp(). */

#if HAS_FEATURE_ADDRESS_SANITIZER
        const void *bottom_old = NULL;
        size_t size_old = 0;

        __sanitizer_finish_switch_fiber(fake_stack_save, &bottom_old, &size_old);

        if (ret_old)
                *ret_old = (struct iovec) {
                        .iov_base = (void*) bottom_old,
                        .iov_len = size_old,
                };
#else
        if (ret_old)
                *ret_old = (struct iovec) {};
#endif
}

_noreturn_ static void fiber_entry_point(void) {
        Fiber *fiber = fiber_get(sd_fiber_get_current());
        void *fake_stack_save = NULL;

        assert(fiber->func);
        assert(fiber->state == FIBER_STATE_INITIAL);

        finish_switch_stack(/* fake_stack_save= */ NULL, &fiber->resume_stack);

        /* Capture our resumable point on the fiber's stack, then bounce back to whoever last set
         * fiber->resume_context. On bootstrap that's fiber_init(); on every subsequent yield it's
         * the most recent fiber_run(). sigsetjmp(buf, 0) skips the signal-mask save: switching is
         * thread-shared with respect to signal masks. */
        if (sigsetjmp(fiber->context, /* savemask= */ 0) == 0) {
                start_switch_stack(&fake_stack_save, &fiber->resume_stack);
                siglongjmp_unchecked(fiber->resume_context, /* val= */ 1);
        }

        /* Re-entered for real via fiber_run()'s siglongjmp(fiber->context). */
        finish_switch_stack(fake_stack_save, &fiber->resume_stack);
        assert(fiber->state == FIBER_STATE_RUNNING);

        /* Block scope so the cleanups attached to LOG_SET_PREFIX / LOG_CONTEXT_PUSH_KEY_VALUE fire
         * before the siglongjmp below — siglongjmp skips _cleanup_ attributes, so we have to make
         * sure the scope ends via a normal control-flow path first. */
        {
                LOG_SET_PREFIX(fiber->name);
                LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", fiber->name);

                fiber->result = fiber->func(fiber->userdata);
                fiber->state = FIBER_STATE_COMPLETED;
        }

        /* Pass NULL fake_stack_save to discard the fiber's fake stack since the fiber is done. */
        start_switch_stack(/* fake_stack_save= */ NULL, &fiber->resume_stack);

        /* Bounce back to whichever fiber_run() call most recently entered us. resume_context is
         * per-fiber so nested fiber_run() — e.g. a bus method dispatched as a fiber handler while
         * sd_event_loop() itself runs in a fiber — is safe. */
        siglongjmp_unchecked(fiber->resume_context, 1);
        assert_not_reached();
}

static int fiber_init(sd_future *f) {
        Fiber *fiber = fiber_get(f);
        ucontext_t uc;
        void *fake_stack_save = NULL;

        if (getcontext(&uc) < 0)
                return -errno;

        struct iovec fiber_stack = fiber_stack_usable(&fiber->stack);

        uc.uc_link = NULL;              /* Unused: trampoline siglongjmps out instead of returning. */
        uc.uc_stack.ss_sp = fiber_stack.iov_base;
        uc.uc_stack.ss_size = fiber_stack.iov_len;
        uc.uc_stack.ss_flags = 0;

        sd_future *prev = sd_fiber_get_current();
        fiber_set_current(f);

        makecontext(&uc, fiber_entry_point, /* argc= */ 0);

        if (sigsetjmp(fiber->resume_context, /* savemask= */ 0) == 0) {
                start_switch_stack(&fake_stack_save, &fiber_stack);
                /* We never come back to this context (the trampoline siglongjmps to resume_context),
                 * so there is nothing to save: use setcontext() rather than swapcontext(). Besides
                 * being cheaper, this avoids the unconditional "ASan doesn't fully support
                 * makecontext/swapcontext functions" warning the ASAN swapcontext() interceptor
                 * prints to stderr on first use, which breaks tests that expect clean stderr. */
                if (setcontext(&uc) < 0) {
                        finish_switch_stack(fake_stack_save, /* ret_old= */ NULL);
                        fiber_set_current(prev);
                        return -errno;
                }
                assert_not_reached();   /* Trampoline siglongjmps back; setcontext doesn't return. */
        }

        finish_switch_stack(fake_stack_save, /* ret_old= */ NULL);

        fiber_set_current(prev);
        return 0;
}

/* Swap the thread-local log prefix and log context with the values stashed in f. While the fiber is
 * suspended, f holds the fiber's own log state; while it's running, f holds the caller's log state. The
 * swap is its own inverse, so the same call drives both directions. */
static void fiber_swap_log_state(Fiber *f) {
        assert(f);
        log_prefix_swap(&f->log_prefix);
        log_context_swap(&f->log_context, &f->log_context_num_fields);
}

static void reset_current_fiber(void) {
        /* Restore the caller's log state stashed in the running fiber (if any) before clearing
         * current_fiber. Without this, the child of a fork() that happened mid-fiber would inherit the
         * fiber's log prefix / context list in its thread-locals even though no fiber is running. */
        sd_future *f = sd_fiber_get_current();
        if (f) {
                Fiber *fiber = fiber_get(f);
                fiber_swap_log_state(fiber);
                fiber_ops_set(/* fiber_ops= */ NULL);
        }
        fiber_set_current(NULL);
}

static sd_event_source* fiber_current_event_source(sd_future *f) {
        Fiber *fiber = fiber_get(f);
        assert(fiber->state != FIBER_STATE_COMPLETED);

        /* SD_EVENT_EXITING only covers the exit callback itself, not the time between callbacks or
         * io_uring completions dispatched while exiting. The exit request persists across all of these. */
        return sd_event_get_exit_code(sd_future_get_event(f), /* ret= */ NULL) >= 0 ?
                fiber->exit_event_source : fiber->defer_event_source;
}

static int atfork_ret;

static void install_atfork(void) {
        /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
         * only half-documented (glibc doesn't document it but LSB does — though only superficially)
         * we'll check for errors only in the most generic fashion possible. */
        atfork_ret = pthread_atfork(/* prepare= */ NULL, /* parent= */ NULL, reset_current_fiber);
        if (atfork_ret != 0)
                log_debug_errno(atfork_ret, "pthread_atfork() failed: %m");
}

static void fiber_resolve(sd_future *f) {
        Fiber *fiber = fiber_get(f);

        fiber->defer_event_source = sd_event_source_disable_unref(fiber->defer_event_source);
        fiber->exit_event_source = sd_event_source_disable_unref(fiber->exit_event_source);
        /* The floating reference may be the last one. Keep it until sd_future_resolve() has marked the
         * future resolved and armed its callbacks; dropping it can free the fiber immediately. */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *floating = TAKE_PTR(fiber->floating);
        sd_future_resolve(f, fiber->result);
}

/* Returns the interruption that the next suspension point of the fiber reports: -ECANCELED if no shield
 * hides the cancellation of the fiber, otherwise -ETIME if the timer of an SD_FIBER_TIMEOUT() scope inside
 * the innermost shield expired, otherwise 0. Neither condition is ever cleared while it applies, so a caller
 * that ignores an interruption gets it again from the next suspension point. */
static int fiber_interruption(Fiber *fiber) {
        assert(fiber);

        if (fiber->cancel > fiber->shield)
                return -ECANCELED;

        for (size_t i = fiber->n_shielded_timeouts; i < fiber->n_timeouts; i++)
                if (sd_future_state(fiber->timeouts[i]) == SD_FUTURE_RESOLVED &&
                    sd_future_result(fiber->timeouts[i]) == -ETIME)
                        return -ETIME;

        return 0;
}

/* Makes a READY or SUSPENDED fiber run again. */
static void fiber_schedule(sd_future *f) {
        Fiber *fiber = fiber_get(f);

        /* INITIAL already has a dispatch queued. RUNNING fibers (including active ancestors in nested
         * loops) check for wakeups at their next fiber_swap(), without needing another dispatch. */
        if (!IN_SET(fiber->state, FIBER_STATE_READY, FIBER_STATE_SUSPENDED))
                return;

        /* In a forked child, the event loop belongs to the parent process and never dispatches the
         * fiber. A finished event loop never dispatches the fiber either. */
        if (event_origin_changed(sd_future_get_event(f)) ||
            sd_event_get_state(sd_future_get_event(f)) == SD_EVENT_FINISHED)
                return;

        /* A READY fiber may have to move from its defer source to its exit source, if the event loop
         * started exiting since the fiber was scheduled. Enabling or disabling a defer or exit source
         * does not allocate, so a failure is a programming error. */
        sd_event_source *source = fiber_current_event_source(f);
        assert_se(sd_event_source_set_enabled(source, SD_EVENT_ONESHOT) >= 0);

        fiber->state = FIBER_STATE_READY;
        if (source == fiber->exit_event_source)
                assert_se(sd_event_source_set_enabled(fiber->defer_event_source, SD_EVENT_OFF) >= 0);
}

static sd_fiber_shield fiber_shield(FiberCancel level) {
        sd_future *f = sd_fiber_get_current();

        assert(IN_SET(level, FIBER_CANCEL_SOFT, FIBER_CANCEL_HARD));

        if (!f)
                return (sd_fiber_shield) {};

        Fiber *fiber = fiber_get(f);
        sd_fiber_shield shield = {
                .fiber = f,
                .saved_level = fiber->shield,
                .saved_n_shielded_timeouts = fiber->n_shielded_timeouts,
        };

        fiber->shield = MAX(fiber->shield, level);
        fiber->n_shielded_timeouts = fiber->n_timeouts;
        return shield;
}

void sd_fiber_shield_end(sd_fiber_shield *shield) {
        assert(shield);

        if (!shield->fiber)
                return;

        assert(shield->fiber == sd_fiber_get_current());

        Fiber *fiber = fiber_get(shield->fiber);

        /* The timeout scopes opened inside the shield have ended, as scopes end in reverse order. */
        assert(fiber->n_timeouts == fiber->n_shielded_timeouts);
        assert(fiber->n_shielded_timeouts >= shield->saved_n_shielded_timeouts);

        fiber->shield = shield->saved_level;
        fiber->n_shielded_timeouts = shield->saved_n_shielded_timeouts;
        *shield = (sd_fiber_shield) {};
}

sd_fiber_shield sd_fiber_shield_begin(void) {
        return fiber_shield(FIBER_CANCEL_SOFT);
}

static bool fiber_event_exiting(void) {
        return IN_SET(sd_event_get_state(sd_fiber_get_event()), SD_EVENT_EXITING, SD_EVENT_FINISHED);
}

static const FiberOps fiber_ops = {
        .ppoll = sd_fiber_ppoll,
        .read = sd_fiber_read,
        .write = sd_fiber_write,
        .timeout = sd_fiber_timeout,
        .timeout_unref = sd_fiber_timeout_unref,
        .shield = fiber_shield,
        .unshield = sd_fiber_shield_end,
        .exiting = fiber_event_exiting,
};

static void fiber_enter(sd_future *f, sd_future *prev, void **fake_stack_save) {
        Fiber *fiber = fiber_get(f);

        fiber_set_current(f);
        fiber_swap_log_state(fiber);
        if (!prev)
                fiber_ops_set(&fiber_ops);

        struct iovec fiber_stack = fiber_stack_usable(&fiber->stack);
        start_switch_stack(fake_stack_save, &fiber_stack);
}

static void fiber_leave(sd_future *f, sd_future *prev, void *fake_stack_save) {
        Fiber *fiber = fiber_get(f);

        finish_switch_stack(fake_stack_save, /* ret_old= */ NULL);
        if (!prev)
                fiber_ops_set(/* fiber_ops= */ NULL);
        fiber_swap_log_state(fiber);
        fiber_set_current(prev);
}

static int fiber_run(sd_future *f) {
        Fiber *fiber = fiber_get(f);
        int r;

        if (fiber->state == FIBER_STATE_COMPLETED)
                return -ESTALE;

        assert(IN_SET(fiber->state, FIBER_STATE_INITIAL, FIBER_STATE_READY));

        static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;
        r = pthread_once(&atfork_once, install_atfork);
        if (r != 0)
                return -r;
        if (atfork_ret != 0)
                return -atfork_ret;

        LOG_SET_PREFIX(fiber->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", fiber->name);

        log_debug("Scheduling fiber");

        /* Save the previously-current fiber (if any) so we can restore it when this fiber yields or
         * completes. This matters when fiber_run() is invoked from within another fiber (e.g. an
         * sd-event dispatch that happens to be running inside a fiber context itself): the
         * LOG_SET_PREFIX/LOG_CONTEXT_PUSH above attached to whichever fiber was current at that moment,
         * and their scope-level cleanup must see the same sd_fiber_get_current() when it runs to detach
         * them from the correct list. */
        sd_future *prev = sd_fiber_get_current();
        void *fake_stack_save = NULL;

        /* INITIAL means the function has never started; READY means it yielded or was woken. Neither
         * includes execution: stay RUNNING until a real yield, suspension, or completion, even while
         * a nested event loop dispatches another fiber and temporarily changes the current fiber. */
        fiber->state = FIBER_STATE_RUNNING;
        fiber_enter(f, prev, &fake_stack_save);

        /* This is where we start executing the fiber. Once it yields, we continue here as if nothing
         * happened. resume_context captures this point; the fiber siglongjmps back to it. */
        if (sigsetjmp(fiber->resume_context, 0) == 0)
                siglongjmp_unchecked(fiber->context, 1);

        fiber_leave(f, prev, fake_stack_save);

        switch (fiber->state) {

        case FIBER_STATE_COMPLETED:
                if (fiber->result < 0 && fiber->result != -ECANCELED)
                        log_debug_errno(fiber->result, "Fiber failed with error: %m");
                else
                        log_debug("Fiber finished executing");

                fiber_resolve(f);
                break;

        case FIBER_STATE_READY:
                log_debug("Fiber yielded execution");

                r = sd_event_source_set_enabled(fiber_current_event_source(f), SD_EVENT_ONESHOT);
                if (r < 0)
                        return r;
                break;

        case FIBER_STATE_SUSPENDED:
                log_debug("Fiber suspended execution");
                /* Fiber is waiting for something - don't re-queue it */
                break;

        default:
                assert_not_reached();
        }

        return 0;
}

static int fiber_cancel_level(sd_future *f, FiberCancel level) {
        Fiber *fiber = fiber_get(f);

        assert(IN_SET(level, FIBER_CANCEL_SOFT, FIBER_CANCEL_HARD));

        if (fiber->state == FIBER_STATE_COMPLETED)
                return 0;

        if (fiber->state == FIBER_STATE_INITIAL) {
                /* The fiber's function has never started, so there are no scope-level cleanups
                 * waiting to run. Skip the dispatch round-trip and settle the future right here —
                 * mirroring the FIBER_STATE_COMPLETED branch of fiber_run(). */
                fiber->result = -ECANCELED;
                fiber->state = FIBER_STATE_COMPLETED;
                fiber_resolve(f);
                return 1;
        }

        bool raised = level > fiber->cancel;
        if (raised)
                fiber->cancel = level;

        if (fiber->cancel <= fiber->shield) {
                /* A full shield hides a hard cancellation, so the fiber keeps waiting for its target. Pass
                 * a hard cancellation on as another cancel of the target, so that the wait can end. For a
                 * process, that turns SIGTERM into SIGKILL. sd_future_cancel_wait_unref() has already
                 * cancelled its target once, so a soft cancellation changes nothing for the target and
                 * isn't passed on. A repeated hard cancellation is passed on too. If the target is a fiber,
                 * the event loop only runs it during the exit after a cancellation moved its dispatch to
                 * the exit source. */
                if (level == FIBER_CANCEL_HARD && fiber->wait.target && !fiber->forwarding_cancel) {
                        fiber->forwarding_cancel = true;
                        (void) sd_future_cancel_full(fiber->wait.target, SD_FUTURE_CANCEL_HARD);
                        fiber->forwarding_cancel = false;
                }

                /* A READY fiber may still have to move its dispatch to the exit source. */
                if (fiber->state == FIBER_STATE_READY)
                        fiber_schedule(f);

                return raised;
        }

        fiber_schedule(f);
        return raised;
}

static int fiber_cancel(sd_future *f, sd_future_cancel_mode_t mode) {
        Fiber *fiber = fiber_get(f);

        return fiber_cancel_level(f, mode == SD_FUTURE_CANCEL_HARD ||
                                    (mode == SD_FUTURE_CANCEL_DEFAULT && fiber->cancel != FIBER_CANCEL_NONE) ?
                                    FIBER_CANCEL_HARD : FIBER_CANCEL_SOFT);
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        return fiber_run(f);
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        Fiber *fiber = fiber_get(f);
        int r;

        /* An INITIAL fiber is cancelled synchronously; a COMPLETED fiber needs no further work.
         * Return directly: cancelling an unstarted floating fiber may drop its last self-reference,
         * so neither f nor fiber may be accessed afterwards. */
        if (IN_SET(fiber->state, FIBER_STATE_INITIAL, FIBER_STATE_COMPLETED))
                return fiber_cancel_level(f, FIBER_CANCEL_HARD);

        /* The event loop only dispatches exit sources from now on, so a fiber that waits for anything
         * else would never finish. The cancellation is therefore hard, which interrupts soft shields. */
        (void) fiber_cancel_level(f, FIBER_CANCEL_HARD);

        /* Under a full shield, the fiber keeps waiting for its target, which the cancellation was passed
         * on to. The target wakes the fiber when it has finished. */
        if (fiber->state != FIBER_STATE_READY)
                return 0;

        /* Run directly in this dispatch. Cancellation re-arms the source for a READY or SUSPENDED
         * fiber; clear that redundant dispatch so cleanup can suspend without being run again
         * prematurely. fiber_run() will re-arm the source itself if the fiber yields. */
        r = sd_event_source_set_enabled(s, SD_EVENT_OFF);
        if (r < 0)
                return r;

        return fiber_run(f);
}

static void fiber_free(sd_future *f) {
        Fiber *fiber = fiber_get(f);

        /* To make sure all memory is deallocated, the fiber has to have completed by the time we free it to
         * make sure its stack has finished unwinding (which will invoke the registered cleanup functions).
         * As this function may get called when not running on a fiber ourselves, we can't guarantee here
         * that we can run the fiber to completion ourselves, so we insist that this happens before we get
         * here. To ensure fibers are cleaned up before exiting the event loop, exit handlers are added for
         * fibers created outside of existing fibers. For fibers created within running fibers, unwinding the
         * outer fiber should take care of cleaning up any created child fibers (for example using
         * sd_future_cancel_wait_unref()).
         *
         * FIBER_STATE_INITIAL is also accepted: the function has never started, so there are no
         * registered cleanups to run. This covers the partial-construction failure path in sd_fiber_new()
         * as well as fibers that are unrefed before the event loop ever dispatches them. */
        assert(IN_SET(fiber->state, FIBER_STATE_INITIAL, FIBER_STATE_COMPLETED));
        assert(!fiber->wait.target);

        if (fiber->destroy)
                fiber->destroy(fiber->userdata);

#if HAVE_VALGRIND_VALGRIND_H
        if (fiber->stack.iov_base)
                VALGRIND_STACK_DEREGISTER(fiber->stack_id);
#endif

        munmap_safe(fiber->stack.iov_base, fiber->stack.iov_len);

        sd_event_source_disable_unref(fiber->defer_event_source);
        sd_event_source_disable_unref(fiber->exit_event_source);

        free(fiber->timeouts);
        free(fiber->name);
}

sd_future* sd_fiber_get_current(void) {
        return current_fiber;
}

int sd_fiber_is_running(void) {
        return !!current_fiber;
}

sd_event* sd_fiber_get_event(void) {
        sd_future *f = sd_fiber_get_current();
        assert_return(f, NULL);
        return sd_future_get_event(f);
}

int sd_fiber_get_priority(int64_t *ret) {
        sd_future *f = sd_fiber_get_current();

        assert_return(ret, -EINVAL);
        assert_return(f, -ESRCH);

        Fiber *fiber = fiber_get(f);
        *ret = fiber->priority;
        return 0;
}

static int fiber_swap(FiberState state) {
        Fiber *fiber = fiber_get(sd_fiber_get_current());

        assert(fiber->state == FIBER_STATE_RUNNING);
        assert(IN_SET(state, FIBER_STATE_READY, FIBER_STATE_SUSPENDED));

        /* If an interruption is in effect, or sd_fiber_resume() queued a value while the fiber was
         * running, return it right away without suspending. The event loop then doesn't have to run the
         * fiber again. Neither yield nor suspend changes the scheduling state in this case, because the
         * caller has to see the result before it suspends or yields again. */
        if (!fiber->result_pending && fiber_interruption(fiber) == 0) {
                fiber->state = state;

                void *fake_stack_save = NULL;

                if (sigsetjmp(fiber->context, 0) == 0) {
                        start_switch_stack(&fake_stack_save, &fiber->resume_stack);
                        siglongjmp_unchecked(fiber->resume_context, 1);
                }

                finish_switch_stack(fake_stack_save, &fiber->resume_stack);
        }

        assert(fiber->state == FIBER_STATE_RUNNING);

        /* Consume the resume value after either path, whether it was queued while running or
         * delivered after a context switch. Clear it unconditionally so it doesn't pollute
         * subsequent suspends or the fiber's eventual return value — both negative errors and
         * positive payloads (byte counts, accepted fds, revents masks) are valid resume values. An
         * interruption replaces the value. Unlike the value, it stays in effect. */
        fiber->result_pending = false;
        int result = TAKE_GENERIC(fiber->result, int, 0);

        int r = fiber_interruption(fiber);
        if (r < 0)
                return r;

        return result;
}

int sd_fiber_yield(void) {
        assert_return(sd_fiber_get_current(), -ESRCH);
        return fiber_swap(FIBER_STATE_READY);
}

int sd_fiber_suspend(void) {
        assert_return(sd_fiber_get_current(), -ESRCH);
        return fiber_swap(FIBER_STATE_SUSPENDED);
}

int sd_fiber_interrupted(void) {
        sd_future *f = sd_fiber_get_current();

        assert_return(f, -ESRCH);

        return fiber_interruption(fiber_get(f));
}

static int fiber_set_priority(sd_future *f, int64_t priority) {
        Fiber *fiber = fiber_get(f);
        int r = 0;

        if (fiber->defer_event_source)
                RET_GATHER(r, sd_event_source_set_priority(fiber->defer_event_source, priority));

        if (fiber->exit_event_source)
                RET_GATHER(r, sd_event_source_set_priority(fiber->exit_event_source, priority));

        if (r >= 0)
                fiber->priority = priority;

        return r;
}

static const sd_future_ops fiber_future_ops;

int sd_fiber_resume(sd_future *f, int result) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        Fiber *fiber = fiber_get(f);

        if (fiber->state == FIBER_STATE_COMPLETED)
                return 0;

        fiber->result = result;
        fiber->result_pending = true;
        fiber_schedule(f);
        return 0;
}

/* The fiber_future ops pass the Fiber pointer through as the future's private state. Once started, the
 * fiber resolves its own future when it finishes running, also after a cancellation. */
static const sd_future_ops fiber_future_ops = {
        .size = sizeof(sd_future_ops),
        .private_size = sizeof(Fiber),
        .free = fiber_free,
        .cancel = fiber_cancel,
        .set_priority = fiber_set_priority,
};

int sd_fiber_new(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_future **ret) {
        int r;

        assert_return(e, -EINVAL);
        assert_return(name, -EINVAL);
        assert_return(func, -EINVAL);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
        r = sd_future_new(e, &fiber_future_ops, &f);
        if (r < 0)
                return r;

        Fiber *fiber = fiber_get(f);

        struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
        if (getrlimit(RLIMIT_STACK, &rl) < 0)
                log_debug_errno(errno, "Reading RLIMIT_STACK failed, ignoring: %m");
        if (rl.rlim_cur == RLIM_INFINITY)
                rl.rlim_cur = 8U * U64_MB; /* Same as the default thread stack size */

        /* Reserve room for the guard page so the usable region stays above PTHREAD_STACK_MIN, which
         * is what libc/pthread routines (e.g. TLS setup on musl) assume. */
        size_t stack_len = ROUND_UP(rl.rlim_cur, page_size());
        if (stack_len < (size_t) PTHREAD_STACK_MIN + page_size())
                stack_len = ROUND_UP((size_t) PTHREAD_STACK_MIN + page_size(), page_size());

        *fiber = (Fiber) {
                .stack.iov_len = stack_len,
                .state = FIBER_STATE_INITIAL,
                .name = strdup(name),
                .func = func,
                .userdata = userdata,
                .wait.fiber = f,
        };
        if (!fiber->name)
                return -ENOMEM;

        r = fiber_allocate_stack(fiber->stack.iov_len, &fiber->stack.iov_base);
        if (r < 0)
                return r;

#if HAVE_VALGRIND_VALGRIND_H
        /* Register the usable stack range (above the guard page) before fiber_bootstrap() so the
         * trampoline's first sigsetjmp doesn't trip Valgrind's stack-tracking heuristics. */
        struct iovec usable = fiber_stack_usable(&fiber->stack);
        fiber->stack_id = VALGRIND_STACK_REGISTER(
                        usable.iov_base,
                        (uint8_t*) usable.iov_base + usable.iov_len);
#endif

        r = fiber_init(f);
        if (r < 0)
                return r;

        /* Execution of the fiber is driven by two event sources, one deferred, one exit. The exit event
         * source kicks in when sd_event_exit() is called, as from that point onwards only exit event
         * sources will be dispatched. */

        r = sd_event_add_defer(e, &fiber->defer_event_source, fiber_on_defer, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(fiber->defer_event_source, fiber->name);
        if (r < 0)
                return r;

        r = sd_event_add_exit(e, &fiber->exit_event_source, fiber_on_exit, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(fiber->exit_event_source, fiber->name);
        if (r < 0)
                return r;

        /* If we're on a fiber, we'll rely on the parent fiber to cancel this fiber if the event loop is
         * exiting. Otherwise, we'll trigger cancellation of this fiber via the exit event source. Why cancel
         * via the exit event source? We can only run the fiber while the event loop is active, so we need to
         * make sure all fibers finish running before the event loop is finished, which an exit event source
         * allows us to do. */
        r = sd_event_source_set_enabled(fiber->exit_event_source, sd_fiber_is_running() ? SD_EVENT_OFF : SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        /* Stays in FIBER_STATE_INITIAL until the event loop first dispatches it via fiber_run(). */

        if (ret)
                *ret = TAKE_PTR(f);
        else {
                /* Fire-and-forget: the fiber is guaranteed to resolve (via completion, cancellation, or
                 * the event loop exit handler), so making the future floating cleans it up. */
                r = sd_fiber_set_floating(f, true);
                if (r < 0)
                        return r;

                /* Floating self-ref keeps the fiber alive; release our local ref without cancelling. */
                f = sd_future_unref(f);
        }

        return 0;
}

int sd_fiber_set_destroy_callback(sd_future *f, sd_fiber_destroy_t callback) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        fiber_get(f)->destroy = callback;
        return 0;
}

int sd_fiber_get_destroy_callback(sd_future *f, sd_fiber_destroy_t *ret) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        sd_fiber_destroy_t callback = fiber_get(f)->destroy;
        if (ret)
                *ret = callback;

        return !!callback;
}

int sd_fiber_set_floating(sd_future *f, int b) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        Fiber *fiber = fiber_get(f);

        if (!!fiber->floating == !!b)
                return 0;

        /* The floating self-ref keeps the future alive until the fiber resolves; fiber_run() drops it
         * in the COMPLETED branch. Only valid for fiber futures because fibers uniquely guarantee
         * resolution (via completion, cancellation, or the event loop exit handler). */
        if (b)
                fiber->floating = sd_future_ref(f);
        else
                fiber->floating = sd_future_unref(fiber->floating);

        return 0;
}

int sd_fiber_get_floating(sd_future *f) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        Fiber *fiber = fiber_get(f);
        return !!fiber->floating;
}

int sd_fiber_sleep(uint64_t usec) {
        sd_future *f = sd_fiber_get_current();
        int r;

        if (!f)
                return usleep_safe(usec);

        if (usec == 0)
                return sd_fiber_yield();

        /* Match usleep_safe(USEC_INFINITY): suspend indefinitely. Passing USEC_INFINITY to
         * sd_event_add_time_relative() would overflow into -EOVERFLOW. */
        if (usec == USEC_INFINITY)
                return sd_fiber_suspend();

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *timer = NULL;
        r = future_new_time_relative(
                        sd_future_get_event(f),
                        CLOCK_MONOTONIC,
                        usec,
                        /* accuracy= */ 1,
                        /* result= */ 0,
                        &timer);
        if (r < 0)
                return r;

        r = sd_fiber_await(timer);
        if (r < 0)
                return r;

        return sd_future_result(timer);
}

sd_future* sd_fiber_get_awaiting(sd_future *f) {
        assert_return(f, NULL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, NULL);

        return fiber_get(f)->wait.target;
}

int sd_fiber_await(sd_future *target) {
        sd_future *f = sd_fiber_get_current();
        int r;

        assert_return(f, -ESRCH);
        assert_return(target, -EINVAL);
        assert_return(target != f, -EDEADLK);
        assert_return(sd_future_get_event(target) == sd_future_get_event(f), -EINVAL);

        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return 0;

        /* The fiber is executing inside event dispatch, so its loop cannot have finished yet.
         * Waking up during exit is handled by the fiber's own exit source. */
        assert(sd_event_get_state(sd_future_get_event(f)) != SD_EVENT_FINISHED);

        future_add_waiter(target, &fiber_get(f)->wait);
        r = sd_fiber_suspend();

        /* The caller does not have to own a reference to the target. The reference that the wait held
         * may then be the last one. Release it only after the checks below, or they read freed memory. */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *ref = future_remove_waiter(&fiber_get(f)->wait);

        /* The target can resolve before a cancellation or timeout wakes us up. The operation has then
         * already taken effect: a channel send, for example, put its item into the channel. If we
         * reported the interruption, the caller would assume that the send failed and that the channel
         * destroyed the item, although a receive will still get the item. Report the completion. The
         * interruption stays in effect, so the next suspension point returns it. */
        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return 0;
        if (r < 0)
                return r;

        return -EBUSY;
}

sd_future* sd_future_cancel_wait_unref(sd_future *f) {
        sd_future *self = sd_fiber_get_current();
        int r;

        if (!f)
                return NULL;

        /* Outside a fiber we can still clean up futures whose cancellation is synchronous, or which
         * are already resolved. Asynchronous cancellation requires a fiber to await completion. */
        if (!self)
                return sd_future_cancel_unref(f);

        /* A fiber cannot wait for itself. Invalid calls still consume their reference: releasing the
         * last reference to a pending future remains a programming error, diagnosed by sd_future_free(). */
        if (f == self) {
                log_debug("Refusing to wait for the calling fiber itself, releasing it without cancelling.");
                return sd_future_unref(f);
        }

        Fiber *fiber = fiber_get(self);

        /* The future can use memory that belongs to the caller. The wait therefore has to finish even if
         * the calling fiber is cancelled or times out, and hides every interruption. */
        _unused_ _cleanup_(sd_fiber_shield_end) sd_fiber_shield shield = fiber_shield(FIBER_CANCEL_HARD);

        r = sd_future_cancel(f);
        if (r < 0)
                log_debug_errno(r, "Failed to cancel future, ignoring: %m");

        /* The calling fiber was already cancelled hard, so cancel the future hard too. */
        if (fiber->cancel == FIBER_CANCEL_HARD) {
                r = sd_future_cancel_full(f, SD_FUTURE_CANCEL_HARD);
                if (r < 0)
                        log_debug_errno(r, "Failed to cancel future again, ignoring: %m");
        }

        while (sd_future_state(f) == SD_FUTURE_PENDING) {
                /* Synchronous cancellation needs no dispatch and works across event loops too, but
                 * waiting for an asynchronous one does not. */
                if (sd_future_get_event(f) != sd_future_get_event(self)) {
                        log_debug("Cannot wait for a future on another event loop to finish cancelling, giving up.");
                        break;
                }

                r = sd_fiber_await(f);
                if (r < 0 && r != -EBUSY)
                        log_debug_errno(r, "Failed to wait for future to finish, ignoring: %m");
        }

        if (sd_future_state(f) == SD_FUTURE_RESOLVED) {
                int fr = sd_future_result(f);
                if (fr < 0 && fr != -ECANCELED)
                        log_debug_errno(fr, "Future resolved with error, ignoring: %m");
        }

        return sd_future_unref(f);
}

DEFINE_POINTER_ARRAY_CLEAR_FUNC(sd_future*, sd_future_cancel_wait_unref);
DEFINE_POINTER_ARRAY_FREE_FUNC(sd_future*, sd_future_cancel_wait_unref);

static int fiber_timeout_callback(sd_future *timer, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        /* A shield can hide the expired timer. The fiber then gets the -ETIME once the shield ends. */
        if (fiber_interruption(fiber_get(f)) < 0)
                fiber_schedule(f);

        return 0;
}

sd_future* sd_fiber_timeout(uint64_t timeout) {
        sd_future *f = sd_fiber_get_current();
        int r;

        assert_return(f, NULL);

        if (timeout == USEC_INFINITY)
                return NULL;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *timer = NULL;
        r = future_new_time_relative(
                        sd_future_get_event(f),
                        CLOCK_MONOTONIC,
                        timeout,
                        /* accuracy= */ 1,
                        /* result= */ -ETIME,
                        &timer);
        if (r < 0)
                return NULL; /* On allocation failure no timer is armed and the scope becomes a no-op.
                              * Errors here are rare; if the caller cares they can compare to NULL. */

        /* The whole point of SD_FIBER_TIMEOUT is to wake the calling fiber when the deadline
         * fires (so a later sd_fiber_suspend / sd_fiber_await returns -ETIME from this timer's
         * resolve). Install a floating resume callback bound to the timer's lifetime. */
        r = sd_future_add_callback(timer, /* ret_slot= */ NULL, fiber_timeout_callback, f);
        if (r < 0)
                return NULL;

        Fiber *fiber = fiber_get(f);
        if (!GREEDY_REALLOC(fiber->timeouts, fiber->n_timeouts + 1))
                return NULL;

        fiber->timeouts[fiber->n_timeouts++] = timer;
        return TAKE_PTR(timer);
}

sd_future* sd_fiber_timeout_unref(sd_future *timer) {
        if (!timer)
                return NULL;

        Fiber *fiber = fiber_get(ASSERT_PTR(sd_fiber_get_current()));

        assert(fiber->n_timeouts > fiber->n_shielded_timeouts && fiber->timeouts[fiber->n_timeouts - 1] == timer);
        fiber->n_timeouts--;

        return sd_future_cancel_wait_unref(timer);
}
