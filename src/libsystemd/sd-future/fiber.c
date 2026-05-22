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
#include "fiber-ops.h"
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
        FIBER_STATE_SUSPENDED,
        FIBER_STATE_COMPLETED,
        _FIBER_STATE_MAX,
        _FIBER_STATE_INVALID = -EINVAL,
} FiberState;

typedef struct Fiber {
        struct iovec stack;
        sigjmp_buf context;             /* Where to jump to when entering or resuming the fiber. */
        sigjmp_buf resume_context;      /* Where to jump back to when the fiber yields or completes. */

        /* Caller's stack range, recorded by fiber_run() on each entry so the fiber's siglongjmp back
         * out (in fiber_swap() or the trampoline's terminate path) can hand AddressSanitizer the
         * destination stack info. With ucontext this comes for free via uc_link/uc_stack; sigjmp_buf
         * is opaque and doesn't carry it. */
        struct iovec resume_stack;

        FiberState state;
        int result;                     /* Either resume error code or final return value */
        bool result_pending;            /* sd_fiber_resume() stashed a value that fiber_swap() hasn't consumed yet */

        /* Monotonic count of interruptions delivered to this fiber — an explicit cancellation
         * (-ECANCELED) or an SD_FIBER_TIMEOUT firing (-ETIME) — bumped only by fiber_cancel() and the
         * timeout resume callback, NOT by ordinary future completions. Transparent wait regions like
         * sd_future_cancel_wait_unref() snapshot it on entry and compare on exit to tell an interruption
         * that targeted *this* fiber from the awaited future merely resolving (possibly negative, e.g.
         * -ECANCELED) — the two are otherwise indistinguishable once collapsed into a single resume
         * value. Cancellations and timeouts are distinct values (-ECANCELED vs -ETIME) but both count
         * here, so the umbrella is "interruption". */
        uint64_t n_interrupts;

        sd_future *floating;            /* Self-ref held while the fiber is floating; dropped on resolve. */

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

        stack = mmap(/* addr= */ NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                     /* fd= */ -EBADF, /* offset= */ 0);
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
                (void) munmap(stack, size);
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

static inline void finish_switch_stack(void *fake_stack_save) {
#if HAS_FEATURE_ADDRESS_SANITIZER
        __sanitizer_finish_switch_fiber(fake_stack_save, NULL, NULL);
#endif
}

/* Refresh f->resume_stack from whoever is currently the running fiber, so the next siglongjmp() out
 * of f (in the trampoline or fiber_swap()) can hand the right destination stack to ASAN. Must be
 * called before fiber_set_current(f) — relies on sd_fiber_get_current() returning the caller. */
static void fiber_set_resume_stack(Fiber *f, Fiber *resume) {
        assert(f);

        if (resume)
                f->resume_stack = fiber_stack_usable(&resume->stack);
        else
                f->resume_stack = (struct iovec) {};
}

_noreturn_ static void fiber_entry_point(void) {
        Fiber *f = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(sd_fiber_get_current())));
        void *fake_stack_save = NULL;

        assert(f->func);
        assert(IN_SET(f->state, FIBER_STATE_INITIAL, FIBER_STATE_READY));

        finish_switch_stack(NULL);

        /* Capture our resumable point on the fiber's stack, then bounce back to whoever last set
         * f->resume_context. On bootstrap that's fiber_bootstrap(); on every subsequent yield it's
         * the most recent fiber_run(). sigsetjmp(buf, 0) skips the signal-mask save: switching is
         * thread-shared with respect to signal masks. */
        if (sigsetjmp(f->context, /* savemask= */ 0) == 0) {
                start_switch_stack(&fake_stack_save, &f->resume_stack);
                siglongjmp_unchecked(f->resume_context, /* val= */ 1);
        }

        /* Re-entered for real via fiber_run()'s siglongjmp(f->context). */
        finish_switch_stack(fake_stack_save);

        /* Block scope so the cleanups attached to LOG_SET_PREFIX / LOG_CONTEXT_PUSH_KEY_VALUE fire
         * before the siglongjmp below — siglongjmp skips _cleanup_ attributes, so we have to make
         * sure the scope ends via a normal control-flow path first. */
        {
                LOG_SET_PREFIX(f->name);
                LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

                f->result = f->func(f->userdata);
                f->state = FIBER_STATE_COMPLETED;
        }

        /* Pass NULL fake_stack_save to discard the fiber's fake stack since the fiber is done. */
        start_switch_stack(NULL, &f->resume_stack);

        /* Bounce back to whichever fiber_run() call most recently entered us. resume_context is
         * per-fiber so nested fiber_run() — e.g. a bus method dispatched as a fiber handler while
         * sd_event_loop() itself runs in a fiber — is safe. */
        siglongjmp_unchecked(f->resume_context, 1);
        assert_not_reached();
}

static int fiber_init(sd_future *f) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        ucontext_t old_uc, uc;
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

        fiber_set_resume_stack(fiber, prev ? sd_future_get_private(prev) : NULL);
        if (sigsetjmp(fiber->resume_context, /* savemask= */ 0) == 0) {
                start_switch_stack(&fake_stack_save, &fiber_stack);
                if (swapcontext(&old_uc, &uc) < 0) {
                        finish_switch_stack(fake_stack_save);
                        fiber_set_current(prev);
                        return -errno;
                }
                assert_not_reached();   /* Trampoline siglongjmps back; swapcontext doesn't return. */
        }

        finish_switch_stack(fake_stack_save);

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
                Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));
                fiber_swap_log_state(fiber);
                fiber_ops_set(NULL);
        }
        fiber_set_current(NULL);
}

static sd_event_source* fiber_current_event_source(Fiber *f) {
        assert(f);
        assert(f->state != FIBER_STATE_COMPLETED);

        sd_event *e = sd_event_source_get_event(ASSERT_PTR(f->defer_event_source));
        return sd_event_get_state(e) == SD_EVENT_EXITING ? f->exit_event_source : f->defer_event_source;
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
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        fiber->defer_event_source = sd_event_source_disable_unref(fiber->defer_event_source);
        fiber->exit_event_source = sd_event_source_disable_unref(fiber->exit_event_source);
        /* The floating self-ref (if any) is potentially the last ref keeping the fiber alive — moving it
         * into a local _cleanup_ slot ensures sd_future_resolve() runs callbacks and waiters while f is
         * still valid; the local's cleanup drops the ref afterwards, at which point no further f->...
         * access can happen. */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *floating = TAKE_PTR(fiber->floating);
        sd_future_resolve(f, fiber->result);
}

static const FiberOps fiber_ops = {
        .ppoll = sd_fiber_ppoll,
        .read = sd_fiber_read,
        .write = sd_fiber_write,
        .timeout = sd_fiber_timeout,
        .cancel_wait_unref = sd_future_cancel_wait_unref,
};

static void fiber_enter(sd_future *f, sd_future *prev, void **fake_stack_save) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        Fiber *prev_fiber = prev ? sd_future_get_private(prev) : NULL;

        fiber_set_current(f);
        fiber_swap_log_state(fiber);
        if (!prev)
                fiber_ops_set(&fiber_ops);

        struct iovec fiber_stack = fiber_stack_usable(&fiber->stack);
        start_switch_stack(fake_stack_save, &fiber_stack);
        fiber_set_resume_stack(fiber, prev_fiber);
}

static void fiber_leave(sd_future *f, sd_future *prev, void *fake_stack_save) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        finish_switch_stack(fake_stack_save);
        if (!prev)
                fiber_ops_set(NULL);
        fiber_swap_log_state(fiber);
        fiber_set_current(prev);
}

static int fiber_run(sd_future *f) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
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

                r = sd_event_source_set_enabled(fiber_current_event_source(fiber), SD_EVENT_ONESHOT);
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

static int fiber_cancel(sd_future *f) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        assert(f != sd_fiber_get_current());

        if (fiber->state == FIBER_STATE_COMPLETED)
                return 0;

        /* Cancellation already queued — idempotent. Return 0 so fiber_on_exit() proceeds to
         * fiber_run() instead of looping through the event source re-arm dance. */
        if (fiber->result_pending && fiber->result == -ECANCELED)
                return 0;

        if (fiber->state == FIBER_STATE_INITIAL) {
                /* The fiber's stack was allocated but never entered, so there are no scope-level cleanups
                 * waiting to run. Skip the dispatch round-trip and settle the future right here —
                 * mirroring the FIBER_STATE_COMPLETED branch of fiber_run(). */
                fiber->result = -ECANCELED;
                fiber->state = FIBER_STATE_COMPLETED;
                fiber_resolve(f);
                return 1;
        }

        /* Record that an interruption (this cancellation) was delivered to this fiber (see
         * Fiber.n_interrupts). The idempotent already-queued case returned above, so reaching here is
         * a genuine delivery. */
        fiber->n_interrupts++;

        /* Queue -ECANCELED as the resume value. sd_fiber_resume() also takes care of the
         * SUSPENDED → READY transition and arming the event source. -ECANCELED is sticky once
         * queued, so a concurrent async wakeup can't silently override the cancellation. */
        r = sd_fiber_resume(f, -ECANCELED);
        if (r < 0)
                return r;

        return 1;
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        return fiber_run(f);
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        int r;

        /* The fiber may already have completed via the regular defer path before sd_event_exit()
         * fires the exit source; in that case there's nothing left to drive and we'd otherwise
         * trip fiber_run()'s -ESTALE return, which sd_event would log spuriously and disable the
         * source for. */
        if (fiber->state == FIBER_STATE_COMPLETED)
                return 0;

        /* If fiber_cancel() returned 1 the fiber was just marked cancelled and its deferred/exit event
         * source was re-armed; we let the event loop dispatch that source on the next iteration so it goes
         * through the normal fiber_on_defer/fiber_on_exit path rather than running it recursively here. */
        r = fiber_cancel(f);
        if (r != 0)
                return r;

        return fiber_run(f);
}

static void* fiber_alloc(void) {
        return new0(Fiber, 1);
}

static void fiber_free(sd_future *f) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        /* To make sure all memory is deallocated, the fiber has to have completed by the time we free it to
         * make sure its stack has finished unwinding (which will invoke the registered cleanup functions).
         * As this function may get called when not running on a fiber ourselves, we can't guarantee here
         * that we can run the fiber to completion ourselves, so we insist that this happens before we get
         * here. To ensure fibers are cleaned up before exiting the event loop, exit handlers are added for
         * fibers created outside of existing fibers. For fibers created within running fibers, unwinding the
         * outer fiber should take care of cleaning up any created child fibers (for example using
         * sd_future_cancel_wait_unref()).
         *
         * FIBER_STATE_INITIAL is also accepted: the stack was allocated but never entered, so there are no
         * registered cleanups to run. This covers the partial-construction failure path in sd_fiber_new()
         * as well as fibers that are unrefed before the event loop ever dispatches them. */
        assert(IN_SET(fiber->state, FIBER_STATE_INITIAL, FIBER_STATE_COMPLETED));

        if (fiber->destroy)
                fiber->destroy(fiber->userdata);

#if HAVE_VALGRIND_VALGRIND_H
        if (fiber->stack.iov_base)
                VALGRIND_STACK_DEREGISTER(fiber->stack_id);
#endif

        if (fiber->stack.iov_base)
                (void) munmap(fiber->stack.iov_base, fiber->stack.iov_len);

        sd_event_source_disable_unref(fiber->defer_event_source);
        sd_event_source_disable_unref(fiber->exit_event_source);

        free(fiber->name);
        free(fiber);
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

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
        *ret = fiber->priority;
        return 0;
}

static int fiber_swap(FiberState state) {
        Fiber *f = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(sd_fiber_get_current())));

        /* A value queued by sd_fiber_resume() while the fiber was running short-circuits the swap:
         * deliver it as if we had suspended and been resumed instantly, without round-tripping
         * through the event loop. */
        if (f->result_pending) {
                f->result_pending = false;
                return TAKE_GENERIC(f->result, int, 0);
        }

        f->state = state;

        void *fake_stack_save = NULL;

        if (sigsetjmp(f->context, 0) == 0) {
                start_switch_stack(&fake_stack_save, &f->resume_stack);
                siglongjmp_unchecked(f->resume_context, 1);
        }

        finish_switch_stack(fake_stack_save);

        /* When we get here, we've been resumed. sd_fiber_resume() stashed the resumer's value
         * (an async wakeup error from a deadline timer, an io_uring CQE result, a -ECANCELED
         * from fiber_cancel(), etc.) into f->result for us to surface here. Consume it
         * unconditionally so it doesn't pollute subsequent suspends or the fiber's eventual
         * return value — both negative errors and positive payloads (byte counts, accepted fds,
         * revents masks) are valid resume values. */
        f->result_pending = false;
        return TAKE_GENERIC(f->result, int, 0);
}

int sd_fiber_yield(void) {
        assert_return(sd_fiber_get_current(), -ESRCH);
        return fiber_swap(FIBER_STATE_READY);
}

int sd_fiber_suspend(void) {
        assert_return(sd_fiber_get_current(), -ESRCH);
        return fiber_swap(FIBER_STATE_SUSPENDED);
}

static int fiber_set_priority(sd_future *f, int64_t priority) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));
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

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(ASSERT_PTR(f)));

        /* Nothing to deliver to once the fiber has terminated. */
        if (fiber->state == FIBER_STATE_COMPLETED)
                return 0;

        /* -ECANCELED and -ETIME are sticky once queued: a concurrent async wakeup (an io_uring CQE,
         * another timer, …) mustn't silently override a pending interruption that targeted this fiber.
         * -ECANCELED outranks -ETIME — a genuine cancellation may escalate a pending timeout, but a
         * timeout must never be downgraded back to a normal completion, and neither may be lost. Equal
         * re-queues (cancel-after-cancel, timeout-after-timeout) fall through as harmless no-ops. */
        if (fiber->result_pending) {
                if (fiber->result == -ECANCELED && result != -ECANCELED)
                        return 0;
                if (fiber->result == -ETIME && !IN_SET(result, -ECANCELED, -ETIME))
                        return 0;
        }

        /* Stash the result so fiber_swap() returns it from the next sd_fiber_suspend() (or
         * sd_fiber_yield()). When the fiber has not yet suspended (state INITIAL or READY) the value
         * is just queued — the next fiber_swap() consumes it without actually yielding to the event
         * loop. This lets callers like sd_future_cancel_wait_unref() forward a cancellation/timeout
         * they observed on the fiber's behalf instead of silently swallowing it. */
        fiber->result = result;
        fiber->result_pending = true;

        if (fiber->state != FIBER_STATE_SUSPENDED)
                return 0;

        fiber->state = FIBER_STATE_READY;
        return sd_event_source_set_enabled(fiber_current_event_source(fiber), SD_EVENT_ONESHOT);
}

/* The fiber_future ops pass the Fiber pointer through as the future's private state. The fiber resolves
 * its own future once it finishes running, so fiber_cancel() intentionally does not resolve. */
static const sd_future_ops fiber_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = fiber_alloc,
        .free = fiber_free,
        .cancel = fiber_cancel,
        .set_priority = fiber_set_priority,
};

int sd_fiber_new(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret) {
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

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));

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
        }

        /* We only take ownership of the given userdata pointer on success so assign the destroy callback
         * at the very end so we don't clean up the userdata pointer on failure. */
        fiber->destroy = destroy;

        return 0;
}

int sd_fiber_set_floating(sd_future *f, int b) {
        assert_return(f, -EINVAL);
        assert_return(sd_future_get_ops(f) == &fiber_future_ops, -EINVAL);

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));

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

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));
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

        return sd_fiber_await(timer);
}

int sd_fiber_await(sd_future *target) {
        sd_future *f = sd_fiber_get_current();
        int r;

        assert_return(f, -ESRCH);
        assert_return(target, -EINVAL);
        assert_return(target != f, -EDEADLK);

        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return sd_future_result(target);

        /* Note that we do allow waiting for other fibers when the event loop is exiting, since waiting for
         * other fibers does not require adding new event sources to the event loop. */
        if (sd_event_get_state(sd_future_get_event(f)) == SD_EVENT_FINISHED)
                return -ECANCELED;

        _cleanup_(sd_future_slot_unrefp) sd_future_slot *slot = NULL;
        r = sd_future_add_callback(target, &slot, sd_future_resume_callback, f);
        if (r < 0)
                return r;

        r = sd_fiber_suspend();
        if (r < 0)
                return r;

        return sd_future_result(target);
}

uint64_t sd_fiber_interrupt_count(void) {
        sd_future *f = sd_fiber_get_current();

        /* Only meaningful on a fiber; a non-fiber context has trivially seen no interruptions. */
        assert_return(f, 0);

        Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));
        return fiber->n_interrupts;
}

static int fiber_timeout_resume_callback(sd_future *timer, void *userdata) {
        sd_future *f = ASSERT_PTR(userdata);

        /* Unlike sd_future_resume_callback() (which delivers an awaited future's own result), an
         * SD_FIBER_TIMEOUT firing interrupts whatever the fiber is currently awaiting, so it counts
         * against Fiber.n_interrupts before resuming the fiber with the timer's -ETIME. */
        Fiber *fiber = ASSERT_PTR(sd_future_get_private(f));
        fiber->n_interrupts++;

        return sd_fiber_resume(f, sd_future_result(timer));
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
        r = sd_future_add_callback(timer, /* ret_slot= */ NULL, fiber_timeout_resume_callback, f);
        if (r < 0)
                return NULL;

        return TAKE_PTR(timer);
}
