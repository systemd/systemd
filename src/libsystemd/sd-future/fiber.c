/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <ucontext.h>

#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "event-future.h"
#include "fiber-def.h"
#include "log-context.h"
#include "log.h"
#include "memory-util.h"
#include "time-util.h"

#if HAS_FEATURE_ADDRESS_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

#define FIBER_DEFAULT_STACK_SIZE UINT64_C(8388608)

static int fiber_allocate_stack(size_t size, void **ret) {
        void *stack = NULL;
        int r;

        assert(size > 0 && size % page_size() == 0);
        assert(ret);

        stack = mmap(/* addr= */ NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                     /* fd= */ -1, /* offset= */ 0);
        if (stack == MAP_FAILED)
                return -errno;

        /* Set up guard page at the bottom of the stack (grows downward) */
        r = RET_NERRNO(mprotect(stack, page_size(), PROT_NONE));
        if (r < 0) {
                (void) munmap(stack, size);
                return r;
        }

        *ret = TAKE_PTR(stack);
        return 0;
}

static void fiber_entry_point(void) {
        Fiber *f = fiber_get_current();

        assert(f);
        assert(f->func);
        assert(IN_SET(f->state, FIBER_STATE_INITIAL, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched from the main stack to a fiber. */
        __sanitizer_finish_switch_fiber(NULL, NULL, NULL);
#endif

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        f->result = f->state == FIBER_STATE_CANCELLED ? -ECANCELED : f->func(f->userdata);
        f->state = FIBER_STATE_COMPLETED;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the caller's stack from the completed fiber. When a
         * fiber finishes we have to pass NULL as the first argument to destroy the fake stack. */
        __sanitizer_start_switch_fiber(NULL, f->resume_context.uc_stack.ss_sp, f->resume_context.uc_stack.ss_size);
#endif
}

static int fiber_makecontext(Fiber *f, const void *stack, size_t size) {
        assert(f);

        if (getcontext(&f->context) < 0)
                return -errno;

        f->context.uc_stack.ss_sp = (uint8_t*) stack + page_size();
        f->context.uc_stack.ss_size = size - page_size();
        /* When the fiber's entry function returns without explicitly yielding, ucontext resumes
         * execution at uc_link. We populate resume_context inside fiber_run() each time we enter the
         * fiber, so this reference is live whenever the fiber is running. Keeping the resume context
         * per-fiber (rather than a thread-global) is what makes nested fiber_run() calls — e.g. a bus
         * method dispatched as a fiber handler while sd_event_loop() itself runs in a fiber — safe. */
        f->context.uc_link = &f->resume_context;
        makecontext(&f->context, fiber_entry_point, 0);

        return 0;
}

static void reset_current_fiber(void) {
        fiber_set_current(NULL);
}

static sd_event_source* fiber_current_event_source(Fiber *f) {
        assert(f);
        assert(f->state != FIBER_STATE_COMPLETED);
        assert(f->event);

        return sd_event_get_state(f->event) == SD_EVENT_EXITING ? f->exit_event_source : f->defer_event_source;
}

static int atfork_ret = 0;

static void install_atfork(void) {
        /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
         * only half-documented (glibc doesn't document it but LSB does — though only superficially)
         * we'll check for errors only in the most generic fashion possible. */
        atfork_ret = pthread_atfork(NULL, NULL, reset_current_fiber);
}

static void fiber_resolve(Fiber *f) {
        assert(f);

        f->defer_event_source = sd_event_source_disable_unref(f->defer_event_source);
        f->exit_event_source = sd_event_source_disable_unref(f->exit_event_source);
        /* The floating self-ref (if any) is potentially the last ref keeping the fiber alive — moving it
         * into a local _cleanup_ slot ensures sd_promise_resolve() runs callbacks and waiters while f is
         * still valid; the local's cleanup drops the ref afterwards, at which point no further f->...
         * access can happen. */
        _unused_ _cleanup_(sd_future_unrefp) sd_future *floating = TAKE_PTR(f->floating);
        sd_promise_resolve(f->promise, f->result);
}

static int fiber_run(Fiber *f) {
        int r;

        assert(f);

        if (f->state == FIBER_STATE_COMPLETED)
                return -ESTALE;

        assert(IN_SET(f->state, FIBER_STATE_INITIAL, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

        static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;
        r = pthread_once(&atfork_once, install_atfork);
        if (r != 0)
                return -r;
        if (atfork_ret != 0)
                return -atfork_ret;

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        log_debug("Scheduling fiber");

        /* Save the previously-current fiber (if any) so we can restore it when this fiber yields or
         * completes. This matters when fiber_run() is invoked from within another fiber (e.g. an
         * sd-event dispatch that happens to be running inside a fiber context itself): the
         * LOG_SET_PREFIX/LOG_CONTEXT_PUSH above attached to whichever fiber was current at that moment,
         * and their scope-level cleanup must see the same fiber_get_current() when it runs to detach
         * them from the correct list. */
        Fiber *prev = fiber_get_current();
        fiber_set_current(f);

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching to the fiber's stack. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->context.uc_stack.ss_sp, f->context.uc_stack.ss_size);
#endif

        /* This looks innocent but this is where we start executing the fiber. Once it yields, we continue
         * here as if nothing happened. */
        r = RET_NERRNO(swapcontext(&f->resume_context, &f->context));

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the caller's stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        fiber_set_current(prev);

        if (r < 0)
                return r;

        switch (f->state) {

        case FIBER_STATE_COMPLETED:
                if (f->result < 0 && f->result != -ECANCELED)
                        log_debug_errno(f->result, "Fiber failed with error: %m");
                else
                        log_debug("Fiber finished executing");

                fiber_resolve(f);
                break;

        case FIBER_STATE_CANCELLED:
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

static int fiber_cancel(void *userdata) {
        Fiber *f = userdata;
        int r;

        assert(f);
        assert(f != fiber_get_current());

        if (IN_SET(f->state, FIBER_STATE_COMPLETED, FIBER_STATE_CANCELLED))
                return 0;

        if (f->state == FIBER_STATE_INITIAL) {
                /* The fiber's stack was allocated but never entered, so there are no scope-level cleanups
                 * waiting to run. Skip the dispatch round-trip that would just have fiber_entry_point()
                 * fall straight through with -ECANCELED, and settle the future right here — mirroring the
                 * FIBER_STATE_COMPLETED branch of fiber_run(). */
                f->result = -ECANCELED;
                f->state = FIBER_STATE_COMPLETED;
                fiber_resolve(f);
                return 1;
        }

        /* Once we cancel a fiber, we want to immediately resume it with -ECANCELED. */
        r = sd_event_source_set_enabled(fiber_current_event_source(f), SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        f->state = FIBER_STATE_CANCELLED;

        return 1;
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        return fiber_run(f);
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        int r;

        /* The fiber may already have completed via the regular defer path before sd_event_exit()
         * fires the exit source; in that case there's nothing left to drive and we'd otherwise
         * trip fiber_run()'s -ESTALE return, which sd_event would log spuriously and disable the
         * source for. */
        if (f->state == FIBER_STATE_COMPLETED)
                return 0;

        /* If fiber_cancel() returned 1 the fiber was just marked cancelled and its deferred/exit event
         * source was re-armed; we let the event loop dispatch that source on the next iteration so it goes
         * through the normal fiber_on_defer/fiber_on_exit path rather than running it recursively here. */
        r = fiber_cancel(f);
        if (r != 0)
                return r;

        return fiber_run(f);
}

static void* fiber_free(void *userdata) {
        Fiber *f = userdata;
        if (!f)
                return NULL;

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
        assert(IN_SET(f->state, FIBER_STATE_INITIAL, FIBER_STATE_COMPLETED));

        if (f->destroy)
                f->destroy(f->userdata);

#if HAVE_VALGRIND_VALGRIND_H
        VALGRIND_STACK_DEREGISTER(f->stack_id);
#endif

        (void) munmap(f->stack, f->stack_size);

        sd_event_source_disable_unref(f->defer_event_source);
        sd_event_source_disable_unref(f->exit_event_source);
        sd_event_unref(f->event);

        free(f->name);
        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Fiber*, fiber_free);

int sd_fiber_is_running(void) {
        return !!fiber_get_current();
}

sd_event* sd_fiber_get_event(void) {
        return ASSERT_PTR(fiber_get_current())->event;
}

int64_t sd_fiber_get_priority(void) {
        return ASSERT_PTR(fiber_get_current())->priority;
}

static int fiber_swap(FiberState state) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        f->state = state;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the caller's stack. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->resume_context.uc_stack.ss_sp, f->resume_context.uc_stack.ss_size);
#endif

        r = RET_NERRNO(swapcontext(&f->context, &f->resume_context));

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the fiber from the caller's stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        if (r < 0)
                return r;

        /* When we get here, we've been resumed. */

        if (f->state == FIBER_STATE_CANCELLED)
                return -ECANCELED;

        /* If something asynchronous (e.g. a deadline timer) stashed a wakeup error in f->result,
         * propagate it to the caller and clear it so it doesn't pollute subsequent suspends or the
         * fiber's eventual return value. */
        return f->result < 0 ? TAKE_GENERIC(f->result, int, 0) : 0;
}

int sd_fiber_yield(void) {
        return fiber_swap(FIBER_STATE_READY);
}

int sd_fiber_suspend(void) {
        return fiber_swap(FIBER_STATE_SUSPENDED);
}

static int fiber_set_priority(void *userdata, int64_t priority) {
        Fiber *f = userdata;
        int r = 0;

        assert(f);

        if (f->defer_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->defer_event_source, priority));

        if (f->exit_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->exit_event_source, priority));

        if (r >= 0)
                f->priority = priority;

        return r;
}

int sd_fiber_resume(sd_future *fiber_future, int result) {
        Fiber *fiber = ASSERT_PTR(sd_future_get_impl(fiber_future));

        if (fiber->state != FIBER_STATE_SUSPENDED)
                return 0;

        /* Stash the result so fiber_swap() returns it from sd_fiber_suspend(). */
        fiber->result = result;
        fiber->state = FIBER_STATE_READY;
        return sd_event_source_set_enabled(fiber_current_event_source(fiber), SD_EVENT_ONESHOT);
}

/* The fiber_future ops pass the Fiber pointer through as opaque userdata — Fiber is already shaped like a
 * future-impl struct (first field is `sd_promise *promise`, stamped by sd_future_new()). The fiber
 * resolves its own future once it finishes running, so fiber_cancel() intentionally does not resolve. */
static const sd_future_ops fiber_future_ops = {
        .free = fiber_free,
        .cancel = fiber_cancel,
        .set_priority = fiber_set_priority,
};

static const FiberOps fiber_ops = {
        .ppoll = sd_fiber_poll,
        .read = sd_fiber_read,
        .write = sd_fiber_write,
        .timeout = sd_fiber_timeout,
        .timeout_done = sd_future_unref,
};

int sd_fiber_new(sd_event *e, const char *name, sd_fiber_func_t func, void *userdata, sd_fiber_destroy_t destroy, sd_future **ret) {
        int r;

        assert(e);
        assert(name);
        assert(func);

        if (IN_SET(sd_event_get_state(e), SD_EVENT_EXITING, SD_EVENT_FINISHED))
                return -ECANCELED;

        _cleanup_(fiber_freep) Fiber *fiber = new(Fiber, 1);
        if (!fiber)
                return -ENOMEM;

        struct rlimit rl = { .rlim_cur = FIBER_DEFAULT_STACK_SIZE };
        if (getrlimit(RLIMIT_STACK, &rl) < 0)
                log_debug_errno(errno, "Reading RLIMIT_STACK failed, ignoring: %m");
        if (rl.rlim_cur == RLIM_INFINITY)
                rl.rlim_cur = FIBER_DEFAULT_STACK_SIZE;

        *fiber = (Fiber) {
                .stack_size = ROUND_UP(rl.rlim_cur, page_size()),
                .state = FIBER_STATE_INITIAL,
                .name = strdup(name),
                .func = func,
                .userdata = userdata,
                .event = sd_event_ref(e),
                .ops = &fiber_ops,
        };
        if (!fiber->name)
                return -ENOMEM;

        r = fiber_allocate_stack(fiber->stack_size, &fiber->stack);
        if (r < 0)
                return r;

        r = fiber_makecontext(fiber, fiber->stack, fiber->stack_size);
        if (r < 0)
                return r;

#if HAVE_VALGRIND_VALGRIND_H
        fiber->stack_id = VALGRIND_STACK_REGISTER(fiber->context.uc_stack.ss_sp,
                                                  (uint8_t*) fiber->context.uc_stack.ss_sp + fiber->context.uc_stack.ss_size);
#endif

        /* Execution of the fiber is driven by two event sources, one deferred, one exit. The exit event
         * source kicks in when sd_event_exit() is called, as from that point onwards only exit event
         * sources will be dispatched. */

        r = sd_event_add_defer(e, &fiber->defer_event_source, fiber_on_defer, fiber);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(fiber->defer_event_source, fiber->name);
        if (r < 0)
                return r;

        r = sd_event_add_exit(e, &fiber->exit_event_source, fiber_on_exit, fiber);
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

        fiber->destroy = destroy;

        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        r = sd_future_new(&fiber_future_ops, fiber, &f);
        if (r < 0)
                return r;

        /* Stays in FIBER_STATE_INITIAL until the event loop first dispatches it via fiber_run(). */
        TAKE_PTR(fiber);

        if (ret)
                *ret = TAKE_PTR(f);
        else {
                /* Fire-and-forget: the fiber is guaranteed to resolve (via completion, cancellation, or
                 * the event loop exit handler), so making the future floating cleans it up. */
                r = sd_fiber_set_floating(f, true);
                if (r < 0)
                        return r;
        }

        return 0;
}

const char* sd_fiber_get_name(sd_future *f) {
        Fiber *fiber;

        if (!f)
                fiber = fiber_get_current();
        else {
                assert(sd_future_get_ops(f) == &fiber_future_ops);
                fiber = sd_future_get_impl(f);
        }

        return ASSERT_PTR(fiber)->name;
}

int sd_fiber_set_floating(sd_future *f, int b) {
        assert(f);
        assert(sd_future_get_ops(f) == &fiber_future_ops);

        Fiber *fiber = sd_future_get_impl(f);

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
        assert(f);
        assert(sd_future_get_ops(f) == &fiber_future_ops);

        Fiber *fiber = sd_future_get_impl(f);
        return !!fiber->floating;
}

int sd_fiber_sleep(uint64_t usec) {
        Fiber *f = fiber_get_current();
        int r;

        if (!f)
                return usleep_safe(usec);

        if (usec == 0)
                return 0;

        /* Match usleep_safe(USEC_INFINITY): suspend indefinitely. Passing USEC_INFINITY to
         * sd_event_add_time_relative() would overflow into -EOVERFLOW. */
        if (usec == USEC_INFINITY)
                return sd_fiber_suspend();

        assert(f->event);

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *timer = NULL;
        r = future_new_time_relative(
                        f->event,
                        CLOCK_MONOTONIC,
                        usec,
                        /* accuracy= */ 1,
                        /* result= */ 0,
                        &timer);
        if (r < 0)
                return r;

        return sd_fiber_suspend();
}

int sd_fiber_await(sd_future *target) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(target);
        assert(target != sd_fiber_get_current());

        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return 0;

        /* Note that we do allow waiting for other fibers when the event loop is exiting, since waiting for
         * other fibers does not require adding new event sources to the event loop. */
        if (sd_event_get_state(f->event) == SD_EVENT_FINISHED)
                return -ECANCELED;

        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *wait = NULL;
        r = sd_future_new_wait(target, &wait);
        if (r < 0)
                return r;

        return sd_fiber_suspend();
}

sd_future* sd_fiber_timeout(uint64_t timeout) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        if (timeout == USEC_INFINITY)
                return NULL;

        sd_future *timer;
        r = future_new_time_relative(
                        f->event,
                        CLOCK_MONOTONIC,
                        timeout,
                        /* accuracy= */ 1,
                        /* result= */ -ETIME,
                        &timer);
        if (r < 0)
                return NULL; /* On allocation failure no timer is armed and the scope becomes a no-op.
                              * Errors here are rare; if the caller cares they can compare to NULL. */

        return timer;
}
