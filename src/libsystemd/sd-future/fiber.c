/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <threads.h>
#include <unistd.h>

#include <ucontext.h>

#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-event.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fiber.h"
#include "fiber-def.h"
#include "future-internal.h"
#include "log-context.h"
#include "log.h"
#include "memory-util.h"
#include "time-util.h"

#if HAS_FEATURE_ADDRESS_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

static thread_local ucontext_t main_context;

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
        assert(IN_SET(f->state, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched from the main stack to a fiber. */
        __sanitizer_finish_switch_fiber(NULL, NULL, NULL);
#endif

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        f->result = f->state == FIBER_STATE_CANCELLED ? -ECANCELED : f->func(f->userdata);
        f->state = FIBER_STATE_COMPLETED;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the main stack from the completed fiber. When a fiber
         * finishes we have to pass NULL as the first argument to destroy the fake stack. */
        __sanitizer_start_switch_fiber(NULL, main_context.uc_stack.ss_sp, main_context.uc_stack.ss_size);
#endif
}

static int fiber_makecontext(ucontext_t *ucp, const void *stack, size_t size) {
        if (getcontext(ucp) < 0)
                return -errno;

        ucp->uc_stack.ss_sp = (uint8_t*) stack + page_size();
        ucp->uc_stack.ss_size = size - page_size();
        ucp->uc_link = &main_context;
        makecontext(ucp, fiber_entry_point, 0);

        return 0;
}

static void reset_current_fiber(void) {
        fiber_set_current(NULL);
        main_context = (ucontext_t) {};
}

static sd_event_source* fiber_current_event_source(Fiber *f) {
        assert(f);
        assert(f->state != FIBER_STATE_COMPLETED);
        assert(f->event);

        return sd_event_get_state(f->event) == SD_EVENT_EXITING ? f->exit_event_source : f->defer_event_source;
}

static int fiber_run(Fiber *f) {
        static bool installed = false;
        int r;

        assert(f);

        if (f->state == FIBER_STATE_COMPLETED)
                return -ESTALE;

        assert(IN_SET(f->state, FIBER_STATE_READY, FIBER_STATE_CANCELLED));

        if (!installed) {
                /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
                 * only half-documented (glibc doesn't document it but LSB does — though only superficially)
                 * we'll check for errors only in the most generic fashion possible. */

                r = pthread_atfork(NULL, NULL, reset_current_fiber);
                if (r != 0)
                        return -r;

                installed = true;
        }

        LOG_SET_PREFIX(f->name);
        LOG_CONTEXT_PUSH_KEY_VALUE("FIBER=", f->name);

        log_debug("Scheduling fiber");

        fiber_set_current(f);

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching to the fiber's stack.. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->context.uc_stack.ss_sp, f->context.uc_stack.ss_size);
#endif

        /* This looks innocent but this is where we start executing the fiber. Once it yields, we continue
         * here as if nothing happened. */
        if (swapcontext(&main_context, &f->context) < 0)
                return -errno;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the main stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        fiber_set_current(NULL);

        switch (f->state) {

        case FIBER_STATE_COMPLETED:
                if (f->result < 0 && f->result != -ECANCELED)
                        log_debug_errno(f->result, "Fiber failed with error: %m");
                else
                        log_debug("Fiber finished executing");

                sd_future_resolve(f->future, f->result);

                f->defer_event_source = sd_event_source_disable_unref(f->defer_event_source);
                f->exit_event_source = sd_event_source_disable_unref(f->exit_event_source);
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

int fiber_cancel(Fiber *f) {
        int r;

        assert(f);
        assert(f != fiber_get_current());

        if (IN_SET(f->state, FIBER_STATE_COMPLETED, FIBER_STATE_CANCELLED))
                return 0;

        f->state = FIBER_STATE_CANCELLED;

        /* Once we cancel a fiber, we want to immediately resume it with -ECANCELED. */
        r = sd_event_source_set_enabled(fiber_current_event_source(f), SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        return 1;
}

static int fiber_on_defer(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        return fiber_run(f);
}

static int fiber_on_exit(sd_event_source *s, void *userdata) {
        Fiber *f = ASSERT_PTR(userdata);
        int r;

        r = fiber_cancel(f);
        if (r != 0)
                return r;

        return fiber_run(f);
}

int fiber_new(sd_event *e, const char *name, FiberFunc func, void *userdata, FiberDestroy destroy, sd_future *future, Fiber **ret) {
        _cleanup_(fiber_freep) Fiber *f = NULL;
        int r;

        assert(e);
        assert(name);
        assert(func);
        assert(future);
        assert(ret);

        f = new(Fiber, 1);
        if (!f)
                return -ENOMEM;

        struct rlimit buffer = { .rlim_cur = 8388608 };
        if (getrlimit(RLIMIT_STACK, &buffer) < 0)
                log_debug_errno(errno, "Reading RLIMIT_STACK failed, ignoring: %m");

        *f = (Fiber) {
                .stack_size = ROUND_UP(buffer.rlim_cur, page_size()),
                .state = FIBER_STATE_COMPLETED,
                .name = strdup(name),
                .func = func,
                .userdata = userdata,
                .destroy = destroy,
                .event = sd_event_ref(e),
                .future = future,
        };
        if (!f->name)
                return -ENOMEM;

        r = fiber_allocate_stack(f->stack_size, &f->stack);
        if (r < 0)
                return r;

        r = fiber_makecontext(&f->context, f->stack, f->stack_size);
        if (r < 0)
                return r;

#if HAVE_VALGRIND_VALGRIND_H
        f->stack_id = VALGRIND_STACK_REGISTER(f->context.uc_stack.ss_sp,
                                              (uint8_t*) f->context.uc_stack.ss_sp + f->context.uc_stack.ss_size);
#endif

        /* Execution of the fiber is driven by two event sources, one deferred, one exit. The exit event
         * source kicks in when sd_event_exit() is called, as from that point onwards only exit event
         * sources will be dispatched. */

        r = sd_event_add_defer(e, &f->defer_event_source, fiber_on_defer, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(f->defer_event_source, f->name);
        if (r < 0)
                return r;

        r = sd_event_add_exit(e, &f->exit_event_source, fiber_on_exit, f);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(f->exit_event_source, f->name);
        if (r < 0)
                return r;

        /* If we're on a fiber, we'll rely on the parent fiber to cancel this fiber if the event loop is
         * exiting. Otherwise, we'll trigger cancellation of this fiber via the exit event source. Why cancel
         * via the exit event source? We can only run the fiber while the event loop is active, so we need to
         * make sure all fibers finish running before the event loop is finished, which an exit event source
         * allows us to do. */
        r = sd_event_source_set_enabled(f->exit_event_source, sd_fiber_is_running() ? SD_EVENT_OFF : SD_EVENT_ONESHOT);
        if (r < 0)
                return r;

        f->state = FIBER_STATE_READY;

        *ret = TAKE_PTR(f);
        return 0;
}

Fiber* fiber_free(Fiber *f) {
        if (!f)
                return NULL;

        /* To make sure all memory is deallocated, the fiber has to have completed by the time we free it to
         * make sure its stack has finished unwinding (which will invoke the registered cleanup functions).
         * As this function may get called when not running on a fiber ourselves, we can't guarantee here
         * that we can run the fiber to completion ourselves, so we insist that this happens before we get
         * here. To ensure fibers are cleaned up before exiting the event loop, exit handlers are added for
         * fibers created outside of existing fibers. For fibers created within running fibers, unwinding the
         * outer fiber should take care of cleaning up any created child fibers (for example using
         * sd_fiber_cancel_wait_unref()). */
        assert(f->state == FIBER_STATE_COMPLETED);

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

sd_future* sd_fiber_cancel_wait_unref(sd_future *f) {
        int r;

        if (!f)
                return NULL;

        /* We have to be able to suspend until the fiber we're waiting for finishes, and that's only
         * possible if we're running on a fiber ourselves. */
        assert(sd_fiber_is_running());

        r = sd_future_cancel(f);
        if (r < 0)
                log_debug_errno(r, "Failed to cancel future, ignoring: %m");

        r = sd_fiber_await(f);
        if (r < 0 && r != -ECANCELED)
                log_debug_errno(r, "Failed to wait for future to finish, ignoring: %m");

        return sd_future_unref(f);
}

int sd_fiber_is_running(void) {
        return !!fiber_get_current();
}

const char* sd_fiber_get_name(void) {
        return ASSERT_PTR(fiber_get_current())->name;
}

sd_event* sd_fiber_get_event(void) {
        return ASSERT_PTR(fiber_get_current())->event;
}

int64_t sd_fiber_get_priority(void) {
        return ASSERT_PTR(fiber_get_current())->priority;
}

static int fiber_swap(FiberState state) {
        Fiber *f = ASSERT_PTR(fiber_get_current());

        f->state = state;

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we're switching back to the main stack. */
        void *fake_stack;
        __sanitizer_start_switch_fiber(&fake_stack, f->context.uc_stack.ss_sp, f->context.uc_stack.ss_size);
#endif

        if (swapcontext(&f->context, &main_context) < 0)
                return -errno;

        /* When we get here, we've been resumed. */

#if HAS_FEATURE_ADDRESS_SANITIZER
        /* Inform ASan that we've switched back to the fiber from the main stack. */
        __sanitizer_finish_switch_fiber(fake_stack, NULL, NULL);
#endif

        return f->state == FIBER_STATE_CANCELLED ? -ECANCELED : 0;
}

int sd_fiber_yield(void) {
        return fiber_swap(FIBER_STATE_READY);
}

int fiber_suspend(void) {
        return fiber_swap(FIBER_STATE_SUSPENDED);
}

int fiber_result(Fiber *f) {
        assert(f);
        assert(f->state == FIBER_STATE_COMPLETED);

        return f->result;
}

int fiber_set_priority(Fiber *f, int64_t priority) {
        int r = 0;

        assert(f);

        if (f->defer_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->defer_event_source, priority));

        if (f->exit_event_source)
                RET_GATHER(r, sd_event_source_set_priority(f->exit_event_source, priority));

        return r;
}

int fiber_resume(sd_future *f, void *userdata) {
        Fiber *fiber = ASSERT_PTR(userdata);

        if (fiber->state != FIBER_STATE_SUSPENDED)
                return 0;

        fiber->state = FIBER_STATE_READY;
        return sd_event_source_set_enabled(fiber_current_event_source(fiber), SD_EVENT_ONESHOT);
}

int sd_fiber_sleep(uint64_t usec) {
        Fiber *f = fiber_get_current();
        int r;

        if (!f)
                return usleep_safe(usec);

        if (usec == 0)
                return 0;

        assert(f->event);

        _cleanup_(sd_future_unrefp) sd_future *timer = NULL;
        r = sd_future_new_time_relative(f->event, CLOCK_MONOTONIC, usec, /* accuracy= */ 1, &timer);
        if (r < 0)
                return r;

        r = sd_future_set_callback(timer, fiber_resume, f);
        if (r < 0)
                return r;

        return fiber_suspend();
}

int sd_fiber_await(sd_future *target) {
        Fiber *f = ASSERT_PTR(fiber_get_current());
        int r;

        assert(target);

        if (sd_future_state(target) == SD_FUTURE_RESOLVED)
                return 0;

        /* Note that we do allow waiting for other fibers when the event loop is exiting, since waiting for
         * other fibers does not require adding new event sources to the event loop. */
        if (sd_event_get_state(f->event) == SD_EVENT_FINISHED)
                return -ECANCELED;

        _cleanup_(sd_future_unrefp) sd_future *wait = NULL;
        r = sd_future_new_wait(target, &wait);
        if (r < 0)
                return r;

        r = sd_future_set_callback(wait, fiber_resume, f);
        if (r < 0)
                return r;

        return fiber_suspend();
}
