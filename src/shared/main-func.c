/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-future.h"

#include "argv-util.h"
#include "ask-password-agent.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "polkit-agent.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "string-util.h"

void main_prepare(int argc, char *argv[]) {
        assert_se(argc > 0 && !isempty(argv[0]));
        save_argc_argv(argc, argv);
}

void main_finalize(int r, int exit_status) {
        if (r < 0)
                (void) sd_notifyf(0, "ERRNO=%i", -r);
        (void) sd_notifyf(0, "EXIT_STATUS=%i", exit_status);
        ask_password_agent_close();
        polkit_agent_close();
        pager_close();
        mac_selinux_finish();
}

int exit_failure_if_negative(int result) {
        return result < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int exit_failure_if_nonzero(int result) {
        return result < 0 ? EXIT_FAILURE : result;
}

typedef struct MainFiberContext {
        int argc;
        char **argv;
        main_fiber_func_t func;

        sd_event *event;
        sd_future *fiber;
        sd_event_source *sigint_source;
        sd_event_source *sigterm_source;

        bool cancelled;
} MainFiberContext;

static void main_fiber_context_disable_signals(MainFiberContext *ctx) {
        assert(ctx);

        if (ctx->sigint_source)
                ctx->sigint_source = sd_event_source_disable_unref(ctx->sigint_source);
        if (ctx->sigterm_source)
                ctx->sigterm_source = sd_event_source_disable_unref(ctx->sigterm_source);
}

static void main_fiber_context_done(MainFiberContext *ctx) {
        int r;

        assert(ctx);

        main_fiber_context_disable_signals(ctx);

        /* If the event loop failed while the fiber was suspended, drive its exit source so its stack is
         * unwound before the future is freed. */
        while (ctx->fiber &&
               sd_future_state(ctx->fiber) != SD_FUTURE_RESOLVED &&
               ctx->event &&
               sd_event_get_state(ctx->event) == SD_EVENT_INITIAL) {
                r = sd_event_exit(ctx->event, 0);
                if (r < 0) {
                        log_debug_errno(r,
                                        "Failed to exit event loop while cleaning up main fiber, ignoring: %m");
                        break;
                }

                r = sd_event_loop(ctx->event);
                if (r < 0)
                        log_debug_errno(r, "Failed to clean up main fiber, retrying: %m");
        }

        if (ctx->fiber && sd_future_state(ctx->fiber) != SD_FUTURE_RESOLVED) {
                /* A finished event loop cannot drive the fiber's exit source anymore. Keep the future alive
                 * rather than freeing a suspended stack. This should only be reachable if event-loop state
                 * handling is broken. */
                log_debug("Unable to unwind main fiber, leaking it.");
                ctx->fiber = NULL;
        } else
                ctx->fiber = sd_future_unref(ctx->fiber);

        ctx->event = sd_event_unref(ctx->event);
}

static int main_fiber_trampoline(void *userdata) {
        MainFiberContext *ctx = ASSERT_PTR(userdata);
        int r;

        r = ctx->func(ctx->argc, ctx->argv);

        /* Tear down the signal handlers so that the always-enabled signal sources no longer keep the event
         * loop busy. Without this the loop never goes idle on the normal completion path and exit-on-idle
         * never fires, leaving the process hanging forever. */
        main_fiber_context_disable_signals(ctx);

        return r;
}

static int main_fiber_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        MainFiberContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(si);

        log_info("Got %s, cancelling main fiber.", signal_to_string(si->ssi_signo));

        r = sd_future_cancel(ctx->fiber);
        if (r < 0) {
                log_warning_errno(r, "Failed to cancel main fiber, ignoring: %m");
                return 0;
        }

        ctx->cancelled = true;

        /* Freeing the sources also restores the original signal mask. Thus, a repeated signal uses its
         * default disposition and can force termination if the fiber gets stuck while unwinding. */
        main_fiber_context_disable_signals(ctx);
        return 0;
}

int run_main_fiber(int argc, char *argv[], main_fiber_func_t func) {
        _cleanup_(main_fiber_context_done) MainFiberContext ctx = {
                .argc = argc,
                .argv = argv,
                .func = func,
        };
        int r;

        assert(func);

        r = sd_event_default(&ctx.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        /* Structured concurrency: when impl returns it cancels and reaps any fibers/event sources
         * it spawned, so once it's done the loop has no work left and should exit on its own. */
        r = sd_event_set_exit_on_idle(ctx.event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-idle on event loop: %m");

        r = sd_fiber_new(ctx.event, program_invocation_short_name,
                         main_fiber_trampoline, &ctx, /* destroy= */ NULL, &ctx.fiber);
        if (r < 0)
                return log_error_errno(r, "Failed to spawn main fiber: %m");

        /* SIGINT and SIGTERM request orderly shutdown. Other terminating signals deliberately retain their
         * default dispositions. */
        r = sd_event_add_signal(ctx.event, &ctx.sigint_source, SIGINT | SD_EVENT_SIGNAL_PROCMASK,
                                main_fiber_signal_handler, &ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT handler: %m");

        r = sd_event_add_signal(ctx.event, &ctx.sigterm_source, SIGTERM | SD_EVENT_SIGNAL_PROCMASK,
                                main_fiber_signal_handler, &ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGTERM handler: %m");

        r = sd_event_loop(ctx.event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        if (sd_future_state(ctx.fiber) != SD_FUTURE_RESOLVED)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Main fiber did not resolve before event loop exit.");

        r = sd_future_result(ctx.fiber);
        /* Orderly signal-driven shutdown is success, not failure. */
        if (r == -ECANCELED && ctx.cancelled)
                r = 0;
        return r;
}
