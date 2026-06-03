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

typedef struct MainFiberCtx {
        int argc;
        char **argv;
        main_fiber_func_t func;
        sd_future *fiber;                       /* For cancellation from the signal handler. */
        sd_event_source *sigint_source;
        sd_event_source *sigterm_source;
} MainFiberCtx;

static int main_fiber_trampoline(void *userdata) {
        MainFiberCtx *ctx = ASSERT_PTR(userdata);
        return ctx->func(ctx->argc, ctx->argv);
}

static int main_fiber_signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        MainFiberCtx *ctx = ASSERT_PTR(userdata);
        int r;

        assert(si);

        log_info("Got %s, cancelling main fiber.", signal_to_string(si->ssi_signo));

        r = sd_future_cancel(ctx->fiber);
        if (r < 0)
                log_warning_errno(r, "Failed to cancel main fiber, ignoring: %m");

        /* Disable both handlers: further signals won't re-fire, and the loop can go idle once the
         * main fiber has finished unwinding. */
        (void) sd_event_source_set_enabled(ctx->sigint_source, SD_EVENT_OFF);
        (void) sd_event_source_set_enabled(ctx->sigterm_source, SD_EVENT_OFF);
        return 0;
}

int run_main_fiber(int argc, char *argv[], main_fiber_func_t func) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_future_unrefp) sd_future *fiber = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *sigint_source = NULL, *sigterm_source = NULL;
        MainFiberCtx ctx = { .argc = argc, .argv = argv, .func = func };
        int r;

        assert(func);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        /* Structured concurrency: when impl returns it cancels and reaps any fibers/event sources
         * it spawned, so once it's done the loop has no work left and should exit on its own. */
        r = sd_event_set_exit_on_idle(event, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable exit-on-idle on event loop: %m");

        r = sd_fiber_new(event, program_invocation_short_name,
                         main_fiber_trampoline, &ctx, /* destroy= */ NULL, &fiber);
        if (r < 0)
                return log_error_errno(r, "Failed to spawn main fiber: %m");

        ctx.fiber = fiber;

        r = sd_event_add_signal(event, &sigint_source, SIGINT | SD_EVENT_SIGNAL_PROCMASK,
                                main_fiber_signal_handler, &ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGINT handler: %m");

        r = sd_event_add_signal(event, &sigterm_source, SIGTERM | SD_EVENT_SIGNAL_PROCMASK,
                                main_fiber_signal_handler, &ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to install SIGTERM handler: %m");

        ctx.sigint_source = sigint_source;
        ctx.sigterm_source = sigterm_source;

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        if (sd_future_state(fiber) != SD_FUTURE_RESOLVED)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Main fiber did not resolve before event loop exit.");
        
        r = sd_future_result(fiber);
        /* Orderly signal-driven shutdown is success, not failure. */
        if (r == -ECANCELED)
                r = 0;
        return r;
}
