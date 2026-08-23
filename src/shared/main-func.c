/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

        int result;
        bool exit_requested;
} MainFiberContext;

static int main_fiber_trampoline(void *userdata) {
        MainFiberContext *ctx = ASSERT_PTR(userdata);
        sd_event *event = ASSERT_PTR(sd_fiber_get_event());

        ctx->result = ctx->func(ctx->argc, ctx->argv);

        /* impl's result is an errno, the exit code an exit status that impl's exit handlers see: keep
         * them apart. */
        ctx->exit_requested = sd_event_get_exit_code(event, /* ret= */ NULL) >= 0;
        if (!ctx->exit_requested)
                (void) sd_event_exit(event, 0);

        return ctx->result;
}

int run_main_fiber(int argc, char *argv[], main_fiber_func_t func) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        MainFiberContext ctx = {
                .argc = argc,
                .argv = argv,
                .func = func,
        };
        int r;

        assert(func);

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        /* The fiber gets a pointer into this frame and is only unwound by the loop we run below, which
         * requires that we own that loop and that sd_fiber_new() arms the fiber's exit event source. */
        if (sd_fiber_is_running() || sd_event_get_state(event) != SD_EVENT_INITIAL)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Refusing to run a main fiber on a busy event loop.");

        /* Fire-and-forget: the loop unwinds the fiber through its exit event source, and a suspended
         * fiber is one we couldn't drop a reference to anyway. */
        r = sd_fiber_new(event, program_invocation_short_name, main_fiber_trampoline, &ctx,
                         /* destroy= */ NULL, /* ret= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to spawn main fiber: %m");

        r = sd_event_loop(event);
        if (sd_event_get_state(event) != SD_EVENT_FINISHED)
                /* Exit sources never ran, so the fiber may still be suspended with no working loop left
                 * to unwind it. Leak both.
                 *
                 * TODO: detach the loop from the default slot, it stays reachable with the abandoned
                 * fiber's sources armed on it, pointing into this frame. */
                return log_error_errno(r, "Event loop failed: %m");

        /* An impl cancelled by the exit request just echoes -ECANCELED back at us, so let the requested
         * status speak. Anything else is impl's own verdict, and its successes stay out of the status. */
        if (ctx.exit_requested && (ctx.result >= 0 || ctx.result == -ECANCELED))
                return r;

        return ctx.result < 0 ? ctx.result : 0;
}
