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
} MainFiberContext;

static int main_fiber_trampoline(void *userdata) {
        MainFiberContext *ctx = ASSERT_PTR(userdata);
        sd_event *event = ASSERT_PTR(sd_fiber_get_event());
        int r;

        r = ctx->func(ctx->argc, ctx->argv);

        /* Exit the loop with impl's result as the exit code, unless an exit was requested already (by impl
         * itself, by sd_event_set_signal_exit(), ...) in which case that exit code wins and we're most
         * likely being unwound by the exit handler that is dispatching us right now. */
        if (sd_event_get_exit_code(event, /* ret= */ NULL) == -ENODATA)
                (void) sd_event_exit(event, r);

        return r;
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

        /* Fire-and-forget: the event loop owns the fiber and is guaranteed to unwind it before it finishes,
         * so we don't have to hold on to a reference that we couldn't drop while the fiber is suspended. */
        r = sd_fiber_new(event, program_invocation_short_name, main_fiber_trampoline, &ctx,
                         /* destroy= */ NULL, /* ret= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to spawn main fiber: %m");

        r = sd_event_loop(event);
        if (r < 0 && sd_event_get_exit_code(event, /* ret= */ NULL) == -ENODATA)
                return log_error_errno(r, "Event loop failed: %m");

        return r;
}
