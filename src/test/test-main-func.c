/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "sd-event.h"
#include "sd-future.h"

#include "main-func.h"
#include "tests.h"

static char *test_argv[] = {
        (char*) "alpha",
        (char*) "beta",
        NULL,
};

static void assert_test_argv(int argc, char *argv[]) {
        ASSERT_EQ(argc, 2);
        ASSERT_PTR_EQ(argv, test_argv);
        ASSERT_STREQ(argv[0], "alpha");
        ASSERT_STREQ(argv[1], "beta");
        ASSERT_NULL(argv[2]);
}

static int run_main_fiber_checked(main_fiber_func_t func) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        r = run_main_fiber(2, test_argv, func);

        /* The main fiber, and with it the event loop it pins, has to be gone by the time run_main_fiber()
         * returns, so allocating the default event again must hand out a fresh one. */
        ASSERT_OK_POSITIVE(sd_event_default(&event));

        return r;
}

static int return_argc(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        return argc;
}

static int return_cancelled(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        return -ECANCELED;
}

TEST(result) {
        /* Positive results mean success and stay out of the exit status. */
        ASSERT_OK_ZERO(run_main_fiber_checked(return_argc));
        ASSERT_ERROR(run_main_fiber_checked(return_cancelled), ECANCELED);
}

static int nested_run(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        /* Attaching another main fiber to the running loop would leave it behind once we return. */
        ASSERT_ERROR(run_main_fiber(argc, argv, return_argc), EBUSY);
        return 0;
}

TEST(nested) {
        ASSERT_OK_ZERO(run_main_fiber_checked(nested_run));
}

static int signal_to_raise;

static int raise_signal(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        ASSERT_OK(sd_event_set_signal_exit(sd_fiber_get_event(), true));

        ASSERT_OK_ERRNO(raise(signal_to_raise));
        ASSERT_ERROR(sd_fiber_suspend(), ECANCELED);
        return -ECANCELED;
}

TEST(signal) {
        FOREACH_ARGUMENT(signal_to_raise, SIGINT, SIGTERM)
                ASSERT_OK_ZERO(run_main_fiber_checked(raise_signal));
}

static int fail_event(sd_event_source *s, void *userdata) {
        ASSERT_NOT_NULL(s);
        ASSERT_NULL(userdata);

        return -EINVAL;
}

static bool fiber_unwound;

static void mark_fiber_unwound(bool *marker) {
        ASSERT_NOT_NULL(marker);
        fiber_unwound = true;
}

static int event_loop_error(int argc, char *argv[]) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *defer = NULL;
        _unused_ _cleanup_(mark_fiber_unwound) bool unwind_marker = false;

        assert_test_argv(argc, argv);

        ASSERT_OK(sd_event_add_defer(sd_fiber_get_event(), &defer, fail_event, /* userdata= */ NULL));
        ASSERT_OK(sd_event_source_set_exit_on_failure(defer, true));
        ASSERT_ERROR(sd_fiber_suspend(), ECANCELED);
        return -ECANCELED;
}

TEST(event_loop_error) {
        fiber_unwound = false;

        ASSERT_ERROR(run_main_fiber_checked(event_loop_error), EINVAL);
        ASSERT_TRUE(fiber_unwound);
}

static int exit_event(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        ASSERT_OK(sd_event_exit(sd_fiber_get_event(), 23));
        ASSERT_ERROR(sd_fiber_suspend(), ECANCELED);
        return -ECANCELED;
}

static int exit_event_and_return(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        ASSERT_OK(sd_event_exit(sd_fiber_get_event(), 23));
        return 0;
}

static int exit_event_and_fail(int argc, char *argv[]) {
        assert_test_argv(argc, argv);

        ASSERT_OK(sd_event_exit(sd_fiber_get_event(), 0));
        return -ENOANO;
}

TEST(event_exit_code) {
        ASSERT_EQ(run_main_fiber_checked(exit_event), 23);
        ASSERT_EQ(run_main_fiber_checked(exit_event_and_return), 23);

        /* Requesting an exit doesn't cancel a running impl, so its failure still wins. */
        ASSERT_ERROR(run_main_fiber_checked(exit_event_and_fail), ENOANO);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
