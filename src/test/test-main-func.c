/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>

#include "sd-event.h"
#include "sd-future.h"

#include "main-func.h"
#include "tests.h"

static int return_argc(int argc, char *argv[]) {
        assert(!argv);

        return argc;
}

static int return_cancelled(int argc, char *argv[]) {
        assert(argc == 0);
        assert(!argv);

        return -ECANCELED;
}

TEST(result) {
        ASSERT_EQ(run_main_fiber(5, /* argv= */ NULL, return_argc), 5);
        ASSERT_ERROR(run_main_fiber(0, /* argv= */ NULL, return_cancelled), ECANCELED);
}

static int raise_signal(int signo, char *argv[]) {
        assert(!argv);

        ASSERT_OK_ERRNO(raise(signo));
        return sd_fiber_suspend();
}

static void test_one_signal(int signo) {
        sigset_t before, after;

        ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, /* set= */ NULL, &before));
        ASSERT_OK_ZERO(run_main_fiber(signo, /* argv= */ NULL, raise_signal));
        ASSERT_OK_ERRNO(sigprocmask(SIG_SETMASK, /* set= */ NULL, &after));

        ASSERT_EQ(sigismember(&after, SIGINT), sigismember(&before, SIGINT));
        ASSERT_EQ(sigismember(&after, SIGTERM), sigismember(&before, SIGTERM));
}

TEST(signal) {
        test_one_signal(SIGINT);
        test_one_signal(SIGTERM);
}

static int fail_event(sd_event_source *s, void *userdata) {
        assert(s);
        assert(!userdata);

        return -EINVAL;
}

static int event_loop_error(int argc, char *argv[]) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *defer = NULL;

        assert(argc == 0);
        assert(!argv);

        ASSERT_OK(sd_event_add_defer(sd_fiber_get_event(), &defer, fail_event, /* userdata= */ NULL));
        return sd_fiber_suspend();
}

TEST(event_loop_error) {
        ASSERT_ERROR(run_main_fiber(0, /* argv= */ NULL, event_loop_error), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
