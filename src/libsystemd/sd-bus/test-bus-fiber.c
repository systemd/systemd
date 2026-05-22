/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-future.h"

#include "bus-future.h"
#include "bus-internal.h"
#include "tests.h"
#include "time-util.h"

typedef struct Context {
        /* Counters for the concurrency check: every Concurrent invocation bumps in_flight on entry
         * and drops it on exit, and tracks the maximum observed concurrency. If fiber dispatch
         * works, two overlapping client calls must both be inside the handler at the same time,
         * giving a max of at least 2. */
        int in_flight;
        int max_in_flight;
        sd_future *waiter;
        sd_bus_message *pending_call;
} Context;

static int method_concurrent(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_OK_POSITIVE(sd_fiber_is_running());

        c->in_flight++;
        if (c->in_flight > c->max_in_flight)
                c->max_in_flight = c->in_flight;

        /* Synchronize on the peer instead of sleeping: the first handler to enter stashes its
         * fiber and suspends; the second resumes it and then yields, so the first runs to
         * completion (sending its reply) before the second proceeds. Both are therefore in
         * flight at the same time regardless of how long any individual dispatch takes, and
         * the reply order matches the request order. */
        if (c->in_flight < 2) {
                assert(!c->waiter);
                c->waiter = sd_fiber_get_current();
                ASSERT_OK(sd_fiber_suspend());
        } else {
                ASSERT_OK(sd_fiber_resume(TAKE_PTR(c->waiter), 0));
                ASSERT_OK(sd_fiber_yield());
        }

        c->in_flight--;

        return sd_bus_reply_method_return(m, NULL);
}

static int method_fail_errno(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK_POSITIVE(sd_fiber_is_running());

        /* Yielding first exercises the deferred-error path in the fiber entry: the handler returns
         * a negative errno after suspending, and bus_maybe_reply_error() must still turn that into
         * a matching sd_bus error reply. */
        ASSERT_OK(sd_fiber_sleep(1 * USEC_PER_MSEC));

        return -EACCES;
}

static int method_fail_error(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        ASSERT_OK_POSITIVE(sd_fiber_is_running());

        ASSERT_OK(sd_fiber_sleep(1 * USEC_PER_MSEC));

        return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "bad arguments from fiber");
}

static int method_hold(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_NULL(c->pending_call);
        c->pending_call = sd_bus_message_ref(m);
        if (c->waiter)
                ASSERT_OK(sd_fiber_resume(TAKE_PTR(c->waiter), 0));
        return 1;
}

static int method_release(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_NOT_NULL(c->pending_call);
        ASSERT_OK(sd_bus_reply_method_return(c->pending_call, /* types= */ NULL));
        c->pending_call = sd_bus_message_unref(c->pending_call);
        return sd_bus_reply_method_return(m, /* types= */ NULL);
}

static const sd_bus_vtable vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Concurrent", NULL, NULL, method_concurrent,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_METHOD_FIBER),
        SD_BUS_METHOD("FailErrno", NULL, NULL, method_fail_errno,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_METHOD_FIBER),
        SD_BUS_METHOD("FailError", NULL, NULL, method_fail_error,
                      SD_BUS_VTABLE_UNPRIVILEGED|SD_BUS_VTABLE_METHOD_FIBER),
        SD_BUS_METHOD("Hold", NULL, NULL, method_hold, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Release", NULL, NULL, method_release, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

typedef struct Setup {
        int fds[2];
        Context *c;
} Setup;

static int attach_pair(Setup *s, sd_bus **ret_server, sd_bus **ret_client) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;
        sd_id128_t id;

        assert(ret_server);
        assert(ret_client);

        ASSERT_OK(sd_id128_randomize(&id));
        ASSERT_OK(sd_bus_new(&server));
        ASSERT_OK(sd_bus_set_description(server, "server"));
        ASSERT_OK(sd_bus_set_fd(server, s->fds[0], s->fds[0]));
        ASSERT_OK(sd_bus_set_server(server, true, id));
        ASSERT_OK(sd_bus_attach_event(server, sd_fiber_get_event(), 0));
        ASSERT_OK(sd_bus_add_object_vtable(server, NULL, "/test", "test.Fiber", vtable, s->c));
        ASSERT_OK(sd_bus_start(server));

        ASSERT_OK(sd_bus_new(&client));
        ASSERT_OK(sd_bus_set_description(client, "client"));
        ASSERT_OK(sd_bus_set_fd(client, s->fds[1], s->fds[1]));
        ASSERT_OK(sd_bus_attach_event(client, sd_fiber_get_event(), 0));
        ASSERT_OK(sd_bus_start(client));

        *ret_server = TAKE_PTR(server);
        *ret_client = TAKE_PTR(client);
        return 0;
}

static int call_concurrent_fiber(void *userdata) {
        sd_bus *client = ASSERT_PTR(userdata);

        /* A plain suspending sd_bus_call() — on a fiber this goes through sd_bus_call_suspend()
         * which multiplexes onto the single client connection, so multiple caller fibers can have
         * calls in flight at the same time. */
        return sd_bus_call_method(client, NULL, "/test", "test.Fiber", "Concurrent",
                                  NULL, NULL, NULL);
}

static int concurrency_fiber(void *userdata) {
        Setup *s = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f_a = NULL, *f_b = NULL;

        ASSERT_OK(attach_pair(s, &server, &client));

        /* Two concurrent calls on the shared client bus. Each lands in method_concurrent which
         * blocks on the peer; if fiber dispatch works the second is entered while the first is
         * suspended, so max_in_flight on the context reaches 2. */
        ASSERT_OK(sd_fiber_new(sd_fiber_get_event(), "call-a", call_concurrent_fiber, client,
                               /* destroy= */ NULL, &f_a));
        ASSERT_OK(sd_fiber_new(sd_fiber_get_event(), "call-b", call_concurrent_fiber, client,
                               /* destroy= */ NULL, &f_b));

        ASSERT_OK(sd_fiber_await(f_a));
        ASSERT_OK(sd_fiber_await(f_b));

        ASSERT_OK(sd_future_result(f_a));
        ASSERT_OK(sd_future_result(f_b));
        return 0;
}

TEST(fiber_method_concurrency) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        Context c = {};
        Setup s = { .c = &c };

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, s.fds));

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ASSERT_OK(sd_fiber_new(e, "concurrency", concurrency_fiber, &s, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(f));
        ASSERT_GE(c.max_in_flight, 2);
}

static int errors_fiber(void *userdata) {
        Setup *s = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;

        ASSERT_OK(attach_pair(s, &server, &client));

        /* A detached bus must report the missing loop at the future API boundary. Reattaching
         * it restores the regular suspending call path used below. */
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *call = NULL;
        _cleanup_(sd_future_cancel_unrefp) sd_future *future = NULL;
        ASSERT_OK(sd_bus_message_new_method_call(client, &call, /* destination= */ NULL,
                                                "/test", "test.Fiber", "FailErrno"));
        ASSERT_OK(sd_bus_detach_event(client));
        ASSERT_ERROR(ASSERT_RETURN_EXPECTED(bus_call_future(client, call, USEC_INFINITY, &future)), ENOPKG);
        ASSERT_NULL(future);
        ASSERT_OK(sd_bus_attach_event(client, sd_fiber_get_event(), 0));

        /* A fiber handler that returns a negative errno gets turned into a matching sd_bus error
         * reply (bus_maybe_reply_error → sd_bus_reply_method_errno). */
        _cleanup_(sd_bus_error_free) sd_bus_error e1 = SD_BUS_ERROR_NULL;
        ASSERT_ERROR(sd_bus_call_method(client, NULL, "/test", "test.Fiber", "FailErrno",
                                        &e1, NULL, NULL),
                     EACCES);
        ASSERT_TRUE(sd_bus_error_has_name(&e1, SD_BUS_ERROR_ACCESS_DENIED));

        /* A fiber handler that populates sd_bus_error directly propagates both name and message. */
        _cleanup_(sd_bus_error_free) sd_bus_error e2 = SD_BUS_ERROR_NULL;
        ASSERT_FAIL(sd_bus_call_method(client, NULL, "/test", "test.Fiber", "FailError",
                                       &e2, NULL, NULL));
        ASSERT_TRUE(sd_bus_error_has_name(&e2, SD_BUS_ERROR_INVALID_ARGS));
        ASSERT_STREQ(e2.message, "bad arguments from fiber");

        return 0;
}

TEST(fiber_method_errors) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        Context c = {};
        Setup s = { .c = &c };

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM, 0, s.fds));

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));

        ASSERT_OK(sd_fiber_new(e, "errors", errors_fiber, &s, /* destroy= */ NULL, &f));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(sd_future_result(f));
}

typedef struct InterruptedCall {
        sd_bus *client;
        int error;
} InterruptedCall;

static int interrupted_call_fiber(void *userdata) {
        InterruptedCall *c = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

        {
                SD_FIBER_TIMEOUT(c->error == ETIME ? 0 : USEC_INFINITY);
                ASSERT_ERROR(sd_bus_call_method(c->client, /* destination= */ NULL,
                                               "/test", "test.Fiber", "Hold", &error, &reply,
                                               /* types= */ NULL), c->error);
        }
        /* D-Bus maps both ETIME and ETIMEDOUT to its Timeout error name; the call's return value
         * above still preserves the original interruption errno. */
        ASSERT_EQ(sd_bus_error_get_errno(&error), c->error == ETIME ? ETIMEDOUT : c->error);
        if (c->error == ETIME)
                ASSERT_TRUE(sd_bus_error_has_name(&error, SD_BUS_ERROR_TIMEOUT));
        ASSERT_NULL(reply);
        sd_bus_error_free(&error);

        /* Release sends the abandoned call's reply before its own. The old reply must neither
         * access a freed future nor wake this new wait, and no interruption may leak into it. */
        ASSERT_OK_POSITIVE(sd_bus_call_method(c->client, /* destination= */ NULL,
                                            "/test", "test.Fiber", "Release", &error, &reply,
                                            /* types= */ NULL));
        ASSERT_NOT_NULL(reply);
        ASSERT_FALSE(sd_bus_error_is_set(&error));
        ASSERT_OK_ZERO(sd_fiber_yield());
        return 0;
}

static int interrupted_calls_fiber(void *userdata) {
        Setup *s = ASSERT_PTR(userdata);
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *server = NULL, *client = NULL;
        int error;

        ASSERT_OK(attach_pair(s, &server, &client));

        FOREACH_ARGUMENT(error, ECANCELED, ETIME, EBUSY) {
                _cleanup_(sd_future_cancel_wait_unrefp) sd_future *caller = NULL;
                InterruptedCall c = { .client = client, .error = error };

                s->c->waiter = error == ETIME ? NULL : sd_fiber_get_current();
                ASSERT_OK(sd_fiber_new(sd_fiber_get_event(), "interrupted-call", interrupted_call_fiber,
                                       &c, /* destroy= */ NULL, &caller));

                if (error != ETIME) {
                        /* Interrupt only once the server has the call in hand and withheld its reply. */
                        ASSERT_OK_ZERO(sd_fiber_suspend());
                        ASSERT_NOT_NULL(s->c->pending_call);
                        if (error == ECANCELED)
                                ASSERT_OK(sd_future_cancel(caller));
                        else
                                ASSERT_OK(sd_fiber_resume(caller, 42));
                }

                ASSERT_OK_ZERO(sd_fiber_await(caller));
                ASSERT_NULL(s->c->pending_call);
                ASSERT_NULL(s->c->waiter);
        }

        return 0;
}

TEST(fiber_method_interrupted) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        Context c = {};
        Setup s = { .c = &c };

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, s.fds));
        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_set_exit_on_idle(e, true));
        ASSERT_OK(sd_fiber_new(e, "interrupted-calls", interrupted_calls_fiber, &s,
                               /* destroy= */ NULL, &f));
        ASSERT_OK(sd_event_loop(e));
        ASSERT_OK_ZERO(sd_future_result(f));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
