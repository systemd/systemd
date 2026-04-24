/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-future.h"
#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "json-stream.h"
#include "qmp-client.h"
#include "string-util.h"
#include "tests.h"

/* Mock QMP server runs as an sd-fiber alongside the client on the same event loop. Its
 * JsonStream uses the suspending json_stream_wait()/json_stream_flush() helpers, so the mock
 * fiber yields whenever it's blocked on I/O and the client makes progress in the meantime. */

static JsonStreamPhase mock_qmp_phase(void *userdata) {
        return JSON_STREAM_PHASE_READING;
}

static int mock_qmp_dispatch(void *userdata) {
        return 0;
}

static void mock_qmp_init(JsonStream *s, int fd) {
        static const JsonStreamParams params = {
                .delimiter = "\r\n",
                .phase = mock_qmp_phase,
                .dispatch = mock_qmp_dispatch,
        };

        ASSERT_OK(json_stream_init(s, &params));
        ASSERT_OK(json_stream_connect_fd_pair(s, fd, fd));
}

static void mock_qmp_recv(JsonStream *s, sd_json_variant **ret) {
        int r;

        for (;;) {
                r = ASSERT_OK(json_stream_parse(s, ret));
                if (r > 0)
                        return;

                r = ASSERT_OK(json_stream_read(s));
                if (r > 0)
                        continue;

                ASSERT_OK(json_stream_wait(s, USEC_INFINITY));
        }
}

static void mock_qmp_send(JsonStream *s, sd_json_variant *v) {
        ASSERT_OK(json_stream_enqueue(s, v));
        ASSERT_OK(json_stream_flush(s));
}

static void mock_qmp_send_greeting(JsonStream *s) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR("QMP", SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR("version", SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR("qemu", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_UNSIGNED("micro", 0),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("minor", 2),
                                        SD_JSON_BUILD_PAIR_UNSIGNED("major", 9))))),
                        SD_JSON_BUILD_PAIR("capabilities", SD_JSON_BUILD_STRV(STRV_MAKE("oob")))))));
        mock_qmp_send(s, v);
}

/* Receive one command, assert it matches `expected_command`, return its id (borrowed from *cmd). */
static sd_json_variant* mock_qmp_expect(JsonStream *s, const char *expected_command, sd_json_variant **cmd) {
        mock_qmp_recv(s, cmd);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(*cmd, "execute")), expected_command);
        return ASSERT_NOT_NULL(sd_json_variant_by_key(*cmd, "id"));
}

/* Send a reply for a previously-received command id. Passing NULL reply_data sends {}. */
static void mock_qmp_reply(JsonStream *s, sd_json_variant *id, sd_json_variant *reply_data) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;

        if (reply_data)
                ASSERT_OK(sd_json_buildo(&response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(reply_data)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));
        else
                ASSERT_OK(sd_json_buildo(&response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_EMPTY_OBJECT),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));

        mock_qmp_send(s, response);
}

static void mock_qmp_expect_and_reply(JsonStream *s, const char *expected_command, sd_json_variant *reply_data) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        mock_qmp_reply(s, mock_qmp_expect(s, expected_command, &cmd), reply_data);
}

static void mock_qmp_expect_and_reply_error(JsonStream *s, const char *expected_command, const char *error_desc) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *response = NULL;
        sd_json_variant *id = mock_qmp_expect(s, expected_command, &cmd);

        ASSERT_OK(sd_json_buildo(&response,
                SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_STRING("class", "GenericError"),
                        SD_JSON_BUILD_PAIR_STRING("desc", error_desc))),
                SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));

        mock_qmp_send(s, response);
}

static void mock_qmp_handshake(JsonStream *s) {
        mock_qmp_send_greeting(s);
        mock_qmp_expect_and_reply(s, "qmp_capabilities", NULL);
}

/* Reply to query-status with a running=true/status="running" payload. */
static void mock_qmp_query_status_running(JsonStream *s) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_buildo(&v,
                SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                SD_JSON_BUILD_PAIR_STRING("status", "running")));
        mock_qmp_expect_and_reply(s, "query-status", v);
}

/* Drive a mock+client pair on a single event loop. The client fiber runs as userdata=client,
 * the mock fiber as userdata=fd (the server-side socket). */
static void run_qmp_test(sd_fiber_func_t mock_fn, sd_fiber_func_t client_fn) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_future_unrefp) sd_future *client_f = NULL;
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_close_pair_ int qmp_fds[2] = EBADF_PAIR;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        ASSERT_OK(qmp_client_connect_fd(&client, TAKE_FD(qmp_fds[0])));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        ASSERT_OK(sd_fiber_new(event, "mock", mock_fn, FD_TO_PTR(TAKE_FD(qmp_fds[1])), NULL, NULL));
        ASSERT_OK(sd_fiber_new(event, "client", client_fn, client, NULL, &client_f));

        ASSERT_OK(sd_event_loop(event));
        ASSERT_OK(sd_future_result(client_f));
}

/* Define a test whose body runs as the client fiber on an event loop shared with `mock_fn`.
 * The body receives `QmpClient *client` as its argument. */
#define QMP_TEST(name, mock_fn)                                                \
        static int test_##name##_body(QmpClient *client);                      \
        static int test_##name##_fiber(void *userdata) {                       \
                int r = test_##name##_body(userdata);                          \
                ASSERT_OK(sd_event_exit(sd_fiber_get_event(), 0));             \
                return r;                                                      \
        }                                                                      \
        TEST(name) {                                                           \
                run_qmp_test(mock_fn, test_##name##_fiber);                    \
        }                                                                      \
        static int test_##name##_body(QmpClient *client)

static int mock_qmp_basic_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *stop_event = NULL;

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        mock_qmp_handshake(&s);

        mock_qmp_query_status_running(&s);
        mock_qmp_expect_and_reply(&s, "stop", NULL);

        ASSERT_OK(sd_json_buildo(&stop_event,
                SD_JSON_BUILD_PAIR_STRING("event", "STOP"),
                SD_JSON_BUILD_PAIR("timestamp", SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_UNSIGNED("seconds", 1234),
                        SD_JSON_BUILD_PAIR_UNSIGNED("microseconds", 5678)))));
        mock_qmp_send(&s, stop_event);

        mock_qmp_expect_and_reply(&s, "cont", NULL);
        return 0;
}

static int test_event_callback(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        bool *event_received = ASSERT_PTR(userdata);

        /* Ignore the synthetic SHUTDOWN emitted when the mock closes the connection. */
        if (streq(event, "STOP"))
                *event_received = true;

        return 0;
}

QMP_TEST(qmp_client_basic, mock_qmp_basic_fiber) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ char *error_desc = NULL;
        bool event_received = false;

        qmp_client_bind_event(client, test_event_callback, &event_received);

        ASSERT_OK_POSITIVE(qmp_client_call(client, "query-status", NULL, &result, &error_desc));
        ASSERT_NULL(error_desc);

        sd_json_variant *running = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "running"));
        ASSERT_TRUE(sd_json_variant_boolean(running));
        sd_json_variant *status = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "status"));
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        ASSERT_OK_POSITIVE(qmp_client_call(client, "stop", NULL, NULL, NULL));
        ASSERT_OK_POSITIVE(qmp_client_call(client, "cont", NULL, NULL, NULL));

        ASSERT_TRUE(event_received);
        return 0;
}

static int mock_qmp_eof_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        mock_qmp_handshake(&s);
        /* Return; _cleanup_ closes the fd → client sees EOF. */
        return 0;
}

QMP_TEST(qmp_client_eof, mock_qmp_eof_fiber) {
        int r = qmp_client_call(client, "query-status", NULL, NULL, NULL);
        ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(r));
        return 0;
}

static int mock_qmp_call_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        mock_qmp_handshake(&s);

        mock_qmp_query_status_running(&s);
        mock_qmp_expect_and_reply_error(&s, "stop", "not running");
        mock_qmp_expect_and_reply_error(&s, "stop", "still not running");
        return 0;
}

QMP_TEST(qmp_client_call, mock_qmp_call_fiber) {
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;
        _cleanup_free_ char *error_desc = NULL;

        /* Exercise qmp_client_call_future() + sd_fiber_await() + future_get_qmp_reply()
         * directly — success path. */
        ASSERT_OK(qmp_client_call_future(client, "query-status", NULL, &f));
        ASSERT_OK(sd_fiber_await(f));
        ASSERT_OK(sd_future_result(f));
        ASSERT_OK(future_get_qmp_reply(f, &result, &error_desc));

        ASSERT_NULL(error_desc);
        sd_json_variant *running = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "running"));
        ASSERT_TRUE(sd_json_variant_boolean(running));
        sd_json_variant *status = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "status"));
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        /* QMP-level error: future resolves with 0 (the reply landed); future_get_qmp_reply()
         * surfaces the error via error_desc, with result left NULL. */
        f = sd_future_unref(f);
        result = sd_json_variant_unref(result);
        error_desc = mfree(error_desc);

        ASSERT_OK(qmp_client_call_future(client, "stop", NULL, &f));
        ASSERT_OK(sd_fiber_await(f));
        ASSERT_OK(sd_future_result(f));
        ASSERT_OK(future_get_qmp_reply(f, &result, &error_desc));

        ASSERT_NULL(result);
        ASSERT_STREQ(error_desc, "not running");

        /* qmp_client_call() surfaces QMP errors as -EIO when the caller doesn't ask for the desc. */
        ASSERT_ERROR(qmp_client_call(client, "stop", NULL, NULL, NULL), EIO);
        return 0;
}

static int mock_qmp_call_disconnect_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *stop_cmd = NULL;

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        mock_qmp_handshake(&s);

        /* Consume the stop command but don't reply — cleanup closes the fd and the client
         * sees a disconnect while suspended. */
        mock_qmp_recv(&s, &stop_cmd);
        return 0;
}

QMP_TEST(qmp_client_call_disconnect, mock_qmp_call_disconnect_fiber) {
        int r = qmp_client_call(client, "stop", NULL, NULL, NULL);
        ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(r));
        return 0;
}

static int mock_qmp_fd_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cap_cmd = NULL, *addfd_cmd = NULL,
                                                          *addfd_return = NULL;

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        ASSERT_OK(json_stream_set_allow_fd_passing_input(&s, true, true));

        mock_qmp_send_greeting(&s);

        /* The fd may ride with either command depending on AF_UNIX coalescing; count across both. */
        sd_json_variant *cap_id = mock_qmp_expect(&s, "qmp_capabilities", &cap_cmd);
        size_t n_fds_total = json_stream_get_n_input_fds(&s);
        json_stream_close_input_fds(&s);
        mock_qmp_reply(&s, cap_id, NULL);

        sd_json_variant *addfd_id = mock_qmp_expect(&s, "add-fd", &addfd_cmd);
        n_fds_total += json_stream_get_n_input_fds(&s);
        json_stream_close_input_fds(&s);
        ASSERT_EQ(n_fds_total, (size_t) 1);

        ASSERT_OK(sd_json_buildo(&addfd_return,
                SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0),
                SD_JSON_BUILD_PAIR_UNSIGNED("fd", 42)));
        mock_qmp_reply(&s, addfd_id, addfd_return);
        return 0;
}

QMP_TEST(qmp_client_invoke_with_fd, mock_qmp_fd_fiber) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *result = NULL;

        fd_to_pass = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));

        ASSERT_OK_POSITIVE(qmp_client_call(client, "add-fd",
                                           QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                           &result, NULL));
        ASSERT_NOT_NULL(result);
        return 0;
}

static int on_dead_peer_reply(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        /* Peer was closed before the write hit the wire; expect a disconnect. */
        ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(error));
        return 0;
}

/* Verify caller-supplied fds passed through QMP_CLIENT_ARGS_FD() are closed on client teardown
 * even when the peer is already dead: invoke enqueues, the queue item owns the fd, unref closes. */
TEST(qmp_client_invoke_failure_closes_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        QmpClient *client = NULL;
        _cleanup_close_pair_ int qmp_fds[2] = EBADF_PAIR;
        int saved_fd_value;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));
        qmp_fds[1] = safe_close(qmp_fds[1]);

        fd_to_pass = ASSERT_OK_ERRNO(eventfd(0, EFD_CLOEXEC));
        saved_fd_value = fd_to_pass;

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));
        ASSERT_OK(qmp_client_connect_fd(&client, TAKE_FD(qmp_fds[0])));

        ASSERT_OK(qmp_client_invoke(client, NULL, "add-fd",
                                    QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                    on_dead_peer_reply, NULL));
        ASSERT_EQ(fd_to_pass, -EBADF);
        ASSERT_OK_ERRNO(fcntl(saved_fd_value, F_GETFD));

        client = qmp_client_unref(client);
        ASSERT_ERROR_ERRNO(fcntl(saved_fd_value, F_GETFD), EBADF);
}

/* Shared mock for the two slot tests: the follow-up stop is what drives the event loop long
 * enough to dispatch the query-status reply. */
static int mock_qmp_slot_fiber(void *userdata) {
        _cleanup_(json_stream_done) JsonStream s = {};

        mock_qmp_init(&s, PTR_TO_FD(userdata));
        mock_qmp_handshake(&s);

        mock_qmp_query_status_running(&s);
        mock_qmp_expect_and_reply(&s, "stop", NULL);
        return 0;
}

static int nop_callback(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        return 0;
}

/* Tripwire for the cancel test: if it fires, the cancel didn't do its job. */
static int tripwire_callback(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        bool *fired = ASSERT_PTR(userdata);
        *fired = true;
        return 0;
}

QMP_TEST(qmp_client_invoke_slot_lifecycle, mock_qmp_slot_fiber) {
        _cleanup_(qmp_slot_unrefp) QmpSlot *slot = NULL;

        ASSERT_OK(qmp_client_invoke(client, &slot, "query-status", NULL, nop_callback, NULL));
        ASSERT_PTR_EQ(qmp_slot_get_client(slot), client);

        /* Drive the loop via a follow-up stop; its suspending call lets both replies dispatch. */
        ASSERT_OK_POSITIVE(qmp_client_call(client, "stop", NULL, NULL, NULL));

        /* After dispatch the slot is disconnected from the client but still owned by us. */
        ASSERT_NULL(qmp_slot_get_client(slot));

        /* Explicit out-of-order unref exercises the already-disconnected path in qmp_slot_free(). */
        slot = qmp_slot_unref(slot);
        return 0;
}

QMP_TEST(qmp_client_invoke_slot_cancel, mock_qmp_slot_fiber) {
        QmpSlot *slot = NULL;
        bool fired = false;

        ASSERT_OK(qmp_client_invoke(client, &slot, "query-status", NULL, tripwire_callback, &fired));

        /* Drop our sole ref → slot disconnects from the client's pending set. The enqueued
         * query-status is still on the wire; its reply lands on an unknown id and is discarded. */
        slot = qmp_slot_unref(slot);

        ASSERT_OK_POSITIVE(qmp_client_call(client, "stop", NULL, NULL, NULL));

        ASSERT_FALSE(fired);
        return 0;
}

TEST(qmp_schema_has_member) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        /* QEMU introspection uses opaque numeric type ids ("0", "1", ...); only member names
         * are the real QAPI strings. Verify we walk all object entries to find members by name. */
        ASSERT_OK(sd_json_build(&schema,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("name", "0"),
                                SD_JSON_BUILD_PAIR_STRING("meta-type", "object"),
                                SD_JSON_BUILD_PAIR("members", SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_STRING("name", "offset"),
                                                SD_JSON_BUILD_PAIR_STRING("type", "int"))))),
                        SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("name", "SomeEnum"),
                                SD_JSON_BUILD_PAIR_STRING("meta-type", "enum")),
                        SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("name", "1"),
                                SD_JSON_BUILD_PAIR_STRING("meta-type", "object"),
                                SD_JSON_BUILD_PAIR("members", SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_STRING("name", "lazy-refcounts"),
                                                SD_JSON_BUILD_PAIR_STRING("type", "bool")),
                                        SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_STRING("name", "discard-no-unref"),
                                                SD_JSON_BUILD_PAIR_STRING("type", "bool"))))))));

        ASSERT_TRUE(qmp_schema_has_member(schema, "discard-no-unref"));
        ASSERT_TRUE(qmp_schema_has_member(schema, "offset"));
        ASSERT_FALSE(qmp_schema_has_member(schema, "definitely-not-a-real-field"));
        ASSERT_FALSE(qmp_schema_has_member(NULL, "discard-no-unref"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
