/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "json-stream.h"
#include "pidref.h"
#include "process-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "tests.h"

/* Mock QMP server: runs in the child process of a fork, communicates via one end of a socketpair.
 * Uses JsonStream as the transport so framing (CRLF delimiter, message queuing, SCM_RIGHTS) is
 * handled the same way as on the client side — individual recv() syscalls may coalesce multiple
 * messages, and the parser must re-emit each one on its own. */

/* We drive the stream manually via read/parse/wait; always report READING so json_stream_wait()
 * asks for POLLIN. */
static JsonStreamPhase mock_qmp_phase(void *userdata) {
        return JSON_STREAM_PHASE_READING;
}

/* Never reached — we don't wire the mock stream up to sd-event — but required at init. */
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

/* Read one complete JSON message, blocking until available. Handles the case where multiple
 * client messages arrived coalesced into a single recv(): the parser walks the input buffer
 * one CRLF-delimited message at a time. */
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

/* Enqueue one JSON variant and block until it has been fully written. */
static void mock_qmp_send(JsonStream *s, sd_json_variant *v) {
        ASSERT_OK(json_stream_enqueue(s, v));
        ASSERT_OK(json_stream_flush(s));
}

/* Parse a literal JSON string and send it. Used for fixed greetings and unsolicited events. */
static void mock_qmp_send_literal(JsonStream *s, const char *msg) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(msg, 0, &v, NULL, NULL));
        mock_qmp_send(s, v);
}

/* Read a command from the client, verify it contains the expected command name, and send a
 * reply carrying the same id. If reply_data is NULL, an empty return object is sent. */
static void mock_qmp_expect_and_reply(JsonStream *s, const char *expected_command, sd_json_variant *reply_data) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *reply_obj = NULL, *response = NULL;

        mock_qmp_recv(s, &cmd);

        sd_json_variant *execute = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "execute"));
        ASSERT_STREQ(sd_json_variant_string(execute), expected_command);

        sd_json_variant *id = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "id"));

        if (!reply_data)
                ASSERT_OK(sd_json_variant_new_object(&reply_obj, NULL, 0));

        ASSERT_OK(sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(reply_data ?: reply_obj)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));

        mock_qmp_send(s, response);
}

/* Same shape as mock_qmp_expect_and_reply() but replies with a QMP error object. */
static void mock_qmp_expect_and_reply_error(JsonStream *s, const char *expected_command, const char *error_desc) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *error_obj = NULL, *response = NULL;

        mock_qmp_recv(s, &cmd);

        sd_json_variant *execute = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "execute"));
        ASSERT_STREQ(sd_json_variant_string(execute), expected_command);

        sd_json_variant *id = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "id"));

        ASSERT_OK(sd_json_buildo(
                        &error_obj,
                        SD_JSON_BUILD_PAIR_STRING("class", "GenericError"),
                        SD_JSON_BUILD_PAIR_STRING("desc", error_desc)));

        ASSERT_OK(sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_VARIANT(error_obj)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));

        mock_qmp_send(s, response);
}

static _noreturn_ void mock_qmp_server(int fd) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *status_return = NULL;

        mock_qmp_init(&s, fd);

        /* Send QMP greeting */
        mock_qmp_send_literal(&s,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 2, \"major\": 9}}, \"capabilities\": [\"oob\"]}}");

        /* Accept qmp_capabilities */
        mock_qmp_expect_and_reply(&s, "qmp_capabilities", NULL);

        /* Accept query-status, reply with running state */
        ASSERT_OK(sd_json_buildo(
                        &status_return,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                        SD_JSON_BUILD_PAIR_STRING("status", "running")));
        mock_qmp_expect_and_reply(&s, "query-status", status_return);

        /* Accept stop */
        mock_qmp_expect_and_reply(&s, "stop", NULL);

        /* Send a STOP event */
        mock_qmp_send_literal(&s,
                "{\"event\": \"STOP\", \"timestamp\": {\"seconds\": 1234, \"microseconds\": 5678}}");

        /* Accept cont */
        mock_qmp_expect_and_reply(&s, "cont", NULL);

        /* json_stream_done() on cleanup closes our fd and signals EOF. */
        _exit(EXIT_SUCCESS);
}

/* Test helper: tracks an async QMP command result and signals completion. */
typedef struct {
        sd_json_variant *result;
        char *error_desc;
        int error;
        bool done;
} QmpTestResult;

static int on_test_result(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        QmpTestResult *t = ASSERT_PTR(userdata);

        t->error = error;
        if (result)
                t->result = sd_json_variant_ref(result);
        if (error_desc)
                t->error_desc = strdup(error_desc);
        t->done = true;
        return 0;
}

/* Run the event loop until the test result callback fires. */
static void qmp_test_wait(sd_event *event, QmpTestResult *t) {
        assert(event);
        assert(t);

        while (!t->done)
                ASSERT_OK(sd_event_run(event, UINT64_MAX));
}

static void qmp_test_result_done(QmpTestResult *t) {
        assert(t);

        sd_json_variant_unref(t->result);
        free(t->error_desc);
        *t = (QmpTestResult) {};
}

static int test_event_callback(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata) {

        bool *event_received = ASSERT_PTR(userdata);

        /* We may also receive a synthetic SHUTDOWN event when the mock server closes the connection;
         * only validate the STOP event we actually care about. */
        if (streq(event, "STOP"))
                *event_received = true;

        return 0;
}

TEST(qmp_client_basic) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        QmpTestResult t = {};
        sd_json_variant *running, *status;
        int qmp_fds[2];
        int r;

        ASSERT_OK(sd_event_new(&event));

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));

        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server(qmp_fds[1]);
        }

        safe_close(qmp_fds[1]);

        /* Connect then attach to event loop — handshake completes transparently
         * inside the first call()/invoke(). */
        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* Set event callback to catch STOP event during cont */
        bool event_received = false;
        qmp_client_bind_event(client, test_event_callback, &event_received);

        /* Execute query-status */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "query-status", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        running = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "running"));
        ASSERT_TRUE(sd_json_variant_boolean(running));

        status = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "status"));
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        qmp_test_result_done(&t);

        /* Execute stop */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "stop", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Execute cont -- the STOP event should be dispatched by the IO callback */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "cont", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Verify the STOP event was received */
        ASSERT_TRUE(event_received);

        /* Wait for child and verify clean exit */
        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pid, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
}

TEST(qmp_client_eof) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        QmpTestResult t = {};
        int qmp_fds[2];
        int r;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-eof)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));

        if (r == 0) {
                _cleanup_(json_stream_done) JsonStream s = {};

                safe_close(qmp_fds[0]);
                mock_qmp_init(&s, qmp_fds[1]);

                /* Send greeting and accept capabilities, then die */
                mock_qmp_send_literal(&s,
                        "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

                mock_qmp_expect_and_reply(&s, "qmp_capabilities", NULL);

                /* _exit() closes our fd via kernel teardown, signalling EOF to the peer. */
                _exit(EXIT_SUCCESS);
        }

        safe_close(qmp_fds[1]);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* Executing a command should fail with a disconnect error because the server
         * closed. The handshake may succeed or fail inside invoke() — either way the
         * invoke itself or the async callback should report a disconnect. */
        r = qmp_client_invoke(client, /* ret_slot= */ NULL, "query-status", NULL, on_test_result, &t);
        if (r < 0)
                ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(r));
        else {
                qmp_test_wait(event, &t);
                ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(t.error));
                qmp_test_result_done(&t);
        }

        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pid, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
}

/* Mock QMP server for the fd-passing test. Drives the wire dance:
 *   greeting → recv qmp_capabilities → reply → recv add-fd → reply
 * Asserts that exactly one SCM_RIGHTS fd arrives total across the two recvs. We can't
 * require the fd to come attached to add-fd specifically: AF_UNIX coalesces the client's
 * non-SCM cap sendmsg forward into the SCM-bearing add-fd sendmsg, so the fd may surface
 * with either recv depending on kernel scheduling. QEMU's FIFO fd queue doesn't care. */
static _noreturn_ void mock_qmp_server_fd(int fd) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cap_cmd = NULL,
                                                          *addfd_cmd = NULL,
                                                          *cap_reply = NULL,
                                                          *addfd_return = NULL,
                                                          *addfd_reply = NULL;

        mock_qmp_init(&s, fd);
        ASSERT_OK(json_stream_set_allow_fd_passing_input(&s, true, /* with_sockopt= */ true));

        /* Greeting */
        mock_qmp_send_literal(&s,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

        /* Receive qmp_capabilities (may or may not carry the fd depending on coalescing). */
        mock_qmp_recv(&s, &cap_cmd);
        size_t n_fds_total = json_stream_get_n_input_fds(&s);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(cap_cmd, "execute")), "qmp_capabilities");
        json_stream_close_input_fds(&s);

        sd_json_variant *cap_id = ASSERT_NOT_NULL(sd_json_variant_by_key(cap_cmd, "id"));
        ASSERT_OK(sd_json_buildo(
                        &cap_reply,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_EMPTY_OBJECT),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(cap_id))));
        mock_qmp_send(&s, cap_reply);

        /* Receive add-fd (fd may already have been consumed with cap's recv). */
        mock_qmp_recv(&s, &addfd_cmd);
        n_fds_total += json_stream_get_n_input_fds(&s);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(addfd_cmd, "execute")), "add-fd");
        json_stream_close_input_fds(&s);

        ASSERT_EQ(n_fds_total, (size_t) 1);

        sd_json_variant *addfd_id = ASSERT_NOT_NULL(sd_json_variant_by_key(addfd_cmd, "id"));
        ASSERT_OK(sd_json_buildo(
                        &addfd_return,
                        SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0),
                        SD_JSON_BUILD_PAIR_UNSIGNED("fd", 42)));
        ASSERT_OK(sd_json_buildo(
                        &addfd_reply,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(addfd_return)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(addfd_id))));
        mock_qmp_send(&s, addfd_reply);

        _exit(EXIT_SUCCESS);
}

/* End-to-end fd-passing through qmp_client_invoke() with QMP_CLIENT_ARGS_FD(): open a real
 * fd, send add-fd, confirm the mock received a single SCM_RIGHTS fd and replied successfully. */
TEST(qmp_client_invoke_with_fd) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        QmpTestResult t = {};
        int qmp_fds[2];
        int r;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-fd)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));

        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_fd(qmp_fds[1]);
        }

        safe_close(qmp_fds[1]);

        /* Open a real fd to pass — /dev/null is universally available. */
        fd_to_pass = open("/dev/null", O_RDWR|O_CLOEXEC);
        ASSERT_OK(fd_to_pass);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));

        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "add-fd",
                                    QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                    on_test_result, &t));

        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);
        qmp_test_result_done(&t);

        /* Wait for the mock. If its fd-count assertion tripped, si.si_status is non-zero. */
        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pid, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
}

/* Regression: the caller-supplied fds — already TAKE_FD()'d through QMP_CLIENT_ARGS_FD() —
 * must never leak, regardless of whether the invoke reaches the wire. Verified here via a
 * dead peer: invoke enqueues (non-blocking), the queue item owns the fd, and client teardown
 * must close it. */
TEST(qmp_client_invoke_failure_closes_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        QmpClient *client = NULL;
        QmpTestResult t = {};
        int qmp_fds[2];
        int saved_fd_value;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        /* Close the peer end immediately so any write attempt sees EPIPE. */
        safe_close(qmp_fds[1]);

        fd_to_pass = open("/dev/null", O_RDWR|O_CLOEXEC);
        ASSERT_OK(fd_to_pass);
        saved_fd_value = fd_to_pass;   /* remember the int value for the closed-check */

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));
        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));

        /* invoke no longer blocks on the handshake — it just enqueues. The fd is now
         * owned by the underlying JsonStream output queue. */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "add-fd",
                                    QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                    on_test_result, &t));
        ASSERT_EQ(fd_to_pass, -EBADF);  /* TAKE_FD cleared our local handle */

        /* The fd is still open here (held in JsonStream's queue). */
        ASSERT_OK_ERRNO(fcntl(saved_fd_value, F_GETFD));

        /* Client teardown (json_stream_done) must close queued output fds, otherwise the
         * saved fd number would still be valid. */
        client = qmp_client_unref(client);
        ASSERT_EQ(fcntl(saved_fd_value, F_GETFD), -1);
        ASSERT_EQ(errno, EBADF);
}

/* Mock for the slot lifecycle + cancel tests: greets, accepts capabilities, then accepts
 * query-status and stop, replying with dummy returns. A cancelled query-status still gets
 * sent on the wire (cancel merely removes the pending slot), so the server must be prepared
 * to read and reply to it. */
static _noreturn_ void mock_qmp_server_slot(int fd) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *status_return = NULL;

        mock_qmp_init(&s, fd);

        mock_qmp_send_literal(&s,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

        mock_qmp_expect_and_reply(&s, "qmp_capabilities", NULL);

        ASSERT_OK(sd_json_buildo(
                        &status_return,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                        SD_JSON_BUILD_PAIR_STRING("status", "running")));
        mock_qmp_expect_and_reply(&s, "query-status", status_return);

        mock_qmp_expect_and_reply(&s, "stop", NULL);

        _exit(EXIT_SUCCESS);
}

/* Verify that when qmp_client_invoke() returns a slot, qmp_slot_get_client() tracks the
 * connection state: the client pointer is reported while the call is in flight, and flipped
 * back to NULL once the reply has been dispatched. The caller must still be able to drop its
 * ref safely after that. */
TEST(qmp_client_invoke_slot_lifecycle) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        _cleanup_(qmp_slot_unrefp) QmpSlot *slot = NULL;
        QmpTestResult t = {};
        int qmp_fds[2];
        int r;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-slot-life)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));
        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_slot(qmp_fds[1]);
        }
        safe_close(qmp_fds[1]);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        ASSERT_OK(qmp_client_invoke(client, &slot, "query-status", NULL, on_test_result, &t));

        /* While in flight the slot still references its client. */
        ASSERT_NOT_NULL(slot);
        ASSERT_PTR_EQ(qmp_slot_get_client(slot), client);

        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        /* Once dispatched, the slot is disconnected from the client but still owned by us. */
        ASSERT_NULL(qmp_slot_get_client(slot));

        qmp_test_result_done(&t);

        /* Drop our ref explicitly (out of order w.r.t. cleanup) to exercise the
         * already-disconnected path in qmp_slot_free(). */
        slot = qmp_slot_unref(slot);
        ASSERT_NULL(slot);
}

/* Verify that dropping the only reference on a pending slot before the reply arrives cancels
 * the callback. The command is already enqueued on the stream at that point, so the server
 * still sees it and replies — but the reply lands on an unknown id and is discarded. */
TEST(qmp_client_invoke_slot_cancel) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        QmpTestResult t_cancelled = {};
        QmpSlot *slot = NULL;
        int qmp_fds[2];
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-slot-cancel)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));
        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_slot(qmp_fds[1]);
        }
        safe_close(qmp_fds[1]);

        /* Drive without an event loop so the subsequent qmp_client_call() owns all pumping;
         * it serializes write→read round-trips, which avoids the mock server seeing the
         * cancelled query-status and the follow-up stop concatenated into a single recv(). */
        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));

        ASSERT_OK(qmp_client_invoke(client, &slot, "query-status", NULL, on_test_result, &t_cancelled));
        ASSERT_NOT_NULL(slot);

        /* Drop our sole ref → slot disconnects itself from the client's pending set. The
         * enqueued query-status is still on the wire; when its reply arrives, dispatch_reply
         * won't find a matching slot and will log-and-discard it. */
        slot = qmp_slot_unref(slot);
        ASSERT_NULL(slot);

        /* Synchronous call drives its own process+wait pump: it first drains the already-
         * enqueued query-status write, consumes (and discards) its reply, then sends stop
         * and waits for that reply. Any improper fire of the cancelled callback would have
         * happened during that process() pass. */
        ASSERT_EQ(qmp_client_call(client, "stop", NULL, NULL, NULL), 1);

        /* The cancelled callback must never have fired. */
        ASSERT_FALSE(t_cancelled.done);
        ASSERT_NULL(t_cancelled.result);
        ASSERT_NULL(t_cancelled.error_desc);
}

/* Drives a small wire dance for the sync call test: greeting, capabilities, one successful
 * command reply, and two error replies (one for the ret_error_desc path, one for the -EIO
 * path). */
static _noreturn_ void mock_qmp_server_call(int fd) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *status_return = NULL;

        mock_qmp_init(&s, fd);

        mock_qmp_send_literal(&s,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

        mock_qmp_expect_and_reply(&s, "qmp_capabilities", NULL);

        ASSERT_OK(sd_json_buildo(
                        &status_return,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                        SD_JSON_BUILD_PAIR_STRING("status", "running")));
        mock_qmp_expect_and_reply(&s, "query-status", status_return);

        mock_qmp_expect_and_reply_error(&s, "stop", "not running");
        mock_qmp_expect_and_reply_error(&s, "stop", "still not running");

        _exit(EXIT_SUCCESS);
}

TEST(qmp_client_call) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int qmp_fds[2];
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-call)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));
        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_call(qmp_fds[1]);
        }
        safe_close(qmp_fds[1]);

        /* qmp_client_call() drives its own process()+wait() pump, so no event loop needed. */
        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));

        /* Successful call: borrowed result pointer is valid until the next call. */
        sd_json_variant *result = NULL;
        const char *error_desc = NULL;
        ASSERT_EQ(qmp_client_call(client, "query-status", NULL, &result, &error_desc), 1);
        ASSERT_NULL(error_desc);
        ASSERT_NOT_NULL(result);

        sd_json_variant *running = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "running"));
        ASSERT_TRUE(sd_json_variant_boolean(running));
        sd_json_variant *status = ASSERT_NOT_NULL(sd_json_variant_by_key(result, "status"));
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        /* QMP error with ret_error_desc provided: returns 1, result NULL, desc set. */
        result = (sd_json_variant*) 0x1;  /* poison to catch lack-of-write */
        error_desc = NULL;
        ASSERT_EQ(qmp_client_call(client, "stop", NULL, &result, &error_desc), 1);
        ASSERT_NULL(result);
        ASSERT_STREQ(error_desc, "not running");

        /* QMP error without ret_error_desc: surfaces as -EIO. */
        ASSERT_EQ(qmp_client_call(client, "stop", NULL, NULL, NULL), -EIO);
}

/* Server variant for the sync-call disconnect test: greets, accepts capabilities, reads one
 * command without replying, then closes the socket so the client sees EOF mid-wait. */
static _noreturn_ void mock_qmp_server_call_disconnect(int fd) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *stop_cmd = NULL;

        mock_qmp_init(&s, fd);

        mock_qmp_send_literal(&s,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

        mock_qmp_expect_and_reply(&s, "qmp_capabilities", NULL);

        /* Consume the stop command but don't reply — json_stream_done() on cleanup closes
         * our fd, triggering EOF while the client is blocked in qmp_client_call()'s
         * process+wait pump. */
        mock_qmp_recv(&s, &stop_cmd);

        _exit(EXIT_SUCCESS);
}

TEST(qmp_client_call_disconnect) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pid = PIDREF_NULL;
        int qmp_fds[2];
        int r;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        r = ASSERT_OK(pidref_safe_fork("(mock-qmp-call-disc)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid));
        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_call_disconnect(qmp_fds[1]);
        }
        safe_close(qmp_fds[1]);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));

        /* The server reads our stop command and closes without replying. qmp_client_call()
         * is driving its own pump, so it must notice the EOF, transition to DISCONNECTED,
         * and return a disconnect error rather than hanging. */
        r = qmp_client_call(client, "stop", NULL, NULL, NULL);
        ASSERT_TRUE(r < 0);
        ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(r));
}

TEST(qmp_schema_has_member) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        /* QEMU introspection uses opaque numeric type ids ("0", "1", ...) — only member names are
         * the actual QAPI strings. Verify we walk all object entries and find the member by name. */
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

static int intro(void) {
        /* Ignore SIGPIPE so that write() to a closed socket returns EPIPE instead of killing us */
        ASSERT_TRUE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, NULL);
