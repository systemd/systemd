/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "pidref.h"
#include "process-util.h"
#include "qmp-client.h"
#include "socket-util.h"
#include "string-util.h"
#include "tests.h"

/* Mock QMP server: runs in the child process of a fork, communicates via one end of a socketpair. */

static void mock_qmp_write_json(int fd, sd_json_variant *v) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(sd_json_variant_format(v, 0, &s));
        ASSERT_NOT_NULL(strextend(&s, "\r\n"));
        ASSERT_OK(loop_write(fd, s, SIZE_MAX));
}

static void mock_qmp_write_literal(int fd, const char *msg) {
        ASSERT_OK(loop_write(fd, msg, SIZE_MAX));
        ASSERT_OK(loop_write(fd, "\r\n", 2));
}

/* Read a command from the QMP client, verify it contains the expected command name, extract the id,
 * and send a reply with that id. If reply_data is NULL, an empty return object is sent. */
static void mock_qmp_expect_and_reply(int fd, const char *expected_command, sd_json_variant *reply_data) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *reply_obj = NULL, *response = NULL;

        buf = ASSERT_NOT_NULL(new(char, 4096));

        ssize_t n = read(fd, buf, 4095);
        assert_se(n > 0);
        buf[n] = '\0';

        ASSERT_OK(sd_json_parse(buf, 0, &cmd, NULL, NULL));

        sd_json_variant *execute = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "execute"));
        ASSERT_STREQ(sd_json_variant_string(execute), expected_command);

        sd_json_variant *id = ASSERT_NOT_NULL(sd_json_variant_by_key(cmd, "id"));

        if (!reply_data)
                ASSERT_OK(sd_json_variant_new_object(&reply_obj, NULL, 0));

        ASSERT_OK(sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(reply_data ?: reply_obj)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))));

        mock_qmp_write_json(fd, response);
}

static _noreturn_ void mock_qmp_server(int fd) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *status_return = NULL;

        /* Send QMP greeting */
        mock_qmp_write_literal(fd,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 2, \"major\": 9}}, \"capabilities\": [\"oob\"]}}");

        /* Accept qmp_capabilities */
        mock_qmp_expect_and_reply(fd, "qmp_capabilities", NULL);

        /* Accept query-status, reply with running state */
        ASSERT_OK(sd_json_buildo(
                        &status_return,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                        SD_JSON_BUILD_PAIR_STRING("status", "running")));
        mock_qmp_expect_and_reply(fd, "query-status", status_return);

        /* Accept stop */
        mock_qmp_expect_and_reply(fd, "stop", NULL);

        /* Send a STOP event */
        mock_qmp_write_literal(fd,
                "{\"event\": \"STOP\", \"timestamp\": {\"seconds\": 1234, \"microseconds\": 5678}}");

        /* Accept cont */
        mock_qmp_expect_and_reply(fd, "cont", NULL);

        /* Close to trigger EOF */
        safe_close(fd);
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

        r = pidref_safe_fork("(mock-qmp)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid);
        ASSERT_OK(r);

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
        ASSERT_OK(qmp_client_invoke(client, "query-status", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        running = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "running"));
        ASSERT_TRUE(sd_json_variant_boolean(running));

        status = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "status"));
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        qmp_test_result_done(&t);

        /* Execute stop */
        ASSERT_OK(qmp_client_invoke(client, "stop", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Execute cont -- the STOP event should be dispatched by the IO callback */
        ASSERT_OK(qmp_client_invoke(client, "cont", NULL, on_test_result, &t));
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

        r = pidref_safe_fork("(mock-qmp-eof)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid);
        ASSERT_OK(r);

        if (r == 0) {
                safe_close(qmp_fds[0]);

                /* Send greeting and accept capabilities, then die */
                mock_qmp_write_literal(qmp_fds[1],
                        "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

                mock_qmp_expect_and_reply(qmp_fds[1], "qmp_capabilities", NULL);

                /* Close immediately to trigger EOF */
                safe_close(qmp_fds[1]);
                _exit(EXIT_SUCCESS);
        }

        safe_close(qmp_fds[1]);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* Executing a command should fail with a disconnect error because the server
         * closed. The handshake may succeed or fail inside invoke() — either way the
         * invoke itself or the async callback should report a disconnect. */
        r = qmp_client_invoke(client, "query-status", NULL, on_test_result, &t);
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

/* Read one QMP command from fd (one recvmsg, expecting it fits in the buffer for typical
 * test commands). Returns the number of SCM_RIGHTS fds that arrived attached to the read,
 * stores the first received fd in *ret_received_fd (or -EBADF if none) and closes any extras,
 * and parses the JSON into *ret_cmd. */
static size_t mock_qmp_recv_command(int fd, sd_json_variant **ret_cmd, int *ret_received_fd) {
        char buf[4096];
        char ctrl[CMSG_SPACE(sizeof(int) * 4)];
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) - 1 };
        struct msghdr mh = {
                .msg_iov = &iov, .msg_iovlen = 1,
                .msg_control = ctrl, .msg_controllen = sizeof(ctrl),
        };
        size_t n_fds = 0;
        int received_fd = -EBADF;

        ssize_t n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC);
        assert_se(n > 0);
        buf[n] = '\0';

        struct cmsghdr *cmsg;
        CMSG_FOREACH(cmsg, &mh) {
                if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
                        continue;
                size_t k = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                int *fds = (int*) CMSG_DATA(cmsg);
                for (size_t i = 0; i < k; i++) {
                        if (received_fd < 0)
                                received_fd = fds[i];
                        else
                                safe_close(fds[i]);
                }
                n_fds += k;
        }

        ASSERT_OK(sd_json_parse(buf, 0, ret_cmd, NULL, NULL));

        if (ret_received_fd)
                *ret_received_fd = received_fd;
        else if (received_fd >= 0)
                safe_close(received_fd);

        return n_fds;
}

/* Mock QMP server for the fd-on-first-invoke regression. Drives the wire dance:
 *   greeting → (recv qmp_capabilities, expect 0 fds) → reply →
 *   (recv add-fd, expect exactly 1 fd) → reply
 * Asserts the cmsg fd counts directly so a regression flips the child to
 * exit_failure and the parent test fails on the wait-for-terminate. */
static _noreturn_ void mock_qmp_server_fd_first(int fd) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cap_cmd = NULL,
                                                          *addfd_cmd = NULL,
                                                          *cap_reply = NULL,
                                                          *addfd_return = NULL,
                                                          *addfd_reply = NULL;
        size_t n_fds;
        int received_fd = -EBADF;

        /* Greeting */
        mock_qmp_write_literal(fd,
                "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 0, \"minor\": 0, \"major\": 9}}, \"capabilities\": []}}");

        /* Receive qmp_capabilities — must arrive with NO fds attached. */
        n_fds = mock_qmp_recv_command(fd, &cap_cmd, /* ret_received_fd= */ NULL);
        ASSERT_EQ(n_fds, (size_t) 0);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(cap_cmd, "execute")), "qmp_capabilities");

        sd_json_variant *cap_id = ASSERT_NOT_NULL(sd_json_variant_by_key(cap_cmd, "id"));
        ASSERT_OK(sd_json_buildo(
                        &cap_reply,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_EMPTY_OBJECT),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(cap_id))));
        mock_qmp_write_json(fd, cap_reply);

        /* Receive add-fd — must arrive with EXACTLY ONE fd attached. */
        n_fds = mock_qmp_recv_command(fd, &addfd_cmd, &received_fd);
        ASSERT_EQ(n_fds, (size_t) 1);
        ASSERT_TRUE(received_fd >= 0);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(addfd_cmd, "execute")), "add-fd");
        safe_close(received_fd);

        sd_json_variant *addfd_id = ASSERT_NOT_NULL(sd_json_variant_by_key(addfd_cmd, "id"));
        ASSERT_OK(sd_json_buildo(
                        &addfd_return,
                        SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0),
                        SD_JSON_BUILD_PAIR_UNSIGNED("fd", 42)));
        ASSERT_OK(sd_json_buildo(
                        &addfd_reply,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(addfd_return)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(addfd_id))));
        mock_qmp_write_json(fd, addfd_reply);

        safe_close(fd);
        _exit(EXIT_SUCCESS);
}

/* Regression: pass an fd in the very first qmp_client_invoke() against a fresh client
 * (lazy-bootstrap state, handshake not yet done). The previous push_fd+invoke split would
 * stage the fd on the stream BEFORE qmp_client_ensure_running() drove the handshake; the
 * handshake's qmp_capabilities enqueue would then steal the staged fd onto its own
 * sendmsg. The new QmpClientArgs API stages fds inside invoke AFTER ensure_running, so
 * the fd lands on add-fd's sendmsg as it should. */
TEST(qmp_client_first_invoke_with_fd) {
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

        r = pidref_safe_fork("(mock-qmp-fd-first)", FORK_DEATHSIG_SIGKILL|FORK_LOG, &pid);
        ASSERT_OK(r);

        if (r == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server_fd_first(qmp_fds[1]);
        }

        safe_close(qmp_fds[1]);

        /* Open a real fd to pass — /dev/null is universally available. */
        fd_to_pass = open("/dev/null", O_RDWR|O_CLOEXEC);
        ASSERT_OK(fd_to_pass);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* Build add-fd args. The fdset-id value is irrelevant — the mock server only
         * cares that the fd arrived with the correct sendmsg. */
        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));

        /* THIS is the previously-broken pattern: very first invoke against the client,
         * carrying an fd, with the handshake still pending. */
        ASSERT_OK(qmp_client_invoke(client, "add-fd",
                                    QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                    on_test_result, &t));

        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);
        qmp_test_result_done(&t);

        /* Wait for the mock server child. If it received fds in the wrong order it
         * exited via the test-assertion failure path and si.si_status will be non-zero. */
        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pid, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
}

/* Regression: when qmp_client_invoke() fails before stage_fds runs (e.g.
 * ensure_running() returns -ENOTCONN because the peer closed mid-handshake), the
 * caller-supplied fds — already TAKE_FD()'d through QMP_CLIENT_ARGS_FD() — must be
 * closed inside invoke. Otherwise they leak. */
TEST(qmp_client_invoke_failure_closes_fds) {
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        QmpTestResult t = {};
        int qmp_fds[2];
        int saved_fd_value;

        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        /* Close the peer end immediately so ensure_running()'s read sees EOF and
         * the client transitions straight to DISCONNECTED inside the first invoke. */
        safe_close(qmp_fds[1]);

        ASSERT_OK(qmp_client_connect_fd(&client, qmp_fds[0]));
        /* Deliberately do NOT attach to an event loop — invoke uses ensure_running()'s
         * synchronous process+wait pump for the handshake. */

        fd_to_pass = open("/dev/null", O_RDWR|O_CLOEXEC);
        ASSERT_OK(fd_to_pass);
        saved_fd_value = fd_to_pass;   /* remember the int value for the closed-check */

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));

        /* invoke must fail because the peer is gone. The TAKE_FD inside the macro
         * has already zeroed our local fd_to_pass; if invoke leaked the fd here,
         * the fd would stay open in our process. */
        int r = qmp_client_invoke(client, "add-fd",
                                  QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                                  on_test_result, &t);
        ASSERT_TRUE(r < 0);
        ASSERT_TRUE(ERRNO_IS_NEG_DISCONNECT(r));

        /* fd_to_pass should now be -EBADF (TAKE_FD'd) and the underlying kernel fd
         * should have been closed by the qmp_client_args_close_fds cleanup in
         * qmp_client_invoke(). fcntl on the old int returns EBADF only if the slot
         * is genuinely free. */
        ASSERT_EQ(fd_to_pass, -EBADF);
        ASSERT_EQ(fcntl(saved_fd_value, F_GETFD), -1);
        ASSERT_EQ(errno, EBADF);
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
