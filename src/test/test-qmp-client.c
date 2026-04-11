/* SPDX-License-Identifier: LGPL-2.1-or-later */

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

        buf = new(char, 4096);
        ASSERT_NOT_NULL(buf);

        ssize_t n = read(fd, buf, 4095);
        ASSERT_GT(n, (ssize_t) 0);
        buf[n] = '\0';

        ASSERT_OK(sd_json_parse(buf, 0, &cmd, NULL, NULL));

        sd_json_variant *execute = sd_json_variant_by_key(cmd, "execute");
        ASSERT_NOT_NULL(execute);
        ASSERT_STREQ(sd_json_variant_string(execute), expected_command);

        sd_json_variant *id = sd_json_variant_by_key(cmd, "id");
        ASSERT_NOT_NULL(id);

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
        r = qmp_client_connect_fd(&client, qmp_fds[0]);
        ASSERT_OK(r);
        r = qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL);
        ASSERT_OK(r);

        /* Set event callback to catch STOP event during cont */
        bool event_received = false;
        qmp_client_set_userdata(client, &event_received);
        qmp_client_bind_event(client, test_event_callback);

        /* Execute query-status */
        r = qmp_client_invoke(client, "query-status", NULL, on_test_result, &t);
        ASSERT_OK(r);
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        running = sd_json_variant_by_key(t.result, "running");
        ASSERT_NOT_NULL(running);
        ASSERT_TRUE(sd_json_variant_boolean(running));

        status = sd_json_variant_by_key(t.result, "status");
        ASSERT_NOT_NULL(status);
        ASSERT_STREQ(sd_json_variant_string(status), "running");

        qmp_test_result_done(&t);

        /* Execute stop */
        r = qmp_client_invoke(client, "stop", NULL, on_test_result, &t);
        ASSERT_OK(r);
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Execute cont -- the STOP event should be dispatched by the IO callback */
        r = qmp_client_invoke(client, "cont", NULL, on_test_result, &t);
        ASSERT_OK(r);
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

        r = qmp_client_connect_fd(&client, qmp_fds[0]);
        ASSERT_OK(r);
        r = qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL);
        ASSERT_OK(r);

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

static int intro(void) {
        /* Ignore SIGPIPE so that write() to a closed socket returns EPIPE instead of killing us */
        ASSERT_TRUE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, NULL);
