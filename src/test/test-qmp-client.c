/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "sd-event.h"
#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "tests.h"

/* Mock QMP server: runs in the child process of a fork, communicates via one end of a socketpair. */

static void mock_qmp_write_json(int fd, sd_json_variant *v) {
        _cleanup_free_ char *s = NULL;

        assert_se(sd_json_variant_format(v, 0, &s) >= 0);
        assert_se(strextend(&s, "\r\n"));
        assert_se(loop_write(fd, s, SIZE_MAX) >= 0);
}

static void mock_qmp_write_literal(int fd, const char *msg) {
        assert_se(loop_write(fd, msg, SIZE_MAX) >= 0);
        assert_se(loop_write(fd, "\r\n", 2) >= 0);
}

/* Read a command from the QMP client, verify it contains the expected command name, extract the id,
 * and send a reply with that id. If reply_data is NULL, an empty return object is sent. */
static void mock_qmp_expect_and_reply(int fd, const char *expected_command, sd_json_variant *reply_data) {
        _cleanup_free_ char *buf = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *reply_obj = NULL, *response = NULL;

        buf = new(char, 4096);
        assert_se(buf);

        ssize_t n = read(fd, buf, 4095);
        assert_se(n > 0);
        buf[n] = '\0';

        assert_se(sd_json_parse(buf, 0, &cmd, NULL, NULL) >= 0);

        sd_json_variant *execute = sd_json_variant_by_key(cmd, "execute");
        assert_se(execute);
        assert_se(streq(sd_json_variant_string(execute), expected_command));

        sd_json_variant *id = sd_json_variant_by_key(cmd, "id");
        assert_se(id);

        if (!reply_data)
                assert_se(sd_json_variant_new_object(&reply_obj, NULL, 0) >= 0);

        assert_se(sd_json_buildo(
                        &response,
                        SD_JSON_BUILD_PAIR("return", SD_JSON_BUILD_VARIANT(reply_data ?: reply_obj)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_VARIANT(id))) >= 0);

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
        assert_se(sd_json_buildo(
                        &status_return,
                        SD_JSON_BUILD_PAIR_BOOLEAN("running", true),
                        SD_JSON_BUILD_PAIR_STRING("status", "running")) >= 0);
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
        char *error_class;
        int error;
        bool done;
} QmpTestResult;

static void on_test_result(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata) {

        QmpTestResult *t = ASSERT_PTR(userdata);

        t->error = error;
        if (result)
                t->result = sd_json_variant_ref(result);
        if (error_class)
                t->error_class = strdup(error_class);
        t->done = true;
}

/* Run the event loop until the test result callback fires. */
static void qmp_test_wait(sd_event *event, QmpTestResult *t) {
        assert(event);
        assert(t);

        while (!t->done)
                assert_se(sd_event_run(event, UINT64_MAX) >= 0);
}

static void qmp_test_result_done(QmpTestResult *t) {
        assert(t);

        sd_json_variant_unref(t->result);
        free(t->error_class);
        *t = (QmpTestResult) {};
}

static bool event_received = false;

static void test_event_callback(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                uint64_t timestamp_seconds,
                uint64_t timestamp_microseconds,
                void *userdata) {

        /* We may also receive a synthetic SHUTDOWN event when the mock server closes the connection;
         * only validate the STOP event we actually care about. */
        if (!streq(event, "STOP"))
                return;

        assert_se(timestamp_seconds == 1234);
        assert_se(timestamp_microseconds == 5678);
        event_received = true;
}

TEST(qmp_client_basic) {
        _cleanup_(qmp_client_freep) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        QmpTestResult t = {};
        sd_json_variant *running, *status;
        int qmp_fds[2];
        int r;

        assert_se(sd_event_new(&event) >= 0);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds) >= 0);

        pid_t pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                safe_close(qmp_fds[0]);
                mock_qmp_server(qmp_fds[1]);
                _exit(EXIT_SUCCESS);
        }

        safe_close(qmp_fds[1]);

        /* Connect (blocking handshake) */
        r = qmp_client_connect_fd(&client, qmp_fds[0], event);
        assert_se(r >= 0);

        /* Set event callback to catch STOP event during cont */
        qmp_client_set_event_callback(client, test_event_callback, NULL);

        /* Execute query-status */
        r = qmp_client_execute(client, "query-status", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        assert_se(t.result);

        running = sd_json_variant_by_key(t.result, "running");
        assert_se(running);
        assert_se(sd_json_variant_boolean(running) == true);

        status = sd_json_variant_by_key(t.result, "status");
        assert_se(status);
        assert_se(streq(sd_json_variant_string(status), "running"));

        qmp_test_result_done(&t);

        /* Execute stop */
        r = qmp_client_execute(client, "stop", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        /* Execute cont -- the STOP event should be dispatched by the IO callback */
        r = qmp_client_execute(client, "cont", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        /* Verify the STOP event was received */
        assert_se(event_received);

        /* Wait for child and verify clean exit */
        int wstatus;
        assert_se(waitpid(pid, &wstatus, 0) >= 0);
        assert_se(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == EXIT_SUCCESS);
}

TEST(qmp_client_eof) {
        _cleanup_(qmp_client_freep) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        QmpTestResult t = {};
        int qmp_fds[2];
        int r;

        assert_se(sd_event_new(&event) >= 0);
        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds) >= 0);

        pid_t pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
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

        r = qmp_client_connect_fd(&client, qmp_fds[0], event);
        assert_se(r >= 0);

        /* Executing a command should fail with a disconnect error because the server closed.
         * Either the write fails with EPIPE (immediate), or the async callback gets -ECONNRESET
         * from the disconnect handler. */
        r = qmp_client_execute(client, "query-status", NULL, on_test_result, &t);
        if (r < 0)
                assert_se(ERRNO_IS_NEG_DISCONNECT(r));
        else {
                qmp_test_wait(event, &t);
                assert_se(ERRNO_IS_NEG_DISCONNECT(t.error));
                qmp_test_result_done(&t);
        }

        int wstatus;
        assert_se(waitpid(pid, &wstatus, 0) >= 0);
        assert_se(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == EXIT_SUCCESS);
}

static int intro(void) {
        /* Ignore SIGPIPE so that write() to a closed socket returns EPIPE instead of killing us */
        assert_se(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, NULL);
