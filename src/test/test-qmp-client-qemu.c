/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Integration test for the QMP client library against a real QEMU instance.
 *
 * Launches QEMU with -machine none (no bootable image needed) to get a live QMP monitor, then exercises the
 * client library against it. Validates the blocking handshake, large response buffering (~200KB for
 * query-qmp-schema), response correlation by id, and async command execution.
 *
 * Skipped automatically if QEMU is not installed. */

#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "sd-event.h"
#include "sd-json.h"

#include "fd-util.h"
#include "path-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static int find_qemu(char **ret) {
        int r;

        assert(ret);

        /* Try common QEMU binary names */
        FOREACH_STRING(s, "qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-s390x",
                       "qemu-system-riscv64", "qemu-system-ppc64", "qemu", "qemu-kvm") {
                r = find_executable(s, ret);
                if (r >= 0)
                        return 0;
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

static pid_t start_qemu(const char *qemu_binary, int fd) {
        _cleanup_free_ char *chardev_arg = NULL;
        pid_t pid;

        assert(qemu_binary);
        assert(fd >= 0);

        assert_se(asprintf(&chardev_arg, "socket,id=qmp,fd=%d", fd) >= 0);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                /* Redirect stdout/stderr to /dev/null to keep test output clean */
                int devnull = open("/dev/null", O_WRONLY|O_CLOEXEC);
                if (devnull >= 0) {
                        (void) dup2(devnull, STDOUT_FILENO);
                        (void) dup2(devnull, STDERR_FILENO);
                        safe_close(devnull);
                }

                execl(qemu_binary, qemu_binary,
                      "-machine", "none",
                      "-nographic",
                      "-nodefaults",
                      "-chardev", chardev_arg,
                      "-mon", "chardev=qmp,mode=control",
                      NULL);
                log_error_errno(errno, "Failed to exec %s: %m", qemu_binary);
                _exit(EXIT_FAILURE);
        }

        return pid;
}

/* Test helper: tracks an async QMP command result and signals completion. */
typedef struct {
        sd_json_variant *result;
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
        t->done = true;
}

static void qmp_test_wait(sd_event *event, QmpTestResult *t) {
        assert(event);
        assert(t);

        while (!t->done)
                assert_se(sd_event_run(event, UINT64_MAX) >= 0);
}

static void qmp_test_result_done(QmpTestResult *t) {
        assert(t);

        sd_json_variant_unref(t->result);
        *t = (QmpTestResult) {};
}

TEST(qmp_client_qemu_handshake_and_schema) {
        _cleanup_free_ char *qemu = NULL;
        _cleanup_(qmp_client_freep) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        QmpTestResult t = {};
        int qmp_fds[2];
        pid_t pid;
        int r;

        if (find_qemu(&qemu) < 0) {
                log_tests_skipped("QEMU not found");
                return;
        }
        log_info("Using QEMU: %s", qemu);

        assert_se(sd_event_new(&event) >= 0);
        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds) >= 0);

        /* Clear CLOEXEC on QEMU's end so it survives exec */
        assert_se(fd_cloexec(qmp_fds[1], false) >= 0);

        pid = start_qemu(qemu, qmp_fds[1]);
        qmp_fds[1] = safe_close(qmp_fds[1]);

        /* Blocking handshake against real QEMU */
        r = qmp_client_connect_fd(&client, qmp_fds[0], event);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP handshake failed (QEMU may not support -machine none)");
                (void) kill(pid, SIGKILL);
                (void) waitpid(pid, NULL, 0);
                return;
        }

        r = qmp_client_start_async(client);
        assert_se(r >= 0);

        /* query-qmp-schema returns ~200KB -- validates the buffered reader handles large multi-read()
         * responses correctly */
        r = qmp_client_execute(client, "query-qmp-schema", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        assert_se(t.result);
        assert_se(sd_json_variant_is_array(t.result));
        assert_se(sd_json_variant_elements(t.result) > 0);
        log_info("query-qmp-schema returned %zu entries", sd_json_variant_elements(t.result));
        qmp_test_result_done(&t);

        /* Clean shutdown */
        r = qmp_client_execute(client, "quit", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        assert_se(waitpid(pid, NULL, 0) >= 0);
}

TEST(qmp_client_qemu_query_status) {
        _cleanup_free_ char *qemu = NULL;
        _cleanup_(qmp_client_freep) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        QmpTestResult t = {};
        sd_json_variant *running, *status;
        int qmp_fds[2];
        pid_t pid;
        int r;

        if (find_qemu(&qemu) < 0) {
                log_tests_skipped("QEMU not found");
                return;
        }

        assert_se(sd_event_new(&event) >= 0);
        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds) >= 0);
        assert_se(fd_cloexec(qmp_fds[1], false) >= 0);

        pid = start_qemu(qemu, qmp_fds[1]);
        qmp_fds[1] = safe_close(qmp_fds[1]);

        r = qmp_client_connect_fd(&client, qmp_fds[0], event);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP handshake failed");
                (void) kill(pid, SIGKILL);
                (void) waitpid(pid, NULL, 0);
                return;
        }

        r = qmp_client_start_async(client);
        assert_se(r >= 0);

        /* query-status validates response parsing against real QEMU output format */
        r = qmp_client_execute(client, "query-status", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        assert_se(t.result);

        status = sd_json_variant_by_key(t.result, "status");
        assert_se(status);
        assert_se(sd_json_variant_is_string(status));

        running = sd_json_variant_by_key(t.result, "running");
        assert_se(running);
        assert_se(sd_json_variant_is_boolean(running));

        log_info("QEMU status: %s, running: %s",
                 sd_json_variant_string(status),
                 true_false(sd_json_variant_boolean(running)));

        qmp_test_result_done(&t);

        /* Test stop + cont to exercise command sequencing and id correlation */
        r = qmp_client_execute(client, "stop", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        /* Verify status changed */
        r = qmp_client_execute(client, "query-status", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        assert_se(t.result);

        running = sd_json_variant_by_key(t.result, "running");
        assert_se(running);
        assert_se(sd_json_variant_boolean(running) == false);
        log_info("After stop: running=%s", true_false(sd_json_variant_boolean(running)));

        qmp_test_result_done(&t);

        r = qmp_client_execute(client, "cont", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        /* Clean shutdown */
        r = qmp_client_execute(client, "quit", NULL, on_test_result, &t);
        assert_se(r >= 0);
        qmp_test_wait(event, &t);
        assert_se(t.error == 0);
        qmp_test_result_done(&t);

        assert_se(waitpid(pid, NULL, 0) >= 0);
}

static int intro(void) {
        assert_se(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, NULL);
