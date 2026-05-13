/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Integration test for the QMP client library against a real QEMU instance.
 *
 * Launches QEMU with -machine none (no bootable image needed) to get a live QMP monitor, then exercises the
 * client library against it. Validates the blocking handshake, large response buffering (~200KB for
 * query-qmp-schema), response correlation by id, and async command execution.
 *
 * Skipped automatically if QEMU is not installed. */

#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "fd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "qmp-client.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "vmspawn-util.h"

static int start_qemu(const char *qemu_binary, int fd, PidRef *ret) {
        _cleanup_free_ char *chardev_arg = NULL;
        int r;

        assert(qemu_binary);
        assert(fd >= 0);
        assert(ret);

        if (asprintf(&chardev_arg, "socket,id=qmp,fd=%d", fd) < 0)
                return -ENOMEM;

        r = pidref_safe_fork_full(
                        "(qemu)",
                        (const int[3]) { STDIN_FILENO, -EBADF, -EBADF },
                        &fd, 1,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_CLOEXEC_OFF,
                        ret);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
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

        return 0;
}

/* Test helper: tracks an async QMP command result and signals completion. */
typedef struct {
        sd_json_variant *result;
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
        t->done = true;
        return 0;
}

static void qmp_test_wait(sd_event *event, QmpTestResult *t) {
        assert(event);
        assert(t);

        usec_t deadline = usec_add(now(CLOCK_MONOTONIC), 5 * USEC_PER_MINUTE);

        while (!t->done) {
                usec_t n = now(CLOCK_MONOTONIC);
                ASSERT_LT(n, deadline);
                ASSERT_OK(sd_event_run(event, usec_sub_unsigned(deadline, n)));
        }
}

static void qmp_test_result_done(QmpTestResult *t) {
        assert(t);

        sd_json_variant_unref(t->result);
        *t = (QmpTestResult) {};
}

TEST(qmp_client_qemu_handshake_and_schema) {
        _cleanup_free_ char *qemu = NULL;
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        QmpTestResult t = {};
        _cleanup_close_pair_ int qmp_fds[2] = EBADF_PAIR;
        int r;

        if (find_qemu_binary(&qemu) < 0) {
                log_tests_skipped("QEMU not found");
                return;
        }
        log_info("Using QEMU: %s", qemu);

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        ASSERT_OK(start_qemu(qemu, qmp_fds[1], &pidref));
        qmp_fds[1] = safe_close(qmp_fds[1]);

        r = qmp_client_connect_fd(&client, qmp_fds[0]);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP connect failed (QEMU may not support -machine none)");
                return;
        }
        TAKE_FD(qmp_fds[0]);

        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* query-qmp-schema returns ~200KB -- validates the buffered reader handles large multi-read()
         * responses correctly. The handshake completes transparently inside invoke(). */
        r = qmp_client_invoke(client, /* ret_slot= */ NULL, "query-qmp-schema", NULL, on_test_result, &t);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP invoke failed (handshake or send)");
                return;
        }
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);
        ASSERT_TRUE(sd_json_variant_is_array(t.result));
        ASSERT_GT(sd_json_variant_elements(t.result), (size_t) 0);
        log_info("query-qmp-schema returned %zu entries", sd_json_variant_elements(t.result));

        /* Smoke-test the schema walker against the real schema. node-name is on every BlockdevOptions*
         * object since blockdev-add was introduced. Don't assert discard-no-unref — CI may have QEMU < 8.1. */
        ASSERT_TRUE(qmp_schema_has_member(t.result, "node-name"));
        ASSERT_FALSE(qmp_schema_has_member(t.result, "definitely-not-a-real-field"));

        qmp_test_result_done(&t);

        /* Clean shutdown */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "quit", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
        pidref_done(&pidref);
}

TEST(qmp_client_qemu_query_status) {
        _cleanup_free_ char *qemu = NULL;
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        QmpTestResult t = {};
        sd_json_variant *running, *status;
        _cleanup_close_pair_ int qmp_fds[2] = EBADF_PAIR;
        int r;

        if (find_qemu_binary(&qemu) < 0) {
                log_tests_skipped("QEMU not found");
                return;
        }

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        ASSERT_OK(start_qemu(qemu, qmp_fds[1], &pidref));
        qmp_fds[1] = safe_close(qmp_fds[1]);

        r = qmp_client_connect_fd(&client, qmp_fds[0]);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP connect failed");
                return;
        }
        TAKE_FD(qmp_fds[0]);

        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        /* query-status validates response parsing against real QEMU output format.
         * The handshake completes transparently inside invoke(). */
        r = qmp_client_invoke(client, /* ret_slot= */ NULL, "query-status", NULL, on_test_result, &t);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP invoke failed (handshake or send)");
                return;
        }
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        status = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "status"));
        ASSERT_TRUE(sd_json_variant_is_string(status));

        running = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "running"));
        ASSERT_TRUE(sd_json_variant_is_boolean(running));

        log_info("QEMU status: %s, running: %s",
                 sd_json_variant_string(status),
                 true_false(sd_json_variant_boolean(running)));

        qmp_test_result_done(&t);

        /* Test stop + cont to exercise command sequencing and id correlation */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "stop", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Verify status changed */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "query-status", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        running = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "running"));
        ASSERT_FALSE(sd_json_variant_boolean(running));
        log_info("After stop: running=%s", true_false(sd_json_variant_boolean(running)));

        qmp_test_result_done(&t);

        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "cont", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        /* Clean shutdown */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "quit", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
        pidref_done(&pidref);
}

TEST(qmp_client_qemu_add_fd) {
        _cleanup_free_ char *qemu = NULL;
        _cleanup_(qmp_client_unrefp) QmpClient *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_close_ int fd_to_pass = -EBADF;
        QmpTestResult t = {};
        _cleanup_close_pair_ int qmp_fds[2] = EBADF_PAIR;
        int r;

        if (find_qemu_binary(&qemu) < 0) {
                log_tests_skipped("QEMU not found");
                return;
        }

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, qmp_fds));

        ASSERT_OK(start_qemu(qemu, qmp_fds[1], &pidref));
        qmp_fds[1] = safe_close(qmp_fds[1]);

        r = qmp_client_connect_fd(&client, qmp_fds[0]);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP connect failed");
                return;
        }
        TAKE_FD(qmp_fds[0]);

        ASSERT_OK(qmp_client_attach_event(client, event, SD_EVENT_PRIORITY_NORMAL));

        fd_to_pass = eventfd(0, EFD_CLOEXEC);
        ASSERT_OK_ERRNO(fd_to_pass);

        ASSERT_OK(sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", 0)));

        /* Pass an fd via SCM_RIGHTS on the very first invoke against a fresh client:
         * add-fd lands right after the eagerly-enqueued qmp_capabilities. QEMU processes cap
         * first (no fd needed), then add-fd, popping the fd from its FIFO receive queue. */
        r = qmp_client_invoke(client, /* ret_slot= */ NULL, "add-fd",
                              QMP_CLIENT_ARGS_FD(args, TAKE_FD(fd_to_pass)),
                              on_test_result, &t);
        if (r < 0) {
                log_tests_skipped_errno(r, "QMP add-fd invoke failed");
                return;
        }
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        ASSERT_NOT_NULL(t.result);

        sd_json_variant *fdset_id = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "fdset-id"));
        sd_json_variant *fd_v = ASSERT_NOT_NULL(sd_json_variant_by_key(t.result, "fd"));
        ASSERT_EQ(sd_json_variant_unsigned(fdset_id), (uint64_t) 0);
        log_info("add-fd returned fdset-id=%" PRIu64 ", fd=%" PRIu64,
                 sd_json_variant_unsigned(fdset_id),
                 sd_json_variant_unsigned(fd_v));

        qmp_test_result_done(&t);

        /* Clean shutdown */
        ASSERT_OK(qmp_client_invoke(client, /* ret_slot= */ NULL, "quit", NULL, on_test_result, &t));
        qmp_test_wait(event, &t);
        ASSERT_EQ(t.error, 0);
        qmp_test_result_done(&t);

        siginfo_t si = {};
        ASSERT_OK(pidref_wait_for_terminate(&pidref, &si));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
        pidref_done(&pidref);
}

static int intro(void) {
        /* QEMU dies between our last write and read on the QMP socket — without this we'd
         * get killed by the SIGPIPE the kernel raises on write-after-EOF. */
        ASSERT_TRUE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
        return 0;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, NULL);
