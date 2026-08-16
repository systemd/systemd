/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "manager.h"
#include "process-util.h"
#include "rm-rf.h"
#include "service.h"
#include "set.h"
#include "tests.h"
#include "unit-serialize.h"

static char *runtime_dir = NULL;

STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

#define EXEC_START_ABSOLUTE \
        "ExecStart 0 /bin/sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""
#define EXEC_START_RELATIVE \
        "ExecStart 0 sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""

static void test_deserialize_exec_command_one(Manager *m, const char *key, const char *line, int expected) {
        _cleanup_(unit_freep) Unit *u = NULL;
        int r;

        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "test.service", &u));

        r = service_deserialize_exec_command(u, key, line);
        log_debug("[%s] → %d (expected: %d)", line, r, expected);
        ASSERT_EQ(r, expected);

        /* Note that the command doesn't match any command in the empty list of commands in 's', so it is
         * always rejected with "Current command vanished from the unit file", and we don't leak anything. */
}

TEST(deserialize_exec_command) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        ASSERT_OK(r);

        test_deserialize_exec_command_one(m, "main-command", EXEC_START_ABSOLUTE, 0);
        test_deserialize_exec_command_one(m, "main-command", EXEC_START_RELATIVE, 0);
        test_deserialize_exec_command_one(m, "control-command", EXEC_START_ABSOLUTE, 0);
        test_deserialize_exec_command_one(m, "control-command", EXEC_START_RELATIVE, 0);

        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /bin/sh \"sh\"", 0);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /no/command ", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /bad/quote \"", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart s /bad/id x y z", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 11", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecWhat 11 /a/b c d e", -EINVAL);
}

TEST(retired_coredump) {
        _cleanup_(pidref_done_sigkill_wait) PidRef retired = PIDREF_NULL, suppressed = PIDREF_NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *source = NULL, *destination = NULL;
        _cleanup_(fdset_freep) FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *marker = NULL;
        sd_id128_t invocation_id, replacement_invocation_id;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }
        ASSERT_OK(r);

        ASSERT_OK_POSITIVE(pidref_safe_fork("(retired-coredump)", FORK_FREEZE, &retired));
        ASSERT_OK_POSITIVE(pidref_safe_fork("(suppressed-coredump)", FORK_FREEZE, &suppressed));

        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "source.service", &source));
        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "destination.service", &destination));

        Service *s = SERVICE(source);
        ASSERT_OK(pidref_copy(&retired, &s->retired_coredump.pidref));
        ASSERT_OK(sd_id128_randomize(&invocation_id));
        s->retired_coredump.invocation_id = invocation_id;
        exec_status_start(&s->retired_coredump.exec_status, retired.pid, /* start_timestamp= */ NULL);
        exec_status_exit(
                        &s->retired_coredump.exec_status,
                        &s->exec_context,
                        retired.pid,
                        CLD_DUMPED,
                        SIGSEGV);
        s->retired_coredump.exec_status.start_timestamp = (dual_timestamp) {
                .realtime = 11,
                .monotonic = 12,
        };
        s->retired_coredump.exec_status.exit_timestamp = (dual_timestamp) {
                .realtime = 21,
                .monotonic = 22,
        };
        s->retired_coredump.exec_status.handoff_timestamp = (dual_timestamp) {
                .realtime = 31,
                .monotonic = 32,
        };
        ASSERT_OK(pidref_copy(&suppressed, &s->coredump_suppressed_pid));

        ASSERT_OK(unit_watch_pidref(source, &s->retired_coredump.pidref, /* exclusive= */ false));
        ASSERT_OK(unit_watch_pidref(source, &s->coredump_suppressed_pid, /* exclusive= */ false));

        ASSERT_NOT_NULL(f = tmpfile());
        ASSERT_NOT_NULL(fds = fdset_new());
        ASSERT_OK(unit_serialize_state(source, f, fds, /* switching_root= */ false));
        rewind(f);

        ASSERT_OK_POSITIVE(read_line(f, LINE_MAX, &marker));
        ASSERT_STREQ(marker, source->id);
        ASSERT_OK(unit_deserialize_state(destination, f, fds));

        Service *d = SERVICE(destination);
        ASSERT_TRUE(pidref_equal(&d->retired_coredump.pidref, &retired));
        ASSERT_TRUE(sd_id128_equal(d->retired_coredump.invocation_id, invocation_id));
        ASSERT_EQ(d->retired_coredump.exec_status.pid, retired.pid);
        ASSERT_EQ(d->retired_coredump.exec_status.code, CLD_DUMPED);
        ASSERT_EQ(d->retired_coredump.exec_status.status, SIGSEGV);
        ASSERT_EQ(d->retired_coredump.exec_status.start_timestamp.realtime, UINT64_C(11));
        ASSERT_EQ(d->retired_coredump.exec_status.start_timestamp.monotonic, UINT64_C(12));
        ASSERT_EQ(d->retired_coredump.exec_status.exit_timestamp.realtime, UINT64_C(21));
        ASSERT_EQ(d->retired_coredump.exec_status.exit_timestamp.monotonic, UINT64_C(22));
        ASSERT_EQ(d->retired_coredump.exec_status.handoff_timestamp.realtime, UINT64_C(31));
        ASSERT_EQ(d->retired_coredump.exec_status.handoff_timestamp.monotonic, UINT64_C(32));
        ASSERT_TRUE(pidref_equal(&d->coredump_suppressed_pid, &suppressed));

        ASSERT_OK(service_vtable.coldplug(destination));
        ASSERT_TRUE(set_contains(destination->pids, &d->retired_coredump.pidref));
        ASSERT_TRUE(set_contains(destination->pids, &d->coredump_suppressed_pid));
        ASSERT_FALSE(service_vtable.may_gc(destination));

        ASSERT_OK(pidref_copy(&suppressed, &d->main_pid));
        d->main_pid_known = true;
        d->state = SERVICE_RUNNING;
        d->result = SERVICE_FAILURE_PROTOCOL;
        d->n_restarts = 7;
        exec_status_start(&d->main_exec_status, suppressed.pid, /* start_timestamp= */ NULL);
        ASSERT_OK(sd_id128_randomize(&replacement_invocation_id));
        destination->invocation_id = replacement_invocation_id;

        unit_unwatch_pidref(destination, &d->retired_coredump.pidref);
        service_vtable.sigchld_event(destination, retired.pid, CLD_DUMPED, SIGSEGV);
        ASSERT_FALSE(pidref_is_set(&d->retired_coredump.pidref));
        ASSERT_TRUE(pidref_is_set(&d->coredump_suppressed_pid));
        ASSERT_TRUE(pidref_equal(&d->main_pid, &suppressed));
        ASSERT_EQ(d->main_exec_status.pid, suppressed.pid);
        ASSERT_EQ(d->state, SERVICE_RUNNING);
        ASSERT_EQ(d->result, SERVICE_FAILURE_PROTOCOL);
        ASSERT_EQ(d->n_restarts, 7U);
        ASSERT_TRUE(sd_id128_equal(destination->invocation_id, replacement_invocation_id));
}

static int intro(void) {
        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
