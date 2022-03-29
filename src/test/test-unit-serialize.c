/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "rm-rf.h"
#include "service.h"
#include "tests.h"

static char *runtime_dir = NULL;

STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

#define EXEC_START_ABSOLUTE \
        "ExecStart 0 /bin/sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""
#define EXEC_START_RELATIVE \
        "ExecStart 0 sh \"sh\" \"-e\" \"-x\" \"-c\" \"systemctl --state=failed --no-legend --no-pager >/failed ; systemctl daemon-reload ; echo OK >/testok\""

static void test_deserialize_exec_command_one(Manager *m, const char *key, const char *line, int expected) {
        _cleanup_(unit_freep) Unit *u = NULL;
        int r;

        assert_se(unit_new_for_name(m, sizeof(Service), "test.service", &u) >= 0);

        r = service_deserialize_exec_command(u, key, line);
        log_debug("[%s] → %d (expected: %d)", line, r, expected);
        assert_se(r == expected);

        /* Note that the command doesn't match any command in the empty list of commands in 's', so it is
         * always rejected with "Current command vanished from the unit file", and we don't leak anything. */
}

TEST(deserialize_exec_command) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        r = manager_new(LOOKUP_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r)) {
                log_notice_errno(r, "Skipping test: manager_new: %m");
                return;
        }

        assert_se(r >= 0);

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

static int intro(void) {
        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
