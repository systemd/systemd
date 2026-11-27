/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "manager.h"
#include "rm-rf.h"
#include "serialize.h"
#include "service.h"
#include "special.h"
#include "string-util.h"
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
        if (manager_errno_skip_test(r))
                return (void) log_notice_errno(r, "Skipping test: manager_new: %m");

        ASSERT_OK(r);

        test_deserialize_exec_command_one(m, "main-command", EXEC_START_ABSOLUTE, /* expected= */ 0);
        test_deserialize_exec_command_one(m, "main-command", EXEC_START_RELATIVE, /* expected= */ 0);
        test_deserialize_exec_command_one(m, "control-command", EXEC_START_ABSOLUTE, /* expected= */ 0);
        test_deserialize_exec_command_one(m, "control-command", EXEC_START_RELATIVE, /* expected= */ 0);

        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /bin/sh \"sh\"", /* expected= */ 0);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /no/command ", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 0 /bad/quote \"", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart s /bad/id x y z", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecStart 11", -EINVAL);
        test_deserialize_exec_command_one(m, "control-command", "ExecWhat 11 /a/b c d e", -EINVAL);
}

TEST(access_selinux_context) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *id = NULL;
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);
        ASSERT_OK(unit_new_for_name(m, sizeof(Service), "label.service", &u));
        ASSERT_NOT_NULL(u->access_selinux_context = strdup("system_u:object_r:old_unit_file_t:s0"));
        ASSERT_NOT_NULL(fds = fdset_new());
        ASSERT_OK(open_serialization_file("test-label", &f));
        ASSERT_OK(unit_serialize_state(u, f, fds, /* switching_root= */ false));
        ASSERT_OK(finish_serialization_file(f));
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &id));
        ASSERT_STREQ(id, u->id);
        fpos_t pos;
        ASSERT_OK_ERRNO(fgetpos(f, &pos));

        u->load_state = UNIT_NOT_FOUND;
        u->access_selinux_context = mfree(u->access_selinux_context);
        ASSERT_OK(unit_deserialize_state(u, f, fds, /* restore_owned_directories= */ true));
        ASSERT_STREQ(u->access_selinux_context, "system_u:object_r:old_unit_file_t:s0");

        ASSERT_OK_ERRNO(fsetpos(f, &pos));
        u->load_state = UNIT_LOADED;
        ASSERT_NOT_NULL(u->fragment_path = strdup("/run/systemd/system/label.service"));
        ASSERT_OK(free_and_strdup(&u->access_selinux_context, "system_u:object_r:new_unit_file_t:s0"));
        ASSERT_OK(unit_deserialize_state(u, f, fds, /* restore_owned_directories= */ true));
        ASSERT_STREQ(u->access_selinux_context, "system_u:object_r:new_unit_file_t:s0");
}

TEST(deserialize_init_scope) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char state[] = "transient=yes\n\n";
        int r;

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(m, /* serialization= */ NULL, /* fds= */ NULL, /* named_listen_fds= */ NULL, /* root= */ NULL));

        Unit *u = ASSERT_PTR(manager_get_unit(m, SPECIAL_INIT_SCOPE));
        ASSERT_NULL(u->fragment_path);
        ASSERT_NOT_NULL(fds = fdset_new());
        ASSERT_NOT_NULL(f = fmemopen_unlocked(state, sizeof(state) - 1, "r"));
        ASSERT_OK(unit_deserialize_state(u, f, fds, /* restore_owned_directories= */ true));
        ASSERT_TRUE(u->transient);

        /* Even a persistent set-property request must write to the transient directory. */
        ASSERT_OK(free_and_strdup(&m->lookup_paths.persistent_control, runtime_dir));
        ASSERT_OK(unit_write_setting(u, UNIT_PERSISTENT, "Description", "Description=Test scope"));
        ASSERT_OK_ERRNO(access(strjoina(m->lookup_paths.transient, "/init.scope.d/50-Description.conf"), F_OK));
}

static int intro(void) {
        if (enter_cgroup_subroot(/* ret_cgroup= */ NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
