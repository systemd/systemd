/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-restrict-fs.h"
#include "load-fragment.h"
#include "manager.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "service.h"
#include "strv.h"
#include "tests.h"
#include "unit.h"
#include "virt.h"

static int test_restrict_filesystems(Manager *m, const char *unit_name, const char *file_path, char **allowed_filesystems) {
        _cleanup_free_ char *exec_start = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        ExecContext *ec = NULL;
        int cld_code, r;

        ASSERT_NOT_NULL(u = unit_new(m, sizeof(Service)));
        ASSERT_OK_ZERO(unit_add_name(u, unit_name));
        ASSERT_NOT_NULL(ec = unit_get_exec_context(u));

        STRV_FOREACH(allow_filesystem, allowed_filesystems) {
                r = config_parse_restrict_filesystems(
                                u->id, "filename", 1, "Service", 1, "RestrictFileSystems", 0,
                                *allow_filesystem, ec, u);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to parse RestrictFileSystems: %m");
        }

        ASSERT_NOT_NULL(exec_start = strjoin("cat ", file_path));
        r = config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart",
                        SERVICE_EXEC_START, exec_start, SERVICE(u)->exec_command, u);
        if (r < 0)
                return log_error_errno(r, "Failed to parse ExecStart");

        SERVICE(u)->type = SERVICE_ONESHOT;
        u->load_state = UNIT_LOADED;

        r = unit_start(u, NULL);
        if (r < 0)
                return log_error_errno(r, "Unit start failed %m");

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED)) {
                r = sd_event_run(m->event, UINT64_MAX);
                if (r < 0)
                        return log_error_errno(r, "Event run failed %m");
        }

        cld_code = SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code;
        if (cld_code != CLD_EXITED)
                return log_error_errno(-SYNTHETIC_ERRNO(EBUSY), "ExecStart didn't exited, code='%s'", sigchld_code_to_string(cld_code));

        if (SERVICE(u)->state != SERVICE_DEAD)
                return log_error_errno(-SYNTHETIC_ERRNO(EBUSY), "Service is not dead");

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *unit_dir = NULL;
        struct rlimit rl;
        int r;

        test_setup_logging(LOG_DEBUG);

        ASSERT_OK(getrlimit(RLIMIT_MEMLOCK, &rl));
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit_closest(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock()");

        if (!bpf_restrict_fs_supported(/* initialize = */ true))
                return log_tests_skipped("LSM BPF hooks are not supported");

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        ASSERT_OK(get_testdata_dir("units", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        ASSERT_OK(manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_BASIC, &m));
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL));

        /* We need to enable access to the filesystem where the binary is so we
         * add @common-block and @application */
        ASSERT_FAIL(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/tracing/printk_formats", STRV_MAKE("@common-block", "@application")));
        ASSERT_OK(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/tracing/printk_formats", STRV_MAKE("tracefs", "@common-block", "@application")));
        ASSERT_FAIL(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/tracing/printk_formats", STRV_MAKE("tracefs", "@common-block", "@application", "~tracefs")));
        ASSERT_FAIL(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/debug/sleep_time", STRV_MAKE("@common-block", "@application")));
        ASSERT_OK(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/debug/sleep_time", STRV_MAKE("debugfs", "@common-block", "@application")));
        ASSERT_FAIL(test_restrict_filesystems(m, "restrict_filesystems_test.service", "/sys/kernel/debug/sleep_time", STRV_MAKE("~debugfs")));

        return 0;
}
