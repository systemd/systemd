/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>
#include <gnu/libc-version.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "sd-event.h"

#include "argv-util.h"
#include "build-path.h"
#include "capability-util.h"
#include "copy.h"
#include "cpu-set-util.h"
#include "dropin.h"
#include "errno-list.h"
#include "event-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "libmount-util.h"
#include "manager.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "process-util.h"
#include "rm-rf.h"
#include "seccomp-util.h"
#include "service.h"
#include "signal-util.h"
#include "stat-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "sysctl-util.h"
#include "tests.h"
#include "unit.h"
#include "user-util.h"
#include "virt.h"

#define PRIVATE_UNIT_DIR "/run/test-execute-unit-dir"

static char *user_runtime_unit_dir = NULL;
static bool can_unshare;
static bool have_net_dummy;
static bool have_netns;
static unsigned n_ran_tests = 0;

STATIC_DESTRUCTOR_REGISTER(user_runtime_unit_dir, freep);

typedef void (*test_function_t)(Manager *m);

static int cld_dumped_to_killed(int code) {
        /* Depending on the system, seccomp version, … some signals might result in dumping, others in plain
         * killing. Let's ignore the difference here, and map both cases to CLD_KILLED */
        return code == CLD_DUMPED ? CLD_KILLED : code;
}

_noreturn_
static int time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Unit *unit = ASSERT_PTR(userdata);
        int r;

        log_error("Test timeout when testing %s", unit->id);
        r = unit_kill(unit, KILL_ALL, /* subgroup= */ NULL, SIGKILL, SI_USER, /* value= */ 0, /* ret_error= */ NULL);
        if (r < 0)
                log_error_errno(r, "Failed to kill %s, ignoring: %m", unit->id);

        abort();
}

static void wait_for_service_finish(Manager *m, Unit *unit) {
        Service *service = SERVICE(ASSERT_PTR(unit));
        usec_t timeout = 2 * USEC_PER_MINUTE;

        ASSERT_NOT_NULL(m);

        /* Bump the timeout when running in plain QEMU, as some more involved tests might start hitting the
         * default 2m timeout (like exec-dynamicuser-statedir.service) */
        if (detect_virtualization() == VIRTUALIZATION_QEMU)
                timeout *= 2;

        printf("%s\n", unit->id);
        exec_context_dump(&service->exec_context, stdout, "\t");

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        ASSERT_OK(sd_event_add_time_relative(m->event, &s, CLOCK_MONOTONIC, timeout, 0, time_handler, unit));

        /* Here, sd_event_loop() cannot be used, as the sd_event object will be reused in the next test case. */
        while (!IN_SET(service->state, SERVICE_DEAD, SERVICE_FAILED))
                ASSERT_OK(sd_event_run(m->event, 100 * USEC_PER_MSEC));
}

static void check_main_result(const char *file, unsigned line, const char *func,
                              Manager *m, Unit *unit, int status_expected, int code_expected) {
        Service *service = NULL;

        ASSERT_NOT_NULL(m);
        ASSERT_NOT_NULL(unit);

        wait_for_service_finish(m, unit);

        service = SERVICE(unit);
        exec_status_dump(&service->main_exec_status, stdout, "\t");

        if (cld_dumped_to_killed(service->main_exec_status.code) != cld_dumped_to_killed(code_expected)) {
                log_error("%s:%u:%s %s: can_unshare=%s: exit code %d, expected %d",
                          file, line, func, unit->id, yes_no(can_unshare),
                          service->main_exec_status.code, code_expected);
                abort();
        }

        if (service->main_exec_status.status != status_expected) {
                log_error("%s:%u:%s: %s: can_unshare=%s: exit status %d, expected %d",
                          file, line, func, unit->id, yes_no(can_unshare),
                          service->main_exec_status.status, status_expected);
                abort();
        }
}

static void check_service_result(const char *file, unsigned line, const char *func,
                                 Manager *m, Unit *unit, ServiceResult result_expected) {
        Service *service = NULL;

        ASSERT_NOT_NULL(m);
        ASSERT_NOT_NULL(unit);

        wait_for_service_finish(m, unit);

        service = SERVICE(unit);

        if (service->result != result_expected) {
                log_error("%s:%u:%s: %s: can_unshare=%s: service end result %s, expected %s",
                          file, line, func, unit->id, yes_no(can_unshare),
                          service_result_to_string(service->result),
                          service_result_to_string(result_expected));
                abort();
        }
}

static bool check_nobody_user_and_group(void) {
        static int cache = -1;
        struct passwd *p;
        struct group *g;

        if (cache >= 0)
                return !!cache;

        if (!synthesize_nobody())
                goto invalid;

        p = getpwnam(NOBODY_USER_NAME);
        if (!p ||
            !streq(p->pw_name, NOBODY_USER_NAME) ||
            p->pw_uid != UID_NOBODY ||
            p->pw_gid != GID_NOBODY)
                goto invalid;

        p = getpwuid(UID_NOBODY);
        if (!p ||
            !streq(p->pw_name, NOBODY_USER_NAME) ||
            p->pw_uid != UID_NOBODY ||
            p->pw_gid != GID_NOBODY)
                goto invalid;

        g = getgrnam(NOBODY_GROUP_NAME);
        if (!g ||
            !streq(g->gr_name, NOBODY_GROUP_NAME) ||
            g->gr_gid != GID_NOBODY)
                goto invalid;

        g = getgrgid(GID_NOBODY);
        if (!g ||
            !streq(g->gr_name, NOBODY_GROUP_NAME) ||
            g->gr_gid != GID_NOBODY)
                goto invalid;

        cache = 1;
        return true;

invalid:
        cache = 0;
        return false;
}

static bool check_user_has_group_with_same_name(const char *name) {
        struct passwd *p;
        struct group *g;

        ASSERT_NOT_NULL(name);

        p = getpwnam(name);
        if (!p ||
            !streq(p->pw_name, name))
                return false;

        g = getgrgid(p->pw_gid);
        if (!g ||
            !streq(g->gr_name, name))
                return false;

        return true;
}

static bool is_inaccessible_available(void) {
        FOREACH_STRING(p,
                       "/run/systemd/inaccessible/reg",
                       "/run/systemd/inaccessible/dir",
                       "/run/systemd/inaccessible/chr",
                       "/run/systemd/inaccessible/blk",
                       "/run/systemd/inaccessible/fifo",
                       "/run/systemd/inaccessible/sock")
                if (access(p, F_OK) < 0)
                        return false;

        return true;
}

static void start_parent_slices(Unit *unit) {
        Unit *slice;

        slice = UNIT_GET_SLICE(unit);
        if (slice) {
                start_parent_slices(slice);
                ASSERT_OK_OR(unit_start(slice, NULL), -EALREADY);
        }
}

static bool apparmor_restrict_unprivileged_userns(void) {
        _cleanup_free_ char *v = NULL;
        int r;

        /* If kernel.apparmor_restrict_unprivileged_userns=1, then we cannot
         * use unprivileged user namespaces. */
        r = sysctl_read("kernel/apparmor_restrict_unprivileged_userns", &v);
        if (r < 0) {
                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to read kernel.apparmor_restrict_unprivileged_userns sysctl, ignoring: %m");

                return false;
        }

        return streq(v, "1");
}

static bool have_userns_privileges(void) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        if (apparmor_restrict_unprivileged_userns())
                return false;

        r = ASSERT_OK(pidref_safe_fork(
                        "(sd-test-check-userns)",
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL,
                        &pidref));

        if (r == 0) {
                /* Keep CAP_SYS_ADMIN if we have it to ensure we give an
                 * accurate result to the caller. Some kernels have a
                 * kernel.unprivileged_userns_clone sysctl which can be
                 * configured to make CLONE_NEWUSER require CAP_SYS_ADMIN.
                 * Additionally, AppArmor may restrict unprivileged user
                 * namespace creation. */
                r = capability_bounding_set_drop(UINT64_C(1) << CAP_SYS_ADMIN, /* right_now= */ true);
                if (r < 0) {
                        log_debug_errno(r, "Failed to drop capabilities: %m");
                        _exit(2);
                }

                r = RET_NERRNO(unshare(CLONE_NEWUSER));
                if (r < 0 && !ERRNO_IS_NEG_PRIVILEGE(r))
                        log_debug_errno(r, "Failed to create user namespace: %m");

                _exit(r >= 0 ? EXIT_SUCCESS : ERRNO_IS_NEG_PRIVILEGE(r) ? EXIT_FAILURE : 2);
        }

        /* The exit code records the result of the check:
         *  EXIT_SUCCESS => we can use user namespaces
         *  EXIT_FAILURE => we can NOT use user namespaces
         *  2            => some other error occurred */
        r = pidref_wait_for_terminate_and_check("(sd-test-check-userns)", &pidref, 0);
        if (!IN_SET(r, EXIT_SUCCESS, EXIT_FAILURE))
                log_debug("Failed to check if user namespaces can be used, assuming not.");

        return r == EXIT_SUCCESS;
}

static void _test(const char *file, unsigned line, const char *func,
                  Manager *m, const char *unit_name, int status_expected, int code_expected) {
        Unit *unit;

        ASSERT_NOT_NULL(unit_name);

        ASSERT_OK(manager_load_startable_unit_or_warn(m, unit_name, NULL, &unit));
        /* We need to start the slices as well otherwise the slice cgroups might be pruned
         * in on_cgroup_empty_event. */
        start_parent_slices(unit);
        ASSERT_OK(unit_start(unit, NULL));
        check_main_result(file, line, func, m, unit, status_expected, code_expected);

        ++n_ran_tests;
}
#define test(m, unit_name, status_expected, code_expected) \
        _test(PROJECT_FILE, __LINE__, __func__, m, unit_name, status_expected, code_expected)

static void _test_service(const char *file, unsigned line, const char *func,
                          Manager *m, const char *unit_name, ServiceResult result_expected) {
        Unit *unit;

        ASSERT_NOT_NULL(unit_name);

        ASSERT_OK(manager_load_startable_unit_or_warn(m, unit_name, NULL, &unit));
        ASSERT_OK(unit_start(unit, NULL));
        check_service_result(file, line, func, m, unit, result_expected);
}
#define test_service(m, unit_name, result_expected) \
        _test_service(PROJECT_FILE, __LINE__, __func__, m, unit_name, result_expected)

static void test_exec_bindpaths(Manager *m) {
        ASSERT_OK(mkdir_p("/tmp/test-exec-bindpaths", 0755));
        ASSERT_OK(mkdir_p("/tmp/test-exec-bindreadonlypaths", 0755));

        test(m, "exec-bindpaths.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec-bindpaths", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/tmp/test-exec-bindreadonlypaths", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_cpuaffinity(Manager *m) {
        _cleanup_(cpu_set_done) CPUSet c = {};

        ASSERT_OK(cpu_set_realloc(&c, 8192)); /* just allocate the maximum possible size */
        ASSERT_OK_ERRNO(sched_getaffinity(0, c.allocated, c.set));

        if (!CPU_ISSET_S(0, c.allocated, c.set)) {
                log_notice("Cannot use CPU 0, skipping %s", __func__);
                return;
        }

        test(m, "exec-cpuaffinity1.service", 0, CLD_EXITED);
        test(m, "exec-cpuaffinity2.service", 0, CLD_EXITED);

        if (!CPU_ISSET_S(1, c.allocated, c.set) ||
            !CPU_ISSET_S(2, c.allocated, c.set)) {
                log_notice("Cannot use CPU 1 or 2, skipping remaining tests in %s", __func__);
                return;
        }

        test(m, "exec-cpuaffinity3.service", 0, CLD_EXITED);
}

static void test_exec_credentials(Manager *m) {
        test(m, "exec-set-credential.service", 0, CLD_EXITED);
        test(m, "exec-load-credential.service", 0, CLD_EXITED);
        test(m, "exec-credentials-dir-specifier.service", 0, CLD_EXITED);
}

static void test_exec_workingdirectory(Manager *m) {
        ASSERT_OK(mkdir_p("/tmp/test-exec_workingdirectory", 0755));

        test(m, "exec-workingdirectory.service", 0, CLD_EXITED);
        test(m, "exec-workingdirectory-trailing-dot.service", 0, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec_workingdirectory", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_execsearchpath(Manager *m) {
        int r;

        ASSERT_OK(r = is_symlink("/bin/ls"));
        if (r > 0)
                return (void) log_tests_skipped("/bin/ls is a symlink, maybe coreutils is built with --enable-single-binary=symlinks");

        ASSERT_OK(mkdir_p("/tmp/test-exec_execsearchpath", 0755));

        ASSERT_OK(copy_file("/bin/ls", "/tmp/test-exec_execsearchpath/ls_temp", 0,  0777, COPY_REPLACE));

        test(m, "exec-execsearchpath.service", 0, CLD_EXITED);

        ASSERT_OK(rm_rf("/tmp/test-exec_execsearchpath", REMOVE_ROOT|REMOVE_PHYSICAL));

        test(m, "exec-execsearchpath.service", EXIT_EXEC, CLD_EXITED);
}

static void test_exec_execsearchpath_specifier(Manager *m) {
        test(m, "exec-execsearchpath-unit-specifier.service", 0, CLD_EXITED);
}

static void test_exec_execsearchpath_environment(Manager *m) {
        test(m, "exec-execsearchpath-environment.service", 0, CLD_EXITED);
        test(m, "exec-execsearchpath-environment-path-set.service", 0, CLD_EXITED);
}

static void test_exec_execsearchpath_environment_files(Manager *m) {
        static const char path_not_set[] =
                "VAR1='word1 word2'\n"
                "VAR2=word3 \n"
                "# comment1\n"
                "\n"
                "; comment2\n"
                " ; # comment3\n"
                "line without an equal\n"
                "VAR3='$word 5 6'\n"
                "VAR4='new\nline'\n"
                "VAR5=password\\with\\backslashes";

        static const char path_set[] =
                "VAR1='word1 word2'\n"
                "VAR2=word3 \n"
                "# comment1\n"
                "\n"
                "; comment2\n"
                " ; # comment3\n"
                "line without an equal\n"
                "VAR3='$word 5 6'\n"
                "VAR4='new\nline'\n"
                "VAR5=password\\with\\backslashes\n"
                "PATH=/usr";

        int r;

        r = write_string_file("/tmp/test-exec_execsearchpath_environmentfile.conf", path_not_set, WRITE_STRING_FILE_CREATE);
        ASSERT_OK(r);

        test(m, "exec-execsearchpath-environmentfile.service", 0, CLD_EXITED);

        (void) unlink("/tmp/test-exec_environmentfile.conf");

        r = write_string_file("/tmp/test-exec_execsearchpath_environmentfile-set.conf", path_set, WRITE_STRING_FILE_CREATE);
        ASSERT_OK(r);

        test(m, "exec-execsearchpath-environmentfile-set.service", 0, CLD_EXITED);

        (void) unlink("/tmp/test-exec_environmentfile-set.conf");
}

static void test_exec_execsearchpath_passenvironment(Manager *m) {
        ASSERT_OK_ERRNO(setenv("VAR1", "word1 word2", 1));
        ASSERT_OK_ERRNO(setenv("VAR2", "word3", 1));
        ASSERT_OK_ERRNO(setenv("VAR3", "$word 5 6", 1));
        ASSERT_OK_ERRNO(setenv("VAR4", "new\nline", 1));
        ASSERT_OK_ERRNO(setenv("VAR5", "passwordwithbackslashes", 1));

        test(m, "exec-execsearchpath-passenvironment.service", 0, CLD_EXITED);

        ASSERT_OK_ERRNO(setenv("PATH", "/usr", 1));
        test(m, "exec-execsearchpath-passenvironment-set.service", 0, CLD_EXITED);

        ASSERT_OK_ERRNO(unsetenv("VAR1"));
        ASSERT_OK_ERRNO(unsetenv("VAR2"));
        ASSERT_OK_ERRNO(unsetenv("VAR3"));
        ASSERT_OK_ERRNO(unsetenv("VAR4"));
        ASSERT_OK_ERRNO(unsetenv("VAR5"));
        ASSERT_OK_ERRNO(unsetenv("PATH"));
}

static void test_exec_personality(Manager *m) {
#if defined(__x86_64__)
        test(m, "exec-personality-x86-64.service", 0, CLD_EXITED);

#elif defined(__s390x__)
        test(m, "exec-personality-s390x.service", 0, CLD_EXITED);

#elif defined(__s390__)
        test(m, "exec-personality-s390.service", 0, CLD_EXITED);

#elif defined(__powerpc64__)
#  if __BYTE_ORDER == __BIG_ENDIAN
        test(m, "exec-personality-ppc64.service", 0, CLD_EXITED);
#  else
        test(m, "exec-personality-ppc64le.service", 0, CLD_EXITED);
#  endif

#elif defined(__aarch64__)
        test(m, "exec-personality-aarch64.service", 0, CLD_EXITED);

#elif defined(__i386__)
        test(m, "exec-personality-x86.service", 0, CLD_EXITED);
#elif defined(__loongarch_lp64)
        test(m, "exec-personality-loongarch64.service", 0, CLD_EXITED);
#else
        log_notice("Unknown personality, skipping %s", __func__);
#endif
}

static void test_exec_ignoresigpipe(Manager *m) {
        test(m, "exec-ignoresigpipe-yes.service", 0, CLD_EXITED);
        test(m, "exec-ignoresigpipe-no.service", SIGPIPE, CLD_KILLED);
}

static void test_exec_privatetmp(Manager *m) {
        ASSERT_OK(touch("/tmp/test-exec_privatetmp"));

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges()) {
                test(m, "exec-privatetmp-yes.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-privatetmp-disabled-by-prefix.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);

                (void) unlink("/tmp/test-exec_privatetmp_disconnected");
                test(m, "exec-privatetmp-disconnected-nodefaultdeps-nor-sandboxing.service", 0, CLD_EXITED);
                ASSERT_OK_ERRNO(access("/tmp/test-exec_privatetmp_disconnected", F_OK));

                FOREACH_STRING(s,
                               "exec-privatetmp-disconnected.service",
                               "exec-privatetmp-disconnected-defaultdependencies-no.service",
                               "exec-privatetmp-disconnected-requires-mounts-for-var.service",
                               "exec-privatetmp-disconnected-wants-mounts-for-var.service",
                               "exec-privatetmp-disconnected-after-and-requires-for-var.service",
                               "exec-privatetmp-disconnected-after-and-wants-for-var.service") {
                        (void) unlink("/tmp/test-exec_privatetmp_disconnected");
                        (void) unlink("/var/tmp/test-exec_privatetmp_disconnected");
                        test(m, s, can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
                        ASSERT_FAIL(access("/tmp/test-exec_privatetmp_disconnected", F_OK));
                        ASSERT_FAIL(access("/var/tmp/test-exec_privatetmp_disconnected", F_OK));
                }
        }

        test(m, "exec-privatetmp-no.service", 0, CLD_EXITED);

        (void) unlink("/tmp/test-exec_privatetmp");
}

static void test_exec_privatedevices(Manager *m) {
        int r;

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping %s", __func__);
                return;
        }
        if (!is_inaccessible_available()) {
                log_notice("Testing without inaccessible, skipping %s", __func__);
                return;
        }

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges()) {
                test(m, "exec-privatedevices-yes.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
                if (access("/dev/kmsg", F_OK) >= 0)
                        test(m, "exec-privatedevices-bind.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-privatedevices-disabled-by-prefix.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-privatedevices-yes-with-group.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
        }

        test(m, "exec-privatedevices-no.service", 0, CLD_EXITED);

        /* We use capsh to test if the capabilities are
         * properly set, so be sure that it exists */
        r = find_executable("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Could not find capsh binary, skipping remaining tests in %s: %m", __func__);
                return;
        }

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges()) {
                test(m, "exec-privatedevices-yes-capability-mknod.service", can_unshare || MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-privatedevices-yes-capability-sys-rawio.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        }

        test(m, "exec-privatedevices-no-capability-mknod.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-privatedevices-no-capability-sys-rawio.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_protecthome(Manager *m) {
        if (!can_unshare) {
                log_notice("Cannot reliably unshare, skipping %s", __func__);
                return;
        }

        test(m, "exec-protecthome-tmpfs-vs-protectsystem-strict.service", 0, CLD_EXITED);
}

static void test_exec_protectkernelmodules(Manager *m) {
        int r;

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping %s", __func__);
                return;
        }
        if (!is_inaccessible_available()) {
                log_notice("Testing without inaccessible, skipping %s", __func__);
                return;
        }

        r = find_executable("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find capsh binary: %m", __func__);
                return;
        }

        test(m, "exec-protectkernelmodules-no-capabilities.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_FAILURE, CLD_EXITED);

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges()) {
                test(m, "exec-protectkernelmodules-yes-capabilities.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-protectkernelmodules-yes-mount-propagation.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
        }
}

static void test_exec_readonlypaths(Manager *m) {

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges())
                test(m, "exec-readonlypaths-simple.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);

        if (path_is_read_only_fs("/var") > 0) {
                log_notice("Directory /var is readonly, skipping remaining tests in %s", __func__);
                return;
        }

        test(m, "exec-readonlypaths.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
        test(m, "exec-readonlypaths-with-bindpaths.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(m, "exec-readonlypaths-mount-propagation.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_readwritepaths(Manager *m) {

        if (path_is_read_only_fs("/") > 0) {
                log_notice("Root directory is readonly, skipping %s", __func__);
                return;
        }

        test(m, "exec-readwritepaths-mount-propagation.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_inaccessiblepaths(Manager *m) {

        if (!is_inaccessible_available()) {
                log_notice("Testing without inaccessible, skipping %s", __func__);
                return;
        }

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges())
                test(m, "exec-inaccessiblepaths-sys.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);

        if (path_is_read_only_fs("/") > 0) {
                log_notice("Root directory is readonly, skipping remaining tests in %s", __func__);
                return;
        }

        test(m, "exec-inaccessiblepaths-mount-propagation.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
}

#if !HAS_FEATURE_ADDRESS_SANITIZER
static int on_spawn_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        char **result = userdata;
        char buf[4096];
        ssize_t l;

        ASSERT_NOT_NULL(s);
        ASSERT_GT(fd, 0);

        l = read(fd, buf, sizeof(buf) - 1);
        if (l < 0) {
                if (errno == EAGAIN)
                        goto reenable;

                return 0;
        }
        if (l == 0)
                return 0;

        buf[l] = '\0';
        if (result)
                ASSERT_NOT_NULL(strextend(result, buf));
        else
                log_error("ldd: %s", buf);

reenable:
        /* Re-enable the event source if we did not encounter EOF */
        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_ONESHOT));
        return 0;
}

static int on_spawn_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        PidRef *pidref = ASSERT_PTR(userdata);

        (void) pidref_kill(pidref, SIGKILL);

        return 1;
}

static int on_spawn_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        int ret = -EIO;

        ASSERT_NOT_NULL(si);

        if (si->si_code == CLD_EXITED)
                ret = si->si_status;

        sd_event_exit(sd_event_source_get_event(s), ret);
        return 1;
}

static int find_libraries(const char *exec, char ***ret) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *sigchld_source = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *stdout_source = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *stderr_source = NULL;
        _cleanup_close_pair_ int outpipe[2] = EBADF_PAIR, errpipe[2] = EBADF_PAIR;
        _cleanup_strv_free_ char **libraries = NULL;
        _cleanup_free_ char *result = NULL;
        int r;

        ASSERT_NOT_NULL(exec);
        ASSERT_NOT_NULL(ret);

        ASSERT_OK_ERRNO(pipe2(outpipe, O_NONBLOCK|O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(errpipe, O_NONBLOCK|O_CLOEXEC));

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(spawn-ldd)",
                        (int[]) { -EBADF, outpipe[1], errpipe[1] },
                        NULL, 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG,
                        &pidref);
        ASSERT_OK(r);
        if (r == 0) {
                execlp("ldd", "ldd", exec, NULL);
                _exit(EXIT_FAILURE);
        }

        outpipe[1] = safe_close(outpipe[1]);
        errpipe[1] = safe_close(errpipe[1]);

        ASSERT_OK(sd_event_new(&e));

        ASSERT_OK(sd_event_add_time_relative(e, NULL, CLOCK_MONOTONIC,
                                             10 * USEC_PER_SEC, USEC_PER_SEC, on_spawn_timeout, &pidref));
        ASSERT_OK(sd_event_add_io(e, &stdout_source, outpipe[0], EPOLLIN, on_spawn_io, &result));
        ASSERT_OK(sd_event_source_set_enabled(stdout_source, SD_EVENT_ONESHOT));
        ASSERT_OK(sd_event_add_io(e, &stderr_source, errpipe[0], EPOLLIN, on_spawn_io, NULL));
        ASSERT_OK(sd_event_source_set_enabled(stderr_source, SD_EVENT_ONESHOT));
        ASSERT_OK(event_add_child_pidref(e, &sigchld_source, &pidref, WEXITED, on_spawn_exit, NULL));
        /* Child exit should be processed after IO is complete */
        ASSERT_OK(sd_event_source_set_priority(sigchld_source, SD_EVENT_PRIORITY_NORMAL + 1));

        ASSERT_OK(sd_event_loop(e));

        _cleanup_strv_free_ char **v = NULL;
        ASSERT_OK(strv_split_newlines_full(&v, result, 0));

        STRV_FOREACH(q, v) {
                _cleanup_free_ char *word = NULL;
                const char *p = *q;

                r = extract_first_word(&p, &word, NULL, 0);
                ASSERT_OK(r);
                if (r == 0)
                        continue;

                if (path_is_absolute(word)) {
                        ASSERT_OK(strv_consume(&libraries, TAKE_PTR(word)));
                        continue;
                }

                word = mfree(word);
                r = extract_first_word(&p, &word, NULL, 0);
                ASSERT_OK(r);
                if (r == 0)
                        continue;

                if (!streq_ptr(word, "=>"))
                        continue;

                word = mfree(word);
                r = extract_first_word(&p, &word, NULL, 0);
                ASSERT_OK(r);
                if (r == 0)
                        continue;

                if (path_is_absolute(word)) {
                        ASSERT_OK(strv_consume(&libraries, TAKE_PTR(word)));
                        continue;
                }
        }

        *ret = TAKE_PTR(libraries);
        return 0;
}
#endif

static void test_exec_mount_apivfs(Manager *m) {
#if !HAS_FEATURE_ADDRESS_SANITIZER
        _cleanup_free_ char *fullpath_touch = NULL, *fullpath_test = NULL, *data = NULL;
        _cleanup_strv_free_ char **libraries = NULL, **libraries_test = NULL;
        int r;

        ASSERT_NOT_NULL(user_runtime_unit_dir);

        r = find_executable("ldd", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find 'ldd' command: %m", __func__);
                return;
        }
        r = find_executable("touch", &fullpath_touch);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find 'touch' command: %m", __func__);
                return;
        }
        r = find_executable("test", &fullpath_test);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find 'test' command: %m", __func__);
                return;
        }

        if (MANAGER_IS_USER(m) && !have_userns_privileges())
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);

        ASSERT_OK(find_libraries(fullpath_touch, &libraries));
        ASSERT_OK(find_libraries(fullpath_test, &libraries_test));
        ASSERT_OK(strv_extend_strv(&libraries, libraries_test, true));

        ASSERT_NOT_NULL(strextend(&data, "[Service]\n"));
        ASSERT_NOT_NULL((strextend(&data, "ExecStart=", fullpath_touch, " /aaa\n")));
        ASSERT_NOT_NULL((strextend(&data, "ExecStart=", fullpath_test, " -f /aaa\n")));
        ASSERT_NOT_NULL((strextend(&data, "BindReadOnlyPaths=", fullpath_touch, "\n")));
        ASSERT_NOT_NULL((strextend(&data, "BindReadOnlyPaths=", fullpath_test, "\n")));

        STRV_FOREACH(p, libraries)
                ASSERT_NOT_NULL((strextend(&data, "BindReadOnlyPaths=", *p, "\n")));

        ASSERT_OK(write_drop_in(user_runtime_unit_dir, "exec-mount-apivfs-no.service", 10, "bind-mount", data));

        ASSERT_OK(mkdir_p("/tmp/test-exec-mount-apivfs-no/root", 0755));

        test(m, "exec-mount-apivfs-no.service", can_unshare || !MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec-mount-apivfs-no/root", REMOVE_ROOT|REMOVE_PHYSICAL);
#endif
}

static void test_exec_noexecpaths(Manager *m) {

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges())
                test(m, "exec-noexecpaths-simple.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
        else
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);
}

static void test_exec_temporaryfilesystem(Manager *m) {

        test(m, "exec-temporaryfilesystem-options.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(m, "exec-temporaryfilesystem-ro.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(m, "exec-temporaryfilesystem-rw.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(m, "exec-temporaryfilesystem-usr.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_systemcallfilter(Manager *m) {
#if HAVE_SECCOMP && !HAS_FEATURE_ADDRESS_SANITIZER
        int r;

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        test(m, "exec-systemcallfilter-writing-handoff-timestamp.service", 0, CLD_EXITED);

        test(m, "exec-systemcallfilter-not-failing.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-not-failing2.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-not-failing3.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-failing.service", SIGSYS, CLD_KILLED);
        test(m, "exec-systemcallfilter-failing2.service", SIGSYS, CLD_KILLED);
        test(m, "exec-systemcallfilter-failing3.service", SIGSYS, CLD_KILLED);

        r = find_executable("python3", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping remaining tests in %s, could not find python3 binary: %m", __func__);
                return;
        }

        test(m, "exec-systemcallfilter-with-errno-name.service", errno_from_name("EILSEQ"), CLD_EXITED);
        test(m, "exec-systemcallfilter-with-errno-number.service", 255, CLD_EXITED);
        test(m, "exec-systemcallfilter-with-errno-multi.service", errno_from_name("EILSEQ"), CLD_EXITED);
        test(m, "exec-systemcallfilter-with-errno-in-allow-list.service", errno_from_name("EILSEQ"), CLD_EXITED);
        test(m, "exec-systemcallfilter-override-error-action.service", SIGSYS, CLD_KILLED);
        test(m, "exec-systemcallfilter-override-error-action2.service", errno_from_name("EILSEQ"), CLD_EXITED);

        test(m, "exec-systemcallfilter-nonewprivileges.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
        test(m, "exec-systemcallfilter-nonewprivileges-protectclock.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);

        r = find_executable("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find capsh binary: %m", __func__);
                return;
        }

        test(m, "exec-systemcallfilter-nonewprivileges-bounding1.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
        test(m, "exec-systemcallfilter-nonewprivileges-bounding2.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
#endif
}

static void test_exec_systemcallerrornumber(Manager *m) {
#if HAVE_SECCOMP && !HAS_FEATURE_ADDRESS_SANITIZER
        int r;

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        r = find_executable("python3", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find python3 binary: %m", __func__);
                return;
        }

        test(m, "exec-systemcallerrornumber-name.service", errno_from_name("EACCES"), CLD_EXITED);
        test(m, "exec-systemcallerrornumber-number.service", 255, CLD_EXITED);
#endif
}

static void test_exec_restrictnamespaces(Manager *m) {
#if HAVE_SECCOMP
        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        test(m, "exec-restrictnamespaces-no.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-restrictnamespaces-yes.service", 1, CLD_EXITED);
        test(m, "exec-restrictnamespaces-mnt.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-restrictnamespaces-mnt-deny-list.service", 1, CLD_EXITED);
        test(m, "exec-restrictnamespaces-merge-and.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-restrictnamespaces-merge-or.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-restrictnamespaces-merge-all.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
#endif
}

static void test_exec_systemcallfilter_system(Manager *m) {
/* Skip this particular test case when running under ASan, as
 * LSan intermittently segfaults when accessing memory right
 * after the test finishes. Generally, ASan & LSan don't like
 * the seccomp stuff.
 */
#if HAVE_SECCOMP && !HAS_FEATURE_ADDRESS_SANITIZER
        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        test(m, "exec-systemcallfilter-system-user.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(m, "exec-systemcallfilter-system-user-" NOBODY_USER_NAME ".service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
#endif
}

static void test_exec_user(Manager *m) {
        test(m, "exec-user.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(m, "exec-user-" NOBODY_USER_NAME ".service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
}

static void test_exec_group(Manager *m) {
        test(m, "exec-group.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_GROUP_NAME, "nobody", "nfsnobody", "nogroup")) {
                log_notice("Unsupported nobody group name '%s', skipping remaining tests in %s", NOBODY_GROUP_NAME, __func__);
                return;
        }

        test(m, "exec-group-" NOBODY_GROUP_NAME ".service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
}

static void test_exec_supplementarygroups(Manager *m) {
        int status = MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP;
        test(m, "exec-supplementarygroups.service", status, CLD_EXITED);
        test(m, "exec-supplementarygroups-single-group.service", status, CLD_EXITED);
        test(m, "exec-supplementarygroups-single-group-user.service", status, CLD_EXITED);
        test(m, "exec-supplementarygroups-multiple-groups-default-group-user.service", status, CLD_EXITED);
        test(m, "exec-supplementarygroups-multiple-groups-withgid.service", status, CLD_EXITED);
        test(m, "exec-supplementarygroups-multiple-groups-withuid.service", status, CLD_EXITED);
}

static char* private_directory_bad(Manager *m) {
        /* This mirrors setup_exec_directory(). */

        for (ExecDirectoryType dt = 0; dt < _EXEC_DIRECTORY_TYPE_MAX; dt++) {
                _cleanup_free_ char *p = NULL;
                struct stat st;

                ASSERT_NOT_NULL((p = path_join(m->prefix[dt], "private")));

                if (stat(p, &st) >= 0 &&
                    (st.st_mode & (S_IRWXG|S_IRWXO)))
                        return TAKE_PTR(p);
        }

        return NULL;
}

static void test_exec_dynamicuser(Manager *m) {
        if (MANAGER_IS_USER(m)) {
                log_notice("Skipping %s for user manager", __func__);
                return;
        }

        _cleanup_free_ char *bad = private_directory_bad(m);
        if (bad) {
                log_warning("%s: %s has bad permissions, skipping test.", __func__, bad);
                return;
        }

        if (strstr_ptr(ci_environment(), "github-actions")) {
                log_notice("%s: skipping test on GH Actions because of systemd/systemd#10337", __func__);
                return;
        }

        int status = can_unshare ? 0 : EXIT_NAMESPACE;

        test(m, "exec-dynamicuser-fixeduser.service", status, CLD_EXITED);
        if (check_user_has_group_with_same_name("adm"))
                test(m, "exec-dynamicuser-fixeduser-adm.service", status, CLD_EXITED);
        if (check_user_has_group_with_same_name("games"))
                test(m, "exec-dynamicuser-fixeduser-games.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-fixeduser-one-supplementarygroup.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-supplementarygroups.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-statedir.service", status, CLD_EXITED);

        (void) rm_rf("/var/lib/quux", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/waldo", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/quux", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/waldo", REMOVE_ROOT|REMOVE_PHYSICAL);

        test(m, "exec-dynamicuser-statedir-migrate-step1.service", 0, CLD_EXITED);
        test(m, "exec-dynamicuser-statedir-migrate-step2.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-statedir-migrate-step1.service", 0, CLD_EXITED);

        (void) rm_rf("/var/lib/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);

        test(m, "exec-dynamicuser-runtimedirectory1.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-runtimedirectory2.service", status, CLD_EXITED);
        test(m, "exec-dynamicuser-runtimedirectory3.service", status, CLD_EXITED);
}

static void test_exec_environment(Manager *m) {
        test(m, "exec-environment-no-substitute.service", 0, CLD_EXITED);
        test(m, "exec-environment.service", 0, CLD_EXITED);
        test(m, "exec-environment-multiple.service", 0, CLD_EXITED);
        test(m, "exec-environment-empty.service", 0, CLD_EXITED);
}

static void test_exec_environmentfile(Manager *m) {
        static const char e[] =
                "VAR1='word1 word2'\n"
                "VAR2=word3 \n"
                "# comment1\n"
                "\n"
                "; comment2\n"
                " ; # comment3\n"
                "line without an equal\n"
                "VAR3='$word 5 6'\n"
                "VAR4='new\nline'\n"
                "VAR5=password\\with\\backslashes";
        int r;

        r = write_string_file("/tmp/test-exec_environmentfile.conf", e, WRITE_STRING_FILE_CREATE);
        ASSERT_OK(r);

        test(m, "exec-environmentfile.service", 0, CLD_EXITED);

        (void) unlink("/tmp/test-exec_environmentfile.conf");
}

static void test_exec_passenvironment(Manager *m) {
        /* test-execute runs under MANAGER_USER which, by default, forwards all
         * variables present in the environment, but only those that are
         * present _at the time it is created_!
         *
         * So these PassEnvironment checks are still expected to work, since we
         * are ensuring the variables are not present at manager creation (they
         * are unset explicitly in main) and are only set here.
         *
         * This is still a good approximation of how a test for MANAGER_SYSTEM
         * would work.
         */
        ASSERT_OK_ERRNO(setenv("VAR1", "word1 word2", 1));
        ASSERT_OK_ERRNO(setenv("VAR2", "word3", 1));
        ASSERT_OK_ERRNO(setenv("VAR3", "$word 5 6", 1));
        ASSERT_OK_ERRNO(setenv("VAR4", "new\nline", 1));
        ASSERT_OK_ERRNO(setenv("VAR5", "passwordwithbackslashes", 1));
        test(m, "exec-passenvironment.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-repeated.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-empty.service", 0, CLD_EXITED);
        ASSERT_OK_ERRNO(unsetenv("VAR1"));
        ASSERT_OK_ERRNO(unsetenv("VAR2"));
        ASSERT_OK_ERRNO(unsetenv("VAR3"));
        ASSERT_OK_ERRNO(unsetenv("VAR4"));
        ASSERT_OK_ERRNO(unsetenv("VAR5"));
        test(m, "exec-passenvironment-absent.service", 0, CLD_EXITED);
}

static void test_exec_umask(Manager *m) {
        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges()) {
                test(m, "exec-umask-default.service", can_unshare || MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
                test(m, "exec-umask-0177.service", can_unshare || MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        } else
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);
}

static void test_exec_runtimedirectory(Manager *m) {
        (void) rm_rf("/run/test-exec_runtimedirectory2", REMOVE_ROOT|REMOVE_PHYSICAL);
        test(m, "exec-runtimedirectory.service", 0, CLD_EXITED);
        (void) rm_rf("/run/test-exec_runtimedirectory2", REMOVE_ROOT|REMOVE_PHYSICAL);

        test(m, "exec-runtimedirectory-mode.service", 0, CLD_EXITED);
        test(m, "exec-runtimedirectory-owner.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_GROUP_NAME, "nobody", "nfsnobody", "nogroup")) {
                log_notice("Unsupported nobody group name '%s', skipping remaining tests in %s", NOBODY_GROUP_NAME, __func__);
                return;
        }

        test(m, "exec-runtimedirectory-owner-" NOBODY_GROUP_NAME ".service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_GROUP, CLD_EXITED);
}

static void test_exec_capabilityboundingset(Manager *m) {
        int r;

        r = find_executable("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find capsh binary: %m", __func__);
                return;
        }

        if (have_effective_cap(CAP_CHOWN) <= 0 ||
            have_effective_cap(CAP_FOWNER) <= 0 ||
            have_effective_cap(CAP_KILL) <= 0) {
                log_notice("Skipping %s, this process does not have enough capabilities", __func__);
                return;
        }

        test(m, "exec-capabilityboundingset-simple.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-reset.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-merge.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-invert.service", 0, CLD_EXITED);
}

static void test_exec_basic(Manager *m) {
        if (isempty(gnu_get_libc_version()))
                return (void) log_tests_skipped("ConditionVersion=glibc will not pass under musl");

        if (MANAGER_IS_SYSTEM(m) || have_userns_privileges())
                test(m, "exec-basic.service", can_unshare || MANAGER_IS_SYSTEM(m) ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        else
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);
}

static void test_exec_ambientcapabilities(Manager *m) {
        int r;

        /* Check if the kernel has support for ambient capabilities. Run
         * the tests only if that's the case. Clearing all ambient
         * capabilities is fine, since we are expecting them to be unset
         * in the first place for the tests. */
        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        if (r < 0 && IN_SET(errno, EINVAL, EOPNOTSUPP, ENOSYS)) {
                log_notice("Skipping %s, the kernel does not support ambient capabilities", __func__);
                return;
        }

        if (have_effective_cap(CAP_CHOWN) <= 0 ||
            have_effective_cap(CAP_NET_RAW) <= 0) {
                log_notice("Skipping %s, this process does not have enough capabilities", __func__);
                return;
        }

        test(m, "exec-ambientcapabilities.service", 0, CLD_EXITED);
        test(m, "exec-ambientcapabilities-merge.service", 0, CLD_EXITED);

        if (have_effective_cap(CAP_SETUID) > 0)
                test(m, "exec-ambientcapabilities-dynuser.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(m, "exec-ambientcapabilities-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
        test(m, "exec-ambientcapabilities-merge-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
}

static void test_exec_privatenetwork(Manager *m) {
        int r;

        if (!have_net_dummy)
                return (void)log_notice("Skipping %s, dummy network interface not available", __func__);

        if (MANAGER_IS_USER(m) && !have_userns_privileges())
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);

        r = find_executable("ip", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find ip binary: %m", __func__);
                return;
        }

        test(m, "exec-privatenetwork-yes-privatemounts-no.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_NETWORK : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-privatenetwork-yes-privatemounts-yes.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_NETWORK : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_networknamespacepath(Manager *m) {
        int r;

        if (!have_net_dummy)
                return (void)log_notice("Skipping %s, dummy network interface not available", __func__);

        if (!have_netns)
                return (void)log_notice("Skipping %s, network namespace not available", __func__);

        if (MANAGER_IS_USER(m) && !have_userns_privileges())
                return (void)log_notice("Skipping %s, do not have user namespace privileges", __func__);

        r = find_executable("ip", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find ip binary: %m", __func__);
                return;
        }

        test(m, "exec-networknamespacepath-privatemounts-no.service", MANAGER_IS_SYSTEM(m) ? EXIT_SUCCESS : EXIT_FAILURE, CLD_EXITED);
        test(m, "exec-networknamespacepath-privatemounts-yes.service", can_unshare ? EXIT_SUCCESS : MANAGER_IS_SYSTEM(m) ? EXIT_FAILURE : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_oomscoreadjust(Manager *m) {
        test(m, "exec-oomscoreadjust-positive.service", 0, CLD_EXITED);

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping remaining tests in %s", __func__);
                return;
        }
        test(m, "exec-oomscoreadjust-negative.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_ioschedulingclass(Manager *m) {
        test(m, "exec-ioschedulingclass-none.service", 0, CLD_EXITED);
        test(m, "exec-ioschedulingclass-idle.service", 0, CLD_EXITED);
        test(m, "exec-ioschedulingclass-best-effort.service", 0, CLD_EXITED);

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping remaining tests in %s", __func__);
                return;
        }
        test(m, "exec-ioschedulingclass-realtime.service", MANAGER_IS_SYSTEM(m) ? 0 : EXIT_IOPRIO, CLD_EXITED);
}

static void test_exec_unsetenvironment(Manager *m) {
        test(m, "exec-unsetenvironment.service", 0, CLD_EXITED);
}

static void test_exec_specifier(Manager *m) {
        test(m, "exec-specifier.service", 0, CLD_EXITED);
        if (MANAGER_IS_SYSTEM(m))
                test(m, "exec-specifier-system.service", 0, CLD_EXITED);
        else
                test(m, "exec-specifier-user.service", 0, CLD_EXITED);
        test(m, "exec-specifier@foo-bar.service", 0, CLD_EXITED);
        test(m, "exec-specifier-interpolation.service", 0, CLD_EXITED);
}

static void test_exec_standardinput(Manager *m) {
        test(m, "exec-standardinput-data.service", 0, CLD_EXITED);
        test(m, "exec-standardinput-file.service", 0, CLD_EXITED);

        ExecOutput saved = m->defaults.std_output;
        m->defaults.std_output = EXEC_OUTPUT_NULL;
        test(m, "exec-standardinput-file-cat.service", 0, CLD_EXITED);
        m->defaults.std_output = saved;
}

static void test_exec_standardoutput(Manager *m) {
        test(m, "exec-standardoutput-file.service", 0, CLD_EXITED);
}

static void test_exec_standardoutput_append(Manager *m) {
        test(m, "exec-standardoutput-append.service", 0, CLD_EXITED);
}

static void test_exec_standardoutput_truncate(Manager *m) {
        test(m, "exec-standardoutput-truncate.service", 0, CLD_EXITED);
}

static void test_exec_condition(Manager *m) {
        test_service(m, "exec-condition-failed.service", SERVICE_FAILURE_EXIT_CODE);
        test_service(m, "exec-condition-skip.service", SERVICE_SKIP_CONDITION);
}

static void test_exec_umask_namespace(Manager *m) {
        /* exec-specifier-credentials-dir.service creates /run/credentials and enables implicit
         * InaccessiblePath= for the directory for all later services with mount namespace. */
        if (!is_inaccessible_available()) {
                log_notice("Testing without inaccessible, skipping %s", __func__);
                return;
        }
        test(m, "exec-umask-namespace.service", can_unshare ? 0 : MANAGER_IS_SYSTEM(m) ? EXIT_NAMESPACE : EXIT_GROUP, CLD_EXITED);
}

typedef struct test_entry {
        test_function_t f;
        const char *name;
} test_entry;

#define entry(x) {x, #x}

static void run_tests(RuntimeScope scope, char **patterns) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_free_ char *unit_paths = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        usec_t start, finish;
        int r;

        static const test_entry tests[] = {
                entry(test_exec_basic),
                entry(test_exec_ambientcapabilities),
                entry(test_exec_bindpaths),
                entry(test_exec_capabilityboundingset),
                entry(test_exec_condition),
                entry(test_exec_cpuaffinity),
                entry(test_exec_credentials),
                entry(test_exec_dynamicuser),
                entry(test_exec_environment),
                entry(test_exec_environmentfile),
                entry(test_exec_execsearchpath),
                entry(test_exec_execsearchpath_environment),
                entry(test_exec_execsearchpath_environment_files),
                entry(test_exec_execsearchpath_passenvironment),
                entry(test_exec_execsearchpath_specifier),
                entry(test_exec_group),
                entry(test_exec_ignoresigpipe),
                entry(test_exec_inaccessiblepaths),
                entry(test_exec_ioschedulingclass),
                entry(test_exec_mount_apivfs),
                entry(test_exec_networknamespacepath),
                entry(test_exec_noexecpaths),
                entry(test_exec_oomscoreadjust),
                entry(test_exec_passenvironment),
                entry(test_exec_personality),
                entry(test_exec_privatedevices),
                entry(test_exec_privatenetwork),
                entry(test_exec_privatetmp),
                entry(test_exec_protecthome),
                entry(test_exec_protectkernelmodules),
                entry(test_exec_readonlypaths),
                entry(test_exec_readwritepaths),
                entry(test_exec_restrictnamespaces),
                entry(test_exec_runtimedirectory),
                entry(test_exec_specifier),
                entry(test_exec_standardinput),
                entry(test_exec_standardoutput),
                entry(test_exec_standardoutput_append),
                entry(test_exec_standardoutput_truncate),
                entry(test_exec_supplementarygroups),
                entry(test_exec_systemcallerrornumber),
                entry(test_exec_systemcallfilter),
                entry(test_exec_systemcallfilter_system),
                entry(test_exec_temporaryfilesystem),
                entry(test_exec_umask),
                entry(test_exec_umask_namespace),
                entry(test_exec_unsetenvironment),
                entry(test_exec_user),
                entry(test_exec_workingdirectory),
                {},
        };

        ASSERT_OK_ERRNO(unsetenv("USER"));
        ASSERT_OK_ERRNO(unsetenv("LOGNAME"));
        ASSERT_OK_ERRNO(unsetenv("SHELL"));
        ASSERT_OK_ERRNO(unsetenv("HOME"));
        ASSERT_OK_ERRNO(unsetenv("TMPDIR"));

        /* Unset VARx, especially, VAR1, VAR2 and VAR3, which are used in the PassEnvironment test cases,
         * otherwise (and if they are present in the environment), `manager_default_environment` will copy
         * them into the default environment which is passed to each created job, which will make the tests
         * that expect those not to be present to fail. */
        ASSERT_OK_ERRNO(unsetenv("VAR1"));
        ASSERT_OK_ERRNO(unsetenv("VAR2"));
        ASSERT_OK_ERRNO(unsetenv("VAR3"));
        ASSERT_OK_ERRNO(unsetenv("VAR4"));
        ASSERT_OK_ERRNO(unsetenv("VAR5"));

        ASSERT_NOT_NULL((runtime_dir = setup_fake_runtime_dir()));
        ASSERT_NOT_NULL((user_runtime_unit_dir = path_join(runtime_dir, "systemd/user")));
        ASSERT_NOT_NULL((unit_paths = strjoin(PRIVATE_UNIT_DIR, ":", user_runtime_unit_dir)));
        ASSERT_OK(setenv_unit_path(unit_paths));

        /* Write credential for test-execute-load-credential to the fake runtime dir, too */
        _cleanup_free_ char *j = ASSERT_PTR(path_join(runtime_dir, "credstore/test-execute.load-credential"));
        ASSERT_OK(write_string_file(j, "foo", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_MKDIR_0755));

        r = manager_new(scope, MANAGER_TEST_RUN_BASIC, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);

        m->defaults.std_output = EXEC_OUTPUT_INHERIT; /* don't rely on host journald */
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL));

        /* Uncomment below if you want to make debugging logs stored to journal. */
        //manager_override_log_target(m, LOG_TARGET_AUTO);
        //manager_override_log_level(m, LOG_DEBUG);

        /* Measure and print the time that it takes to run tests, excluding startup of the manager object,
         * to try and measure latency of spawning services */
        n_ran_tests = 0;
        start = now(CLOCK_MONOTONIC);

        for (const test_entry *test = tests; test->f; test++)
                if (strv_fnmatch_or_empty(patterns, test->name, FNM_NOESCAPE)) {
                        log_info("Starting %s.", test->name);
                        test->f(m);
                } else
                        log_info("Skipping %s because it does not match any pattern.", test->name);

        finish = now(CLOCK_MONOTONIC);

        log_info("ran %u tests with %s manager + unshare=%s in: %s",
                 n_ran_tests,
                 scope == RUNTIME_SCOPE_SYSTEM ? "system" : "user",
                 yes_no(can_unshare),
                 FORMAT_TIMESPAN(finish - start, USEC_PER_MSEC));
}

static int prepare_ns(const char *process_name) {
        int r;

        r = pidref_safe_fork(
                        process_name,
                        FORK_RESET_SIGNALS|
                        FORK_CLOSE_ALL_FDS|
                        FORK_DEATHSIG_SIGTERM|
                        FORK_WAIT|
                        FORK_REOPEN_LOG|
                        FORK_LOG|
                        FORK_NEW_MOUNTNS|
                        FORK_MOUNTNS_SLAVE,
                        NULL);
        ASSERT_OK(r);
        if (r == 0) {
                _cleanup_free_ char *unit_dir = NULL, *build_dir = NULL, *build_dir_mount = NULL;

                const char *coverage = getenv("COVERAGE_BUILD_DIR");
                if (!coverage)
                        /* Make "/" read-only. */
                        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, NULL, "/", NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL));

                /* Creating a new user namespace in the above means all MS_SHARED mounts become MS_SLAVE.
                 * Let's put them back to MS_SHARED here, since that's what we want as defaults. (This will
                 * not reconnect propagation, but simply create new peer groups for all our mounts). */
                ASSERT_OK(mount_follow_verbose(LOG_DEBUG, NULL, "/", NULL, MS_SHARED|MS_REC, NULL));

                ASSERT_OK(mkdir_p(PRIVATE_UNIT_DIR, 0755));
                ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, "tmpfs", PRIVATE_UNIT_DIR, "tmpfs", MS_NOSUID|MS_NODEV, NULL));
                /* Mark our test "playground" as MS_SLAVE, so we can MS_MOVE mounts underneath it. */
                ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, NULL, PRIVATE_UNIT_DIR, NULL, MS_SLAVE, NULL));

                /* Copy unit files to make them accessible even when unprivileged. */
                ASSERT_OK(get_testdata_dir("test-execute/", &unit_dir));
                ASSERT_OK(copy_directory_at(AT_FDCWD, unit_dir, AT_FDCWD, PRIVATE_UNIT_DIR, UID_INVALID, GID_INVALID, COPY_MERGE_EMPTY));

                /* Mount tmpfs on the following directories to make not StateDirectory= or friends disturb the host. */
                ASSERT_OK_OR(get_build_exec_dir(&build_dir), -ENOEXEC);

                if (build_dir) {
                        /* Account for a build directory being in one of the soon-to-be-tmpfs directories. If we
                         * overmount it with an empty tmpfs, manager_new() will pin the wrong systemd-executor binary,
                         * which can then lead to unexpected (and painful to debug) test fails. */
                        ASSERT_OK_ERRNO(access(build_dir, F_OK));
                        ASSERT_NOT_NULL((build_dir_mount = path_join(PRIVATE_UNIT_DIR, "build_dir")));
                        ASSERT_OK(mkdir_p(build_dir_mount, 0755));
                        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, build_dir, build_dir_mount, NULL, MS_BIND, NULL));
                }

                FOREACH_STRING(p, "/dev/shm", "/root", "/tmp", "/var/tmp", "/var/lib")
                        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, "tmpfs", p, "tmpfs", MS_NOSUID|MS_NODEV, NULL));

                if (build_dir_mount) {
                        int k;

                        ASSERT_OK_OR(k = RET_NERRNO(access(build_dir, F_OK)), -ENOENT);

                        if (k == -ENOENT) {
                                /* The build directory got overmounted by tmpfs, so let's use the "backup" bind mount to
                                 * bring it back. */
                                ASSERT_OK(mkdir_p(build_dir, 0755));
                                ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, build_dir_mount, build_dir, NULL, MS_MOVE, NULL));
                        }
                }

                /* Prepare credstore like tmpfiles.d/credstore.conf for LoadCredential= tests. */
                FOREACH_STRING(p, "/run/credstore", "/run/credstore.encrypted") {
                        ASSERT_OK(mkdir_p(p, 0700));
                        ASSERT_OK(mount_nofollow_verbose(LOG_DEBUG, "tmpfs", p, "tmpfs", MS_NOSUID|MS_NODEV, "mode=0700"));
                }

                ASSERT_OK(write_string_file("/run/credstore/test-execute.load-credential", "foo", WRITE_STRING_FILE_CREATE));
        }

        return r;
}

TEST(run_tests_root) {
        _cleanup_strv_free_ char **filters = NULL;

        if (!have_namespaces())
                return (void) log_tests_skipped("unshare() is disabled");

        /* safe_fork() clears saved_argv in the child process. Let's copy it. */
        ASSERT_NOT_NULL((filters = strv_copy(strv_skip(saved_argv, 1))));

        if (prepare_ns("(test-execute-root)") == 0) {
                can_unshare = true;
                run_tests(RUNTIME_SCOPE_SYSTEM, filters);
                _exit(EXIT_SUCCESS);
        }
}

TEST(run_tests_without_unshare) {
        if (!have_namespaces()) {
                /* unshare() is already filtered. */
                can_unshare = false;
                run_tests(RUNTIME_SCOPE_SYSTEM, strv_skip(saved_argv, 1));
                return;
        }

#if HAVE_SECCOMP
        _cleanup_strv_free_ char **filters = NULL;
        int r;

        /* The following tests are for 1beab8b0d0ff2d7d1436b52d4a0c3d56dc908962. */
        if (!is_seccomp_available())
                return (void) log_tests_skipped("Seccomp not available, cannot run unshare() filtered tests");

        /* safe_fork() clears saved_argv in the child process. Let's copy it. */
        ASSERT_NOT_NULL((filters = strv_copy(strv_skip(saved_argv, 1))));

        if (prepare_ns("(test-execute-without-unshare)") == 0) {
                _cleanup_hashmap_free_ Hashmap *s = NULL;

                r = sym_seccomp_syscall_resolve_name("unshare");
                ASSERT_NE(r, __NR_SCMP_ERROR);
                ASSERT_OK(hashmap_ensure_put(&s, NULL, UINT32_TO_PTR(r + 1), INT_TO_PTR(-1)));
                ASSERT_OK(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EOPNOTSUPP), true));

                /* Check unshare() is actually filtered. */
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWNS), EOPNOTSUPP);

                can_unshare = false;
                run_tests(RUNTIME_SCOPE_SYSTEM, filters);
                _exit(EXIT_SUCCESS);
        }
#else
        log_tests_skipped("Built without seccomp support, cannot run unshare() filtered tests");
#endif
}

TEST(run_tests_unprivileged) {
        _cleanup_strv_free_ char **filters = NULL;

        if (!have_namespaces())
                return (void) log_tests_skipped("unshare() is disabled");

        /* safe_fork() clears saved_argv in the child process. Let's copy it. */
        ASSERT_NOT_NULL((filters = strv_copy(strv_skip(saved_argv, 1))));

        if (prepare_ns("(test-execute-unprivileged)") == 0) {
                ASSERT_OK(capability_bounding_set_drop(0, /* right_now= */ true));

                can_unshare = false;
                run_tests(RUNTIME_SCOPE_USER, filters);
                _exit(EXIT_SUCCESS);
        }
}

static int intro(void) {
        int r;

#if HAS_FEATURE_ADDRESS_SANITIZER
        if (strstr_ptr(ci_environment(), "travis") || strstr_ptr(ci_environment(), "github-actions"))
                return log_tests_skipped("Running on Travis CI/GH Actions under ASan, see https://github.com/systemd/systemd/issues/10696");
#endif
        /* It is needed otherwise cgroup creation fails */
        if (geteuid() != 0 || have_effective_cap(CAP_SYS_ADMIN) <= 0)
                return log_tests_skipped("not privileged");

        if (running_in_chroot() != 0)
                return log_tests_skipped("running in chroot");

        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        if (path_is_read_only_fs("/sys") > 0)
                return log_tests_skipped("/sys is mounted read-only");

        r = dlopen_libmount();
        if (r < 0)
                return log_tests_skipped("libmount not available.");

        /* Create dummy network interface for testing PrivateNetwork=yes */
        have_net_dummy = system("ip link add dummy-test-exec type dummy") == 0;

        if (have_net_dummy) {
                /* Create a network namespace and a dummy interface in it for NetworkNamespacePath= */
                have_netns = system("ip netns add test-execute-netns") == 0;
                have_netns = have_netns && system("ip netns exec test-execute-netns ip link add dummy-test-ns type dummy") == 0;
        }

        return EXIT_SUCCESS;
}

static int outro(void) {
        if (have_net_dummy) {
                (void) system("ip link del dummy-test-exec");
                (void) system("ip netns del test-execute-netns");
        }

        (void) rmdir(PRIVATE_UNIT_DIR);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, outro);
