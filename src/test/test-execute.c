/* SPDX-License-Identifier: LGPL-2.1+ */

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "capability-util.h"
#include "cpu-set-util.h"
#include "errno-list.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "manager.h"
#include "missing_prctl.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#if HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "service.h"
#include "stat-util.h"
#include "test-helper.h"
#include "tests.h"
#include "unit.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

static bool can_unshare;

typedef void (*test_function_t)(Manager *m);

static int cld_dumped_to_killed(int code) {
        /* Depending on the system, seccomp version, … some signals might result in dumping, others in plain
         * killing. Let's ignore the difference here, and map both cases to CLD_KILLED */
        return code == CLD_DUMPED ? CLD_KILLED : code;
}

static void wait_for_service_finish(Manager *m, Unit *unit) {
        Service *service = NULL;
        usec_t ts;
        usec_t timeout = 2 * USEC_PER_MINUTE;

        assert_se(m);
        assert_se(unit);

        service = SERVICE(unit);
        printf("%s\n", unit->id);
        exec_context_dump(&service->exec_context, stdout, "\t");
        ts = now(CLOCK_MONOTONIC);
        while (!IN_SET(service->state, SERVICE_DEAD, SERVICE_FAILED)) {
                int r;
                usec_t n;

                r = sd_event_run(m->event, 100 * USEC_PER_MSEC);
                assert_se(r >= 0);

                n = now(CLOCK_MONOTONIC);
                if (ts + timeout < n) {
                        log_error("Test timeout when testing %s", unit->id);
                        r = unit_kill(unit, KILL_ALL, SIGKILL, NULL);
                        if (r < 0)
                                log_error_errno(r, "Failed to kill %s: %m", unit->id);
                        exit(EXIT_FAILURE);
                }
        }
}

static void check_main_result(const char *func, Manager *m, Unit *unit, int status_expected, int code_expected) {
        Service *service = NULL;

        assert_se(m);
        assert_se(unit);

        wait_for_service_finish(m, unit);

        service = SERVICE(unit);
        exec_status_dump(&service->main_exec_status, stdout, "\t");

        if (cld_dumped_to_killed(service->main_exec_status.code) != cld_dumped_to_killed(code_expected)) {
                log_error("%s: %s: exit code %d, expected %d",
                          func, unit->id,
                          service->main_exec_status.code, code_expected);
                abort();
        }

        if (service->main_exec_status.status != status_expected) {
                log_error("%s: %s: exit status %d, expected %d",
                          func, unit->id,
                          service->main_exec_status.status, status_expected);
                abort();
        }
}

static void check_service_result(const char *func, Manager *m, Unit *unit, ServiceResult result_expected) {
        Service *service = NULL;

        assert_se(m);
        assert_se(unit);

        wait_for_service_finish(m, unit);

        service = SERVICE(unit);

        if (service->result != result_expected) {
                log_error("%s: %s: service end result %s, expected %s",
                          func, unit->id,
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

        assert(name);

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
        const char *p;

        FOREACH_STRING(p,
                "/run/systemd/inaccessible/reg",
                "/run/systemd/inaccessible/dir",
                "/run/systemd/inaccessible/chr",
                "/run/systemd/inaccessible/blk",
                "/run/systemd/inaccessible/fifo",
                "/run/systemd/inaccessible/sock"
        ) {
                if (access(p, F_OK) < 0)
                        return false;
        }

        return true;
}

static void test(const char *func, Manager *m, const char *unit_name, int status_expected, int code_expected) {
        Unit *unit;

        assert_se(unit_name);

        assert_se(manager_load_startable_unit_or_warn(m, unit_name, NULL, &unit) >= 0);
        assert_se(unit_start(unit) >= 0);
        check_main_result(func, m, unit, status_expected, code_expected);
}

static void test_service(const char *func, Manager *m, const char *unit_name, ServiceResult result_expected) {
        Unit *unit;

        assert_se(unit_name);

        assert_se(manager_load_startable_unit_or_warn(m, unit_name, NULL, &unit) >= 0);
        assert_se(unit_start(unit) >= 0);
        check_service_result(func, m, unit, result_expected);
}

static void test_exec_bindpaths(Manager *m) {
        assert_se(mkdir_p("/tmp/test-exec-bindpaths", 0755) >= 0);
        assert_se(mkdir_p("/tmp/test-exec-bindreadonlypaths", 0755) >= 0);

        test(__func__, m, "exec-bindpaths.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec-bindpaths", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/tmp/test-exec-bindreadonlypaths", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_cpuaffinity(Manager *m) {
        _cleanup_(cpu_set_reset) CPUSet c = {};

        assert_se(cpu_set_realloc(&c, 8192) >= 0); /* just allocate the maximum possible size */
        assert_se(sched_getaffinity(0, c.allocated, c.set) >= 0);

        if (!CPU_ISSET_S(0, c.allocated, c.set)) {
                log_notice("Cannot use CPU 0, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-cpuaffinity1.service", 0, CLD_EXITED);
        test(__func__, m, "exec-cpuaffinity2.service", 0, CLD_EXITED);

        if (!CPU_ISSET_S(1, c.allocated, c.set) ||
            !CPU_ISSET_S(2, c.allocated, c.set)) {
                log_notice("Cannot use CPU 1 or 2, skipping remaining tests in %s", __func__);
                return;
        }

        test(__func__, m, "exec-cpuaffinity3.service", 0, CLD_EXITED);
}

static void test_exec_workingdirectory(Manager *m) {
        assert_se(mkdir_p("/tmp/test-exec_workingdirectory", 0755) >= 0);

        test(__func__, m, "exec-workingdirectory.service", 0, CLD_EXITED);
        test(__func__, m, "exec-workingdirectory-trailing-dot.service", 0, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec_workingdirectory", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_personality(Manager *m) {
#if defined(__x86_64__)
        test(__func__, m, "exec-personality-x86-64.service", 0, CLD_EXITED);

#elif defined(__s390__)
        test(__func__, m, "exec-personality-s390.service", 0, CLD_EXITED);

#elif defined(__powerpc64__)
#  if __BYTE_ORDER == __BIG_ENDIAN
        test(__func__, m, "exec-personality-ppc64.service", 0, CLD_EXITED);
#  else
        test(__func__, m, "exec-personality-ppc64le.service", 0, CLD_EXITED);
#  endif

#elif defined(__aarch64__)
        test(__func__, m, "exec-personality-aarch64.service", 0, CLD_EXITED);

#elif defined(__i386__)
        test(__func__, m, "exec-personality-x86.service", 0, CLD_EXITED);
#else
        log_notice("Unknown personality, skipping %s", __func__);
#endif
}

static void test_exec_ignoresigpipe(Manager *m) {
        test(__func__, m, "exec-ignoresigpipe-yes.service", 0, CLD_EXITED);
        test(__func__, m, "exec-ignoresigpipe-no.service", SIGPIPE, CLD_KILLED);
}

static void test_exec_privatetmp(Manager *m) {
        assert_se(touch("/tmp/test-exec_privatetmp") >= 0);

        test(__func__, m, "exec-privatetmp-yes.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-privatetmp-no.service", 0, CLD_EXITED);

        unlink("/tmp/test-exec_privatetmp");
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

        test(__func__, m, "exec-privatedevices-yes.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-privatedevices-no.service", 0, CLD_EXITED);
        test(__func__, m, "exec-privatedevices-disabled-by-prefix.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);

        /* We use capsh to test if the capabilities are
         * properly set, so be sure that it exists */
        r = find_binary("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Could not find capsh binary, skipping remaining tests in %s: %m", __func__);
                return;
        }

        test(__func__, m, "exec-privatedevices-yes-capability-mknod.service", 0, CLD_EXITED);
        test(__func__, m, "exec-privatedevices-no-capability-mknod.service", 0, CLD_EXITED);
        test(__func__, m, "exec-privatedevices-yes-capability-sys-rawio.service", 0, CLD_EXITED);
        test(__func__, m, "exec-privatedevices-no-capability-sys-rawio.service", 0, CLD_EXITED);
}

static void test_exec_protecthome(Manager *m) {
        if (!can_unshare) {
                log_notice("Cannot reliably unshare, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-protecthome-tmpfs-vs-protectsystem-strict.service", 0, CLD_EXITED);
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

        r = find_binary("capsh", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find capsh binary: %m", __func__);
                return;
        }

        test(__func__, m, "exec-protectkernelmodules-no-capabilities.service", 0, CLD_EXITED);
        test(__func__, m, "exec-protectkernelmodules-yes-capabilities.service", 0, CLD_EXITED);
        test(__func__, m, "exec-protectkernelmodules-yes-mount-propagation.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_readonlypaths(Manager *m) {

        test(__func__, m, "exec-readonlypaths-simple.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);

        if (path_is_read_only_fs("/var") > 0) {
                log_notice("Directory /var is readonly, skipping remaining tests in %s", __func__);
                return;
        }

        test(__func__, m, "exec-readonlypaths.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-readonlypaths-with-bindpaths.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-readonlypaths-mount-propagation.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_readwritepaths(Manager *m) {

        if (path_is_read_only_fs("/") > 0) {
                log_notice("Root directory is readonly, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-readwritepaths-mount-propagation.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_inaccessiblepaths(Manager *m) {

        if (!is_inaccessible_available()) {
                log_notice("Testing without inaccessible, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-inaccessiblepaths-sys.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);

        if (path_is_read_only_fs("/") > 0) {
                log_notice("Root directory is readonly, skipping remaining tests in %s", __func__);
                return;
        }

        test(__func__, m, "exec-inaccessiblepaths-mount-propagation.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
}

static void test_exec_temporaryfilesystem(Manager *m) {

        test(__func__, m, "exec-temporaryfilesystem-options.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-temporaryfilesystem-ro.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-temporaryfilesystem-rw.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-temporaryfilesystem-usr.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
}

static void test_exec_systemcallfilter(Manager *m) {
#if HAVE_SECCOMP
        int r;

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-systemcallfilter-not-failing.service", 0, CLD_EXITED);
        test(__func__, m, "exec-systemcallfilter-not-failing2.service", 0, CLD_EXITED);
        test(__func__, m, "exec-systemcallfilter-failing.service", SIGSYS, CLD_KILLED);
        test(__func__, m, "exec-systemcallfilter-failing2.service", SIGSYS, CLD_KILLED);

        r = find_binary("python3", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping remaining tests in %s, could not find python3 binary: %m", __func__);
                return;
        }

        test(__func__, m, "exec-systemcallfilter-with-errno-name.service", errno_from_name("EILSEQ"), CLD_EXITED);
        test(__func__, m, "exec-systemcallfilter-with-errno-number.service", 255, CLD_EXITED);
        test(__func__, m, "exec-systemcallfilter-with-errno-multi.service", errno_from_name("EILSEQ"), CLD_EXITED);
#endif
}

static void test_exec_systemcallerrornumber(Manager *m) {
#if HAVE_SECCOMP
        int r;

        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        r = find_binary("python3", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find python3 binary: %m", __func__);
                return;
        }

        test(__func__, m, "exec-systemcallerrornumber-name.service", errno_from_name("EACCES"), CLD_EXITED);
        test(__func__, m, "exec-systemcallerrornumber-number.service", 255, CLD_EXITED);
#endif
}

static void test_exec_restrictnamespaces(Manager *m) {
#if HAVE_SECCOMP
        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping %s", __func__);
                return;
        }

        test(__func__, m, "exec-restrictnamespaces-no.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-yes.service", 1, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-mnt.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-mnt-blacklist.service", 1, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-merge-and.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-merge-or.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
        test(__func__, m, "exec-restrictnamespaces-merge-all.service", can_unshare ? 0 : EXIT_FAILURE, CLD_EXITED);
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

        test(__func__, m, "exec-systemcallfilter-system-user.service", 0, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(__func__, m, "exec-systemcallfilter-system-user-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
#endif
}

static void test_exec_user(Manager *m) {
        test(__func__, m, "exec-user.service", 0, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(__func__, m, "exec-user-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
}

static void test_exec_group(Manager *m) {
        test(__func__, m, "exec-group.service", 0, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_GROUP_NAME, "nobody", "nfsnobody", "nogroup")) {
                log_notice("Unsupported nobody group name '%s', skipping remaining tests in %s", NOBODY_GROUP_NAME, __func__);
                return;
        }

        test(__func__, m, "exec-group-" NOBODY_GROUP_NAME ".service", 0, CLD_EXITED);
}

static void test_exec_supplementarygroups(Manager *m) {
        test(__func__, m, "exec-supplementarygroups.service", 0, CLD_EXITED);
        test(__func__, m, "exec-supplementarygroups-single-group.service", 0, CLD_EXITED);
        test(__func__, m, "exec-supplementarygroups-single-group-user.service", 0, CLD_EXITED);
        test(__func__, m, "exec-supplementarygroups-multiple-groups-default-group-user.service", 0, CLD_EXITED);
        test(__func__, m, "exec-supplementarygroups-multiple-groups-withgid.service", 0, CLD_EXITED);
        test(__func__, m, "exec-supplementarygroups-multiple-groups-withuid.service", 0, CLD_EXITED);
}

static void test_exec_dynamicuser(Manager *m) {

        test(__func__, m, "exec-dynamicuser-fixeduser.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        if (check_user_has_group_with_same_name("adm"))
                test(__func__, m, "exec-dynamicuser-fixeduser-adm.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        if (check_user_has_group_with_same_name("games"))
                test(__func__, m, "exec-dynamicuser-fixeduser-games.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-dynamicuser-fixeduser-one-supplementarygroup.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-dynamicuser-supplementarygroups.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);
        test(__func__, m, "exec-dynamicuser-statedir.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        (void) rm_rf("/var/lib/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);

        test(__func__, m, "exec-dynamicuser-statedir-migrate-step1.service", 0, CLD_EXITED);
        test(__func__, m, "exec-dynamicuser-statedir-migrate-step2.service", can_unshare ? 0 : EXIT_NAMESPACE, CLD_EXITED);

        (void) rm_rf("/var/lib/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate", REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf("/var/lib/private/test-dynamicuser-migrate2", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_environment(Manager *m) {
        test(__func__, m, "exec-environment-no-substitute.service", 0, CLD_EXITED);
        test(__func__, m, "exec-environment.service", 0, CLD_EXITED);
        test(__func__, m, "exec-environment-multiple.service", 0, CLD_EXITED);
        test(__func__, m, "exec-environment-empty.service", 0, CLD_EXITED);
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
        assert_se(r == 0);

        test(__func__, m, "exec-environmentfile.service", 0, CLD_EXITED);

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
        assert_se(setenv("VAR1", "word1 word2", 1) == 0);
        assert_se(setenv("VAR2", "word3", 1) == 0);
        assert_se(setenv("VAR3", "$word 5 6", 1) == 0);
        assert_se(setenv("VAR4", "new\nline", 1) == 0);
        assert_se(setenv("VAR5", "passwordwithbackslashes", 1) == 0);
        test(__func__, m, "exec-passenvironment.service", 0, CLD_EXITED);
        test(__func__, m, "exec-passenvironment-repeated.service", 0, CLD_EXITED);
        test(__func__, m, "exec-passenvironment-empty.service", 0, CLD_EXITED);
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);
        assert_se(unsetenv("VAR4") == 0);
        assert_se(unsetenv("VAR5") == 0);
        test(__func__, m, "exec-passenvironment-absent.service", 0, CLD_EXITED);
}

static void test_exec_umask(Manager *m) {
        test(__func__, m, "exec-umask-default.service", 0, CLD_EXITED);
        test(__func__, m, "exec-umask-0177.service", 0, CLD_EXITED);
}

static void test_exec_runtimedirectory(Manager *m) {
        test(__func__, m, "exec-runtimedirectory.service", 0, CLD_EXITED);
        test(__func__, m, "exec-runtimedirectory-mode.service", 0, CLD_EXITED);
        test(__func__, m, "exec-runtimedirectory-owner.service", 0, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_GROUP_NAME, "nobody", "nfsnobody", "nogroup")) {
                log_notice("Unsupported nobody group name '%s', skipping remaining tests in %s", NOBODY_GROUP_NAME, __func__);
                return;
        }

        test(__func__, m, "exec-runtimedirectory-owner-" NOBODY_GROUP_NAME ".service", 0, CLD_EXITED);
}

static void test_exec_capabilityboundingset(Manager *m) {
        int r;

        r = find_binary("capsh", NULL);
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

        test(__func__, m, "exec-capabilityboundingset-simple.service", 0, CLD_EXITED);
        test(__func__, m, "exec-capabilityboundingset-reset.service", 0, CLD_EXITED);
        test(__func__, m, "exec-capabilityboundingset-merge.service", 0, CLD_EXITED);
        test(__func__, m, "exec-capabilityboundingset-invert.service", 0, CLD_EXITED);
}

static void test_exec_basic(Manager *m) {
        test(__func__, m, "exec-basic.service", 0, CLD_EXITED);
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

        test(__func__, m, "exec-ambientcapabilities.service", 0, CLD_EXITED);
        test(__func__, m, "exec-ambientcapabilities-merge.service", 0, CLD_EXITED);

        if (!check_nobody_user_and_group()) {
                log_notice("nobody user/group is not synthesized or may conflict to other entries, skipping remaining tests in %s", __func__);
                return;
        }

        if (!STR_IN_SET(NOBODY_USER_NAME, "nobody", "nfsnobody")) {
                log_notice("Unsupported nobody user name '%s', skipping remaining tests in %s", NOBODY_USER_NAME, __func__);
                return;
        }

        test(__func__, m, "exec-ambientcapabilities-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
        test(__func__, m, "exec-ambientcapabilities-merge-" NOBODY_USER_NAME ".service", 0, CLD_EXITED);
}

static void test_exec_privatenetwork(Manager *m) {
        int r;

        r = find_binary("ip", NULL);
        if (r < 0) {
                log_notice_errno(r, "Skipping %s, could not find ip binary: %m", __func__);
                return;
        }

        test(__func__, m, "exec-privatenetwork-yes.service", can_unshare ? 0 : EXIT_NETWORK, CLD_EXITED);
}

static void test_exec_oomscoreadjust(Manager *m) {
        test(__func__, m, "exec-oomscoreadjust-positive.service", 0, CLD_EXITED);

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping remaining tests in %s", __func__);
                return;
        }
        test(__func__, m, "exec-oomscoreadjust-negative.service", 0, CLD_EXITED);
}

static void test_exec_ioschedulingclass(Manager *m) {
        test(__func__, m, "exec-ioschedulingclass-none.service", 0, CLD_EXITED);
        test(__func__, m, "exec-ioschedulingclass-idle.service", 0, CLD_EXITED);
        test(__func__, m, "exec-ioschedulingclass-best-effort.service", 0, CLD_EXITED);

        if (detect_container() > 0) {
                log_notice("Testing in container, skipping remaining tests in %s", __func__);
                return;
        }
        test(__func__, m, "exec-ioschedulingclass-realtime.service", 0, CLD_EXITED);
}

static void test_exec_unsetenvironment(Manager *m) {
        test(__func__, m, "exec-unsetenvironment.service", 0, CLD_EXITED);
}

static void test_exec_specifier(Manager *m) {
        test(__func__, m, "exec-specifier.service", 0, CLD_EXITED);
        test(__func__, m, "exec-specifier@foo-bar.service", 0, CLD_EXITED);
        test(__func__, m, "exec-specifier-interpolation.service", 0, CLD_EXITED);
}

static void test_exec_standardinput(Manager *m) {
        test(__func__, m, "exec-standardinput-data.service", 0, CLD_EXITED);
        test(__func__, m, "exec-standardinput-file.service", 0, CLD_EXITED);
}

static void test_exec_standardoutput(Manager *m) {
        test(__func__, m, "exec-standardoutput-file.service", 0, CLD_EXITED);
}

static void test_exec_standardoutput_append(Manager *m) {
        test(__func__, m, "exec-standardoutput-append.service", 0, CLD_EXITED);
}

static void test_exec_condition(Manager *m) {
        test_service(__func__, m, "exec-condition-failed.service", SERVICE_FAILURE_EXIT_CODE);
        test_service(__func__, m, "exec-condition-skip.service", SERVICE_SKIP_CONDITION);
}

typedef struct test_entry {
        test_function_t f;
        const char *name;
} test_entry;

#define entry(x) {x, #x}

static int run_tests(UnitFileScope scope, const test_entry tests[], char **patterns) {
        const test_entry *test = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert_se(tests);

        r = manager_new(scope, MANAGER_TEST_RUN_BASIC, &m);
        if (MANAGER_SKIP_TEST(r))
                return log_tests_skipped_errno(r, "manager_new");
        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        for (test = tests; test && test->f; test++)
                if (strv_fnmatch_or_empty(patterns, test->name, FNM_NOESCAPE))
                        test->f(m);
                else
                        log_info("Skipping %s because it does not match any pattern.", test->name);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_free_ char *test_execute_path = NULL;

        static const test_entry user_tests[] = {
                entry(test_exec_basic),
                entry(test_exec_ambientcapabilities),
                entry(test_exec_bindpaths),
                entry(test_exec_capabilityboundingset),
                entry(test_exec_condition),
                entry(test_exec_cpuaffinity),
                entry(test_exec_environment),
                entry(test_exec_environmentfile),
                entry(test_exec_group),
                entry(test_exec_ignoresigpipe),
                entry(test_exec_inaccessiblepaths),
                entry(test_exec_ioschedulingclass),
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
                entry(test_exec_standardinput),
                entry(test_exec_standardoutput),
                entry(test_exec_standardoutput_append),
                entry(test_exec_supplementarygroups),
                entry(test_exec_systemcallerrornumber),
                entry(test_exec_systemcallfilter),
                entry(test_exec_temporaryfilesystem),
                entry(test_exec_umask),
                entry(test_exec_unsetenvironment),
                entry(test_exec_user),
                entry(test_exec_workingdirectory),
                {},
        };
        static const test_entry system_tests[] = {
                entry(test_exec_dynamicuser),
                entry(test_exec_specifier),
                entry(test_exec_systemcallfilter_system),
                {},
        };
        int r;

        test_setup_logging(LOG_DEBUG);

#if HAS_FEATURE_ADDRESS_SANITIZER
        if (is_run_on_travis_ci()) {
                log_notice("Running on TravisCI under ASan, skipping, see https://github.com/systemd/systemd/issues/10696");
                return EXIT_TEST_SKIP;
        }
#endif

        (void) unsetenv("USER");
        (void) unsetenv("LOGNAME");
        (void) unsetenv("SHELL");
        (void) unsetenv("HOME");

        can_unshare = have_namespaces();

        /* It is needed otherwise cgroup creation fails */
        if (getuid() != 0)
                return log_tests_skipped("not root");

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(runtime_dir = setup_fake_runtime_dir());
        test_execute_path = path_join(get_testdata_dir(), "test-execute");
        assert_se(set_unit_path(test_execute_path) >= 0);

        /* Unset VAR1, VAR2 and VAR3 which are used in the PassEnvironment test
         * cases, otherwise (and if they are present in the environment),
         * `manager_default_environment` will copy them into the default
         * environment which is passed to each created job, which will make the
         * tests that expect those not to be present to fail.
         */
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);

        r = run_tests(UNIT_FILE_USER, user_tests, argv + 1);
        if (r != 0)
                return r;

        r = run_tests(UNIT_FILE_SYSTEM, system_tests, argv + 1);
        if (r != 0)
                return r;

#if HAVE_SECCOMP
        /* The following tests are for 1beab8b0d0ff2d7d1436b52d4a0c3d56dc908962. */
        if (!is_seccomp_available()) {
                log_notice("Seccomp not available, skipping unshare() filtered tests.");
                return 0;
        }

        _cleanup_hashmap_free_ Hashmap *s = NULL;
        assert_se(s = hashmap_new(NULL));
        r = seccomp_syscall_resolve_name("unshare");
        assert_se(r != __NR_SCMP_ERROR);
        assert_se(hashmap_put(s, UINT32_TO_PTR(r + 1), INT_TO_PTR(-1)) >= 0);
        assert_se(seccomp_load_syscall_filter_set_raw(SCMP_ACT_ALLOW, s, SCMP_ACT_ERRNO(EOPNOTSUPP), true) >= 0);
        assert_se(unshare(CLONE_NEWNS) < 0);
        assert_se(errno == EOPNOTSUPP);

        can_unshare = false;

        r = run_tests(UNIT_FILE_USER, user_tests, argv + 1);
        if (r != 0)
                return r;

        return run_tests(UNIT_FILE_SYSTEM, system_tests, argv + 1);
#else
        return 0;
#endif
}
