/***
  This file is part of systemd.

  Copyright 2014 Ronny Chevalier

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>

#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "manager.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "unit.h"
#include "util.h"

typedef void (*test_function_t)(Manager *m);

static void check(Manager *m, Unit *unit, int status_expected, int code_expected) {
        Service *service = NULL;
        usec_t ts;
        usec_t timeout = 2 * USEC_PER_SEC;

        assert_se(m);
        assert_se(unit);

        service = SERVICE(unit);
        printf("%s\n", unit->id);
        exec_context_dump(&service->exec_context, stdout, "\t");
        ts = now(CLOCK_MONOTONIC);
        while (service->state != SERVICE_DEAD && service->state != SERVICE_FAILED) {
                int r;
                usec_t n;

                r = sd_event_run(m->event, 100 * USEC_PER_MSEC);
                assert_se(r >= 0);

                n = now(CLOCK_MONOTONIC);
                if (ts + timeout < n) {
                        log_error("Test timeout when testing %s", unit->id);
                        exit(EXIT_FAILURE);
                }
        }
        exec_status_dump(&service->main_exec_status, stdout, "\t");
        assert_se(service->main_exec_status.status == status_expected);
        assert_se(service->main_exec_status.code == code_expected);
}

static void test(Manager *m, const char *unit_name, int status_expected, int code_expected) {
        Unit *unit;

        assert_se(unit_name);

        assert_se(manager_load_unit(m, unit_name, NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);
        check(m, unit, status_expected, code_expected);
}

static void test_exec_workingdirectory(Manager *m) {
        assert_se(mkdir_p("/tmp/test-exec_workingdirectory", 0755) >= 0);

        test(m, "exec-workingdirectory.service", 0, CLD_EXITED);

        (void) rm_rf("/tmp/test-exec_workingdirectory", REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_exec_personality(Manager *m) {
#if defined(__x86_64__)
        test(m, "exec-personality-x86-64.service", 0, CLD_EXITED);

#elif defined(__s390__)
        test(m, "exec-personality-s390.service", 0, CLD_EXITED);

#else
        test(m, "exec-personality-x86.service", 0, CLD_EXITED);
#endif
}

static void test_exec_ignoresigpipe(Manager *m) {
        test(m, "exec-ignoresigpipe-yes.service", 0, CLD_EXITED);
        test(m, "exec-ignoresigpipe-no.service", SIGPIPE, CLD_KILLED);
}

static void test_exec_privatetmp(Manager *m) {
        assert_se(touch("/tmp/test-exec_privatetmp") >= 0);

        test(m, "exec-privatetmp-yes.service", 0, CLD_EXITED);
        test(m, "exec-privatetmp-no.service", 0, CLD_EXITED);

        unlink("/tmp/test-exec_privatetmp");
}

static void test_exec_privatedevices(Manager *m) {
        test(m, "exec-privatedevices-yes.service", 0, CLD_EXITED);
        test(m, "exec-privatedevices-no.service", 0, CLD_EXITED);
}

static void test_exec_systemcallfilter(Manager *m) {
#ifdef HAVE_SECCOMP
        test(m, "exec-systemcallfilter-not-failing.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-not-failing2.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-failing.service", SIGSYS, CLD_KILLED);
        test(m, "exec-systemcallfilter-failing2.service", SIGSYS, CLD_KILLED);
#endif
}

static void test_exec_systemcallerrornumber(Manager *m) {
#ifdef HAVE_SECCOMP
        test(m, "exec-systemcallerrornumber.service", 1, CLD_EXITED);
#endif
}

static void test_exec_user(Manager *m) {
        if (getpwnam("nobody"))
                test(m, "exec-user.service", 0, CLD_EXITED);
        else
                log_error_errno(errno, "Skipping test_exec_user, could not find nobody user: %m");
}

static void test_exec_group(Manager *m) {
        if (getgrnam("nobody"))
                test(m, "exec-group.service", 0, CLD_EXITED);
        else
                log_error_errno(errno, "Skipping test_exec_group, could not find nobody group: %m");
}

static void test_exec_environment(Manager *m) {
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
                "VAR3='$word 5 6'\n";
        int r;

        r = write_string_file("/tmp/test-exec_environmentfile.conf", e, WRITE_STRING_FILE_CREATE);
        assert_se(r == 0);

        test(m, "exec-environmentfile.service", 0, CLD_EXITED);

        unlink("/tmp/test-exec_environmentfile.conf");
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
        test(m, "exec-passenvironment.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-repeated.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-empty.service", 0, CLD_EXITED);
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);
        test(m, "exec-passenvironment-absent.service", 0, CLD_EXITED);
}

static void test_exec_umask(Manager *m) {
        test(m, "exec-umask-default.service", 0, CLD_EXITED);
        test(m, "exec-umask-0177.service", 0, CLD_EXITED);
}

static void test_exec_runtimedirectory(Manager *m) {
        test(m, "exec-runtimedirectory.service", 0, CLD_EXITED);
        test(m, "exec-runtimedirectory-mode.service", 0, CLD_EXITED);
        if (getgrnam("nobody"))
                test(m, "exec-runtimedirectory-owner.service", 0, CLD_EXITED);
        else
                log_error_errno(errno, "Skipping test_exec_runtimedirectory-owner, could not find nobody group: %m");
}

static void test_exec_capabilityboundingset(Manager *m) {
        int r;

        /* We use capsh to test if the capabilities are
         * properly set, so be sure that it exists */
        r = find_binary("capsh", NULL);
        if (r < 0) {
                log_error_errno(r, "Skipping test_exec_capabilityboundingset, could not find capsh binary: %m");
                return;
        }

        test(m, "exec-capabilityboundingset-simple.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-reset.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-merge.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-invert.service", 0, CLD_EXITED);
}

static void test_exec_privatenetwork(Manager *m) {
        int r;

        r = find_binary("ip", NULL);
        if (r < 0) {
                log_error_errno(r, "Skipping test_exec_privatenetwork, could not find ip binary: %m");
                return;
        }

        test(m, "exec-privatenetwork-yes.service", 0, CLD_EXITED);
}

static void test_exec_oomscoreadjust(Manager *m) {
        test(m, "exec-oomscoreadjust-positive.service", 0, CLD_EXITED);
        test(m, "exec-oomscoreadjust-negative.service", 0, CLD_EXITED);
}

static void test_exec_ioschedulingclass(Manager *m) {
        test(m, "exec-ioschedulingclass-none.service", 0, CLD_EXITED);
        test(m, "exec-ioschedulingclass-idle.service", 0, CLD_EXITED);
        test(m, "exec-ioschedulingclass-realtime.service", 0, CLD_EXITED);
        test(m, "exec-ioschedulingclass-best-effort.service", 0, CLD_EXITED);
}

int main(int argc, char *argv[]) {
        test_function_t tests[] = {
                test_exec_workingdirectory,
                test_exec_personality,
                test_exec_ignoresigpipe,
                test_exec_privatetmp,
                test_exec_privatedevices,
                test_exec_privatenetwork,
                test_exec_systemcallfilter,
                test_exec_systemcallerrornumber,
                test_exec_user,
                test_exec_group,
                test_exec_environment,
                test_exec_environmentfile,
                test_exec_passenvironment,
                test_exec_umask,
                test_exec_runtimedirectory,
                test_exec_capabilityboundingset,
                test_exec_oomscoreadjust,
                test_exec_ioschedulingclass,
                NULL,
        };
        test_function_t *test = NULL;
        Manager *m = NULL;
        int r;

        log_parse_environment();
        log_open();

        /* It is needed otherwise cgroup creation fails */
        if (getuid() != 0) {
                printf("Skipping test: not root\n");
                return EXIT_TEST_SKIP;
        }

        assert_se(setenv("XDG_RUNTIME_DIR", "/tmp/", 1) == 0);
        assert_se(set_unit_path(TEST_DIR "/test-execute/") >= 0);

        /* Unset VAR1, VAR2 and VAR3 which are used in the PassEnvironment test
         * cases, otherwise (and if they are present in the environment),
         * `manager_default_environment` will copy them into the default
         * environment which is passed to each created job, which will make the
         * tests that expect those not to be present to fail.
         */
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);

        r = manager_new(MANAGER_USER, true, &m);
        if (IN_SET(r, -EPERM, -EACCES, -EADDRINUSE, -EHOSTDOWN, -ENOENT)) {
                printf("Skipping test: manager_new: %s", strerror(-r));
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        for (test = tests; test && *test; test++)
                (*test)(m);

        manager_free(m);

        return 0;
}
