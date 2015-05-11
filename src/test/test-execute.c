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

#include <stdio.h>

#include "unit.h"
#include "manager.h"
#include "util.h"
#include "macro.h"
#include "mkdir.h"
#include "rm-rf.h"

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
        test(m, "exec-personality-x86.service", 0, CLD_EXITED);

#if defined(__x86_64__)
        test(m, "exec-personality-x86-64.service", 0, CLD_EXITED);
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
        test(m, "exec-user.service", 0, CLD_EXITED);
}

static void test_exec_group(Manager *m) {
        test(m, "exec-group.service", 0, CLD_EXITED);
}

static void test_exec_environment(Manager *m) {
        test(m, "exec-environment.service", 0, CLD_EXITED);
        test(m, "exec-environment-multiple.service", 0, CLD_EXITED);
        test(m, "exec-environment-empty.service", 0, CLD_EXITED);
}

static void test_exec_umask(Manager *m) {
        test(m, "exec-umask-default.service", 0, CLD_EXITED);
        test(m, "exec-umask-0177.service", 0, CLD_EXITED);
}

int main(int argc, char *argv[]) {
        test_function_t tests[] = {
                test_exec_workingdirectory,
                test_exec_personality,
                test_exec_ignoresigpipe,
                test_exec_privatetmp,
                test_exec_privatedevices,
                test_exec_systemcallfilter,
                test_exec_systemcallerrornumber,
                test_exec_user,
                test_exec_group,
                test_exec_environment,
                test_exec_umask,
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

        assert_se(set_unit_path(TEST_DIR) >= 0);

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
