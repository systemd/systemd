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
#include <stdbool.h>

#include "unit.h"
#include "manager.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "mkdir.h"
#include "rm-rf.h"

typedef void (*test_function_t)(Manager *m);

static int setup_test(Manager **m) {
        char **tests_path = STRV_MAKE("exists", "existsglobFOOBAR", "changed", "modified", "unit",
                                      "directorynotempty", "makedirectory");
        char **test_path;
        Manager *tmp = NULL;
        int r;

        assert_se(m);

        r = manager_new(MANAGER_USER, true, &tmp);
        if (IN_SET(r, -EPERM, -EACCES, -EADDRINUSE, -EHOSTDOWN, -ENOENT, -ENOEXEC)) {
                printf("Skipping test: manager_new: %s", strerror(-r));
                return -EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);
        assert_se(manager_startup(tmp, NULL, NULL) >= 0);

        STRV_FOREACH(test_path, tests_path) {
                _cleanup_free_ char *p = NULL;

                p = strjoin("/tmp/test-path_", *test_path, NULL);
                assert_se(p);

                (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
        }

        *m = tmp;

        return 0;
}

static void shutdown_test(Manager *m) {
        assert_se(m);

        manager_free(m);
}

static void check_stop_unlink(Manager *m, Unit *unit, const char *test_path, const char *service_name) {
        _cleanup_free_ char *tmp = NULL;
        Unit *service_unit = NULL;
        Service *service = NULL;
        usec_t ts;
        usec_t timeout = 2 * USEC_PER_SEC;

        assert_se(m);
        assert_se(unit);
        assert_se(test_path);

        if (!service_name) {
                assert_se(tmp = strreplace(unit->id, ".path", ".service"));
                service_unit = manager_get_unit(m, tmp);
        } else
                service_unit = manager_get_unit(m, service_name);
        assert_se(service_unit);
        service = SERVICE(service_unit);

        ts = now(CLOCK_MONOTONIC);
        /* We process events until the service related to the path has been successfully started */
        while(service->result != SERVICE_SUCCESS || service->state != SERVICE_START) {
                usec_t n;
                int r;

                r = sd_event_run(m->event, 100 * USEC_PER_MSEC);
                assert_se(r >= 0);

                printf("%s: state = %s; result = %s \n",
                                service_unit->id,
                                service_state_to_string(service->state),
                                service_result_to_string(service->result));


                /* But we timeout if the service has not been started in the allocated time */
                n = now(CLOCK_MONOTONIC);
                if (ts + timeout < n) {
                        log_error("Test timeout when testing %s", unit->id);
                        exit(EXIT_FAILURE);
                }
        }

        assert_se(UNIT_VTABLE(unit)->stop(unit) >= 0);
        (void) rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL);
}

static void test_path_exists(Manager *m) {
        const char *test_path = "/tmp/test-path_exists";
        Unit *unit = NULL;

        assert_se(m);

        assert_se(manager_load_unit(m, "path-exists.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        assert_se(touch(test_path) >= 0);

        check_stop_unlink(m, unit, test_path, NULL);
}

static void test_path_existsglob(Manager *m) {
        const char *test_path = "/tmp/test-path_existsglobFOOBAR";
        Unit *unit = NULL;

        assert_se(m);
        assert_se(manager_load_unit(m, "path-existsglob.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        assert_se(touch(test_path) >= 0);

        check_stop_unlink(m, unit, test_path, NULL);
}

static void test_path_changed(Manager *m) {
        const char *test_path = "/tmp/test-path_changed";
        FILE *f;
        Unit *unit = NULL;

        assert_se(m);

        assert_se(touch(test_path) >= 0);

        assert_se(manager_load_unit(m, "path-changed.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        f = fopen(test_path, "w");
        assert_se(f);
        fclose(f);

        check_stop_unlink(m, unit, test_path, NULL);
}

static void test_path_modified(Manager *m) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *test_path = "/tmp/test-path_modified";
        Unit *unit = NULL;

        assert_se(m);

        assert_se(touch(test_path) >= 0);

        assert_se(manager_load_unit(m, "path-modified.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        f = fopen(test_path, "w");
        assert_se(f);
        fputs("test", f);

        check_stop_unlink(m, unit, test_path, NULL);
}

static void test_path_unit(Manager *m) {
        const char *test_path = "/tmp/test-path_unit";
        Unit *unit = NULL;

        assert_se(m);

        assert_se(manager_load_unit(m, "path-unit.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        assert_se(touch(test_path) >= 0);

        check_stop_unlink(m, unit, test_path, "path-mycustomunit.service");
}

static void test_path_directorynotempty(Manager *m) {
        const char *test_path = "/tmp/test-path_directorynotempty/";
        Unit *unit = NULL;

        assert_se(m);

        assert_se(access(test_path, F_OK) < 0);

        assert_se(manager_load_unit(m, "path-directorynotempty.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        /* MakeDirectory default to no */
        assert_se(access(test_path, F_OK) < 0);

        assert_se(mkdir_p(test_path, 0755) >= 0);
        assert_se(touch(strjoina(test_path, "test_file")) >= 0);

        check_stop_unlink(m, unit, test_path, NULL);
}

static void test_path_makedirectory_directorymode(Manager *m) {
        const char *test_path = "/tmp/test-path_makedirectory/";
        Unit *unit = NULL;
        struct stat s;

        assert_se(m);

        assert_se(access(test_path, F_OK) < 0);

        assert_se(manager_load_unit(m, "path-makedirectory.path", NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);

        /* Check if the directory has been created */
        assert_se(access(test_path, F_OK) >= 0);

        /* Check the mode we specified with DirectoryMode=0744 */
        assert_se(stat(test_path, &s) >= 0);
        assert_se((s.st_mode & S_IRWXU) == 0700);
        assert_se((s.st_mode & S_IRWXG) == 0040);
        assert_se((s.st_mode & S_IRWXO) == 0004);

        assert_se(UNIT_VTABLE(unit)->stop(unit) >= 0);
        (void) rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL);
}

int main(int argc, char *argv[]) {
        test_function_t tests[] = {
                test_path_exists,
                test_path_existsglob,
                test_path_changed,
                test_path_modified,
                test_path_unit,
                test_path_directorynotempty,
                test_path_makedirectory_directorymode,
                NULL,
        };
        test_function_t *test = NULL;
        Manager *m = NULL;

        log_parse_environment();
        log_open();

        assert_se(set_unit_path(TEST_DIR) >= 0);

        for (test = tests; test && *test; test++) {
                int r;

                /* We create a clean environment for each test */
                r = setup_test(&m);
                if (r < 0)
                        return -r;

                (*test)(m);

                shutdown_test(m);
        }

        return 0;
}
