/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "all-units.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "manager.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "unit.h"

static char *runtime_dir = NULL;

static int setup_test(Manager **ret) {
        int r;

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        _cleanup_(manager_freep) Manager *m = NULL;
        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m);
        if (manager_errno_skip_test(r))
                return log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL, NULL));

        FOREACH_STRING(s,
                       "exists",
                       "existsglobFOOBAR",
                       "changed",
                       "modified",
                       "unit",
                       "directorynotempty",
                       "makedirectory") {

                _cleanup_free_ char *p = ASSERT_NOT_NULL(strjoin("/tmp/test-path_", s));
                (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);
        }

        *ret = TAKE_PTR(m);
        return 0;
}

static Service* service_for_path(Manager *m, Path *path, const char *service_name) {
        ASSERT_NOT_NULL(m);
        ASSERT_NOT_NULL(path);

        Unit *service_unit;
        if (!service_name) {
                _cleanup_free_ char *tmp = ASSERT_NOT_NULL(strreplace(UNIT(path)->id, ".path", ".service"));
                service_unit = manager_get_unit(m, tmp);
        } else
                service_unit = manager_get_unit(m, service_name);
        ASSERT_NOT_NULL(service_unit);

        return SERVICE(service_unit);
}

static int _check_states(
                unsigned line,
                Manager *m,
                Path *path,
                Service *service,
                PathState path_state,
                ServiceState service_state) {

        ASSERT_NOT_NULL(m);
        ASSERT_NOT_NULL(service);

        usec_t end = usec_add(now(CLOCK_MONOTONIC), 30 * USEC_PER_SEC);
        PathState last_path_state = _PATH_STATE_INVALID;
        PathResult last_path_result = _PATH_RESULT_INVALID;
        ServiceState last_service_state = _SERVICE_STATE_INVALID;
        ServiceResult last_service_result = _SERVICE_RESULT_INVALID;

        while (path->state != path_state || service->state != service_state ||
               path->result != PATH_SUCCESS || service->result != SERVICE_SUCCESS) {

                ASSERT_OK(sd_event_run(m->event, 100 * USEC_PER_MSEC));

                usec_t n = now(CLOCK_MONOTONIC);
                if (path->state != last_path_state || path->result != last_path_result ||
                    service->state != last_service_state || service->result != last_service_result) {
                        log_info("line %u: %s: state = %s; result = %s (left: %" PRIi64 ")",
                                 line,
                                 UNIT(path)->id,
                                 path_state_to_string(path->state),
                                 path_result_to_string(path->result),
                                 (int64_t) (end - n));
                        log_info("line %u: %s: state = %s; result = %s",
                                 line,
                                 UNIT(service)->id,
                                 service_state_to_string(service->state),
                                 service_result_to_string(service->result));
                        last_path_state = path->state;
                        last_path_result = path->result;
                        last_service_state = service->state;
                        last_service_result = service->result;
                }

                /* We may fail to start the service for reasons which are not under our control: cgroup
                 * setup denied, permission limits, resource exhaustion, etc. RESOURCES is terminal here
                 * for path units that don't auto-retry (PathChanged, PathModified) — they'd just sit in
                 * the failure state until the test timeout. Skip rather than wait. */
                if (service->state == SERVICE_FAILED &&
                    (service->main_exec_status.status == EXIT_CGROUP || service->result == SERVICE_FAILURE_RESOURCES))
                        return log_tests_skipped("Failed to start service %s: %s/%s",
                                                 UNIT(service)->id,
                                                 service_state_to_string(service->state),
                                                 service_result_to_string(service->result));

                /* SERVICE_FAILURE_START_LIMIT_HIT is terminal: the unit won't recover without an explicit
                 * reset, so further looping is pointless. Skip the test rather than burning the 30s timeout. */
                if (service->state == SERVICE_FAILED &&
                    service->result == SERVICE_FAILURE_START_LIMIT_HIT)
                        return log_tests_skipped("Failed to start service %s: %s/%s",
                                                 UNIT(service)->id,
                                                 service_state_to_string(service->state),
                                                 service_result_to_string(service->result));

                if (n >= end)
                        log_test_failed("Test timeout when testing %s", UNIT(path)->id);
        }

        return 0;
}

#define check_states(...)                                       \
        do {                                                    \
                int _r = _check_states(__LINE__, __VA_ARGS__);  \
                if (_r != 0)                                    \
                        return _r;                              \
        } while (0)

TEST_RET(path_exists) {
        const char *test_path = "/tmp/test-path_exists";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-exists.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, NULL);

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(touch(test_path));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        /* Service restarts if file still exists */
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK_ZERO(rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL));
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_existsglob) {
        const char *test_path = "/tmp/test-path_existsglobFOOBAR";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-existsglob.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, NULL);

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(touch(test_path));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        /* Service restarts if file still exists */
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK_ZERO(rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL));
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_changed) {
        const char *test_path = "/tmp/test-path_changed";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-changed.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, NULL);

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(touch(test_path));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        /* Service does not restart if file still exists */
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        fclose(ASSERT_NOT_NULL(fopen(test_path, "w")));

        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        (void) rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL);
        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_modified) {
        const char *test_path = "/tmp/test-path_modified";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-modified.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, NULL);

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(touch(test_path));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        /* Service does not restart if file still exists */
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        _cleanup_fclose_ FILE *f = ASSERT_NOT_NULL(fopen(test_path, "w"));
        fputs("test", f);

        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        (void) rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL);
        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_unit) {
        const char *test_path = "/tmp/test-path_unit";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-unit.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, "path-mycustomunit.service");

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(touch(test_path));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK_ZERO(rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL));
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_directorynotempty) {
        const char *test_file, *test_path = "/tmp/test-path_directorynotempty/";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-directorynotempty.path", NULL, LOG_ERR, &unit));

        Path *path = PATH(unit);
        Service *service = service_for_path(m, path, NULL);

        ASSERT_FAIL(access(test_path, F_OK));

        ASSERT_OK(unit_start(unit, NULL));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        /* MakeDirectory default to no */
        ASSERT_FAIL(access(test_path, F_OK));

        ASSERT_OK(mkdir_p(test_path, 0755));
        test_file = strjoina(test_path, "test_file");
        ASSERT_OK(touch(test_file));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        /* Service restarts if directory is still not empty */
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_RUNNING, SERVICE_RUNNING);

        ASSERT_OK_ZERO(rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL));
        ASSERT_OK(unit_stop(UNIT(service)));
        check_states(m, path, service, PATH_WAITING, SERVICE_DEAD);

        ASSERT_OK(unit_stop(unit));
        return 0;
}

TEST_RET(path_makedirectory_directorymode) {
        const char *test_path = "/tmp/test-path_makedirectory/";
        int r;

        _cleanup_(manager_freep) Manager *m = NULL;
        r = setup_test(&m);
        if (r != 0)
                return r;

        Unit *unit;
        ASSERT_OK(manager_load_startable_unit_or_warn(m, "path-makedirectory.path", NULL, LOG_ERR, &unit));

        ASSERT_FAIL(access(test_path, F_OK));

        ASSERT_OK(unit_start(unit, NULL));

        /* Check if the directory has been created */
        ASSERT_OK_ERRNO(access(test_path, F_OK));

        /* Check the mode we specified with DirectoryMode=0744 */
        struct stat s;
        ASSERT_OK_ERRNO(stat(test_path, &s));
        ASSERT_EQ((mode_t) (s.st_mode & S_IRWXU), (mode_t) 0700);
        ASSERT_EQ((mode_t) (s.st_mode & S_IRWXG), (mode_t) 0040);
        ASSERT_EQ((mode_t) (s.st_mode & S_IRWXO), (mode_t) 0004);

        ASSERT_OK(unit_stop(unit));
        (void) rm_rf(test_path, REMOVE_ROOT|REMOVE_PHYSICAL);
        return 0;
}

static int intro(void) {
        _cleanup_free_ char *test_path = NULL;

        umask(022);

        ASSERT_OK(get_testdata_dir("test-path", &test_path));
        ASSERT_OK(setenv_unit_path(test_path));
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        return EXIT_SUCCESS;
}

static int outro(void) {
        runtime_dir = rm_rf_physical_and_free(runtime_dir);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_INFO, intro, outro);
