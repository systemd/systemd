/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bpf-socket-bind.h"
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

static int find_netcat_executable(char **ret_path) {
        char **candidates = STRV_MAKE("ncat", "nc", "netcat");
        int r = 0;

        STRV_FOREACH(c, candidates) {
                r = find_executable(*c, ret_path);
                if (r == 0)
                        break;
        }

        return r;
}

static int test_socket_bind(
                Manager *m,
                const char *unit_name,
                const char *netcat_path,
                const char *port,
                char **allow_rules,
                char **deny_rules) {
        _cleanup_free_ char *exec_start = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        CGroupContext *cc = NULL;
        int cld_code, r;

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, unit_name) == 0);
        assert_se(cc = unit_get_cgroup_context(u));

        STRV_FOREACH(rule, allow_rules) {
                r = config_parse_cgroup_socket_bind(
                                u->id, "filename", 1, "Service", 1, "SocketBindAllow", 0,
                                *rule, &cc->socket_bind_allow, u);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to parse SocketBindAllow: %m");
        }

        fprintf(stderr, "SocketBindAllow:");
        LIST_FOREACH(socket_bind_items, bi, cc->socket_bind_allow)
                cgroup_context_dump_socket_bind_item(bi, stderr);
        fputc('\n', stderr);

        STRV_FOREACH(rule, deny_rules) {
                r = config_parse_cgroup_socket_bind(
                                u->id, "filename", 1, "Service", 1, "SocketBindDeny", 0,
                                *rule, &cc->socket_bind_deny, u);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to parse SocketBindDeny: %m");
        }

        fprintf(stderr, "SocketBindDeny:");
        LIST_FOREACH(socket_bind_items, bi, cc->socket_bind_deny)
                cgroup_context_dump_socket_bind_item(bi, stderr);
        fputc('\n', stderr);

        exec_start = strjoin("-timeout --preserve-status -sSIGTERM 1s ", netcat_path, " -l ", port, " -vv");
        assert_se(exec_start != NULL);

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
                        return log_error_errno(errno, "Event run failed %m");
        }

        cld_code = SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code;
        if (cld_code != CLD_EXITED)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "ExecStart didn't exited, code='%s'", sigchld_code_to_string(cld_code));

        if (SERVICE(u)->state != SERVICE_DEAD)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Service is not dead");

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *unit_dir = NULL, *netcat_path = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        struct rlimit rl;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (detect_container() > 0)
                return log_tests_skipped("test-socket-bind fails inside LXC and Docker containers: https://github.com/systemd/systemd/issues/9666");

        assert_se(getrlimit(RLIMIT_MEMLOCK, &rl) >= 0);
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit_closest(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock()");

        r = bpf_socket_bind_supported();
        if (r <= 0)
                return log_tests_skipped("socket-bind is not supported");

        if (find_netcat_executable(&netcat_path) != 0)
                return log_tests_skipped("Cannot find netcat executable");

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(get_testdata_dir("units", &unit_dir) >= 0);
        assert_se(set_unit_path(unit_dir) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());

        assert_se(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m) >= 0);
        assert_se(manager_startup(m, NULL, NULL, NULL) >= 0);

        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "2000", STRV_MAKE("2000"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "2000", STRV_MAKE("ipv6:2001-2002"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "6666", STRV_MAKE("ipv4:6666", "6667"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "6666", STRV_MAKE("6667", "6668", ""), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "7777", STRV_MAKE_EMPTY, STRV_MAKE_EMPTY) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "8888", STRV_MAKE("any"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "8888", STRV_MAKE("ipv6:tcp:8888-8889"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "10000", STRV_MAKE("ipv6:udp:9999-10000"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "6666", STRV_MAKE("ipv4:tcp:6666"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "6666", STRV_MAKE("ipv4:udp:6666"), STRV_MAKE("any")) >= 0);
        assert_se(test_socket_bind(m, "socket_bind_test.service", netcat_path, "6666", STRV_MAKE("tcp:6666"), STRV_MAKE("any")) >= 0);

        return 0;
}
