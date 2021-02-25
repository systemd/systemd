/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "load-fragment.h"
#include "manager.h"
#include "process-util.h"
#include "restrict-ifaces.h"
#include "rm-rf.h"
#include "service.h"
#include "strv.h"
#include "tests.h"
#include "unit.h"
#include "virt.h"

/* create_veth_pairs creates n network namespaces and n veth pairs. One
 * peer of each veth pair is moved to a different network namespace.
 * Each veth pair forms a /30 network, the first address of the subnet
 * is assigned to the peer in the network namespace and the next one to
 * the peer on the host network namespace. Pinging the address of the
 * peer in the network namespace forces the packets to pass through
 * the corresponding veth peer in the host network namespace.
 *
 * The IP address used to ping in this test are the following ones:
 * - basenetwork.1 -> veth0
 * - basenetwork.5 -> veth1
 * - basenetwork.9 -> veth2
 * - basenetwork.${4*N+1} -> veth${N}
 */

static int create_veth_pairs(int nveths, const char *basenetwork) {
        int r;
        char cmd[1024];
        const char setup_veth[] = "#! /bin/sh\n"
                                "set -euxo\n"
                                "for i in `seq 0 %d`;\n"
                                "do\n"
                                "    ip netns del ns${i} || true\n"
                                "    ip link del veth${i} || true\n"
                                "    ip netns add ns${i}\n"
                                "    ip link add veth${i} type veth peer name veth${i}_\n"
                                "    ip link set veth${i}_ netns ns${i}\n"
                                "    ip -n ns${i} link set dev veth${i}_ up\n"
                                "    ip -n ns${i} link set dev lo up\n"
                                "    ip -n ns${i} addr add %s$((4*i+1))/30 dev veth${i}_\n"
                                "    ip link set dev veth${i} up\n"
                                "    ip addr add %s$((4*i+2))/30 dev veth${i}\n"
                                "done";
        r = snprintf(cmd, sizeof(cmd), setup_veth, nveths-1, basenetwork, basenetwork);
        if ((size_t) r >= sizeof(cmd))
                return -1;
        r = system(cmd);
        if (r < 0)
                return r;
        if (WEXITSTATUS(r) != 0)
                return -1;
        return 0;
}

static void remove_veth_pairs(int *nveths) {
        int r;
        char cmd[1024];
        const char remove_veth[] = "#! /bin/sh\n"
                                "for i in `seq 0 %d`;\n"
                                "do\n"
                                "    ip netns del ns${i}\n"
                                "    ip link del veth${i}\n"
                                "done";
        r = snprintf(cmd, sizeof(cmd), remove_veth, *nveths-1);
        if ((size_t) r >= sizeof(cmd))
                return;
        (void) system(cmd);
}

typedef enum {
        NO_SET,
        FAIL,
        PASS
} PingResult;

struct command {
    const char *ip;
    PingResult expected_result;
};

static int test_restrict_ifaces(
                Manager *m,
                const char *unit_name,
                struct command *cmds,
                int ncmds,
                char **ifaces) {
        _cleanup_(unit_freep) Unit *u = NULL;
        CGroupContext *cc = NULL;
        char **iface;
        int cld_code, exit_status, r, i;
        ExecCommand *cmd;

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, unit_name) == 0);
        assert_se(cc = unit_get_cgroup_context(u));

        SERVICE(u)->type = SERVICE_ONESHOT;
        u->load_state = UNIT_LOADED;

        STRV_FOREACH(iface, ifaces) {
                r = config_parse_restrict_network_interfaces(
                                u->id, "filename", 1, "Service", 1, "RestrictNetworkInterfaces", 0,
                                *iface, cc, NULL);
                if (r < 0)
                        return log_unit_error_errno(u, r, "Failed to parse RestrictNetworkInterfaces: %m");
        }

        for (i = 0; i < ncmds; i++) {
                _cleanup_free_ char *exec_start = NULL;
                /* use -W (timeout) 0.2 to avoid waiting too much on tests that should fail */
                exec_start = strjoin("-/bin/ping -c 1 -W 0.2 ", cmds[i].ip);
                assert_se(exec_start);
                r = config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart",
                            SERVICE_EXEC_START, exec_start, SERVICE(u)->exec_command, u);
                if (r < 0)
                    return log_error_errno(r, "Failed to parse ExecStart");
        }

        r = unit_start(u);
        if (r < 0)
                return log_error_errno(r, "Unit start failed %m");

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED)) {
                r = sd_event_run(m->event, UINT64_MAX);
                if (r < 0)
                        return log_error_errno(errno, "Event run failed %m");
        }

        if (SERVICE(u)->state != SERVICE_DEAD)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Service is not dead");

        i = 0;
        LIST_FOREACH(command, cmd, SERVICE(u)->exec_command[SERVICE_EXEC_START]) {
                cld_code = cmd->exec_status.code;
                if (cld_code != CLD_EXITED)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                "ExecStart didn't exited, code='%s'", sigchld_code_to_string(cld_code));

                exit_status = cmd->exec_status.status;
                switch (cmds[i].expected_result) {
                case FAIL:
                        if (exit_status == EXIT_SUCCESS) {
                                log_error("ping to %s should have failed", cmds[i].ip);
                                return -1;
                        }
                        break;
                case PASS:
                        if (exit_status != EXIT_SUCCESS) {
                                log_error("ping to %s should *not* have failed", cmds[i].ip);
                                return -1;
                        }
                        break;
                default:
                        log_error("bad value for expected result");
                        return -1;
                }

                i++;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *unit_dir = NULL;
        const char *file = "restrict_ifaces.service";
        struct rlimit rl;
        char **strv;
        int r;

        _cleanup_(remove_veth_pairs) int nveths = 3;
        const char *basenetwork = "192.168.113.";
        const char *veth0_address = "192.168.113.1";
        const char *veth1_address = "192.168.113.5";
        const char *veth2_address = "192.168.113.9";

        test_setup_logging(LOG_DEBUG);

        if (detect_container() > 0)
                return log_tests_skipped("test-bpf fails inside LXC and Docker containers: https://github.com/systemd/systemd/issues/9666");

        if (getuid() != 0)
                return log_tests_skipped("not running as root");

        assert_se(getrlimit(RLIMIT_MEMLOCK, &rl) >= 0);
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock(), skipping.");

        r = restrict_network_interfaces_supported();
        if (r <= 0)
                return log_tests_skipped("RestrictNetworkInterfaces is not supported: %m");

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(get_testdata_dir("units", &unit_dir) >= 0);
        assert_se(set_unit_path(unit_dir) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());

        assert_se(manager_new(UNIT_FILE_USER, MANAGER_TEST_RUN_BASIC, &m) >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        assert_se(create_veth_pairs(nveths, basenetwork) == 0);

        /* All pings work when there's not restriction in place */
        strv = STRV_MAKE("");
        struct command cmds0[] = {
                {veth0_address, PASS},
                {veth1_address, PASS},
                {veth2_address, PASS},
        };
        assert_se(test_restrict_ifaces(m, file, cmds0, ELEMENTSOF(cmds0), strv) == 0);

        /* Test allow-list */
        strv = STRV_MAKE("veth0", "veth1");
        struct command cmds1[] = {
                {veth0_address, PASS},
                {veth1_address, PASS},
                {veth2_address, FAIL},
        };
        assert_se(test_restrict_ifaces(m, file, cmds1, ELEMENTSOF(cmds1), strv) == 0);

        /* Test deny-list */
        strv = STRV_MAKE("~veth0", "~veth1");
        struct command cmds2[] = {
                {veth0_address, FAIL},
                {veth1_address, FAIL},
                {veth2_address, PASS},
        };
        assert_se(test_restrict_ifaces(m, file, cmds2, ELEMENTSOF(cmds2), strv) == 0);

        /* Empty assignment resets the filter */
        strv = STRV_MAKE("veth0", "");
        struct command cmds3[] = {
                {veth0_address, PASS},
                {veth1_address, PASS},
                {veth2_address, PASS},
        };
        assert_se(test_restrict_ifaces(m, file, cmds3, ELEMENTSOF(cmds3), strv) == 0);

        /* Invert assigment removes from the set
         * Also checks that repeated interfaces don't cause issues.
         */
        strv = STRV_MAKE("veth0 veth0 veth1", "~veth0");
        struct command cmds4[] = {
                {veth0_address, FAIL},
                {veth1_address, PASS},
                {veth2_address, FAIL},
        };
        assert_se(test_restrict_ifaces(m, file, cmds4, ELEMENTSOF(cmds4), strv) == 0);

        return 0;
}
