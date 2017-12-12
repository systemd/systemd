/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack
  Copyright 2017 Intel Corporation.

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

#include <linux/libbpf.h>
#include <string.h>
#include <unistd.h>

#include "bpf-firewall.h"
#include "bpf-program.h"
#include "load-fragment.h"
#include "manager.h"
#include "rm-rf.h"
#include "service.h"
#include "test-helper.h"
#include "tests.h"
#include "unit.h"

int main(int argc, char *argv[]) {
        struct bpf_insn exit_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        CGroupContext *cc = NULL;
        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;
        Manager *m = NULL;
        Unit *u, *u2;
        int r;
        const char *connection_test_path = NULL;
        const char *udp_test_path = NULL;
        char log_buf[65535];
        char cmd_buf[256];

        if (argc == 2)
                connection_test_path = argv[1];
        else {
#ifdef CONNECT_TEST_PATH
                connection_test_path = CONNECT_TEST_PATH;
#endif
        }

        if (argc == 3)
                udp_test_path = argv[2];
        else {
#ifdef RECEIVE_UDP_TEST_PATH
                udp_test_path = RECEIVE_UDP_TEST_PATH;
#endif
        }

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        assert(connection_test_path != NULL);
        log_notice("using connection test binary at '%s'", connection_test_path);

        assert(udp_test_path != NULL);
        log_notice("using UDP packet receive test binary at '%s'", udp_test_path);

        r = enter_cgroup_subroot();
        if (r == -ENOMEDIUM) {
                log_notice("cgroupfs not available, skipping tests");
                return EXIT_TEST_SKIP;
        }

        assert_se(set_unit_path(get_testdata_dir("")) >= 0);
        assert_se(runtime_dir = setup_fake_runtime_dir());

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, &p);
        assert(r == 0);

        r = bpf_program_add_instructions(p, exit_insn, ELEMENTSOF(exit_insn));
        assert(r == 0);

        if (getuid() != 0) {
                log_notice("Not running as root, skipping kernel related tests.");
                return EXIT_TEST_SKIP;
        }

        r = bpf_firewall_supported();
        if (r == 0) {
                log_notice("BPF firewalling not supported, skipping");
                return EXIT_TEST_SKIP;
        }
        assert_se(r > 0);

        r = bpf_program_load_kernel(p, log_buf, ELEMENTSOF(log_buf));
        assert(r >= 0);

        assert_se(manager_new(UNIT_FILE_USER, true, &m) >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        /*
         * Start a service to try out egress and ingress firewalling. Note: this
         * tests tries to bind and connect to TCP ports 17200 and 17230,
         * expecting that there was no service listening there previously. So if
         * the test fails, make sure that nothing is running at those ports.
         */

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "bpf-tcp-ports.service") == 0);
        assert_se(cc = unit_get_cgroup_context(u));
        u->perpetual = true;
        cc->ip_accounting = false;

        assert_se(config_parse_port_range_access(u->id, "filename", 1, "Service", 1, "IPPortEgressDeny", 0, "any/tcp", &cc->port_egress_deny, NULL) == 0);
        assert_se(config_parse_port_range_access(u->id, "filename", 1, "Service", 1, "IPPortEgressAllow", 0, "17200-17300/tcp", &cc->port_egress_allow, NULL) == 0);
        assert_se(config_parse_port_range_access(u->id, "filename", 1, "Service", 1, "IPPortIngressDeny", 0, "any/tcp", &cc->port_ingress_deny, NULL) == 0);
        assert_se(config_parse_port_range_access(u->id, "filename", 1, "Service", 1, "IPPortIngressAllow", 0, "17200-17300/tcp", &cc->port_ingress_allow, NULL) == 0);

        /*
         * Allowing addresses must not affect the port filtering.
         */
        assert_se(config_parse_ip_address_access(u->id, "filename", 1, "Service", 1, "IPAddressAllow", 0, "::1 127.0.0.1", &cc->ip_address_allow, NULL) == 0);

        /*
         * One item in egress deny list: [ 0/0 ]
         */

        assert(cc->port_egress_deny);
        assert(!cc->port_egress_deny->items_next);

        /*
         * Should have five items in egress allow list:
         * [ 17200/12 17216/10 17280/12 17296/14 17300/16 ]
         */

        assert(cc->port_egress_allow);
        assert(cc->port_egress_allow->items_next);
        assert(cc->port_egress_allow->items_next->items_next);
        assert(cc->port_egress_allow->items_next->items_next->items_next);
        assert(cc->port_egress_allow->items_next->items_next->items_next->items_next);
        assert(!cc->port_egress_allow->items_next->items_next->items_next->items_next->items_next);

        /*
         * The same items in ingress allow/deny lists.
         */

        assert(cc->port_ingress_deny);
        assert(!cc->port_ingress_deny->items_next);


        assert(cc->port_ingress_allow);
        assert(cc->port_ingress_allow->items_next);
        assert(cc->port_ingress_allow->items_next->items_next);
        assert(cc->port_ingress_allow->items_next->items_next->items_next);
        assert(cc->port_ingress_allow->items_next->items_next->items_next->items_next);
        assert(!cc->port_ingress_allow->items_next->items_next->items_next->items_next->items_next);

        /*
         * Port is open for egress and ingress, should go through the firewall
         * (successful connection).
         */

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17200 1s success", connection_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u)->exec_command, u) == 0);

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17299 1s success", connection_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u)->exec_command, u) == 0);

        /*
         * Blocked port, should be blocked by the firewall (1s timeout,
         * because packet is dropped).
         */

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17199 1s timeout", connection_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u)->exec_command, u) == 0);

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17301 1s timeout", connection_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u)->exec_command, u) == 0);

        /*
         * Ping (ICMP) needs to pass regardless of port
         * settings in the firewall.
         */

        assert_se(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, "/bin/ping -c 1 127.0.0.1 -W 5", SERVICE(u)->exec_command, u) == 0);

        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->command_next);
        assert_se(!SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->command_next->command_next);

        SERVICE(u)->type = SERVICE_ONESHOT;
        u->load_state = UNIT_LOADED;

        unit_dump(u, stdout, NULL);

        r = bpf_firewall_compile(u);
        if (IN_SET(r, -ENOTTY, -ENOSYS, -EPERM )) {
                /* Kernel doesn't support the necessary bpf bits, or masked out via seccomp? */
                manager_free(m);
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);

        assert(u->ip_bpf_egress);
        assert(u->ip_bpf_ingress);

#if 0
        r = bpf_program_load_kernel(u->ip_bpf_egress, log_buf, ELEMENTSOF(log_buf));

        log_notice("log:");
        log_notice("-------");
        printf("%s", log_buf);
        log_notice("-------");

        assert(r >= 0);
#endif
        /*
         * Unit_start finally calls bpf_firewall_install, which compiles
         * and attaches the firewall.
         */

        assert_se(unit_start(u) >= 0);

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED))
                assert_se(sd_event_run(m->event, UINT64_MAX) >= 0);

        /*
         * All tests should succeed -- connection-test returns
         * EXIT_SUCCESS if the outcome matches the result provided on
         * the command line.
         */

        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code == CLD_EXITED &&
                  SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next->command_next->command_next->exec_status.status == EXIT_SUCCESS);

        /*
         * Start a service to try out ingress firewalling. Note: this tests tries
         * to listen at UDP port 17301, expecting that there is no service listening
         * there. So if the test fails, make sure that nothing is running on those
         * ports.
         */

        /*
         * Check if 'udp6' command is available for connection testing. If not,
         * skip these tests. The command is available from
         * https://github.com/fgont/ipv6toolkit .
         */
        r = access("/usr/sbin/udp6", X_OK);
        if (r < 0) {
                log_notice("'/usr/sbin/udp6' not available, skipping");
                manager_free(m);
                return 0;
        }

        assert_se(u2 = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u2, "bpf-udp-ports.service") == 0);
        assert_se(cc = unit_get_cgroup_context(u2));
        u2->perpetual = true;
        cc->ip_accounting = false;

        assert_se(config_parse_port_range_access(u2->id, "filename", 1, "Service", 1, "IPPortIngressDeny", 0, "1-65535/udp", &cc->port_ingress_deny, NULL) == 0);
        assert_se(config_parse_port_range_access(u2->id, "filename", 1, "Service", 1, "IPPortIngressAllow", 0, "17301/udp", &cc->port_ingress_allow, NULL) == 0);

        /*
         * Sixteen item in ingress deny list:
         *   [ 1/16 2/15 4/14 8/13 16/12 32/11 64/10 128/9 256/8 512/7 1024/6 2048/5 4096/4 8192/3 16384/2 32768/1 ]
         * This is also the maximum possible list.
         */

        assert(cc->port_ingress_deny);

        /*
         * Should have one items in ingress allow list:
         *   [ 17301/16 ]
         */

        assert(cc->port_ingress_allow);
        assert(!cc->port_ingress_allow->items_next);

        /* Start the UDP packet receiving service. It also sends the packet. */

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17301 5s success /usr/sbin/udp6", udp_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u2->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u2)->exec_command, u2) == 0);

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17302 2s timeout /usr/sbin/udp6", udp_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u2->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u2)->exec_command, u2) == 0);

        snprintf(cmd_buf, sizeof(cmd_buf), "%s 17300 2s timeout /usr/sbin/udp6", udp_test_path);
        cmd_buf[sizeof(cmd_buf)-1] = '\0';
        assert_se(config_parse_exec(u2->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, cmd_buf, SERVICE(u2)->exec_command, u2) == 0);

        assert_se(SERVICE(u2)->exec_command[SERVICE_EXEC_START]);

        SERVICE(u2)->type = SERVICE_ONESHOT;
        u2->load_state = UNIT_LOADED;

        unit_dump(u2, stdout, NULL);

        r = bpf_firewall_compile(u2);
        if (IN_SET(r, -ENOTTY, -ENOSYS, -EPERM )) {
                /* Kernel doesn't support the necessary bpf bits, or masked out via seccomp? */
                manager_free(m);
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);

        /*
         * Unit_start finally calls bpf_firewall_install, which compiles
         * and attaches the firewall.
         */

        assert_se(unit_start(u2) >= 0);

        while (!IN_SET(SERVICE(u2)->state, SERVICE_DEAD, SERVICE_FAILED))
                assert_se(sd_event_run(m->event, UINT64_MAX) >= 0);

        /*
         * All tests should succeed -- connection-test returns
         * EXIT_SUCCESS if the outcome matches the result provided on
         * the command line.
         */

        assert_se(SERVICE(u2)->exec_command[SERVICE_EXEC_START]->exec_status.code == CLD_EXITED &&
                  SERVICE(u2)->exec_command[SERVICE_EXEC_START]->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u2)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u2)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.status == EXIT_SUCCESS);
        assert_se(SERVICE(u2)->exec_command[SERVICE_EXEC_START]->command_next->command_next->exec_status.code == CLD_EXITED &&
                  SERVICE(u2)->exec_command[SERVICE_EXEC_START]->command_next->command_next->exec_status.status == EXIT_SUCCESS);

        manager_free(m);

        return 0;
}
