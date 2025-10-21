/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/bpf.h>
#include <linux/bpf_insn.h>
#include <unistd.h>

#include "bpf-firewall.h"
#include "bpf-program.h"
#include "cgroup-setup.h"
#include "in-addr-prefix-util.h"
#include "load-fragment.h"
#include "manager.h"
#include "path-util.h"
#include "rm-rf.h"
#include "service.h"
#include "set.h"
#include "tests.h"
#include "unit-serialize.h"
#include "virt.h"

int main(int argc, char *argv[]) {
        const struct bpf_insn exit_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 0), /* drop */
                BPF_EXIT_INSN()
        };

        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        CGroupContext *cc = NULL;
        _cleanup_(bpf_program_freep) BPFProgram *p = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        char log_buf[65535];
        struct rlimit rl;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (detect_container() > 0)
                return log_tests_skipped("test-bpf-firewall fails inside LXC and Docker containers: https://github.com/systemd/systemd/issues/9666");

        r = bpf_program_supported();
        if (r < 0)
                return log_tests_skipped_errno(r, "BPF firewalling not supported");
        ASSERT_TRUE(r);

        ASSERT_OK(getrlimit(RLIMIT_MEMLOCK, &rl));
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock()");

        if (cg_is_ready() <= 0)
                return log_tests_skipped("Unified hierarchy is required");

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        r = find_executable("ping", NULL);
        if (r < 0)
                return log_tests_skipped_errno(r, "Can't find ping binary: %m");

        _cleanup_free_ char *unit_dir = NULL;
        ASSERT_OK(get_testdata_dir("units", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        ASSERT_OK(bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, "sd_trivial", &p));
        ASSERT_OK(bpf_program_add_instructions(p, exit_insn, ELEMENTSOF(exit_insn)));
        ASSERT_OK(bpf_program_load_kernel(p, log_buf, ELEMENTSOF(log_buf)));

        const char *test_prog = "/sys/fs/bpf/test-dropper";
        (void) unlink(test_prog);
        ASSERT_OK(bpf_program_pin(p->kernel_fd, test_prog));

        p = bpf_program_free(p);

        /* The simple tests succeeded. Now let's try full unit-based use-case. */

        ASSERT_OK(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m));
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL));

        ASSERT_NOT_NULL(u = unit_new(m, sizeof(Service)));
        ASSERT_EQ(unit_add_name(u, "foo.service"), 0);
        ASSERT_NOT_NULL(cc = unit_get_cgroup_context(u));
        u->perpetual = true;

        cc->ip_accounting = true;

        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressAllow", 0, "10.0.1.0/24", &cc->ip_address_allow, NULL), 0);
        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressAllow", 0, "127.0.0.2", &cc->ip_address_allow, NULL), 0);
        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressDeny", 0, "127.0.0.3", &cc->ip_address_deny, NULL), 0);
        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressDeny", 0, "10.0.3.2/24", &cc->ip_address_deny, NULL), 0);
        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressDeny", 0, "127.0.0.1/25", &cc->ip_address_deny, NULL), 0);
        ASSERT_EQ(config_parse_in_addr_prefixes(u->id, "filename", 1, "Service", 1, "IPAddressDeny", 0, "127.0.0.4", &cc->ip_address_deny, NULL), 0);

        ASSERT_EQ(set_size(cc->ip_address_allow), 2u);
        ASSERT_EQ(set_size(cc->ip_address_deny), 4u);

        /* The deny list is defined redundantly, let's ensure it will be properly reduced */
        ASSERT_OK(in_addr_prefixes_reduce(cc->ip_address_allow));
        ASSERT_OK(in_addr_prefixes_reduce(cc->ip_address_deny));

        ASSERT_EQ(set_size(cc->ip_address_allow), 2u);
        ASSERT_EQ(set_size(cc->ip_address_deny), 2u);

        ASSERT_TRUE(set_contains(cc->ip_address_allow, &(struct in_addr_prefix) {
                                .family = AF_INET,
                                .address.in.s_addr = htobe32((UINT32_C(10) << 24) | (UINT32_C(1) << 8)),
                                .prefixlen = 24 }));
        ASSERT_TRUE(set_contains(cc->ip_address_allow, &(struct in_addr_prefix) {
                                .family = AF_INET,
                                .address.in.s_addr = htobe32(0x7f000002),
                                .prefixlen = 32 }));
        ASSERT_TRUE(set_contains(cc->ip_address_deny, &(struct in_addr_prefix) {
                                .family = AF_INET,
                                .address.in.s_addr = htobe32(0x7f000000),
                                .prefixlen = 25 }));
        ASSERT_TRUE(set_contains(cc->ip_address_deny, &(struct in_addr_prefix) {
                                .family = AF_INET,
                                .address.in.s_addr = htobe32((UINT32_C(10) << 24) | (UINT32_C(3) << 8)),
                                .prefixlen = 24 }));

        ASSERT_OK(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, "/bin/ping -c 1 127.0.0.2 -W 5", SERVICE(u)->exec_command, u));
        ASSERT_OK(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, "/bin/ping -c 1 127.0.0.3 -W 5", SERVICE(u)->exec_command, u));

        ASSERT_NOT_NULL(SERVICE(u)->exec_command[SERVICE_EXEC_START]);
        ASSERT_NOT_NULL(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next);
        ASSERT_NULL(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->command_next);

        SERVICE(u)->type = SERVICE_ONESHOT;
        u->load_state = UNIT_LOADED;

        CGroupRuntime *crt = ASSERT_PTR(unit_setup_cgroup_runtime(u));

        unit_dump(u, stdout, NULL);

        r = bpf_firewall_compile(u);
        if (IN_SET(r, -ENOTTY, -ENOSYS, -EPERM))
                return log_tests_skipped("Kernel doesn't support the necessary bpf bits (masked out via seccomp?)");
        ASSERT_OK(r);

        ASSERT_NOT_NULL(crt->ip_bpf_ingress);
        ASSERT_NOT_NULL(crt->ip_bpf_egress);

        r = bpf_program_load_kernel(crt->ip_bpf_ingress, log_buf, ELEMENTSOF(log_buf));

        log_notice("log:");
        log_notice("-------");
        log_notice("%s", log_buf);
        log_notice("-------");

        ASSERT_OK(r);

        r = bpf_program_load_kernel(crt->ip_bpf_egress, log_buf, ELEMENTSOF(log_buf));

        log_notice("log:");
        log_notice("-------");
        log_notice("%s", log_buf);
        log_notice("-------");

        ASSERT_OK(r);

        ASSERT_OK(unit_patch_contexts(u));
        ASSERT_OK(unit_start(u, NULL));

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED))
                ASSERT_OK(sd_event_run(m->event, UINT64_MAX));

        ASSERT_EQ(SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code, CLD_EXITED);
        ASSERT_EQ(SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.status, EXIT_SUCCESS);

        ASSERT_TRUE(SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.code != CLD_EXITED ||
                    SERVICE(u)->exec_command[SERVICE_EXEC_START]->command_next->exec_status.status != EXIT_SUCCESS);

        /* testing custom filter */
        ASSERT_NOT_NULL(u = unit_new(m, sizeof(Service)));
        ASSERT_OK(unit_add_name(u, "custom-filter.service"));
        ASSERT_NOT_NULL(cc = unit_get_cgroup_context(u));
        u->perpetual = true;

        cc->ip_accounting = true;

        ASSERT_OK(config_parse_ip_filter_bpf_progs(u->id, "filename", 1, "Service", 1, "IPIngressFilterPath", 0, test_prog, &cc->ip_filters_ingress, u));
        ASSERT_OK(config_parse_exec(u->id, "filename", 1, "Service", 1, "ExecStart", SERVICE_EXEC_START, "-/bin/ping -c 1 127.0.0.1 -W 5", SERVICE(u)->exec_command, u));

        SERVICE(u)->type = SERVICE_ONESHOT;
        u->load_state = UNIT_LOADED;

        ASSERT_OK(unit_patch_contexts(u));
        ASSERT_OK(unit_start(u, NULL));

        while (!IN_SET(SERVICE(u)->state, SERVICE_DEAD, SERVICE_FAILED))
                ASSERT_OK(sd_event_run(m->event, UINT64_MAX));

        ASSERT_TRUE(SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code != CLD_EXITED ||
                    SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.status != EXIT_SUCCESS);

        (void) unlink(test_prog);
        ASSERT_EQ(SERVICE(u)->state, SERVICE_DEAD);

        return 0;
}
