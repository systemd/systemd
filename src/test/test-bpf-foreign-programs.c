/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/bpf_insn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bpf-foreign.h"
#include "load-fragment.h"
#include "manager.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "service.h"
#include "tests.h"
#include "unit.h"
#include "virt.h"

struct Test {
        const char *option_name;
        enum bpf_prog_type prog_type;
        enum bpf_attach_type attach_type;
        const char *bpffs_path;
};

typedef struct Test Test;

#define BPFFS_PATH(prog_suffix) ("/sys/fs/bpf/test-bpf-foreing-" # prog_suffix)
static const Test single_prog[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_INGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        },
};
static const Test path_split_test[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_INGRESS,
                .bpffs_path = BPFFS_PATH("path:split:test"),
        },
};

static const Test same_prog_same_hook[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SOCK,
                .attach_type = BPF_CGROUP_INET_SOCK_CREATE,
                .bpffs_path = BPFFS_PATH("trivial-sock"),
        },
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SOCK,
                .attach_type = BPF_CGROUP_INET_SOCK_CREATE,
                .bpffs_path = BPFFS_PATH("trivial-sock"),
        }
};

static const Test multi_prog_same_hook[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SOCK,
                .attach_type = BPF_CGROUP_INET_SOCK_CREATE,
                .bpffs_path = BPFFS_PATH("trivial-sock-0"),
        },
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SOCK,
                .attach_type = BPF_CGROUP_INET_SOCK_CREATE,
                .bpffs_path = BPFFS_PATH("trivial-sock-1"),
        }
};

static const Test same_prog_multi_hook[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_INGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        },
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_EGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        }
};

static const Test same_prog_multi_option_0[] = {
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_INGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        },
        {
                .option_name = "IPIngressFilterPath",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_INGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        }
};

static const Test same_prog_multi_option_1[] = {
        {
                .option_name = "IPEgressFilterPath",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_EGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        },
        {
                .option_name = "BPFProgram",
                .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
                .attach_type = BPF_CGROUP_INET_EGRESS,
                .bpffs_path = BPFFS_PATH("trivial-skb"),
        }
};
#undef BPFFS_PATH

static int bpf_foreign_test_to_string(enum bpf_attach_type attach_type, const char *bpffs_path, char **ret_str) {
        const char *s = NULL;

        assert_se(bpffs_path);
        assert_se(ret_str);

        assert_se(s = bpf_cgroup_attach_type_to_string(attach_type));
        assert_se(*ret_str = strjoin(s, ":", bpffs_path));

        return 0;
}

static char **unlink_paths_and_free(char **paths) {
        STRV_FOREACH(i, paths)
                (void) unlink(*i);

        return strv_free(paths);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(char **, unlink_paths_and_free);

static int pin_programs(Unit *u, CGroupContext *cc, const Test *test_suite, size_t test_suite_size, char ***paths_ret) {
        _cleanup_(unlink_paths_and_freep) char **bpffs_paths = NULL;
        static const struct bpf_insn trivial[] = {
                BPF_MOV64_IMM(BPF_REG_0, 0),
                BPF_EXIT_INSN()
        };
        char log_buf[0xffff];
        int r;

        assert_se(paths_ret);

        for (size_t i = 0; i < test_suite_size; i++) {
                _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
                _cleanup_free_ char *str = NULL;

                r = bpf_foreign_test_to_string(test_suite[i].attach_type, test_suite[i].bpffs_path, &str);
                if (r < 0)
                        return log_error_errno(r, "Failed to convert program to string");

                r = bpf_program_new(test_suite[i].prog_type, "sd_trivial", &prog);
                if (r < 0)
                        return log_error_errno(r, "Failed to create program '%s'", str);

                r = bpf_program_add_instructions(prog, trivial, ELEMENTSOF(trivial));
                if (r < 0)
                        return log_error_errno(r, "Failed to add trivial instructions for '%s'", str);

                r = bpf_program_load_kernel(prog, log_buf, ELEMENTSOF(log_buf));
                if (r < 0)
                        return log_error_errno(r, "Failed to load BPF program '%s'", str);

                if (strv_contains(bpffs_paths, test_suite[i].bpffs_path))
                        continue;

                r = strv_extend(&bpffs_paths, test_suite[i].bpffs_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to put path into a vector: %m");

                r = bpf_program_pin(prog->kernel_fd, test_suite[i].bpffs_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin BPF program '%s'", str);
        }

        *paths_ret = TAKE_PTR(bpffs_paths);
        return 0;
}

static int test_bpf_cgroup_programs(Manager *m, const char *unit_name, const Test *test_suite, size_t test_suite_size) {
        _cleanup_(unlink_paths_and_freep) char **bpffs_paths = NULL;
        _cleanup_(unit_freep) Unit *u = NULL;
        CGroupContext *cc = NULL;
        int cld_code, r;

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, unit_name) == 0);
        assert_se(cc = unit_get_cgroup_context(u));

        r = pin_programs(u, cc, test_suite, test_suite_size, &bpffs_paths);
        if (r < 0)
                return log_error_errno(r, "Failed to pin programs: %m");

        for (size_t i = 0; i < test_suite_size; i++) {
                if (streq(test_suite[i].option_name, "BPFProgram")) {
                        _cleanup_free_ char *option = NULL;
                        r = bpf_foreign_test_to_string(test_suite[i].attach_type, test_suite[i].bpffs_path, &option);
                        if (r < 0)
                                return log_error_errno(r, "Failed to compose option string: %m");
                        r = config_parse_bpf_foreign_program(
                                        u->id, "filename", 1, "Service", 1, test_suite[i].option_name, 0, option, cc, u);

                        if (r < 0)
                                return log_error_errno(r, "Failed to parse option string '%s': %m", option);
                } else if (STR_IN_SET(test_suite[i].option_name, "IPIngressFilterPath", "IPEgressFilterPath")) {
                        const char *option = test_suite[i].bpffs_path;
                        void *paths = NULL;

                        if (streq(test_suite[i].option_name, "IPIngressFilterPath"))
                                paths = &cc->ip_filters_ingress;
                        else
                                paths = &cc->ip_filters_egress;

                        r = config_parse_ip_filter_bpf_progs(
                                        u->id, "filename", 1, "Service", 1, test_suite[i].option_name, 0, option, paths, u);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse option string '%s': %m", option);
                }
        }

        r = config_parse_exec(
                        u->id,
                        "filename",
                        1,
                        "Service",
                        1,
                        "ExecStart",
                        SERVICE_EXEC_START,
                        "-/bin/ping -c 5 127.0.0.1 -W 1",
                        SERVICE(u)->exec_command,
                        u);
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
                        return log_error_errno(r, "Event run failed %m");
        }

        cld_code = SERVICE(u)->exec_command[SERVICE_EXEC_START]->exec_status.code;
        if (cld_code != CLD_EXITED)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                "Child didn't exit normally, code='%s'", sigchld_code_to_string(cld_code));

        if (SERVICE(u)->state != SERVICE_DEAD)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Service is not dead");

        return r;
}

int main(int argc, char *argv[]) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_free_ char *unit_dir = NULL;
        struct rlimit rl;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (detect_container() > 0)
                return log_tests_skipped("test-bpf fails inside LXC and Docker containers: https://github.com/systemd/systemd/issues/9666");

        if (getuid() != 0)
                return log_tests_skipped("not running as root");

        ASSERT_OK(getrlimit(RLIMIT_MEMLOCK, &rl));
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit_closest(RLIMIT_MEMLOCK, &rl);

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock()");

        r = cg_all_unified();
        if (r <= 0)
                return log_tests_skipped("Unified hierarchy is required");

        r = enter_cgroup_subroot(NULL);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        ASSERT_OK(get_testdata_dir("units", &unit_dir));
        ASSERT_OK(setenv_unit_path(unit_dir));
        assert_se(runtime_dir = setup_fake_runtime_dir());

        ASSERT_OK(manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_BASIC, &m));
        ASSERT_OK(manager_startup(m, NULL, NULL, NULL));

        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "single_prog.service", single_prog, ELEMENTSOF(single_prog)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "multi_prog_same_hook.service",
                                multi_prog_same_hook, ELEMENTSOF(multi_prog_same_hook)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "same_prog_multi_hook.service",
                                same_prog_multi_hook, ELEMENTSOF(same_prog_multi_hook)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "same_prog_multi_option_0.service",
                                same_prog_multi_option_0, ELEMENTSOF(same_prog_multi_option_0)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "same_prog_multi_option_1.service",
                                same_prog_multi_option_1, ELEMENTSOF(same_prog_multi_option_1)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "same_prog_same_hook.service",
                                same_prog_same_hook,
                                ELEMENTSOF(same_prog_same_hook)));
        ASSERT_OK(test_bpf_cgroup_programs(m,
                                "path_split_test.service",
                                path_split_test,
                                ELEMENTSOF(path_split_test)));
        return 0;
}
