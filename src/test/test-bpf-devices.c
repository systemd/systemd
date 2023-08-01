/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-devices.h"
#include "bpf-program.h"
#include "cgroup-setup.h"
#include "errno-list.h"
#include "fd-util.h"
#include "fs-util.h"
#include "path-util.h"
#include "tests.h"

static void test_policy_closed(const char *cgroup_path, BPFProgram **installed_prog) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        unsigned wrong = 0;
        int r;

        log_info("/* %s */", __func__);

        r = bpf_devices_cgroup_init(&prog, CGROUP_DEVICE_POLICY_CLOSED, true);
        assert_se(r >= 0);

        r = bpf_devices_allow_list_static(prog, cgroup_path);
        assert_se(r >= 0);

        r = bpf_devices_apply_policy(&prog, CGROUP_DEVICE_POLICY_CLOSED, true, cgroup_path, installed_prog);
        assert_se(r >= 0);

        FOREACH_STRING(s, "/dev/null",
                          "/dev/zero",
                          "/dev/full",
                          "/dev/random",
                          "/dev/urandom",
                          "/dev/tty",
                          "/dev/ptmx") {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd < 0 && errno == EPERM;
                /* We ignore errors other than EPERM, e.g. ENOENT or ENXIO */

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 < 0 && errno == EPERM;
        }
        assert_se(wrong == 0);
}

static void test_policy_strict(const char *cgroup_path, BPFProgram **installed_prog) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        unsigned wrong = 0;
        int r;

        log_info("/* %s */", __func__);

        r = bpf_devices_cgroup_init(&prog, CGROUP_DEVICE_POLICY_STRICT, true);
        assert_se(r >= 0);

        r = bpf_devices_allow_list_device(prog, cgroup_path, "/dev/null", "rw");
        assert_se(r >= 0);

        r = bpf_devices_allow_list_device(prog, cgroup_path, "/dev/random", "r");
        assert_se(r >= 0);

        r = bpf_devices_allow_list_device(prog, cgroup_path, "/dev/zero", "w");
        assert_se(r >= 0);

        r = bpf_devices_apply_policy(&prog, CGROUP_DEVICE_POLICY_STRICT, true, cgroup_path, installed_prog);
        assert_se(r >= 0);

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/null";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd < 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 < 0;
        }

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/random";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd < 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 >= 0;
        }

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/zero";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd >= 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 < 0;
        }

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/full";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd >= 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 >= 0;
        }

        assert_se(wrong == 0);
}

static void test_policy_allow_list_major(const char *pattern, const char *cgroup_path, BPFProgram **installed_prog) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        unsigned wrong = 0;
        int r;

        log_info("/* %s(%s) */", __func__, pattern);

        r = bpf_devices_cgroup_init(&prog, CGROUP_DEVICE_POLICY_STRICT, true);
        assert_se(r >= 0);

        r = bpf_devices_allow_list_major(prog, cgroup_path, pattern, 'c', "rw");
        assert_se(r >= 0);

        r = bpf_devices_apply_policy(&prog, CGROUP_DEVICE_POLICY_STRICT, true, cgroup_path, installed_prog);
        assert_se(r >= 0);

        /* /dev/null, /dev/full have major==1, /dev/tty has major==5 */
        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/null";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd < 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 < 0;
        }

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/full";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd < 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 < 0;
        }

        {
                _cleanup_close_ int fd = -EBADF, fd2 = -EBADF;
                const char *s = "/dev/tty";

                fd = open(s, O_CLOEXEC|O_RDONLY|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd >= 0;

                fd2 = open(s, O_CLOEXEC|O_WRONLY|O_NOCTTY);
                log_debug("open(%s, \"w\") = %d/%s", s, fd2, fd2 < 0 ? errno_to_name(errno) : "-");
                wrong += fd2 >= 0;
        }

        assert_se(wrong == 0);
}

static void test_policy_allow_list_major_star(char type, const char *cgroup_path, BPFProgram **installed_prog) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        unsigned wrong = 0;
        int r;

        log_info("/* %s(type=%c) */", __func__, type);

        r = bpf_devices_cgroup_init(&prog, CGROUP_DEVICE_POLICY_STRICT, true);
        assert_se(r >= 0);

        r = bpf_devices_allow_list_major(prog, cgroup_path, "*", type, "rw");
        assert_se(r >= 0);

        r = bpf_devices_apply_policy(&prog, CGROUP_DEVICE_POLICY_STRICT, true, cgroup_path, installed_prog);
        assert_se(r >= 0);

        {
                _cleanup_close_ int fd = -EBADF;
                const char *s = "/dev/null";

                fd = open(s, O_CLOEXEC|O_RDWR|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                if (type == 'c')
                        wrong += fd < 0;
                else
                        wrong += fd >= 0;
        }

        assert_se(wrong == 0);
}

static void test_policy_empty(bool add_mismatched, const char *cgroup_path, BPFProgram **installed_prog) {
        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
        unsigned wrong = 0;
        int r;

        log_info("/* %s(add_mismatched=%s) */", __func__, yes_no(add_mismatched));

        r = bpf_devices_cgroup_init(&prog, CGROUP_DEVICE_POLICY_STRICT, add_mismatched);
        assert_se(r >= 0);

        if (add_mismatched) {
                r = bpf_devices_allow_list_major(prog, cgroup_path, "foobarxxx", 'c', "rw");
                assert_se(r < 0);
        }

        r = bpf_devices_apply_policy(&prog, CGROUP_DEVICE_POLICY_STRICT, false, cgroup_path, installed_prog);
        assert_se(r >= 0);

        {
                _cleanup_close_ int fd = -EBADF;
                const char *s = "/dev/null";

                fd = open(s, O_CLOEXEC|O_RDWR|O_NOCTTY);
                log_debug("open(%s, \"r\") = %d/%s", s, fd, fd < 0 ? errno_to_name(errno) : "-");
                wrong += fd >= 0;
        }

        assert_se(wrong == 0);
}


int main(int argc, char *argv[]) {
        _cleanup_free_ char *cgroup = NULL, *parent = NULL;
        _cleanup_(rmdir_and_freep) char *controller_path = NULL;
        CGroupMask supported;
        struct rlimit rl;
        int r;

        test_setup_logging(LOG_DEBUG);

        assert_se(getrlimit(RLIMIT_MEMLOCK, &rl) >= 0);
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit(RLIMIT_MEMLOCK, &rl);

        r = cg_all_unified();
        if (r <= 0)
                return log_tests_skipped("We don't seem to be running with unified cgroup hierarchy");

        if (!can_memlock())
                return log_tests_skipped("Can't use mlock()");

        r = enter_cgroup_subroot(&cgroup);
        if (r == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");
        if (r < 0)
                return log_tests_skipped_errno(r, "Failed to prepare cgroup subtree");

        r = bpf_devices_supported();
        if (r == 0)
                return log_tests_skipped("BPF device filter not supported");
        assert_se(r == 1);

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, cgroup, NULL, &controller_path);
        assert_se(r >= 0);

        _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;

        test_policy_closed(cgroup, &prog);
        test_policy_strict(cgroup, &prog);

        test_policy_allow_list_major("mem", cgroup, &prog);
        test_policy_allow_list_major("1", cgroup, &prog);

        test_policy_allow_list_major_star('c', cgroup, &prog);
        test_policy_allow_list_major_star('b', cgroup, &prog);

        test_policy_empty(false, cgroup, &prog);
        test_policy_empty(true, cgroup, &prog);

        assert_se(path_extract_directory(cgroup, &parent) >= 0);

        assert_se(cg_mask_supported(&supported) >= 0);
        r = cg_attach_everywhere(supported, parent, 0, NULL, NULL);
        assert_se(r >= 0);

        return 0;
}
