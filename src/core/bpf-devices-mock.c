/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpf-devices.h"

#include "log.h"

int bpf_devices_cgroup_init(BPFProgram **ret, CGroupDevicePolicy policy, bool whitelist) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_devices_apply_policy(
                BPFProgram *prog,
                CGroupDevicePolicy policy,
                bool whitelist,
                const char *cgroup_path,
                BPFProgram **prog_installed) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_devices_supported(void) {
        return 0;
}

int bpf_devices_whitelist_device(BPFProgram *prog, const char *path, const char *node, const char *acc) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_devices_whitelist_major(BPFProgram *prog, const char *path, const char *name, char type, const char *acc) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_devices_whitelist_static(BPFProgram *prog, const char *path) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}
