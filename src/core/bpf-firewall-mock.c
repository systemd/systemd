/* SPDX-License-Identifier: LGPL-2.1+ */

#include "bpf-firewall.h"
#include "unit.h"

int bpf_firewall_supported(void) {
        return BPF_FIREWALL_UNSUPPORTED;
}

int bpf_firewall_compile(Unit *u) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_firewall_install(Unit *u) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_firewall_load_custom(Unit *u) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_firewall_read_accounting(
                int map_fd,
                uint64_t *ret_bytes,
                uint64_t *ret_packets) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

int bpf_firewall_reset_accounting(int map_fd) {
        log_error("BPF is not supported. Mock is called");
        return -1;
}

void emit_bpf_firewall_warning(Unit *u) {
        static bool warned = false;

        if (!warned) {
                log_unit_warning(u, "unit configures an IP firewall, but "
                              "the local system does not support BPF/cgroup firewalling\n"
                              "(This warning is only shown for the first unit using IP firewalling.)");
                warned = true;
        }
}
