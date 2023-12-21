/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include "macro.h"

#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#define ARCHITECTURE_SUPPORTS_SMBIOS 1
#else
#define ARCHITECTURE_SUPPORTS_SMBIOS 0
#endif

typedef struct OvmfConfig {
        char *path;
        char *vars;
        bool supports_sb;
} OvmfConfig;

OvmfConfig* ovmf_config_free(OvmfConfig *ovmf_config);
DEFINE_TRIVIAL_CLEANUP_FUNC(OvmfConfig*, ovmf_config_free);

typedef enum QemuNetworkStack {
        QEMU_NET_TAP,
        QEMU_NET_USER,
        QEMU_NET_NONE,
        _QEMU_NET_MAX,
        _QEMU_NET_INVALID = -EINVAL,
} QemuNetworkStack;

QemuNetworkStack parse_qemu_network_stack(const char *s);

int qemu_check_kvm_support(void);
int qemu_check_vsock_support(void);
int find_ovmf_config(int search_sb, OvmfConfig **ret_ovmf_config);
int find_qemu_binary(char **ret_qemu_binary);
int vsock_fix_child_cid(int vsock_fd, unsigned *machine_cid, const char *machine);
