/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include "macro.h"

#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#  define ARCHITECTURE_SUPPORTS_SMBIOS 1
#else
#  define ARCHITECTURE_SUPPORTS_SMBIOS 0
#endif

#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
#  define ARCHITECTURE_SUPPORTS_TPM 1
#else
#  define ARCHITECTURE_SUPPORTS_TPM 0
#endif

#if defined(__x86_64__) || defined(__i386__)
#  define ARCHITECTURE_SUPPORTS_SMM 1
#else
#  define ARCHITECTURE_SUPPORTS_SMM 0
#endif

#if defined(__x86_64__) || defined(__i386__)
#  define QEMU_MACHINE_TYPE "q35"
#elif defined(__arm__) || defined(__aarch64__) || defined(__riscv) || defined(__loongarch64)
#  define QEMU_MACHINE_TYPE "virt"
#elif defined(__s390__) || defined(__s390x__)
#  define QEMU_MACHINE_TYPE "s390-ccw-virtio"
#elif defined(__powerpc__) || defined(__powerpc64__)
#  define QEMU_MACHINE_TYPE "pseries"
#elif defined(__mips__)
#  define QEMU_MACHINE_TYPE "malta"
#else
#  error "No qemu machine defined for this architecture"
#endif

typedef struct OvmfConfig {
        char *path;
        char *format;
        char *vars;
        char *vars_format;
        bool supports_sb;
} OvmfConfig;

static inline const char* ovmf_config_format(const OvmfConfig *c) {
        return ASSERT_PTR(c)->format ?: "raw";
}

static inline const char* ovmf_config_vars_format(const OvmfConfig *c) {
        return ASSERT_PTR(c)->vars_format ?: "raw";
}

OvmfConfig* ovmf_config_free(OvmfConfig *ovmf_config);
DEFINE_TRIVIAL_CLEANUP_FUNC(OvmfConfig*, ovmf_config_free);

typedef enum NetworkStack {
        NETWORK_STACK_TAP,
        NETWORK_STACK_USER,
        NETWORK_STACK_NONE,
        _NETWORK_STACK_MAX,
        _NETWORK_STACK_INVALID = -EINVAL,
} NetworkStack;

static const char* const network_stack_table[_NETWORK_STACK_MAX] = {
        [NETWORK_STACK_TAP]  = "tap",
        [NETWORK_STACK_USER] = "user",
        [NETWORK_STACK_NONE] = "none",
};

const char* network_stack_to_string(NetworkStack type) _const_;
NetworkStack network_stack_from_string(const char *s) _pure_;

int qemu_check_kvm_support(void);
int qemu_check_vsock_support(void);
int list_ovmf_config(char ***ret);
int load_ovmf_config(const char *path, OvmfConfig **ret);
int find_ovmf_config(int search_sb, OvmfConfig **ret);
int find_qemu_binary(char **ret_qemu_binary);
int vsock_fix_child_cid(int vsock_fd, unsigned *machine_cid, const char *machine);

char* escape_qemu_value(const char *s);
