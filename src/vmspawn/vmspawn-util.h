/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#  define ARCHITECTURE_SUPPORTS_SMBIOS 1
#else
#  define ARCHITECTURE_SUPPORTS_SMBIOS 0
#endif

#if defined(__x86_64__) || defined(__i386__)
# define ARCHITECTURE_SUPPORTS_VMGENID 1
#else
# define ARCHITECTURE_SUPPORTS_VMGENID 0
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
#  define ARCHITECTURE_SUPPORTS_HPET 1
#else
#  define ARCHITECTURE_SUPPORTS_HPET 0
#endif

#if defined(__x86_64__) || defined(__aarch64__)
#  define ARCHITECTURE_SUPPORTS_CXL 1
#else
#  define ARCHITECTURE_SUPPORTS_CXL 0
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__) || defined(__riscv) || defined(__loongarch64)
#  define ARCHITECTURE_SUPPORTS_FW_CFG 1
#else
#  define ARCHITECTURE_SUPPORTS_FW_CFG 0
#endif

/* QEMU's fw_cfg file path buffer is FW_CFG_MAX_FILE_PATH (56) bytes including NUL */
#define QEMU_FW_CFG_MAX_KEY_LEN 55

/* These match the kernel's COMMAND_LINE_SIZE for each architecture */
#if defined(__loongarch64)
#  define KERNEL_CMDLINE_SIZE 4096
#elif defined(__x86_64__) || defined(__i386__) || defined(__aarch64__)
#  define KERNEL_CMDLINE_SIZE 2048
#elif defined(__arm__) || defined(__riscv)
#  define KERNEL_CMDLINE_SIZE 1024
#else
#  define KERNEL_CMDLINE_SIZE 512
#endif

#if defined(__x86_64__) || defined(__i386__)
#  define QEMU_MACHINE_TYPE "q35"
#elif defined(__arm__) || defined(__aarch64__) || defined(__riscv) || defined(__loongarch64) || defined(__m68k__)
#  define QEMU_MACHINE_TYPE "virt"
#elif defined(__s390__) || defined(__s390x__)
#  define QEMU_MACHINE_TYPE "s390-ccw-virtio"
#elif defined(__powerpc__) || defined(__powerpc64__)
#  define QEMU_MACHINE_TYPE "pseries"
#elif defined(__mips__)
#  define QEMU_MACHINE_TYPE "malta"
#elif defined(__sparc__)
#  define QEMU_MACHINE_TYPE "sun4u"
#else
#  define QEMU_MACHINE_TYPE "none"
#endif

#if defined(__arm__) || defined(__aarch64__)
#  define QEMU_SERIAL_CONSOLE_NAME "ttyAMA0"
#else
#  define QEMU_SERIAL_CONSOLE_NAME "ttyS0"
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

DECLARE_STRING_TABLE_LOOKUP(network_stack, NetworkStack);

int qemu_check_kvm_support(void);
int qemu_check_vsock_support(void);
int list_ovmf_config(char ***ret);
int list_ovmf_firmware_features(char ***ret);
int load_ovmf_config(const char *path, OvmfConfig **ret);
int find_ovmf_config(Set *features_include, Set *features_exclude, OvmfConfig **ret, sd_json_variant **ret_firmware_json);
int find_qemu_binary(char **ret_qemu_binary);
int vsock_fix_child_cid(int vhost_device_fd, unsigned *machine_cid, const char *machine);

char* escape_qemu_value(const char *s);
