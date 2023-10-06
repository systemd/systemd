/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
#define ARCHITECTURE_SUPPORTS_SMBIOS
#endif

bool qemu_check_kvm_support(void);
int find_ovmf_firmware(const char **ret_firmware_path);
int find_qemu_binary(char **ret_qemu_binary);
int find_ovmf_vars(const char **ret_ovmf_vars);
