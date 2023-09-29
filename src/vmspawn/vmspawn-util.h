/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

bool qemu_check_kvm_support(bool log);
int find_ovmf_firmware(const char **ret_firmware_path);
int find_qemu_binary(char **ret_qemu_binary);
int find_ovmf_vars(const char** ret_ovmf_vars);
