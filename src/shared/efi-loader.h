/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Various calls that interface with EFI variables implementing https://systemd.io/BOOT_LOADER_INTERFACE */

int efi_loader_get_device_part_uuid(sd_id128_t *ret);
int efi_stub_get_device_part_uuid(sd_id128_t *ret);
int efi_loader_get_boot_usec(usec_t *ret_firmware, usec_t *ret_loader);

int efi_loader_get_entries(char ***ret);

int efi_loader_get_features(uint64_t *ret);
int efi_stub_get_features(uint64_t *ret);

int efi_measured_uki(int log_level);

int efi_loader_get_config_timeout_one_shot(usec_t *ret);
int efi_loader_update_entry_one_shot_cache(char **cache, struct stat *cache_stat);

int efi_get_variable_id128(const char *variable, sd_id128_t *ret);

bool efi_loader_entry_name_valid(const char *s);
