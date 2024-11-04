/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "efivars-fundamental.h"
#include "efivars.h"

/* Various calls that interface with EFI variables implementing https://systemd.io/BOOT_LOADER_INTERFACE */

#if ENABLE_EFI

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

#else

static inline int efi_loader_get_device_part_uuid(sd_id128_t *u) {
        return -EOPNOTSUPP;
}

static inline int efi_stub_get_device_part_uuid(sd_id128_t *ret) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_get_entries(char ***ret) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_get_features(uint64_t *ret) {
        return -EOPNOTSUPP;
}

static inline int efi_stub_get_features(uint64_t *ret) {
        return -EOPNOTSUPP;
}

static inline int efi_measured_uki(int log_level) {
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "Compiled without support for EFI");
}

static inline int efi_loader_get_config_timeout_one_shot(usec_t *ret) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_update_entry_one_shot_cache(char **cache, struct stat *cache_stat) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable_id128(const char *variable, sd_id128_t *ret) {
        return -EOPNOTSUPP;
}

#endif

bool efi_loader_entry_name_valid(const char *s);
