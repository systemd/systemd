/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "efi-loader-features.h"
#include "efivars.h"

#if ENABLE_EFI

int efi_reboot_to_firmware_supported(void);
int efi_get_reboot_to_firmware(void);
int efi_set_reboot_to_firmware(bool value);

int efi_get_boot_option(uint16_t nr, char **title, sd_id128_t *part_uuid, char **path, bool *active);
int efi_add_boot_option(uint16_t id, const char *title, uint32_t part, uint64_t pstart, uint64_t psize, sd_id128_t part_uuid, const char *path);
int efi_remove_boot_option(uint16_t id);
int efi_get_boot_order(uint16_t **order);
int efi_set_boot_order(uint16_t *order, size_t n);
int efi_get_boot_options(uint16_t **options);

int efi_loader_get_device_part_uuid(sd_id128_t *u);
int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader);

int efi_loader_get_entries(char ***ret);

int efi_loader_get_features(uint64_t *ret);

int efi_loader_get_config_timeout_one_shot(usec_t *ret);
int efi_loader_update_entry_one_shot_cache(char **cache, struct stat *cache_stat);

bool efi_has_tpm2(void);

#else

static inline int efi_reboot_to_firmware_supported(void) {
        return -EOPNOTSUPP;
}

static inline int efi_get_reboot_to_firmware(void) {
        return -EOPNOTSUPP;
}

static inline int efi_set_reboot_to_firmware(bool value) {
        return -EOPNOTSUPP;
}

static inline int efi_get_boot_option(uint16_t nr, char **title, sd_id128_t *part_uuid, char **path, bool *active) {
        return -EOPNOTSUPP;
}

static inline int efi_add_boot_option(uint16_t id, const char *title, uint32_t part, uint64_t pstart, uint64_t psize, sd_id128_t part_uuid, const char *path) {
        return -EOPNOTSUPP;
}

static inline int efi_remove_boot_option(uint16_t id) {
        return -EOPNOTSUPP;
}

static inline int efi_get_boot_order(uint16_t **order) {
        return -EOPNOTSUPP;
}

static inline int efi_set_boot_order(uint16_t *order, size_t n) {
        return -EOPNOTSUPP;
}

static inline int efi_get_boot_options(uint16_t **options) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_get_device_part_uuid(sd_id128_t *u) {
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

static inline int efi_loader_get_config_timeout_one_shot(usec_t *ret) {
        return -EOPNOTSUPP;
}

static inline int efi_loader_update_entry_one_shot_cache(char **cache, struct stat *cache_stat) {
        return -EOPNOTSUPP;
}

static inline bool efi_has_tpm2(void) {
        return false;
}

#endif

bool efi_loader_entry_name_valid(const char *s);

char *efi_tilt_backslashes(char *s);
