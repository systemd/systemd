/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "sd-id128.h"
#include "time-util.h"

#define EFI_VENDOR_LOADER SD_ID128_MAKE(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_GLOBAL SD_ID128_MAKE(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004

#ifdef ENABLE_EFI

bool is_efi_boot(void);
bool is_efi_secure_boot(void);
bool is_efi_secure_boot_setup_mode(void);
int efi_reboot_to_firmware_supported(void);
int efi_get_reboot_to_firmware(void);
int efi_set_reboot_to_firmware(bool value);

int efi_get_variable(sd_id128_t vendor, const char *name, uint32_t *attribute, void **value, size_t *size);
int efi_set_variable(sd_id128_t vendor, const char *name, const void *value, size_t size);
int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p);

int efi_get_boot_option(uint16_t nr, char **title, sd_id128_t *part_uuid, char **path, bool *active);
int efi_add_boot_option(uint16_t id, const char *title, uint32_t part, uint64_t pstart, uint64_t psize, sd_id128_t part_uuid, const char *path);
int efi_remove_boot_option(uint16_t id);
int efi_get_boot_order(uint16_t **order);
int efi_set_boot_order(uint16_t *order, size_t n);
int efi_get_boot_options(uint16_t **options);

int efi_loader_get_device_part_uuid(sd_id128_t *u);
int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader);

#else

static inline bool is_efi_boot(void) {
        return false;
}

static inline bool is_efi_secure_boot(void) {
        return false;
}

static inline bool is_efi_secure_boot_setup_mode(void) {
        return false;
}

static inline int efi_reboot_to_firmware_supported(void) {
        return -EOPNOTSUPP;
}

static inline int efi_get_reboot_to_firmware(void) {
        return -EOPNOTSUPP;
}

static inline int efi_set_reboot_to_firmware(bool value) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable(sd_id128_t vendor, const char *name, uint32_t *attribute, void **value, size_t *size) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable(sd_id128_t vendor, const char *name, const void *value, size_t size) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p) {
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

#endif

char *efi_tilt_backslashes(char *s);
