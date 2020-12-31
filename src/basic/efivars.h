/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_EFI
#  include <errno.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sd-id128.h"

#include "time-util.h"

#define EFI_VENDOR_LOADER  SD_ID128_MAKE(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_GLOBAL  SD_ID128_MAKE(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VENDOR_SYSTEMD SD_ID128_MAKE(8c,f2,64,4b,4b,0b,42,8f,93,87,6d,87,60,50,dc,67)
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004

#if ENABLE_EFI

char* efi_variable_path(sd_id128_t vendor, const char *name);
int efi_get_variable(sd_id128_t vendor, const char *name, uint32_t *attribute, void **value, size_t *size);
int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p);
int efi_set_variable(sd_id128_t vendor, const char *name, const void *value, size_t size);
int efi_set_variable_string(sd_id128_t vendor, const char *name, const char *p);

bool is_efi_boot(void);
bool is_efi_secure_boot(void);
bool is_efi_secure_boot_setup_mode(void);

int cache_efi_options_variable(void);
int systemd_efi_options_variable(char **line);

#else

static inline char* efi_variable_path(sd_id128_t vendor, const char *name) {
        return NULL;
}

static inline int efi_get_variable(sd_id128_t vendor, const char *name, uint32_t *attribute, void **value, size_t *size) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable_string(sd_id128_t vendor, const char *name, char **p) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable(sd_id128_t vendor, const char *name, const void *value, size_t size) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable_string(sd_id128_t vendor, const char *name, const char *p) {
        return -EOPNOTSUPP;
}

static inline bool is_efi_boot(void) {
        return false;
}

static inline bool is_efi_secure_boot(void) {
        return false;
}

static inline bool is_efi_secure_boot_setup_mode(void) {
        return false;
}

static inline int cache_efi_options_variable(void) {
        return -EOPNOTSUPP;
}

static inline int systemd_efi_options_variable(char **line) {
        return -ENODATA;
}

#endif
