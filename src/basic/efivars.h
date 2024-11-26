/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !ENABLE_EFI
#  include <errno.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sd-id128.h"

#include "efivars-fundamental.h"
#include "string-util.h"
#include "time-util.h"

#define EFI_VENDOR_LOADER       SD_ID128_MAKE(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_LOADER_STR   SD_ID128_MAKE_UUID_STR(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_GLOBAL       SD_ID128_MAKE(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VENDOR_GLOBAL_STR   SD_ID128_MAKE_UUID_STR(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VENDOR_DATABASE     SD_ID128_MAKE(d7,19,b2,cb,3d,3a,45,96,a3,bc,da,d0,0e,67,65,6f)
#define EFI_VENDOR_DATABASE_STR SD_ID128_MAKE_UUID_STR(d7,19,b2,cb,3d,3a,45,96,a3,bc,da,d0,0e,67,65,6f)
#define EFI_VENDOR_SYSTEMD      SD_ID128_MAKE(8c,f2,64,4b,4b,0b,42,8f,93,87,6d,87,60,50,dc,67)
#define EFI_VENDOR_SYSTEMD_STR  SD_ID128_MAKE_UUID_STR(8c,f2,64,4b,4b,0b,42,8f,93,87,6d,87,60,50,dc,67)

#define EFI_VARIABLE_NON_VOLATILE                          UINT32_C(0x00000001)
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    UINT32_C(0x00000002)
#define EFI_VARIABLE_RUNTIME_ACCESS                        UINT32_C(0x00000004)
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS UINT32_C(0x00000020)

/* Note that the <lowercaseuuid>-<varname> naming scheme is an efivarfs convention, i.e. part of the Linux
 * API file system implementation for EFI. EFI itself processes UIDS in binary form.
 */

#define EFI_VENDOR_VARIABLE_STR(vendor, name) name "-" vendor

#define EFI_GLOBAL_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_GLOBAL_STR, name)
#define EFI_LOADER_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_LOADER_STR, name)
#define EFI_SYSTEMD_VARIABLE_STR(name) EFI_VENDOR_VARIABLE_STR(EFI_VENDOR_SYSTEMD_STR, name)

#define EFIVAR_PATH(variable) "/sys/firmware/efi/efivars/" variable
#define EFIVAR_CACHE_PATH(variable) "/run/systemd/efivars/" variable

#if ENABLE_EFI

int efi_get_variable(const char *variable, uint32_t *attribute, void **ret_value, size_t *ret_size);
int efi_get_variable_string(const char *variable, char **ret);
int efi_get_variable_path(const char *variable, char **ret);
int efi_set_variable(const char *variable, const void *value, size_t size);
int efi_set_variable_string(const char *variable, const char *p);

bool is_efi_boot(void);
bool is_efi_secure_boot(void);
SecureBootMode efi_get_secure_boot_mode(void);

int cache_efi_options_variable(void);
int systemd_efi_options_variable(char **ret);
int systemd_efi_options_efivarfs_if_newer(char **ret);

#else

static inline int efi_get_variable(const char *variable, uint32_t *attribute, void **value, size_t *size) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable_string(const char *variable, char **ret) {
        return -EOPNOTSUPP;
}

static inline int efi_get_variable_path(const char *variable, char **ret) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable(const char *variable, const void *value, size_t size) {
        return -EOPNOTSUPP;
}

static inline int efi_set_variable_string(const char *variable, const char *p) {
        return -EOPNOTSUPP;
}

static inline bool is_efi_boot(void) {
        return false;
}

static inline bool is_efi_secure_boot(void) {
        return false;
}

static inline SecureBootMode efi_get_secure_boot_mode(void) {
        return SECURE_BOOT_UNKNOWN;
}

static inline int cache_efi_options_variable(void) {
        return -EOPNOTSUPP;
}

static inline int systemd_efi_options_variable(char **line) {
        return -ENODATA;
}

static inline int systemd_efi_options_efivarfs_if_newer(char **line) {
        return -ENODATA;
}
#endif

static inline char *efi_tilt_backslashes(char *s) {
        return string_replace_char(s, '\\', '/');
}
