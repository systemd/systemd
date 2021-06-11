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

#define EFI_VENDOR_LOADER      SD_ID128_MAKE(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_LOADER_STR  SD_ID128_MAKE_UUID_STR(4a,67,b0,82,0a,4c,41,cf,b6,c7,44,0b,29,bb,8c,4f)
#define EFI_VENDOR_GLOBAL      SD_ID128_MAKE(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VENDOR_GLOBAL_STR  SD_ID128_MAKE_UUID_STR(8b,e4,df,61,93,ca,11,d2,aa,0d,00,e0,98,03,2b,8c)
#define EFI_VENDOR_SYSTEMD     SD_ID128_MAKE(8c,f2,64,4b,4b,0b,42,8f,93,87,6d,87,60,50,dc,67)
#define EFI_VENDOR_SYSTEMD_STR SD_ID128_MAKE_UUID_STR(8c,f2,64,4b,4b,0b,42,8f,93,87,6d,87,60,50,dc,67)
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004

#define EFI_VENDOR_VARIABLE(vendor, name) name "-" vendor

/* Define the variable. Keep original capitalization to make to avoid confusion. */
#define EFI_VARIABLE_BootOrder \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_GLOBAL_STR, "BootOrder")
#define EFI_VARIABLE_OsIndicationsSupported \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_GLOBAL_STR, "OsIndicationsSupported")
#define EFI_VARIABLE_OsIndications \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_GLOBAL_STR, "OsIndications")
#define EFI_VARIABLE_SecureBoot \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_GLOBAL_STR, "SecureBoot")
#define EFI_VARIABLE_SetupMode \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_GLOBAL_STR, "SetupMode")

#define EFI_VARIABLE_LoaderBootCountPath \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderBootCountPath")
#define EFI_VARIABLE_LoaderConfigTimeout \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderConfigTimeout")
#define EFI_VARIABLE_LoaderConfigTimeoutOneShot \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderConfigTimeoutOneShot")
#define EFI_VARIABLE_LoaderDevicePartUUID \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderDevicePartUUID")
#define EFI_VARIABLE_LoaderEntries \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderEntries")
#define EFI_VARIABLE_LoaderEntryOneShot \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderEntryOneShot")
#define EFI_VARIABLE_LoaderEntryDefault \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderEntryDefault")
#define EFI_VARIABLE_LoaderEntrySelected \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderEntrySelected")
#define EFI_VARIABLE_LoaderFeatures \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderFeatures")
#define EFI_VARIABLE_LoaderFirmwareInfo \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderFirmwareInfo")
#define EFI_VARIABLE_LoaderFirmwareType \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderFirmwareType")
#define EFI_VARIABLE_LoaderImageIdentifier \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderImageIdentifier")
#define EFI_VARIABLE_LoaderInfo \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderInfo")
#define EFI_VARIABLE_LoaderSystemToken \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderSystemToken")
#define EFI_VARIABLE_LoaderTimeInitUSec \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderLoaderTimeInitUSec")
#define EFI_VARIABLE_LoaderTimeExecUSec \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderLoaderTimeExecUSec")
#define EFI_VARIABLE_LoaderRandomSeed \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "LoaderRandomSeed")
#define EFI_VARIABLE_StubInfo \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_LOADER_STR, "StubInfo")

#define EFI_VARIABLE_SystemdOptions \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_SYSTEMD_STR, "SystemdOptions")
#define EFI_VARIABLE_FactoryReset \
        EFI_VENDOR_VARIABLE(EFI_VENDOR_SYSTEMD_STR, "FactoryReset")

#define EFIVAR_PATH(variable) "/sys/firmware/efi/efivars/" variable
#define EFIVAR_CACHE_PATH(variable) "/run/systemd/efivars/" variable


#if ENABLE_EFI

int efi_get_variable(const char *variable, uint32_t *attribute, void **value, size_t *size);
int efi_get_variable_string(const char *variable, char **p);
int efi_set_variable(const char *variable, const void *value, size_t size);
int efi_set_variable_string(const char *variable, const char *p);

bool is_efi_boot(void);
bool is_efi_secure_boot(void);
bool is_efi_secure_boot_setup_mode(void);

int cache_efi_options_variable(void);
int systemd_efi_options_variable(char **line);

#else

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
