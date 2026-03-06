/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum InstallSource {
        INSTALL_SOURCE_IMAGE,
        INSTALL_SOURCE_HOST,
        INSTALL_SOURCE_AUTO,
        _INSTALL_SOURCE_MAX,
        _INSTALL_SOURCE_INVALID = -EINVAL,
} InstallSource;

typedef enum GracefulMode {
        ARG_GRACEFUL_NO,
        ARG_GRACEFUL_YES,
        ARG_GRACEFUL_FORCE,
} GracefulMode;

extern char *arg_esp_path;
extern char *arg_xbootldr_path;
extern bool arg_print_esp_path;
extern bool arg_print_dollar_boot_path;
extern unsigned arg_print_root_device;
extern int arg_touch_variables;
extern bool arg_install_random_seed;
extern PagerFlags arg_pager_flags;
extern bool arg_quiet;
extern int arg_make_entry_directory; /* tri-state: < 0 for automatic logic */
extern sd_id128_t arg_machine_id;
extern char *arg_install_layout;
extern BootEntryTokenType arg_entry_token_type;
extern char *arg_entry_token;
extern sd_json_format_flags_t arg_json_format_flags;
extern bool arg_arch_all;
extern char *arg_root;
extern char *arg_image;
extern InstallSource arg_install_source;
extern char *arg_efi_boot_option_description;
extern bool arg_efi_boot_option_description_with_device;
extern bool arg_dry_run;
extern ImagePolicy *arg_image_policy;
extern bool arg_varlink;
extern bool arg_secure_boot_auto_enroll;
extern char *arg_certificate;
extern CertificateSourceType arg_certificate_source_type;
extern char *arg_certificate_source;
extern char *arg_private_key;
extern KeySourceType arg_private_key_source_type;
extern char *arg_private_key_source;

static inline const char* arg_dollar_boot_path(void) {
        /* $BOOT shall be the XBOOTLDR partition if it exists, and otherwise the ESP */
        return arg_xbootldr_path ?: arg_esp_path;
}

GracefulMode arg_graceful(void);

int acquire_esp(int unprivileged_mode, bool graceful, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int acquire_xbootldr(int unprivileged_mode, sd_id128_t *ret_uuid, dev_t *ret_devid);

/* EFI_BOOT_OPTION_DESCRIPTION_MAX sets the maximum length for the boot option description
 * stored in NVRAM. The UEFI spec does not specify a minimum or maximum length for this
 * string, but we limit the length to something reasonable to prevent from the firmware
 * having to deal with a potentially too long string. */
#define EFI_BOOT_OPTION_DESCRIPTION_MAX ((size_t) 255)
