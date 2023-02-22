/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "image-policy.h"
#include "json.h"
#include "pager.h"

typedef enum EntryTokenType {
        ARG_ENTRY_TOKEN_MACHINE_ID,
        ARG_ENTRY_TOKEN_OS_IMAGE_ID,
        ARG_ENTRY_TOKEN_OS_ID,
        ARG_ENTRY_TOKEN_LITERAL,
        ARG_ENTRY_TOKEN_AUTO,
} EntryTokenType;

typedef enum InstallSource {
        ARG_INSTALL_SOURCE_IMAGE,
        ARG_INSTALL_SOURCE_HOST,
        ARG_INSTALL_SOURCE_AUTO,
} InstallSource;

extern char *arg_esp_path;
extern char *arg_xbootldr_path;
extern bool arg_print_esp_path;
extern bool arg_print_dollar_boot_path;
extern unsigned arg_print_root_device;
extern bool arg_touch_variables;
extern PagerFlags arg_pager_flags;
extern bool arg_graceful;
extern bool arg_quiet;
extern int arg_make_entry_directory; /* tri-state: < 0 for automatic logic */
extern sd_id128_t arg_machine_id;
extern char *arg_install_layout;
extern EntryTokenType arg_entry_token_type;
extern char *arg_entry_token;
extern JsonFormatFlags arg_json_format_flags;
extern bool arg_arch_all;
extern char *arg_root;
extern char *arg_image;
extern InstallSource arg_install_source;
extern char *arg_efi_boot_option_description;
extern bool arg_dry_run;
extern ImagePolicy *arg_image_policy;

static inline const char *arg_dollar_boot_path(void) {
        /* $BOOT shall be the XBOOTLDR partition if it exists, and otherwise the ESP */
        return arg_xbootldr_path ?: arg_esp_path;
}

int acquire_esp(bool unprivileged_mode, bool graceful, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int acquire_xbootldr(bool unprivileged_mode, sd_id128_t *ret_uuid, dev_t *ret_devid);
