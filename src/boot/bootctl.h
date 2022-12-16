/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "json.h"
#include "pager.h"

extern char *arg_esp_path;
extern char *arg_xbootldr_path;
extern bool arg_print_esp_path;
extern bool arg_print_dollar_boot_path;
extern bool arg_touch_variables;
extern PagerFlags arg_pager_flags;
extern bool arg_graceful;
extern bool arg_quiet;
extern int arg_make_entry_directory; /* tri-state: < 0 for automatic logic */
extern sd_id128_t arg_machine_id;
extern char *arg_install_layout;
extern char *arg_entry_token;
extern JsonFormatFlags arg_json_format_flags;
extern bool arg_arch_all;
extern char *arg_root;
extern char *arg_image;
extern char *arg_efi_boot_option_description;
