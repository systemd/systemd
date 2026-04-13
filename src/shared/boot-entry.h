/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "shared-forward.h"

typedef enum BootEntryTokenType {
        BOOT_ENTRY_TOKEN_MACHINE_ID,
        BOOT_ENTRY_TOKEN_OS_IMAGE_ID,
        BOOT_ENTRY_TOKEN_OS_ID,
        BOOT_ENTRY_TOKEN_LITERAL,
        BOOT_ENTRY_TOKEN_AUTO,
        _BOOT_ENTRY_TOKEN_TYPE_MAX,
        _BOOT_ENTRY_TOKEN_TYPE_INVALID = -EINVAL,
} BootEntryTokenType;

bool boot_entry_token_valid(const char *p);

int boot_entry_token_ensure(
                const char *root,
                const char *conf_root,   /* will be prefixed with root, typically /etc/kernel. */
                sd_id128_t machine_id,
                bool machine_id_is_random,
                BootEntryTokenType *type, /* input and output */
                char **token);            /* output, but do not pass uninitialized value. */
int boot_entry_token_ensure_at(
                int rfd,
                const char *conf_root,
                sd_id128_t machine_id,
                bool machine_id_is_random,
                BootEntryTokenType *type,
                char **token);

int parse_boot_entry_token_type(const char *s, BootEntryTokenType *type, char **token);

DECLARE_STRING_TABLE_LOOKUP(boot_entry_token_type, BootEntryTokenType);
