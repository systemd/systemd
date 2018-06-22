/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

typedef struct BootEntry {
        char *id;       /* This is the file basename without extension */
        char *path;     /* This is the full path to the file */
        char *title;
        char *show_title;
        char *version;
        char *machine_id;
        char *architecture;
        char **options;
        char *kernel;        /* linux is #defined to 1, yikes! */
        char *efi;
        char **initrd;
        char *device_tree;
} BootEntry;

typedef struct BootConfig {
        char *default_pattern;
        char *timeout;
        char *editor;
        char *auto_entries;
        char *auto_firmware;
        char *console_mode;

        char *entry_oneshot;
        char *entry_default;

        BootEntry *entries;
        size_t n_entries;
        ssize_t default_entry;
} BootConfig;

void boot_config_free(BootConfig *config);
int boot_entries_load_config(const char *esp_path, BootConfig *config);

static inline const char* boot_entry_title(const BootEntry *entry) {
        return entry->show_title ?: entry->title ?: entry->id;
}

int find_esp_and_warn(const char *path, bool unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid);

int find_default_boot_entry(const char *esp_path, char **esp_where, BootConfig *config, const BootEntry **e);
