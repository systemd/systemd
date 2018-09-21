/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stdlib.h>

typedef struct BootEntry {
        char *filename;

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

void boot_entry_free(BootEntry *entry);
int boot_entry_load(const char *path, BootEntry *entry);
int boot_entries_find(const char *dir, BootEntry **entries, size_t *n_entries);

int boot_loader_read_conf(const char *path, BootConfig *config);
void boot_config_free(BootConfig *config);
int boot_entries_load_config(const char *esp_path, BootConfig *config);

static inline const char* boot_entry_title(const BootEntry *entry) {
        return entry->show_title ?: entry->title ?: entry->filename;
}

int find_esp_and_warn(const char *path, bool unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid);
