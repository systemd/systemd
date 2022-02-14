/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "string-util.h"

typedef enum BootEntryType {
        BOOT_ENTRY_CONF,        /* Boot Loader Specification Type #1 entries: *.conf files */
        BOOT_ENTRY_UNIFIED,     /* Boot Loader Specification Type #2 entries: *.efi files */
        BOOT_ENTRY_LOADER,      /* Additional entries augmented from LoaderEntries EFI variable (regular entries) */
        BOOT_ENTRY_LOADER_AUTO, /* Additional entries augmented from LoaderEntries EFI variable (special "automatic" entries) */
        _BOOT_ENTRY_TYPE_MAX,
        _BOOT_ENTRY_TYPE_INVALID = -EINVAL,
} BootEntryType;

typedef struct BootEntry {
        BootEntryType type;
        bool reported_by_loader;
        char *id;       /* This is the file basename (including extension!) */
        char *id_old;   /* Old-style ID, for deduplication purposes. */
        char *path;     /* This is the full path to the drop-in file */
        char *root;     /* The root path in which the drop-in was found, i.e. to which 'kernel', 'efi' and 'initrd' are relative */
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
        char **device_tree_overlay;
} BootEntry;

typedef struct BootConfig {
        char *default_pattern;
        char *timeout;
        char *editor;
        char *auto_entries;
        char *auto_firmware;
        char *console_mode;
        char *random_seed_mode;
        char *beep;

        char *entry_oneshot;
        char *entry_default;
        char *entry_selected;

        BootEntry *entries;
        size_t n_entries;
        ssize_t default_entry;
        ssize_t selected_entry;
} BootConfig;

static inline BootEntry* boot_config_find_entry(BootConfig *config, const char *id) {
        assert(config);
        assert(id);

        for (size_t j = 0; j < config->n_entries; j++)
                if (streq_ptr(config->entries[j].id, id) ||
                    streq_ptr(config->entries[j].id_old, id))
                        return config->entries + j;

        return NULL;
}

static inline BootEntry* boot_config_default_entry(BootConfig *config) {
        assert(config);

        if (config->default_entry < 0)
                return NULL;

        return config->entries + config->default_entry;
}

void boot_config_free(BootConfig *config);
int boot_entries_load_config(const char *esp_path, const char *xbootldr_path, BootConfig *config);
int boot_entries_load_config_auto(const char *override_esp_path, const char *override_xbootldr_path, BootConfig *config);
int boot_entries_augment_from_loader(BootConfig *config, char **list, bool only_auto);

static inline const char* boot_entry_title(const BootEntry *entry) {
        assert(entry);

        return entry->show_title ?: entry->title ?: entry->id;
}

int find_esp_and_warn(const char *path, bool unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid, dev_t *ret_devid);
int find_xbootldr_and_warn(const char *path, bool unprivileged_mode, char **ret_path,sd_id128_t *ret_uuid, dev_t *ret_devid);
