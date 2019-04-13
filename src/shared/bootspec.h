/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "string-util.h"

typedef enum BootEntryType {
        BOOT_ENTRY_CONF,     /* Type #1 entries: *.conf files */
        BOOT_ENTRY_UNIFIED,  /* Type #2 entries: *.efi files */
        BOOT_ENTRY_LOADER,   /* Additional entries augmented from LoaderEntries EFI var */
        _BOOT_ENTRY_MAX,
        _BOOT_ENTRY_INVALID = -1,
} BootEntryType;

typedef struct BootEntry {
        BootEntryType type;
        char *id;       /* This is the file basename without extension */
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

static inline bool boot_config_has_entry(BootConfig *config, const char *id) {
        size_t j;

        for (j = 0; j < config->n_entries; j++)
                if (streq(config->entries[j].id, id))
                        return true;

        return false;
}

static inline BootEntry* boot_config_default_entry(BootConfig *config) {
        if (config->default_entry < 0)
                return NULL;

        return config->entries + config->default_entry;
}

void boot_config_free(BootConfig *config);
int boot_entries_load_config(const char *esp_path, const char *xbootldr_path, BootConfig *config);
int boot_entries_load_config_auto(const char *override_esp_path, const char *override_xbootldr_path, BootConfig *config);
#if ENABLE_EFI
int boot_entries_augment_from_loader(BootConfig *config, bool only_auto);
#else
static inline int boot_entries_augment_from_loader(BootConfig *config, bool only_auto) {
        return -EOPNOTSUPP;
}
#endif

static inline const char* boot_entry_title(const BootEntry *entry) {
        return entry->show_title ?: entry->title ?: entry->id;
}

int find_esp_and_warn(const char *path, bool unprivileged_mode, char **ret_path, uint32_t *ret_part, uint64_t *ret_pstart, uint64_t *ret_psize, sd_id128_t *ret_uuid);
int find_xbootldr_and_warn(const char *path, bool unprivileged_mode, char **ret_path,sd_id128_t *ret_uuid);
