/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "shared-forward.h"

typedef enum BootEntryType {
        BOOT_ENTRY_TYPE1,     /* Boot Loader Specification Type #1 entries: *.conf files */
        BOOT_ENTRY_TYPE2,     /* Boot Loader Specification Type #2 entries: *.efi files (UKIs) */
        BOOT_ENTRY_LOADER,    /* Additional entries augmented from LoaderEntries EFI variable (regular entries) */
        BOOT_ENTRY_AUTO,      /* Additional entries augmented from LoaderEntries EFI variable (special "automatic" entries) */
        _BOOT_ENTRY_TYPE_MAX,
        _BOOT_ENTRY_TYPE_INVALID = -EINVAL,
} BootEntryType;

typedef enum BootEntrySource {
        BOOT_ENTRY_ESP,
        BOOT_ENTRY_XBOOTLDR,
        _BOOT_ENTRY_SOURCE_MAX,
        _BOOT_ENTRY_SOURCE_INVALID = -EINVAL,
} BootEntrySource;

typedef struct BootEntryAddon {
        char *location;
        char *cmdline;
} BootEntryAddon;

typedef struct BootEntryAddons {
        BootEntryAddon *items;
        size_t n_items;
} BootEntryAddons;

typedef struct BootEntry {
        BootEntryType type;
        BootEntrySource source;
        bool reported_by_loader;
        char *id;       /* This is the file basename (including extension!) */
        char *id_old;   /* Old-style ID, for deduplication purposes. */
        char *id_without_profile; /* id without profile suffixed */
        char *path;     /* This is the full path to the drop-in file */
        char *root;     /* The root path in which the drop-in was found, i.e. to which 'kernel', 'efi' and 'initrd' are relative */
        char *title;
        char *show_title;
        char *sort_key;
        char *version;
        char *machine_id;
        char *architecture;
        char **options;
        BootEntryAddons local_addons;
        const BootEntryAddons *global_addons; /* Backpointer into the BootConfig; we don't own this here */
        char *kernel;        /* linux is #defined to 1, yikes! */
        char *efi;
        char *uki;
        char *uki_url;
        char **initrd;
        char *device_tree;
        char **device_tree_overlay;
        unsigned tries_left;
        unsigned tries_done;
        unsigned profile;
} BootEntry;

#define BOOT_ENTRY_INIT(t, s)                   \
        {                                       \
                .type = (t),                    \
                .source = (s),                  \
                .tries_left = UINT_MAX,         \
                .tries_done = UINT_MAX,         \
                .profile = UINT_MAX,            \
        }

typedef struct BootConfig {
        int loader_conf_status;  /* 0 → before loading, 1 → loaded, negative → error. */

        char *default_pattern;
        char *preferred_pattern;

        char *entry_oneshot;
        char *entry_preferred;
        char *entry_default;
        char *entry_selected;
        char *entry_sysfail;

        BootEntry *entries;
        size_t n_entries;

        BootEntryAddons global_addons[_BOOT_ENTRY_SOURCE_MAX];

        ssize_t default_entry;
        ssize_t selected_entry;

        Set *inodes_seen;
} BootConfig;

#define BOOT_CONFIG_NULL              \
        {                             \
                .default_entry = -1,  \
                .selected_entry = -1, \
        }

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(boot_entry_type_description, BootEntryType);
DECLARE_STRING_TABLE_LOOKUP(boot_entry_type, BootEntryType);

DECLARE_STRING_TABLE_LOOKUP_TO_STRING(boot_entry_source_description, BootEntrySource);
DECLARE_STRING_TABLE_LOOKUP_TO_STRING(boot_entry_source, BootEntrySource);

BootEntry* boot_config_find_entry(BootConfig *config, const char *id);

static inline const BootEntry* boot_config_default_entry(const BootConfig *config) {
        assert(config);

        if (config->default_entry < 0)
                return NULL;

        assert((size_t) config->default_entry < config->n_entries);
        return config->entries + config->default_entry;
}

void boot_config_free(BootConfig *config);

int boot_loader_read_conf(BootConfig *config, FILE *file, const char *path);

int boot_config_load_type1(
                BootConfig *config,
                FILE *f,
                const char *root,
                BootEntrySource source,
                const char *dir,
                const char *filename);

int boot_config_finalize(BootConfig *config);
int boot_config_load(BootConfig *config, const char *esp_path, const char *xbootldr_path);
int boot_config_load_auto(BootConfig *config, const char *override_esp_path, const char *override_xbootldr_path);
int boot_config_augment_from_loader(BootConfig *config, char **found_by_loader, bool auto_only);

int boot_config_select_special_entries(BootConfig *config, bool skip_efivars);

static inline const char* boot_entry_title(const BootEntry *entry) {
        assert(entry);
        return ASSERT_PTR(entry->show_title ?: entry->title ?: entry->id);
}

int show_boot_entry(
                const BootEntry *e,
                bool show_as_default,
                bool show_as_selected,
                bool show_reported);
int show_boot_entries(
                const BootConfig *config,
                sd_json_format_flags_t json_format);

int boot_filename_extract_tries(const char *fname, char **ret_stripped, unsigned *ret_tries_left, unsigned *ret_tries_done);

int boot_entry_to_json(const BootConfig *c, size_t i, sd_json_variant **ret);
