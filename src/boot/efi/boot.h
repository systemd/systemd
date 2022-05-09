/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"
#include "random-seed.h"

#ifndef GNU_EFI_USE_MS_ABI
        /* We do not use uefi_call_wrapper() in systemd-boot. As such, we rely on the
         * compiler to do the calling convention conversion for us. This is check is
         * to make sure the -DGNU_EFI_USE_MS_ABI was passed to the comiler. */
        #error systemd-boot requires compilation with GNU_EFI_USE_MS_ABI defined.
#endif

#define TEXT_ATTR_SWAP(c) EFI_TEXT_ATTR(((c) & 0b11110000) >> 4, (c) & 0b1111)

enum loader_type {
        LOADER_UNDEFINED,
        LOADER_AUTO,
        LOADER_EFI,
        LOADER_LINUX,         /* Boot loader spec type #1 entries */
        LOADER_UNIFIED_LINUX, /* Boot loader spec type #2 entries */
};

/* These values have been chosen so that the transitions the user sees could
 * employ unsigned over-/underflow like this:
 * efivar unset ↔ force menu ↔ no timeout/skip menu ↔ 1 s ↔ 2 s ↔ … */
enum {
        TIMEOUT_MIN         = 1,
        TIMEOUT_MAX         = UINT32_MAX - 2U,
        TIMEOUT_UNSET       = UINT32_MAX - 1U,
        TIMEOUT_MENU_FORCE  = UINT32_MAX,
        TIMEOUT_MENU_HIDDEN = 0,
        TIMEOUT_TYPE_MAX    = UINT32_MAX,
};

enum {
        IDX_MAX = INT16_MAX,
        IDX_INVALID,
};

typedef enum {
        ENROLL_OFF,         /* no Secure Boot key enrollment whatsoever, even manual entries are not generated */
        ENROLL_MANUAL,      /* Secure Boot key enrollment is strictly manual: manual entries are generated and need to be selected by the user */
        ENROLL_FORCE,       /* Secure Boot key enrollment may be automatic if it is available but might not be safe */
        _ENROLL_MAX,
} secure_boot_enroll;

static const CHAR16 * const secure_boot_enroll_table[_ENROLL_MAX] = {
        [ENROLL_OFF]    = L"off",
        [ENROLL_MANUAL] = L"manual",
        [ENROLL_FORCE]  = L"force",
};

typedef struct Config Config;

typedef struct {
        char16_t *id;         /* The unique identifier for this entry (typically the filename of the file defining the entry) */
        char16_t *title_show; /* The string to actually display (this is made unique before showing) */
        char16_t *title;      /* The raw (human readable) title string of the entry (not necessarily unique) */
        char16_t *sort_key;   /* The string to use as primary sort key, usually ID= from os-release, possibly suffixed */
        char16_t *version;    /* The raw (human readable) version string of the entry */
        char16_t *machine_id;
        EFI_HANDLE *device;
        enum loader_type type;
        char16_t *loader;
        char16_t *devicetree;
        char16_t *options;
        char16_t **initrd;
        char16_t key;
        EFI_STATUS (*call)(void);
        int tries_done;
        int tries_left;
        char16_t *path;
        char16_t *current_name;
        char16_t *next_name;
} ConfigEntry;

typedef struct Config {
        ConfigEntry **entries;
        UINTN entry_count;
        UINTN idx_default;
        UINTN idx_default_efivar;
        uint32_t timeout_sec; /* Actual timeout used (efi_main() override > efivar > config). */
        uint32_t timeout_sec_config;
        uint32_t timeout_sec_efivar;
        char16_t *entry_default_config;
        char16_t *entry_default_efivar;
        char16_t *entry_oneshot;
        char16_t *entry_saved;
        bool editor;
        bool auto_entries;
        bool auto_firmware;
        bool reboot_for_bitlocker;
        bool force_menu;
        bool use_saved_entry;
        bool use_saved_entry_efivar;
        bool beep;
        int64_t console_mode;
        int64_t console_mode_efivar;
        RandomSeedMode random_seed_mode;
} Config;
