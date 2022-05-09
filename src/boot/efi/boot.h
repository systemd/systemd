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
        LOADER_SECURE_BOOT_KEYS,
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

typedef struct ConfigEntry {
        CHAR16 *id;         /* The unique identifier for this entry (typically the filename of the file defining the entry) */
        CHAR16 *title_show; /* The string to actually display (this is made unique before showing) */
        CHAR16 *title;      /* The raw (human readable) title string of the entry (not necessarily unique) */
        CHAR16 *sort_key;   /* The string to use as primary sort key, usually ID= from os-release, possibly suffixed */
        CHAR16 *version;    /* The raw (human readable) version string of the entry */
        CHAR16 *machine_id;
        EFI_HANDLE *device;
        enum loader_type type;
        CHAR16 *loader;
        CHAR16 *devicetree;
        CHAR16 *options;
        CHAR16 key;
        EFI_STATUS (*call)(void);
        UINTN tries_done;
        UINTN tries_left;
        CHAR16 *path;
        CHAR16 *current_name;
        CHAR16 *next_name;
} ConfigEntry;

typedef struct Config {
        ConfigEntry **entries;
        UINTN entry_count;
        UINTN idx_default;
        UINTN idx_default_efivar;
        UINT32 timeout_sec; /* Actual timeout used (efi_main() override > efivar > config). */
        UINT32 timeout_sec_config;
        UINT32 timeout_sec_efivar;
        CHAR16 *entry_default_config;
        CHAR16 *entry_default_efivar;
        CHAR16 *entry_oneshot;
        CHAR16 *entry_saved;
        CHAR16 *options_edit;
        BOOLEAN editor;
        BOOLEAN auto_entries;
        BOOLEAN auto_firmware;
        BOOLEAN reboot_for_bitlocker;
        secure_boot_enroll secure_boot_enroll;
        BOOLEAN force_menu;
        BOOLEAN use_saved_entry;
        BOOLEAN use_saved_entry_efivar;
        BOOLEAN beep;
        INT64 console_mode;
        INT64 console_mode_efivar;
        RandomSeedMode random_seed_mode;
} Config;
