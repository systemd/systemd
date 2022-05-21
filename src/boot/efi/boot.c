/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efigpt.h>
#include <efilib.h>

#include "bcd.h"
#include "bootspec-fundamental.h"
#include "console.h"
#include "devicetree.h"
#include "disk.h"
#include "drivers.h"
#include "efivars-fundamental.h"
#include "graphics.h"
#include "initrd.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "random-seed.h"
#include "secure-boot.h"
#include "shim.h"
#include "ticks.h"
#include "util.h"
#include "xbootldr.h"

#ifndef GNU_EFI_USE_MS_ABI
        /* We do not use uefi_call_wrapper() in systemd-boot. As such, we rely on the
         * compiler to do the calling convention conversion for us. This is check is
         * to make sure the -DGNU_EFI_USE_MS_ABI was passed to the comiler. */
        #error systemd-boot requires compilation with GNU_EFI_USE_MS_ABI defined.
#endif

#define TEXT_ATTR_SWAP(c) EFI_TEXT_ATTR(((c) & 0b11110000) >> 4, (c) & 0b1111)

/* Magic string for recognizing our own binaries */
_used_ _section_(".sdmagic") static const char magic[] =
        "#### LoaderInfo: systemd-boot " GIT_VERSION " ####";

/* Makes systemd-boot available from \EFI\Linux\ for testing purposes. */
_used_ _section_(".osrel") static const char osrel[] =
        "ID=systemd-boot\n"
        "VERSION=\"" GIT_VERSION "\"\n"
        "NAME=\"systemd-boot " GIT_VERSION "\"\n";

enum loader_type {
        LOADER_UNDEFINED,
        LOADER_AUTO,
        LOADER_EFI,
        LOADER_LINUX,         /* Boot loader spec type #1 entries */
        LOADER_UNIFIED_LINUX, /* Boot loader spec type #2 entries */
};

typedef struct {
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
        CHAR16 **initrd;
        CHAR16 key;
        EFI_STATUS (*call)(void);
        UINTN tries_done;
        UINTN tries_left;
        CHAR16 *path;
        CHAR16 *current_name;
        CHAR16 *next_name;
} ConfigEntry;

typedef struct {
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
        BOOLEAN editor;
        BOOLEAN auto_entries;
        BOOLEAN auto_firmware;
        BOOLEAN reboot_for_bitlocker;
        BOOLEAN force_menu;
        BOOLEAN use_saved_entry;
        BOOLEAN use_saved_entry_efivar;
        BOOLEAN beep;
        INT64 console_mode;
        INT64 console_mode_efivar;
        RandomSeedMode random_seed_mode;
} Config;

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

static void cursor_left(UINTN *cursor, UINTN *first) {
        assert(cursor);
        assert(first);

        if ((*cursor) > 0)
                (*cursor)--;
        else if ((*first) > 0)
                (*first)--;
}

static void cursor_right(
                UINTN *cursor,
                UINTN *first,
                UINTN x_max,
                UINTN len) {

        assert(cursor);
        assert(first);

        if ((*cursor)+1 < x_max)
                (*cursor)++;
        else if ((*first) + (*cursor) < len)
                (*first)++;
}

static BOOLEAN line_edit(
                CHAR16 **line_in,
                UINTN x_max,
                UINTN y_pos) {

        _cleanup_freepool_ CHAR16 *line = NULL, *print = NULL;
        UINTN size, len, first = 0, cursor = 0, clear = 0;

        assert(line_in);

        len = strlen_ptr(*line_in);
        size = len + 1024;
        line = xnew(CHAR16, size);
        print = xnew(CHAR16, x_max + 1);
        StrCpy(line, strempty(*line_in));

        for (;;) {
                EFI_STATUS err;
                UINT64 key;
                UINTN j;
                UINTN cursor_color = TEXT_ATTR_SWAP(COLOR_EDIT);

                j = MIN(len - first, x_max);
                CopyMem(print, line + first, j * sizeof(CHAR16));
                while (clear > 0 && j < x_max) {
                        clear--;
                        print[j++] = ' ';
                }
                print[j] = '\0';

                /* See comment at edit_line() call site for why we start at 1. */
                print_at(1, y_pos, COLOR_EDIT, print);

                if (!print[cursor])
                        print[cursor] = ' ';
                print[cursor+1] = '\0';
                do {
                        print_at(cursor + 1, y_pos, cursor_color, print + cursor);
                        cursor_color = TEXT_ATTR_SWAP(cursor_color);

                        err = console_key_read(&key, 750 * 1000);
                        if (!IN_SET(err, EFI_SUCCESS, EFI_TIMEOUT, EFI_NOT_READY))
                                return FALSE;

                        print_at(cursor + 1, y_pos, COLOR_EDIT, print + cursor);
                } while (EFI_ERROR(err));

                switch (key) {
                case KEYPRESS(0, SCAN_ESC, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'c'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'g'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('c')):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('g')):
                        return FALSE;

                case KEYPRESS(0, SCAN_HOME, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'a'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('a')):
                        /* beginning-of-line */
                        cursor = 0;
                        first = 0;
                        continue;

                case KEYPRESS(0, SCAN_END, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'e'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('e')):
                        /* end-of-line */
                        cursor = len - first;
                        if (cursor+1 >= x_max) {
                                cursor = x_max-1;
                                first = len - (x_max-1);
                        }
                        continue;

                case KEYPRESS(0, SCAN_DOWN, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, 'f'):
                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_RIGHT, 0):
                        /* forward-word */
                        while (line[first + cursor] == ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        while (line[first + cursor] && line[first + cursor] != ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        continue;

                case KEYPRESS(0, SCAN_UP, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, 'b'):
                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_LEFT, 0):
                        /* backward-word */
                        if ((first + cursor) > 0 && line[first + cursor-1] == ' ') {
                                cursor_left(&cursor, &first);
                                while ((first + cursor) > 0 && line[first + cursor] == ' ')
                                        cursor_left(&cursor, &first);
                        }
                        while ((first + cursor) > 0 && line[first + cursor-1] != ' ')
                                cursor_left(&cursor, &first);
                        continue;

                case KEYPRESS(0, SCAN_RIGHT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'f'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('f')):
                        /* forward-char */
                        if (first + cursor == len)
                                continue;
                        cursor_right(&cursor, &first, x_max, len);
                        continue;

                case KEYPRESS(0, SCAN_LEFT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'b'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('b')):
                        /* backward-char */
                        cursor_left(&cursor, &first);
                        continue;

                case KEYPRESS(EFI_ALT_PRESSED, 0, 'd'):
                        /* kill-word */
                        clear = 0;

                        UINTN k;
                        for (k = first + cursor; k < len && line[k] == ' '; k++)
                                clear++;
                        for (; k < len && line[k] != ' '; k++)
                                clear++;

                        for (UINTN i = first + cursor; i + clear < len; i++)
                                line[i] = line[i + clear];
                        len -= clear;
                        line[len] = '\0';
                        continue;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'w'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('w')):
                case KEYPRESS(EFI_ALT_PRESSED, 0, CHAR_BACKSPACE):
                        /* backward-kill-word */
                        clear = 0;
                        if ((first + cursor) > 0 && line[first + cursor-1] == ' ') {
                                cursor_left(&cursor, &first);
                                clear++;
                                while ((first + cursor) > 0 && line[first + cursor] == ' ') {
                                        cursor_left(&cursor, &first);
                                        clear++;
                                }
                        }
                        while ((first + cursor) > 0 && line[first + cursor-1] != ' ') {
                                cursor_left(&cursor, &first);
                                clear++;
                        }

                        for (UINTN i = first + cursor; i + clear < len; i++)
                                line[i] = line[i + clear];
                        len -= clear;
                        line[len] = '\0';
                        continue;

                case KEYPRESS(0, SCAN_DELETE, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'd'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('d')):
                        if (len == 0)
                                continue;
                        if (first + cursor == len)
                                continue;
                        for (UINTN i = first + cursor; i < len; i++)
                                line[i] = line[i+1];
                        clear = 1;
                        len--;
                        continue;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'k'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('k')):
                        /* kill-line */
                        line[first + cursor] = '\0';
                        clear = len - (first + cursor);
                        len = first + cursor;
                        continue;

                case KEYPRESS(0, 0, CHAR_LINEFEED):
                case KEYPRESS(0, 0, CHAR_CARRIAGE_RETURN):
                case KEYPRESS(0, CHAR_CARRIAGE_RETURN, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, CHAR_CARRIAGE_RETURN, CHAR_CARRIAGE_RETURN): /* Teclast X98+ II firmware sends malformed events */
                        if (!streq(line, *line_in)) {
                                FreePool(*line_in);
                                *line_in = TAKE_PTR(line);
                        }
                        return TRUE;

                case KEYPRESS(0, 0, CHAR_BACKSPACE):
                        if (len == 0)
                                continue;
                        if (first == 0 && cursor == 0)
                                continue;
                        for (UINTN i = first + cursor-1; i < len; i++)
                                line[i] = line[i+1];
                        clear = 1;
                        len--;
                        if (cursor > 0)
                                cursor--;
                        if (cursor > 0 || first == 0)
                                continue;
                        /* show full line if it fits */
                        if (len < x_max) {
                                cursor = first;
                                first = 0;
                                continue;
                        }
                        /* jump left to see what we delete */
                        if (first > 10) {
                                first -= 10;
                                cursor = 10;
                        } else {
                                cursor = first;
                                first = 0;
                        }
                        continue;

                case KEYPRESS(0, 0, ' ') ... KEYPRESS(0, 0, '~'):
                case KEYPRESS(0, 0, 0x80) ... KEYPRESS(0, 0, 0xffff):
                        if (len+1 == size)
                                continue;
                        for (UINTN i = len; i > first + cursor; i--)
                                line[i] = line[i-1];
                        line[first + cursor] = KEYCHAR(key);
                        len++;
                        line[len] = '\0';
                        if (cursor+1 < x_max)
                                cursor++;
                        else if (first + cursor < len)
                                first++;
                        continue;
                }
        }
}

static UINTN entry_lookup_key(Config *config, UINTN start, CHAR16 key) {
        assert(config);

        if (key == 0)
                return IDX_INVALID;

        /* select entry by number key */
        if (key >= '1' && key <= '9') {
                UINTN i = key - '0';
                if (i > config->entry_count)
                        i = config->entry_count;
                return i-1;
        }

        /* find matching key in config entries */
        for (UINTN i = start; i < config->entry_count; i++)
                if (config->entries[i]->key == key)
                        return i;

        for (UINTN i = 0; i < start; i++)
                if (config->entries[i]->key == key)
                        return i;

        return IDX_INVALID;
}

static CHAR16 *update_timeout_efivar(UINT32 *t, BOOLEAN inc) {
        assert(t);

        switch (*t) {
        case TIMEOUT_MAX:
                *t = inc ? TIMEOUT_MAX : (*t - 1);
                break;
        case TIMEOUT_UNSET:
                *t = inc ? TIMEOUT_MENU_FORCE : TIMEOUT_UNSET;
                break;
        case TIMEOUT_MENU_FORCE:
                *t = inc ? TIMEOUT_MENU_HIDDEN : TIMEOUT_UNSET;
                break;
        case TIMEOUT_MENU_HIDDEN:
                *t = inc ? TIMEOUT_MIN : TIMEOUT_MENU_FORCE;
                break;
        default:
                *t += inc ? 1 : -1;
        }

        switch (*t) {
        case TIMEOUT_UNSET:
                return xstrdup(L"Menu timeout defined by configuration file.");
        case TIMEOUT_MENU_FORCE:
                return xstrdup(L"Timeout disabled, menu will always be shown.");
        case TIMEOUT_MENU_HIDDEN:
                return xstrdup(L"Menu disabled. Hold down key at bootup to show menu.");
        default:
                return xpool_print(L"Menu timeout set to %u s.", *t);
        }
}

static BOOLEAN unicode_supported(void) {
        static INTN cache = -1;

        if (cache < 0)
                /* Basic unicode box drawing support is mandated by the spec, but it does
                 * not hurt to make sure it works. */
                cache = !EFI_ERROR(ST->ConOut->TestString(ST->ConOut, (CHAR16 *) L"─"));

        return cache;
}

static void ps_string(const CHAR16 *fmt, const void *value) {
        assert(fmt);
        if (value)
                Print(fmt, value);
}

static void ps_bool(const CHAR16 *fmt, BOOLEAN value) {
        assert(fmt);
        Print(fmt, yes_no(value));
}

static BOOLEAN ps_continue(void) {
        UINT64 key;
        EFI_STATUS err;

        if (unicode_supported())
                Print(L"\n─── Press any key to continue, ESC or q to quit. ───\n\n");
        else
                Print(L"\n--- Press any key to continue, ESC or q to quit. ---\n\n");

        err = console_key_read(&key, UINT64_MAX);
        return !EFI_ERROR(err) && !IN_SET(key, KEYPRESS(0, SCAN_ESC, 0), KEYPRESS(0, 0, 'q'), KEYPRESS(0, 0, 'Q'));
}

static void print_status(Config *config, CHAR16 *loaded_image_path) {
        UINTN x_max, y_max;
        UINT32 screen_width = 0, screen_height = 0;
        SecureBootMode secure;
        _cleanup_freepool_ CHAR16 *device_part_uuid = NULL;

        assert(config);
        assert(loaded_image_path);

        clear_screen(COLOR_NORMAL);
        console_query_mode(&x_max, &y_max);
        query_screen_resolution(&screen_width, &screen_height);

        secure = secure_boot_mode();
        (void) efivar_get(LOADER_GUID, L"LoaderDevicePartUUID", &device_part_uuid);

        /* We employ some unusual indentation here for readability. */

        ps_string(L"  systemd-boot version: %a\n",      GIT_VERSION);
        ps_string(L"          loaded image: %s\n",      loaded_image_path);
        ps_string(L" loader partition UUID: %s\n",      device_part_uuid);
        ps_string(L"          architecture: %a\n",      EFI_MACHINE_TYPE_NAME);
            Print(L"    UEFI specification: %u.%02u\n", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        ps_string(L"       firmware vendor: %s\n",      ST->FirmwareVendor);
            Print(L"      firmware version: %u.%02u\n", ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
            Print(L"        OS indications: %lu\n",     get_os_indications_supported());
            Print(L"           secure boot: %s (%s)\n", yes_no(IN_SET(secure, SECURE_BOOT_USER, SECURE_BOOT_DEPLOYED)), secure_boot_mode_to_string(secure));
          ps_bool(L"                  shim: %s\n",      shim_loaded());
          ps_bool(L"                   TPM: %s\n",      tpm_present());
            Print(L"          console mode: %d/%ld (%" PRIuN L"x%" PRIuN L" @%ux%u)\n", ST->ConOut->Mode->Mode, ST->ConOut->Mode->MaxMode - INT64_C(1), x_max, y_max, screen_width, screen_height);

        if (!ps_continue())
                return;

        switch (config->timeout_sec_config) {
        case TIMEOUT_UNSET:
            break;
        case TIMEOUT_MENU_FORCE:
            Print(L"      timeout (config): menu-force\n"); break;
        case TIMEOUT_MENU_HIDDEN:
            Print(L"      timeout (config): menu-hidden\n"); break;
        default:
            Print(L"      timeout (config): %u s\n", config->timeout_sec_config);
        }

        switch (config->timeout_sec_efivar) {
        case TIMEOUT_UNSET:
            break;
        case TIMEOUT_MENU_FORCE:
            Print(L"     timeout (EFI var): menu-force\n"); break;
        case TIMEOUT_MENU_HIDDEN:
            Print(L"     timeout (EFI var): menu-hidden\n"); break;
        default:
            Print(L"     timeout (EFI var): %u s\n", config->timeout_sec_efivar);
        }

        ps_string(L"      default (config): %s\n", config->entry_default_config);
        ps_string(L"     default (EFI var): %s\n", config->entry_default_efivar);
        ps_string(L"    default (one-shot): %s\n", config->entry_oneshot);
        ps_string(L"           saved entry: %s\n", config->entry_saved);
          ps_bool(L"                editor: %s\n", config->editor);
          ps_bool(L"          auto-entries: %s\n", config->auto_entries);
          ps_bool(L"         auto-firmware: %s\n", config->auto_firmware);
          ps_bool(L"                  beep: %s\n", config->beep);
          ps_bool(L"  reboot-for-bitlocker: %s\n", config->reboot_for_bitlocker);
        ps_string(L"      random-seed-mode: %s\n", random_seed_modes_table[config->random_seed_mode]);

        switch (config->console_mode) {
        case CONSOLE_MODE_AUTO:
            Print(L" console-mode (config): %s\n", L"auto"); break;
        case CONSOLE_MODE_KEEP:
            Print(L" console-mode (config): %s\n", L"keep"); break;
        case CONSOLE_MODE_FIRMWARE_MAX:
            Print(L" console-mode (config): %s\n", L"max"); break;
        default:
            Print(L" console-mode (config): %ld\n", config->console_mode); break;
        }

        /* EFI var console mode is always a concrete value or unset. */
        if (config->console_mode_efivar != CONSOLE_MODE_KEEP)
            Print(L"console-mode (EFI var): %ld\n", config->console_mode_efivar);

        if (!ps_continue())
                return;

        for (UINTN i = 0; i < config->entry_count; i++) {
                ConfigEntry *entry = config->entries[i];

                    Print(L"  config entry: %" PRIuN L"/%" PRIuN L"\n", i + 1, config->entry_count);
                ps_string(L"            id: %s\n", entry->id);
                ps_string(L"         title: %s\n", entry->title);
                ps_string(L"    title show: %s\n", streq_ptr(entry->title, entry->title_show) ? NULL : entry->title_show);
                ps_string(L"      sort key: %s\n", entry->sort_key);
                ps_string(L"       version: %s\n", entry->version);
                ps_string(L"    machine-id: %s\n", entry->machine_id);
                if (entry->device)
                    Print(L"        device: %D\n", DevicePathFromHandle(entry->device));
                ps_string(L"        loader: %s\n", entry->loader);
                STRV_FOREACH(initrd, entry->initrd)
                    Print(L"        initrd: %s\n", *initrd);
                ps_string(L"    devicetree: %s\n", entry->devicetree);
                ps_string(L"       options: %s\n", entry->options);
                  ps_bool(L" internal call: %s\n", !!entry->call);

                  ps_bool(L"counting boots: %s\n", entry->tries_left != UINTN_MAX);
                if (entry->tries_left != UINTN_MAX) {
                    Print(L"         tries: %" PRIuN L" done, %" PRIuN L" left\n", entry->tries_done, entry->tries_left);
                    Print(L"  current path: %s\\%s\n",  entry->path, entry->current_name);
                    Print(L"     next path: %s\\%s\n",  entry->path, entry->next_name);
                }

                if (!ps_continue())
                        return;
        }
}

static EFI_STATUS reboot_into_firmware(void) {
        UINT64 osind = 0;
        EFI_STATUS err;

        if (!FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI))
                return log_error_status_stall(EFI_UNSUPPORTED, L"Reboot to firmware interface not supported.");

        (void) efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", &osind);
        osind |= EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        err = efivar_set_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", osind, EFI_VARIABLE_NON_VOLATILE);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error setting OsIndications: %r", err);

        err = RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        return log_error_status_stall(err, L"Error calling ResetSystem: %r", err);
}

static BOOLEAN menu_run(
                Config *config,
                ConfigEntry **chosen_entry,
                CHAR16 *loaded_image_path) {

        assert(config);
        assert(chosen_entry);
        assert(loaded_image_path);

        EFI_STATUS err;
        UINTN visible_max = 0;
        UINTN idx_highlight = config->idx_default;
        UINTN idx_highlight_prev = 0;
        UINTN idx, idx_first = 0, idx_last = 0;
        BOOLEAN new_mode = TRUE, clear = TRUE;
        BOOLEAN refresh = TRUE, highlight = FALSE;
        UINTN x_start = 0, y_start = 0, y_status = 0;
        UINTN x_max, y_max;
        _cleanup_(strv_freep) CHAR16 **lines = NULL;
        _cleanup_freepool_ CHAR16 *clearline = NULL, *separator = NULL, *status = NULL;
        UINT32 timeout_efivar_saved = config->timeout_sec_efivar;
        UINT32 timeout_remain = config->timeout_sec == TIMEOUT_MENU_FORCE ? 0 : config->timeout_sec;
        BOOLEAN exit = FALSE, run = TRUE, firmware_setup = FALSE;
        INT64 console_mode_initial = ST->ConOut->Mode->Mode, console_mode_efivar_saved = config->console_mode_efivar;
        UINTN default_efivar_saved = config->idx_default_efivar;

        graphics_mode(FALSE);
        ST->ConIn->Reset(ST->ConIn, FALSE);
        ST->ConOut->EnableCursor(ST->ConOut, FALSE);

        /* draw a single character to make ClearScreen work on some firmware */
        Print(L" ");

        err = console_set_mode(config->console_mode_efivar != CONSOLE_MODE_KEEP ?
                               config->console_mode_efivar : config->console_mode);
        if (EFI_ERROR(err)) {
                clear_screen(COLOR_NORMAL);
                log_error_stall(L"Error switching console mode: %r", err);
        }

        UINTN line_width = 0, entry_padding = 3;
        while (!exit) {
                UINT64 key;

                if (new_mode) {
                        console_query_mode(&x_max, &y_max);

                        /* account for padding+status */
                        visible_max = y_max - 2;

                        /* Drawing entries starts at idx_first until idx_last. We want to make
                        * sure that idx_highlight is centered, but not if we are close to the
                        * beginning/end of the entry list. Otherwise we would have a half-empty
                        * screen. */
                        if (config->entry_count <= visible_max || idx_highlight <= visible_max / 2)
                                idx_first = 0;
                        else if (idx_highlight >= config->entry_count - (visible_max / 2))
                                idx_first = config->entry_count - visible_max;
                        else
                                idx_first = idx_highlight - (visible_max / 2);
                        idx_last = idx_first + visible_max - 1;

                        /* length of the longest entry */
                        line_width = 0;
                        for (UINTN i = 0; i < config->entry_count; i++)
                                line_width = MAX(line_width, StrLen(config->entries[i]->title_show));
                        line_width = MIN(line_width + 2 * entry_padding, x_max);

                        /* offsets to center the entries on the screen */
                        x_start = (x_max - (line_width)) / 2;
                        if (config->entry_count < visible_max)
                                y_start = ((visible_max - config->entry_count) / 2) + 1;
                        else
                                y_start = 0;

                        /* Put status line after the entry list, but give it some breathing room. */
                        y_status = MIN(y_start + MIN(visible_max, config->entry_count) + 1, y_max - 1);

                        lines = strv_free(lines);
                        clearline = mfree(clearline);
                        separator = mfree(separator);

                        /* menu entries title lines */
                        lines = xnew(CHAR16*, config->entry_count + 1);

                        for (UINTN i = 0; i < config->entry_count; i++) {
                                UINTN j, padding;

                                lines[i] = xnew(CHAR16, line_width + 1);
                                padding = (line_width - MIN(StrLen(config->entries[i]->title_show), line_width)) / 2;

                                for (j = 0; j < padding; j++)
                                        lines[i][j] = ' ';

                                for (UINTN k = 0; config->entries[i]->title_show[k] != '\0' && j < line_width; j++, k++)
                                        lines[i][j] = config->entries[i]->title_show[k];

                                for (; j < line_width; j++)
                                        lines[i][j] = ' ';
                                lines[i][line_width] = '\0';
                        }
                        lines[config->entry_count] = NULL;

                        clearline = xnew(CHAR16, x_max + 1);
                        separator = xnew(CHAR16, x_max + 1);
                        for (UINTN i = 0; i < x_max; i++) {
                                clearline[i] = ' ';
                                separator[i] = unicode_supported() ? L'─' : L'-';
                        }
                        clearline[x_max] = 0;
                        separator[x_max] = 0;

                        new_mode = FALSE;
                        clear = TRUE;
                }

                if (clear) {
                        clear_screen(COLOR_NORMAL);
                        clear = FALSE;
                        refresh = TRUE;
                }

                if (refresh) {
                        for (UINTN i = idx_first; i <= idx_last && i < config->entry_count; i++) {
                                print_at(x_start, y_start + i - idx_first,
                                         (i == idx_highlight) ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                         lines[i]);
                                if (i == config->idx_default_efivar)
                                        print_at(x_start, y_start + i - idx_first,
                                                 (i == idx_highlight) ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                                 (CHAR16*) (unicode_supported() ? L" ►" : L"=>"));
                        }
                        refresh = FALSE;
                } else if (highlight) {
                        print_at(x_start, y_start + idx_highlight_prev - idx_first, COLOR_ENTRY, lines[idx_highlight_prev]);
                        print_at(x_start, y_start + idx_highlight - idx_first, COLOR_HIGHLIGHT, lines[idx_highlight]);
                        if (idx_highlight_prev == config->idx_default_efivar)
                                print_at(x_start , y_start + idx_highlight_prev - idx_first, COLOR_ENTRY, (CHAR16*) (unicode_supported() ? L" ►" : L"=>"));
                        if (idx_highlight == config->idx_default_efivar)
                                print_at(x_start, y_start + idx_highlight - idx_first, COLOR_HIGHLIGHT, (CHAR16*) (unicode_supported() ? L" ►" : L"=>"));
                        highlight = FALSE;
                }

                if (timeout_remain > 0) {
                        FreePool(status);
                        status = xpool_print(L"Boot in %u s.", timeout_remain);
                }

                if (status) {
                        /* If we draw the last char of the last line, the screen will scroll and break our
                         * input. Therefore, draw one less character then we could for the status message.
                         * Note that the same does not apply for the separator line as it will never be drawn
                         * on the last line. */
                        UINTN len = StrnLen(status, x_max - 1);
                        UINTN x = (x_max - len) / 2;
                        status[len] = '\0';
                        print_at(0, y_status, COLOR_NORMAL, clearline + x_max - x);
                        ST->ConOut->OutputString(ST->ConOut, status);
                        ST->ConOut->OutputString(ST->ConOut, clearline + 1 + x + len);

                        len = MIN(MAX(len, line_width) + 2 * entry_padding, x_max);
                        x = (x_max - len) / 2;
                        print_at(x, y_status - 1, COLOR_NORMAL, separator + x_max - len);
                } else {
                        print_at(0, y_status - 1, COLOR_NORMAL, clearline);
                        print_at(0, y_status, COLOR_NORMAL, clearline + 1); /* See comment above. */
                }

                /* Beep several times so that the selected entry can be distinguished. */
                if (config->beep)
                        beep(idx_highlight + 1);

                err = console_key_read(&key, timeout_remain > 0 ? 1000 * 1000 : UINT64_MAX);
                if (err == EFI_NOT_READY)
                        /* No input device returned a key, try again. This
                         * normally should not happen. */
                        continue;
                if (err == EFI_TIMEOUT) {
                        assert(timeout_remain > 0);
                        timeout_remain--;
                        if (timeout_remain == 0) {
                                exit = TRUE;
                                break;
                        }

                        /* update status */
                        continue;
                }
                if (EFI_ERROR(err)) {
                        exit = TRUE;
                        break;
                }

                timeout_remain = 0;

                /* clear status after keystroke */
                status = mfree(status);

                idx_highlight_prev = idx_highlight;

                if (firmware_setup) {
                        firmware_setup = FALSE;
                        if (key == KEYPRESS(0, 0, CHAR_CARRIAGE_RETURN))
                                reboot_into_firmware();
                        continue;
                }

                switch (key) {
                case KEYPRESS(0, SCAN_UP, 0):
                case KEYPRESS(0, 0, 'k'):
                case KEYPRESS(0, 0, 'K'):
                        if (idx_highlight > 0)
                                idx_highlight--;
                        break;

                case KEYPRESS(0, SCAN_DOWN, 0):
                case KEYPRESS(0, 0, 'j'):
                case KEYPRESS(0, 0, 'J'):
                        if (idx_highlight < config->entry_count-1)
                                idx_highlight++;
                        break;

                case KEYPRESS(0, SCAN_HOME, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '<'):
                        if (idx_highlight > 0) {
                                refresh = TRUE;
                                idx_highlight = 0;
                        }
                        break;

                case KEYPRESS(0, SCAN_END, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '>'):
                        if (idx_highlight < config->entry_count-1) {
                                refresh = TRUE;
                                idx_highlight = config->entry_count-1;
                        }
                        break;

                case KEYPRESS(0, SCAN_PAGE_UP, 0):
                        if (idx_highlight > visible_max)
                                idx_highlight -= visible_max;
                        else
                                idx_highlight = 0;
                        break;

                case KEYPRESS(0, SCAN_PAGE_DOWN, 0):
                        idx_highlight += visible_max;
                        if (idx_highlight > config->entry_count-1)
                                idx_highlight = config->entry_count-1;
                        break;

                case KEYPRESS(0, 0, CHAR_LINEFEED):
                case KEYPRESS(0, 0, CHAR_CARRIAGE_RETURN):
                case KEYPRESS(0, CHAR_CARRIAGE_RETURN, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, CHAR_CARRIAGE_RETURN, CHAR_CARRIAGE_RETURN): /* Teclast X98+ II firmware sends malformed events */
                case KEYPRESS(0, SCAN_RIGHT, 0):
                        exit = TRUE;
                        break;

                case KEYPRESS(0, SCAN_F1, 0):
                case KEYPRESS(0, 0, 'h'):
                case KEYPRESS(0, 0, 'H'):
                case KEYPRESS(0, 0, '?'):
                        /* This must stay below 80 characters! Q/v/Ctrl+l/f deliberately not advertised. */
                        status = xstrdup(L"(d)efault (t/T)timeout (e)dit (r/R)resolution (p)rint (h)elp");
                        break;

                case KEYPRESS(0, 0, 'Q'):
                        exit = TRUE;
                        run = FALSE;
                        break;

                case KEYPRESS(0, 0, 'd'):
                case KEYPRESS(0, 0, 'D'):
                        if (config->idx_default_efivar != idx_highlight) {
                                FreePool(config->entry_default_efivar);
                                config->entry_default_efivar = xstrdup(config->entries[idx_highlight]->id);
                                config->idx_default_efivar = idx_highlight;
                                status = xstrdup(L"Default boot entry selected.");
                        } else {
                                config->entry_default_efivar = mfree(config->entry_default_efivar);
                                config->idx_default_efivar = IDX_INVALID;
                                status = xstrdup(L"Default boot entry cleared.");
                        }
                        config->use_saved_entry_efivar = FALSE;
                        refresh = TRUE;
                        break;

                case KEYPRESS(0, 0, '-'):
                case KEYPRESS(0, 0, 'T'):
                        status = update_timeout_efivar(&config->timeout_sec_efivar, FALSE);
                        break;

                case KEYPRESS(0, 0, '+'):
                case KEYPRESS(0, 0, 't'):
                        status = update_timeout_efivar(&config->timeout_sec_efivar, TRUE);
                        break;

                case KEYPRESS(0, 0, 'e'):
                case KEYPRESS(0, 0, 'E'):
                        /* only the options of configured entries can be edited */
                        if (!config->editor || !IN_SET(config->entries[idx_highlight]->type,
                            LOADER_EFI, LOADER_LINUX, LOADER_UNIFIED_LINUX))
                                break;

                        /* Unified kernels that are signed as a whole will not accept command line options
                         * when secure boot is enabled unless there is none embedded in the image. Do not try
                         * to pretend we can edit it to only have it be ignored. */
                        if (config->entries[idx_highlight]->type == LOADER_UNIFIED_LINUX &&
                            secure_boot_enabled() &&
                            config->entries[idx_highlight]->options)
                                break;

                        /* The edit line may end up on the last line of the screen. And even though we're
                         * not telling the firmware to advance the line, it still does in this one case,
                         * causing a scroll to happen that screws with our beautiful boot loader output.
                         * Since we cannot paint the last character of the edit line, we simply start
                         * at x-offset 1 for symmetry. */
                        print_at(1, y_status, COLOR_EDIT, clearline + 2);
                        exit = line_edit(&config->entries[idx_highlight]->options, x_max - 2, y_status);
                        print_at(1, y_status, COLOR_NORMAL, clearline + 2);
                        break;

                case KEYPRESS(0, 0, 'v'):
                        status = xpool_print(
                                        L"systemd-boot " GIT_VERSION L" (" EFI_MACHINE_TYPE_NAME L"), "
                                        L"UEFI Specification %u.%02u, Vendor %s %u.%02u",
                                        ST->Hdr.Revision >> 16,
                                        ST->Hdr.Revision & 0xffff,
                                        ST->FirmwareVendor,
                                        ST->FirmwareRevision >> 16,
                                        ST->FirmwareRevision & 0xffff);
                        break;

                case KEYPRESS(0, 0, 'p'):
                case KEYPRESS(0, 0, 'P'):
                        print_status(config, loaded_image_path);
                        clear = TRUE;
                        break;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'l'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('l')):
                        clear = TRUE;
                        break;

                case KEYPRESS(0, 0, 'r'):
                        err = console_set_mode(CONSOLE_MODE_NEXT);
                        if (EFI_ERROR(err))
                                status = xpool_print(L"Error changing console mode: %r", err);
                        else {
                                config->console_mode_efivar = ST->ConOut->Mode->Mode;
                                status = xpool_print(L"Console mode changed to %ld.", config->console_mode_efivar);
                        }
                        new_mode = TRUE;
                        break;

                case KEYPRESS(0, 0, 'R'):
                        config->console_mode_efivar = CONSOLE_MODE_KEEP;
                        err = console_set_mode(config->console_mode == CONSOLE_MODE_KEEP ?
                                               console_mode_initial : config->console_mode);
                        if (EFI_ERROR(err))
                                status = xpool_print(L"Error resetting console mode: %r", err);
                        else
                                status = xpool_print(L"Console mode reset to %s default.",
                                                     config->console_mode == CONSOLE_MODE_KEEP ? L"firmware" : L"configuration file");
                        new_mode = TRUE;
                        break;

                case KEYPRESS(0, 0, 'f'):
                case KEYPRESS(0, 0, 'F'):
                case KEYPRESS(0, SCAN_F2, 0):     /* Most vendors. */
                case KEYPRESS(0, SCAN_F10, 0):    /* HP and Lenovo. */
                case KEYPRESS(0, SCAN_DELETE, 0): /* Same as F2. */
                case KEYPRESS(0, SCAN_ESC, 0):    /* HP. */
                        if (FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI)) {
                                firmware_setup = TRUE;
                                /* Let's make sure the user really wants to do this. */
                                status = xpool_print(L"Press Enter to reboot into firmware interface.");
                        } else
                                status = xpool_print(L"Reboot into firmware interface not supported.");
                        break;

                default:
                        /* jump with a hotkey directly to a matching entry */
                        idx = entry_lookup_key(config, idx_highlight+1, KEYCHAR(key));
                        if (idx == IDX_INVALID)
                                break;
                        idx_highlight = idx;
                        refresh = TRUE;
                }

                if (idx_highlight > idx_last) {
                        idx_last = idx_highlight;
                        idx_first = 1 + idx_highlight - visible_max;
                        refresh = TRUE;
                } else if (idx_highlight < idx_first) {
                        idx_first = idx_highlight;
                        idx_last = idx_highlight + visible_max-1;
                        refresh = TRUE;
                }

                if (!refresh && idx_highlight != idx_highlight_prev)
                        highlight = TRUE;
        }

        *chosen_entry = config->entries[idx_highlight];

        /* Update EFI vars after we left the menu to reduce NVRAM writes. */

        if (default_efivar_saved != config->idx_default_efivar)
                efivar_set(LOADER_GUID, L"LoaderEntryDefault", config->entry_default_efivar, EFI_VARIABLE_NON_VOLATILE);

        if (console_mode_efivar_saved != config->console_mode_efivar) {
                if (config->console_mode_efivar == CONSOLE_MODE_KEEP)
                        efivar_set(LOADER_GUID, L"LoaderConfigConsoleMode", NULL, EFI_VARIABLE_NON_VOLATILE);
                else
                        efivar_set_uint_string(LOADER_GUID, L"LoaderConfigConsoleMode",
                                               config->console_mode_efivar, EFI_VARIABLE_NON_VOLATILE);
        }

        if (timeout_efivar_saved != config->timeout_sec_efivar) {
                if (config->timeout_sec_efivar == TIMEOUT_UNSET)
                        efivar_set(LOADER_GUID, L"LoaderConfigTimeout", NULL, EFI_VARIABLE_NON_VOLATILE);
                else
                        efivar_set_uint_string(LOADER_GUID, L"LoaderConfigTimeout",
                                               config->timeout_sec_efivar, EFI_VARIABLE_NON_VOLATILE);
        }

        clear_screen(COLOR_NORMAL);
        return run;
}

static void config_add_entry(Config *config, ConfigEntry *entry) {
        assert(config);
        assert(entry);

        /* This is just for paranoia. */
        assert(config->entry_count < IDX_MAX);

        if ((config->entry_count & 15) == 0) {
                UINTN i = config->entry_count + 16;
                config->entries = xreallocate_pool(
                                config->entries,
                                sizeof(void *) * config->entry_count,
                                sizeof(void *) * i);
        }
        config->entries[config->entry_count++] = entry;
}

static void config_entry_free(ConfigEntry *entry) {
        if (!entry)
                return;

        FreePool(entry->id);
        FreePool(entry->title_show);
        FreePool(entry->title);
        FreePool(entry->sort_key);
        FreePool(entry->version);
        FreePool(entry->machine_id);
        FreePool(entry->loader);
        FreePool(entry->devicetree);
        FreePool(entry->options);
        strv_free(entry->initrd);
        FreePool(entry->path);
        FreePool(entry->current_name);
        FreePool(entry->next_name);
        FreePool(entry);
}

static inline void config_entry_freep(ConfigEntry **entry) {
        config_entry_free(*entry);
}

static CHAR8 *line_get_key_value(
                CHAR8 *content,
                const CHAR8 *sep,
                UINTN *pos,
                CHAR8 **key_ret,
                CHAR8 **value_ret) {

        CHAR8 *line, *value;
        UINTN linelen;

        assert(content);
        assert(sep);
        assert(pos);
        assert(key_ret);
        assert(value_ret);

        for (;;) {
                line = content + *pos;
                if (*line == '\0')
                        return NULL;

                linelen = 0;
                while (line[linelen] && !strchra((CHAR8 *) "\n\r", line[linelen]))
                        linelen++;

                /* move pos to next line */
                *pos += linelen;
                if (content[*pos])
                        (*pos)++;

                /* empty line */
                if (linelen == 0)
                        continue;

                /* terminate line */
                line[linelen] = '\0';

                /* remove leading whitespace */
                while (strchra((CHAR8 *) " \t", *line)) {
                        line++;
                        linelen--;
                }

                /* remove trailing whitespace */
                while (linelen > 0 && strchra((CHAR8 *) " \t", line[linelen - 1]))
                        linelen--;
                line[linelen] = '\0';

                if (*line == '#')
                        continue;

                /* split key/value */
                value = line;
                while (*value && !strchra(sep, *value))
                        value++;
                if (*value == '\0')
                        continue;
                *value = '\0';
                value++;
                while (*value && strchra(sep, *value))
                        value++;

                /* unquote */
                if (value[0] == '"' && line[linelen - 1] == '"') {
                        value++;
                        line[linelen - 1] = '\0';
                }

                *key_ret = line;
                *value_ret = value;
                return line;
        }
}

static void config_defaults_load_from_file(Config *config, CHAR8 *content) {
        CHAR8 *line;
        UINTN pos = 0;
        CHAR8 *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(content);

        while ((line = line_get_key_value(content, (CHAR8 *)" \t", &pos, &key, &value))) {
                if (strcmpa((CHAR8 *)"timeout", key) == 0) {
                        if (strcmpa((CHAR8*) "menu-force", value) == 0)
                                config->timeout_sec_config = TIMEOUT_MENU_FORCE;
                        else if (strcmpa((CHAR8*) "menu-hidden", value) == 0)
                                config->timeout_sec_config = TIMEOUT_MENU_HIDDEN;
                        else {
                                _cleanup_freepool_ CHAR16 *s = NULL;

                                s = xstra_to_str(value);
                                config->timeout_sec_config = MIN(Atoi(s), TIMEOUT_TYPE_MAX);
                        }
                        config->timeout_sec = config->timeout_sec_config;
                        continue;
                }

                if (strcmpa((CHAR8 *)"default", key) == 0) {
                        if (value[0] == '@' && strcmpa((CHAR8 *)"@saved", value) != 0) {
                                log_error_stall(L"Unsupported special entry identifier: %a", value);
                                continue;
                        }
                        FreePool(config->entry_default_config);
                        config->entry_default_config = xstra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"editor", key) == 0) {
                        err = parse_boolean(value, &config->editor);
                        if (EFI_ERROR(err))
                                log_error_stall(L"Error parsing 'editor' config option: %a", value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"auto-entries", key) == 0) {
                        err = parse_boolean(value, &config->auto_entries);
                        if (EFI_ERROR(err))
                                log_error_stall(L"Error parsing 'auto-entries' config option: %a", value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"auto-firmware", key) == 0) {
                        err = parse_boolean(value, &config->auto_firmware);
                        if (EFI_ERROR(err))
                                log_error_stall(L"Error parsing 'auto-firmware' config option: %a", value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"beep", key) == 0) {
                        err = parse_boolean(value, &config->beep);
                        if (EFI_ERROR(err))
                                log_error_stall(L"Error parsing 'beep' config option: %a", value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"reboot-for-bitlocker", key) == 0) {
                        err = parse_boolean(value, &config->reboot_for_bitlocker);
                        if (EFI_ERROR(err))
                                log_error_stall(L"Error parsing 'reboot-for-bitlocker' config option: %a", value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"console-mode", key) == 0) {
                        if (strcmpa((CHAR8 *)"auto", value) == 0)
                                config->console_mode = CONSOLE_MODE_AUTO;
                        else if (strcmpa((CHAR8 *)"max", value) == 0)
                                config->console_mode = CONSOLE_MODE_FIRMWARE_MAX;
                        else if (strcmpa((CHAR8 *)"keep", value)  == 0)
                                config->console_mode = CONSOLE_MODE_KEEP;
                        else {
                                _cleanup_freepool_ CHAR16 *s = NULL;

                                s = xstra_to_str(value);
                                config->console_mode = MIN(Atoi(s), (UINTN)CONSOLE_MODE_RANGE_MAX);
                        }
                        continue;
                }

                if (strcmpa((CHAR8*) "random-seed-mode", key) == 0) {
                        if (strcmpa((CHAR8*) "off", value) == 0)
                                config->random_seed_mode = RANDOM_SEED_OFF;
                        else if (strcmpa((CHAR8*) "with-system-token", value) == 0)
                                config->random_seed_mode = RANDOM_SEED_WITH_SYSTEM_TOKEN;
                        else if (strcmpa((CHAR8*) "always", value) == 0)
                                config->random_seed_mode = RANDOM_SEED_ALWAYS;
                        else {
                                BOOLEAN on;

                                err = parse_boolean(value, &on);
                                if (EFI_ERROR(err)) {
                                        log_error_stall(L"Error parsing 'random-seed-mode' config option: %a", value);
                                        continue;
                                }

                                config->random_seed_mode = on ? RANDOM_SEED_ALWAYS : RANDOM_SEED_OFF;
                        }
                        continue;
                }
        }
}

static void config_entry_parse_tries(
                ConfigEntry *entry,
                const CHAR16 *path,
                const CHAR16 *file,
                const CHAR16 *suffix) {

        UINTN left = UINTN_MAX, done = UINTN_MAX, factor = 1, i, next_left, next_done;
        _cleanup_freepool_ CHAR16 *prefix = NULL;

        assert(entry);
        assert(path);
        assert(file);

        /*
         * Parses a suffix of two counters (one going down, one going up) in the form "+LEFT-DONE" from the end of the
         * filename (but before the .efi/.conf suffix), where the "-DONE" part is optional and may be left out (in
         * which case that counter as assumed to be zero, i.e. the missing part is synonymous to "-0").
         *
         * Names we grok, and the series they result in:
         *
         * foobar+3.efi   → foobar+2-1.efi → foobar+1-2.efi → foobar+0-3.efi → STOP!
         * foobar+4-0.efi → foobar+3-1.efi → foobar+2-2.efi → foobar+1-3.efi → foobar+0-4.efi → STOP!
         */

        i = StrLen(file);

        /* Chop off any suffix such as ".conf" or ".efi" */
        if (suffix) {
                UINTN suffix_length;

                suffix_length = StrLen(suffix);
                if (i < suffix_length)
                        return;

                i -= suffix_length;
        }

        /* Go backwards through the string and parse everything we encounter */
        for (;;) {
                if (i == 0)
                        return;

                i--;

                switch (file[i]) {

                case '+':
                        if (left == UINTN_MAX) /* didn't read at least one digit for 'left'? */
                                return;

                        if (done == UINTN_MAX) /* no 'done' counter? If so, it's equivalent to 0 */
                                done = 0;

                        goto good;

                case '-':
                        if (left == UINTN_MAX) /* didn't parse any digit yet? */
                                return;

                        if (done != UINTN_MAX) /* already encountered a dash earlier? */
                                return;

                        /* So we encountered a dash. This means this counter is of the form +LEFT-DONE. Let's assign
                         * what we already parsed to 'done', and start fresh for the 'left' part. */

                        done = left;
                        left = UINTN_MAX;
                        factor = 1;
                        break;

                case '0'...'9': {
                        UINTN new_factor;

                        if (left == UINTN_MAX)
                                left = file[i] - '0';
                        else {
                                UINTN new_left, digit;

                                digit = file[i] - '0';
                                if (digit > UINTN_MAX / factor) /* overflow check */
                                        return;

                                new_left = left + digit * factor;
                                if (new_left < left) /* overflow check */
                                        return;

                                if (new_left == UINTN_MAX) /* don't allow us to be confused */
                                        return;
                        }

                        new_factor = factor * 10;
                        if (new_factor < factor) /* overflow check */
                                return;

                        factor = new_factor;
                        break;
                }

                default:
                        return;
                }
        }

good:
        entry->tries_left = left;
        entry->tries_done = done;

        entry->path = xstrdup(path);
        entry->current_name = xstrdup(file);

        next_left = left <= 0 ? 0 : left - 1;
        next_done = done >= (UINTN) -2 ? (UINTN) -2 : done + 1;

        prefix = xstrdup(file);
        prefix[i] = 0;

        entry->next_name = xpool_print(L"%s+%" PRIuN L"-%" PRIuN L"%s", prefix, next_left, next_done, strempty(suffix));
}

static void config_entry_bump_counters(ConfigEntry *entry, EFI_FILE *root_dir) {
        _cleanup_freepool_ CHAR16* old_path = NULL, *new_path = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *file_info = NULL;
        UINTN file_info_size;
        EFI_STATUS err;

        assert(entry);
        assert(root_dir);

        if (entry->tries_left == UINTN_MAX)
                return;

        if (!entry->path || !entry->current_name || !entry->next_name)
                return;

        old_path = xpool_print(L"%s\\%s", entry->path, entry->current_name);

        err = root_dir->Open(root_dir, &handle, old_path, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (EFI_ERROR(err))
                return;

        err = get_file_info_harder(handle, &file_info, &file_info_size);
        if (EFI_ERROR(err))
                return;

        /* And rename the file */
        StrCpy(file_info->FileName, entry->next_name);
        err = handle->SetInfo(handle, &GenericFileInfo, file_info_size, file_info);
        if (EFI_ERROR(err)) {
                log_error_stall(L"Failed to rename '%s' to '%s', ignoring: %r", old_path, entry->next_name, err);
                return;
        }

        /* Flush everything to disk, just in case… */
        (void) handle->Flush(handle);

        /* Let's tell the OS that we renamed this file, so that it knows what to rename to the counter-less name on
         * success */
        new_path = xpool_print(L"%s\\%s", entry->path, entry->next_name);
        efivar_set(LOADER_GUID, L"LoaderBootCountPath", new_path, 0);

        /* If the file we just renamed is the loader path, then let's update that. */
        if (StrCmp(entry->loader, old_path) == 0) {
                FreePool(entry->loader);
                entry->loader = TAKE_PTR(new_path);
        }
}

static void config_entry_add_from_file(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const CHAR16 *path,
                const CHAR16 *file,
                CHAR8 *content,
                const CHAR16 *loaded_image_path) {

        _cleanup_(config_entry_freep) ConfigEntry *entry = NULL;
        CHAR8 *line;
        UINTN pos = 0, n_initrd = 0;
        CHAR8 *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);
        assert(path);
        assert(file);
        assert(content);

        entry = xnew(ConfigEntry, 1);
        *entry = (ConfigEntry) {
                .tries_done = UINTN_MAX,
                .tries_left = UINTN_MAX,
        };

        while ((line = line_get_key_value(content, (CHAR8 *)" \t", &pos, &key, &value))) {
                if (strcmpa((CHAR8 *)"title", key) == 0) {
                        FreePool(entry->title);
                        entry->title = xstra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"sort-key", key) == 0) {
                        FreePool(entry->sort_key);
                        entry->sort_key = xstra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"version", key) == 0) {
                        FreePool(entry->version);
                        entry->version = xstra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"machine-id", key) == 0) {
                        FreePool(entry->machine_id);
                        entry->machine_id = xstra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"linux", key) == 0) {
                        FreePool(entry->loader);
                        entry->type = LOADER_LINUX;
                        entry->loader = xstra_to_path(value);
                        entry->key = 'l';
                        continue;
                }

                if (strcmpa((CHAR8 *)"efi", key) == 0) {
                        entry->type = LOADER_EFI;
                        FreePool(entry->loader);
                        entry->loader = xstra_to_path(value);

                        /* do not add an entry for ourselves */
                        if (loaded_image_path && StriCmp(entry->loader, loaded_image_path) == 0) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }
                        continue;
                }

                if (strcmpa((CHAR8 *)"architecture", key) == 0) {
                        /* do not add an entry for an EFI image of architecture not matching with that of the image */
                        if (strcmpa((CHAR8 *)EFI_MACHINE_TYPE_NAME, value) != 0) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }
                        continue;
                }

                if (strcmpa((CHAR8 *)"devicetree", key) == 0) {
                        FreePool(entry->devicetree);
                        entry->devicetree = xstra_to_path(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"initrd", key) == 0) {
                        entry->initrd = xreallocate_pool(
                                entry->initrd,
                                n_initrd == 0 ? 0 : (n_initrd + 1) * sizeof(UINT16 *),
                                (n_initrd + 2) * sizeof(UINT16 *));
                        entry->initrd[n_initrd++] = xstra_to_path(value);
                        entry->initrd[n_initrd] = NULL;
                        continue;
                }

                if (strcmpa((CHAR8 *)"options", key) == 0) {
                        _cleanup_freepool_ CHAR16 *new = NULL;

                        new = xstra_to_str(value);
                        if (entry->options) {
                                CHAR16 *s;

                                s = xpool_print(L"%s %s", entry->options, new);
                                FreePool(entry->options);
                                entry->options = s;
                        } else
                                entry->options = TAKE_PTR(new);

                        continue;
                }
        }

        if (entry->type == LOADER_UNDEFINED)
                return;

        /* check existence */
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        err = root_dir->Open(root_dir, &handle, entry->loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return;

        entry->device = device;
        entry->id = xstrdup(file);
        StrLwr(entry->id);

        config_add_entry(config, entry);

        config_entry_parse_tries(entry, path, file, L".conf");
        TAKE_PTR(entry);
}

static void config_load_defaults(Config *config, EFI_FILE *root_dir) {
        _cleanup_freepool_ CHAR8 *content = NULL;
        UINTN value;
        EFI_STATUS err;

        assert(root_dir);

        *config = (Config) {
                .editor = TRUE,
                .auto_entries = TRUE,
                .auto_firmware = TRUE,
                .reboot_for_bitlocker = FALSE,
                .random_seed_mode = RANDOM_SEED_WITH_SYSTEM_TOKEN,
                .idx_default_efivar = IDX_INVALID,
                .console_mode = CONSOLE_MODE_KEEP,
                .console_mode_efivar = CONSOLE_MODE_KEEP,
                .timeout_sec_config = TIMEOUT_UNSET,
                .timeout_sec_efivar = TIMEOUT_UNSET,
        };

        err = file_read(root_dir, L"\\loader\\loader.conf", 0, 0, &content, NULL);
        if (!EFI_ERROR(err))
                config_defaults_load_from_file(config, content);

        err = efivar_get_uint_string(LOADER_GUID, L"LoaderConfigTimeout", &value);
        if (!EFI_ERROR(err)) {
                config->timeout_sec_efivar = MIN(value, TIMEOUT_TYPE_MAX);
                config->timeout_sec = config->timeout_sec_efivar;
        }

        err = efivar_get_uint_string(LOADER_GUID, L"LoaderConfigTimeoutOneShot", &value);
        if (!EFI_ERROR(err)) {
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_set(LOADER_GUID, L"LoaderConfigTimeoutOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);

                config->timeout_sec = MIN(value, TIMEOUT_TYPE_MAX);
                config->force_menu = TRUE; /* force the menu when this is set */
        }

        err = efivar_get_uint_string(LOADER_GUID, L"LoaderConfigConsoleMode", &value);
        if (!EFI_ERROR(err))
                config->console_mode_efivar = value;

        err = efivar_get(LOADER_GUID, L"LoaderEntryOneShot", &config->entry_oneshot);
        if (!EFI_ERROR(err))
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_set(LOADER_GUID, L"LoaderEntryOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);

        (void) efivar_get(LOADER_GUID, L"LoaderEntryDefault", &config->entry_default_efivar);

        config->use_saved_entry = streq_ptr(config->entry_default_config, L"@saved");
        config->use_saved_entry_efivar = streq_ptr(config->entry_default_efivar, L"@saved");
        if (config->use_saved_entry || config->use_saved_entry_efivar)
                (void) efivar_get(LOADER_GUID, L"LoaderEntryLastBooted", &config->entry_saved);
}

static void config_load_entries(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const CHAR16 *loaded_image_path) {

        _cleanup_(file_closep) EFI_FILE *entries_dir = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *f = NULL;
        UINTN f_size = 0;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);

        /* Adds Boot Loader Type #1 entries (i.e. /loader/entries/….conf) */

        err = open_directory(root_dir, L"\\loader\\entries", &entries_dir);
        if (EFI_ERROR(err))
                return;

        for (;;) {
                _cleanup_freepool_ CHAR8 *content = NULL;

                err = readdir_harder(entries_dir, &f, &f_size);
                if (EFI_ERROR(err) || !f)
                        break;

                if (f->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(f->Attribute, EFI_FILE_DIRECTORY))
                        continue;

                if (!endswith_no_case(f->FileName, L".conf"))
                        continue;
                if (startswith(f->FileName, L"auto-"))
                        continue;

                err = file_read(entries_dir, f->FileName, 0, 0, &content, NULL);
                if (!EFI_ERROR(err))
                        config_entry_add_from_file(config, device, root_dir, L"\\loader\\entries", f->FileName, content, loaded_image_path);
        }
}

static INTN config_entry_compare(const ConfigEntry *a, const ConfigEntry *b) {
        INTN r;

        assert(a);
        assert(b);

        /* Order entries that have no tries left to the end of the list */
        r = CMP(a->tries_left == 0, b->tries_left == 0);
        if (r != 0)
                return r;

        /* If there's a sort key defined for *both* entries, then we do new-style ordering, i.e. by
         * sort-key/machine-id/version, with a final fallback to id. If there's no sort key for either, we do
         * old-style ordering, i.e. by id only. If one has sort key and the other does not, we put new-style
         * before old-style. */
        r = CMP(!a->sort_key, !b->sort_key);
        if (r != 0) /* one is old-style, one new-style */
                return r;

        if (a->sort_key && b->sort_key) {
                r = strcmp(a->sort_key, b->sort_key);
                if (r != 0)
                        return r;

                /* If multiple installations of the same OS are around, group by machine ID */
                r = strcmp_ptr(a->machine_id, b->machine_id);
                if (r != 0)
                        return r;

                /* If the sort key was defined, then order by version now (downwards, putting the newest first) */
                r = -strverscmp_improved(a->version, b->version);
                if (r != 0)
                        return r;
        }

        /* Now order by ID. The version is likely part of the ID, thus note that this will generatelly put
         * the newer versions earlier. Specifying a sort key explicitly is preferable, because it gives an
         * explicit sort order. */
        r = -strverscmp_improved(a->id, b->id);
        if (r != 0)
                return r;

        if (a->tries_left == UINTN_MAX || b->tries_left == UINTN_MAX)
                return 0;

        /* If both items have boot counting, and otherwise are identical, put the entry with more tries left first */
        r = -CMP(a->tries_left, b->tries_left);
        if (r != 0)
                return r;

        /* If they have the same number of tries left, then let the one win which was tried fewer times so far */
        return CMP(a->tries_done, b->tries_done);
}

static UINTN config_entry_find(Config *config, const CHAR16 *needle) {
        assert(config);

        if (!needle)
                return IDX_INVALID;

        for (UINTN i = 0; i < config->entry_count; i++)
                if (MetaiMatch(config->entries[i]->id, (CHAR16*) needle))
                        return i;

        return IDX_INVALID;
}

static void config_default_entry_select(Config *config) {
        UINTN i;

        assert(config);

        i = config_entry_find(config, config->entry_oneshot);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        i = config_entry_find(config, config->use_saved_entry_efivar ? config->entry_saved : config->entry_default_efivar);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                config->idx_default_efivar = i;
                return;
        }

        if (config->use_saved_entry)
                /* No need to do the same thing twice. */
                i = config->use_saved_entry_efivar ? IDX_INVALID : config_entry_find(config, config->entry_saved);
        else
                i = config_entry_find(config, config->entry_default_config);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        /* select the first suitable entry */
        for (i = 0; i < config->entry_count; i++) {
                if (config->entries[i]->type == LOADER_AUTO || config->entries[i]->call)
                        continue;
                config->idx_default = i;
                return;
        }

        /* If no configured entry to select from was found, enable the menu. */
        config->idx_default = 0;
        if (config->timeout_sec == 0)
                config->timeout_sec = 10;
}

static BOOLEAN entries_unique(ConfigEntry **entries, BOOLEAN *unique, UINTN entry_count) {
        BOOLEAN is_unique = TRUE;

        assert(entries);
        assert(unique);

        for (UINTN i = 0; i < entry_count; i++)
                for (UINTN k = i + 1; k < entry_count; k++) {
                        if (StrCmp(entries[i]->title_show, entries[k]->title_show) != 0)
                                continue;

                        is_unique = unique[i] = unique[k] = FALSE;
                }

        return is_unique;
}

/* generate a unique title, avoiding non-distinguishable menu entries */
static void config_title_generate(Config *config) {
        assert(config);

        BOOLEAN unique[config->entry_count];

        /* set title */
        for (UINTN i = 0; i < config->entry_count; i++) {
                assert(!config->entries[i]->title_show);
                unique[i] = TRUE;
                config->entries[i]->title_show = xstrdup(config->entries[i]->title ?: config->entries[i]->id);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add version to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                unique[i] = TRUE;

                if (!config->entries[i]->version)
                        continue;

                _cleanup_freepool_ CHAR16 *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(L"%s (%s)", t, config->entries[i]->version);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add machine-id to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                unique[i] = TRUE;

                if (!config->entries[i]->machine_id)
                        continue;

                _cleanup_freepool_ CHAR16 *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(
                        L"%s (%.*s)",
                        t,
                        StrnLen(config->entries[i]->machine_id, 8),
                        config->entries[i]->machine_id);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add file name to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                _cleanup_freepool_ CHAR16 *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(L"%s (%s)", t, config->entries[i]->id);
        }
}

static BOOLEAN config_entry_add_call(
                Config *config,
                const CHAR16 *id,
                const CHAR16 *title,
                EFI_STATUS (*call)(void)) {

        ConfigEntry *entry;

        assert(config);
        assert(id);
        assert(title);
        assert(call);

        entry = xnew(ConfigEntry, 1);
        *entry = (ConfigEntry) {
                .id = xstrdup(id),
                .title = xstrdup(title),
                .call = call,
                .tries_done = UINTN_MAX,
                .tries_left = UINTN_MAX,
        };

        config_add_entry(config, entry);
        return TRUE;
}

static ConfigEntry *config_entry_add_loader(
                Config *config,
                EFI_HANDLE *device,
                enum loader_type type,
                const CHAR16 *id,
                CHAR16 key,
                const CHAR16 *title,
                const CHAR16 *loader,
                const CHAR16 *sort_key,
                const CHAR16 *version) {

        ConfigEntry *entry;

        assert(config);
        assert(device);
        assert(id);
        assert(title);
        assert(loader);

        entry = xnew(ConfigEntry, 1);
        *entry = (ConfigEntry) {
                .type = type,
                .title = xstrdup(title),
                .version = version ? xstrdup(version) : NULL,
                .device = device,
                .loader = xstrdup(loader),
                .id = xstrdup(id),
                .sort_key = sort_key ? xstrdup(sort_key) : NULL,
                .key = key,
                .tries_done = UINTN_MAX,
                .tries_left = UINTN_MAX,
        };

        StrLwr(entry->id);

        config_add_entry(config, entry);
        return entry;
}

static BOOLEAN is_sd_boot(EFI_FILE *root_dir, const CHAR16 *loader_path) {
        EFI_STATUS err;
        const CHAR8 *sections[] = {
                (CHAR8 *)".sdmagic",
                NULL
        };
        UINTN offset = 0, size = 0, read;
        _cleanup_freepool_ CHAR8 *content = NULL;

        assert(root_dir);
        assert(loader_path);

        err = pe_file_locate_sections(root_dir, loader_path, sections, &offset, &size);
        if (EFI_ERROR(err) || size != sizeof(magic))
                return FALSE;

        err = file_read(root_dir, loader_path, offset, size, &content, &read);
        if (EFI_ERROR(err) || size != read)
                return FALSE;

        return CompareMem(content, magic, sizeof(magic)) == 0;
}

static ConfigEntry *config_entry_add_loader_auto(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const CHAR16 *loaded_image_path,
                const CHAR16 *id,
                CHAR16 key,
                const CHAR16 *title,
                const CHAR16 *loader) {

        assert(config);
        assert(device);
        assert(root_dir);
        assert(id);
        assert(title);
        assert(loader || loaded_image_path);

        if (!config->auto_entries)
                return NULL;

        if (loaded_image_path) {
                loader = L"\\EFI\\BOOT\\BOOT" EFI_MACHINE_TYPE_NAME ".efi";

                /* We are trying to add the default EFI loader here,
                 * but we do not want to do that if that would be us.
                 *
                 * If the default loader is not us, it might be shim. It would
                 * chainload GRUBX64.EFI in that case, which might be us.*/
                if (StriCmp(loader, loaded_image_path) == 0 ||
                    is_sd_boot(root_dir, loader) ||
                    is_sd_boot(root_dir, L"\\EFI\\BOOT\\GRUB" EFI_MACHINE_TYPE_NAME L".EFI"))
                        return NULL;
        }

        /* check existence */
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        EFI_STATUS err = root_dir->Open(root_dir, &handle, (CHAR16*) loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return NULL;

        return config_entry_add_loader(config, device, LOADER_AUTO, id, key, title, loader, NULL, NULL);
}

static void config_entry_add_osx(Config *config) {
        EFI_STATUS err;
        UINTN n_handles = 0;
        _cleanup_freepool_ EFI_HANDLE *handles = NULL;

        assert(config);

        if (!config->auto_entries)
                return;

        err = LibLocateHandle(ByProtocol, &FileSystemProtocol, NULL, &n_handles, &handles);
        if (EFI_ERROR(err))
                return;

        for (UINTN i = 0; i < n_handles; i++) {
                _cleanup_(file_closep) EFI_FILE *root = LibOpenRoot(handles[i]);
                if (!root)
                        continue;

                if (config_entry_add_loader_auto(
                                config,
                                handles[i],
                                root,
                                NULL,
                                L"auto-osx",
                                'a',
                                L"macOS",
                                L"\\System\\Library\\CoreServices\\boot.efi"))
                        break;
        }
}

static EFI_STATUS boot_windows_bitlocker(void) {
        _cleanup_freepool_ EFI_HANDLE *handles = NULL;
        UINTN n_handles;
        EFI_STATUS err;

        // FIXME: Experimental for now. Should be generalized, and become a per-entry option that can be
        // enabled independently of BitLocker, and without a BootXXXX entry pre-existing.

        /* BitLocker key cannot be sealed without a TPM present. */
        if (!tpm_present())
                return EFI_NOT_FOUND;

        err = BS->LocateHandleBuffer(ByProtocol, &BlockIoProtocol, NULL, &n_handles, &handles);
        if (EFI_ERROR(err))
                return err;

        /* Look for BitLocker magic string on all block drives. */
        BOOLEAN found = FALSE;
        for (UINTN i = 0; i < n_handles; i++) {
                EFI_BLOCK_IO *block_io;
                err = BS->HandleProtocol(handles[i], &BlockIoProtocol, (void **) &block_io);
                if (EFI_ERROR(err) || block_io->Media->BlockSize < 512 || block_io->Media->BlockSize > 4096)
                        continue;

                CHAR8 buf[4096];
                err = block_io->ReadBlocks(block_io, block_io->Media->MediaId, 0, sizeof(buf), buf);
                if (EFI_ERROR(err))
                        continue;

                if (CompareMem(buf + 3, "-FVE-FS-", STRLEN("-FVE-FS-")) == 0) {
                        found = TRUE;
                        break;
                }
        }

        /* If no BitLocker drive was found, we can just chainload bootmgfw.efi directly. */
        if (!found)
                return EFI_NOT_FOUND;

        _cleanup_freepool_ UINT16 *boot_order = NULL;
        UINTN boot_order_size;

        /* There can be gaps in Boot#### entries. Instead of iterating over the full
         * EFI var list or UINT16 namespace, just look for "Windows Boot Manager" in BootOrder. */
        err = efivar_get_raw(EFI_GLOBAL_GUID, L"BootOrder", (CHAR8 **) &boot_order, &boot_order_size);
        if (EFI_ERROR(err) || boot_order_size % sizeof(UINT16) != 0)
                return err;

        for (UINTN i = 0; i < boot_order_size / sizeof(UINT16); i++) {
                _cleanup_freepool_ CHAR8 *buf = NULL;
                CHAR16 name[sizeof(L"Boot0000")];
                UINTN buf_size;

                SPrint(name, sizeof(name), L"Boot%04x", (UINT32) boot_order[i]);
                err = efivar_get_raw(EFI_GLOBAL_GUID, name, &buf, &buf_size);
                if (EFI_ERROR(err))
                        continue;

                /* Boot#### are EFI_LOAD_OPTION. But we really are only interested
                 * for the description, which is at this offset. */
                UINTN offset = sizeof(UINT32) + sizeof(UINT16);
                if (buf_size < offset + sizeof(CHAR16))
                        continue;

                if (streq((CHAR16 *) (buf + offset), L"Windows Boot Manager")) {
                        err = efivar_set_raw(
                                EFI_GLOBAL_GUID,
                                L"BootNext",
                                boot_order + i,
                                sizeof(boot_order[i]),
                                EFI_VARIABLE_NON_VOLATILE);
                        if (EFI_ERROR(err))
                                return err;
                        return RT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
                }
        }

        return EFI_NOT_FOUND;
}

static void config_entry_add_windows(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
        _cleanup_freepool_ CHAR8 *bcd = NULL;
        CHAR16 *title = NULL;
        EFI_STATUS err;
        UINTN len;

        assert(config);
        assert(device);
        assert(root_dir);

        if (!config->auto_entries)
                return;

        /* Try to find a better title. */
        err = file_read(root_dir, L"\\EFI\\Microsoft\\Boot\\BCD", 0, 100*1024, &bcd, &len);
        if (!EFI_ERROR(err))
                title = get_bcd_title((UINT8 *) bcd, len);

        ConfigEntry *e = config_entry_add_loader_auto(config, device, root_dir, NULL,
                                                      L"auto-windows", 'w', title ?: L"Windows Boot Manager",
                                                      L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

        if (config->reboot_for_bitlocker)
                e->call = boot_windows_bitlocker;
#endif
}

static void config_entry_add_linux(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir) {

        _cleanup_(file_closep) EFI_FILE *linux_dir = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *f = NULL;
        ConfigEntry *entry;
        UINTN f_size = 0;
        EFI_STATUS err;

        /* Adds Boot Loader Type #2 entries (i.e. /EFI/Linux/….efi) */

        assert(config);
        assert(device);
        assert(root_dir);

        err = open_directory(root_dir, L"\\EFI\\Linux", &linux_dir);
        if (EFI_ERROR(err))
                return;

        for (;;) {
                enum {
                        SECTION_CMDLINE,
                        SECTION_OSREL,
                        _SECTION_MAX,
                };

                static const CHAR8* const sections[_SECTION_MAX + 1] = {
                        [SECTION_CMDLINE] = (const CHAR8 *) ".cmdline",
                        [SECTION_OSREL]   = (const CHAR8 *) ".osrel",
                        NULL,
                };

                _cleanup_freepool_ CHAR16 *os_pretty_name = NULL, *os_image_id = NULL, *os_name = NULL, *os_id = NULL,
                        *os_image_version = NULL, *os_version = NULL, *os_version_id = NULL, *os_build_id = NULL,
                        *path = NULL;
                const CHAR16 *good_name, *good_version, *good_sort_key;
                _cleanup_freepool_ CHAR8 *content = NULL;
                UINTN offs[_SECTION_MAX] = {};
                UINTN szs[_SECTION_MAX] = {};
                CHAR8 *line;
                UINTN pos = 0;
                CHAR8 *key, *value;

                err = readdir_harder(linux_dir, &f, &f_size);
                if (EFI_ERROR(err) || !f)
                        break;

                if (f->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(f->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!endswith_no_case(f->FileName, L".efi"))
                        continue;
                if (startswith(f->FileName, L"auto-"))
                        continue;

                /* look for .osrel and .cmdline sections in the .efi binary */
                err = pe_file_locate_sections(linux_dir, f->FileName, (const CHAR8**) sections, offs, szs);
                if (EFI_ERROR(err) || szs[SECTION_OSREL] == 0)
                        continue;

                err = file_read(linux_dir, f->FileName, offs[SECTION_OSREL], szs[SECTION_OSREL], &content, NULL);
                if (EFI_ERROR(err))
                        continue;

                /* read properties from the embedded os-release file */
                while ((line = line_get_key_value(content, (CHAR8 *)"=", &pos, &key, &value))) {
                        if (strcmpa((const CHAR8*) "PRETTY_NAME", key) == 0) {
                                FreePool(os_pretty_name);
                                os_pretty_name = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "IMAGE_ID", key) == 0) {
                                FreePool(os_image_id);
                                os_image_id = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "NAME", key) == 0) {
                                FreePool(os_name);
                                os_name = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "ID", key) == 0) {
                                FreePool(os_id);
                                os_id = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "IMAGE_VERSION", key) == 0) {
                                FreePool(os_image_version);
                                os_image_version = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "VERSION", key) == 0) {
                                FreePool(os_version);
                                os_version = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "VERSION_ID", key) == 0) {
                                FreePool(os_version_id);
                                os_version_id = xstra_to_str(value);
                                continue;
                        }

                        if (strcmpa((const CHAR8*) "BUILD_ID", key) == 0) {
                                FreePool(os_build_id);
                                os_build_id = xstra_to_str(value);
                                continue;
                        }
                }

                if (!bootspec_pick_name_version_sort_key(
                                    os_pretty_name,
                                    os_image_id,
                                    os_name,
                                    os_id,
                                    os_image_version,
                                    os_version,
                                    os_version_id,
                                    os_build_id,
                                    &good_name,
                                    &good_version,
                                    &good_sort_key))
                        continue;

                path = xpool_print(L"\\EFI\\Linux\\%s", f->FileName);
                entry = config_entry_add_loader(
                                config,
                                device,
                                LOADER_UNIFIED_LINUX,
                                /* id= */ f->FileName,
                                /* key= */ 'l',
                                /* title= */ good_name,
                                /* loader= */ path,
                                /* sort_key= */ good_sort_key,
                                good_version);

                config_entry_parse_tries(entry, L"\\EFI\\Linux", f->FileName, L".efi");

                if (szs[SECTION_CMDLINE] == 0)
                        continue;

                content = mfree(content);

                /* read the embedded cmdline file */
                err = file_read(linux_dir, f->FileName, offs[SECTION_CMDLINE], szs[SECTION_CMDLINE], &content, NULL);
                if (!EFI_ERROR(err)) {
                        /* chomp the newline */
                        if (content[szs[SECTION_CMDLINE] - 1] == '\n')
                                content[szs[SECTION_CMDLINE] - 1] = '\0';

                        entry->options = xstra_to_str(content);
                }
        }
}

static void config_load_xbootldr(
                Config *config,
                EFI_HANDLE *device) {

        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        EFI_HANDLE new_device;
        EFI_STATUS err;

        assert(config);
        assert(device);

        err = xbootldr_open(device, &new_device, &root_dir);
        if (EFI_ERROR(err))
                return;

        config_entry_add_linux(config, new_device, root_dir);
        config_load_entries(config, new_device, root_dir, NULL);
}

static EFI_STATUS initrd_prepare(
                EFI_FILE *root,
                const ConfigEntry *entry,
                CHAR16 **ret_options,
                void **ret_initrd,
                UINTN *ret_initrd_size) {

        assert(root);
        assert(entry);
        assert(ret_options);
        assert(ret_initrd);
        assert(ret_initrd_size);

        if (entry->type != LOADER_LINUX || !entry->initrd) {
                ret_options = NULL;
                ret_initrd = NULL;
                ret_initrd_size = 0;
                return EFI_SUCCESS;
        }

        /* Note that order of initrds matters. The kernel will only look for microcode updates in the very
         * first one it sees. */

        /* Add initrd= to options for older kernels that do not support LINUX_INITRD_MEDIA. Should be dropped
         * if linux_x86.c is dropped. */
        _cleanup_freepool_ CHAR16 *options = NULL;

        EFI_STATUS err;
        UINTN size = 0;
        _cleanup_freepool_ UINT8 *initrd = NULL;

        STRV_FOREACH(i, entry->initrd) {
                _cleanup_freepool_ CHAR16 *o = options;
                if (o)
                        options = xpool_print(L"%s initrd=%s", o, *i);
                else
                        options = xpool_print(L"initrd=%s", *i);

                _cleanup_(file_closep) EFI_FILE *handle = NULL;
                err = root->Open(root, &handle, *i, EFI_FILE_MODE_READ, 0);
                if (EFI_ERROR(err))
                        return err;

                _cleanup_freepool_ EFI_FILE_INFO *info = NULL;
                err = get_file_info_harder(handle, &info, NULL);
                if (EFI_ERROR(err))
                        return err;

                UINTN new_size, read_size = info->FileSize;
                if (__builtin_add_overflow(size, read_size, &new_size))
                        return EFI_OUT_OF_RESOURCES;
                initrd = xreallocate_pool(initrd, size, new_size);

                err = handle->Read(handle, &read_size, initrd + size);
                if (EFI_ERROR(err))
                        return err;

                /* Make sure the actual read size is what we expected. */
                assert(size + read_size == new_size);
                size = new_size;
        }

        if (entry->options) {
                _cleanup_freepool_ CHAR16 *o = options;
                options = xpool_print(L"%s %s", o, entry->options);
        }

        *ret_options = TAKE_PTR(options);
        *ret_initrd = TAKE_PTR(initrd);
        *ret_initrd_size = size;
        return EFI_SUCCESS;
}

static EFI_STATUS image_start(
                EFI_HANDLE parent_image,
                const ConfigEntry *entry) {

        _cleanup_(devicetree_cleanup) struct devicetree_state dtstate = {};
        _cleanup_(unload_imagep) EFI_HANDLE image = NULL;
        _cleanup_freepool_ EFI_DEVICE_PATH *path = NULL;
        EFI_STATUS err;

        assert(entry);

        /* If this loader entry has a special way to boot, try that first. */
        if (entry->call)
                (void) entry->call();

        _cleanup_(file_closep) EFI_FILE *image_root = LibOpenRoot(entry->device);
        if (!image_root)
                return log_error_status_stall(EFI_DEVICE_ERROR, L"Error opening root path.");

        path = FileDevicePath(entry->device, entry->loader);
        if (!path)
                return log_error_status_stall(EFI_INVALID_PARAMETER, L"Error getting device path.");

        UINTN initrd_size = 0;
        _cleanup_freepool_ void *initrd = NULL;
        _cleanup_freepool_ CHAR16 *options_initrd = NULL;
        err = initrd_prepare(image_root, entry, &options_initrd, &initrd, &initrd_size);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error preparing initrd: %r", err);

        err = BS->LoadImage(FALSE, parent_image, path, NULL, 0, &image);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error loading %s: %r", entry->loader, err);

        if (entry->devicetree) {
                err = devicetree_install(&dtstate, image_root, entry->devicetree);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error loading %s: %r", entry->devicetree, err);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd, initrd_size, &initrd_handle);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error registering initrd: %r", err);

        EFI_LOADED_IMAGE *loaded_image;
        err = BS->HandleProtocol(image, &LoadedImageProtocol, (void **) &loaded_image);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error getting LoadedImageProtocol handle: %r", err);

        CHAR16 *options = options_initrd ?: entry->options;
        if (options) {
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = StrSize(options);

                /* Try to log any options to the TPM, especially to catch manually edited options */
                (void) tpm_log_load_options(options);
        }

        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeExecUSec", 0);
        err = BS->StartImage(image, NULL, NULL);
        graphics_mode(FALSE);
        if (err == EFI_SUCCESS)
                return EFI_SUCCESS;

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && entry->type == LOADER_LINUX) {
                UINT32 kernel_entry_address;

                err = pe_alignment_info(loaded_image->ImageBase, &kernel_entry_address, NULL, NULL);
                if (EFI_ERROR(err)) {
                        if (err != EFI_UNSUPPORTED)
                                return log_error_status_stall(err, L"Error finding kernel compat entry address: %r", err);
                } else {
                        EFI_IMAGE_ENTRY_POINT kernel_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((UINT8 *) loaded_image->ImageBase + kernel_entry_address);

                        err = kernel_entry(image, ST);
                        graphics_mode(FALSE);
                        if (err == EFI_SUCCESS)
                                return EFI_SUCCESS;
                }
        }

        return log_error_status_stall(err, L"Failed to execute %s (%s): %r", entry->title_show, entry->loader, err);
}

static void config_free(Config *config) {
        assert(config);
        for (UINTN i = 0; i < config->entry_count; i++)
                config_entry_free(config->entries[i]);
        FreePool(config->entries);
        FreePool(config->entry_default_config);
        FreePool(config->entry_oneshot);
}

static void config_write_entries_to_variable(Config *config) {
        _cleanup_freepool_ CHAR8 *buffer = NULL;
        UINTN sz = 0;
        CHAR8 *p;

        assert(config);

        for (UINTN i = 0; i < config->entry_count; i++)
                sz += StrSize(config->entries[i]->id);

        p = buffer = xallocate_pool(sz);

        for (UINTN i = 0; i < config->entry_count; i++) {
                UINTN l;

                l = StrSize(config->entries[i]->id);
                CopyMem(p, config->entries[i]->id, l);

                p += l;
        }

        assert(p == buffer + sz);

        /* Store the full list of discovered entries. */
        (void) efivar_set_raw(LOADER_GUID, L"LoaderEntries", buffer, sz, 0);
}

static void save_selected_entry(const Config *config, const ConfigEntry *entry) {
        assert(config);
        assert(entry);
        assert(entry->loader || !entry->call);

        /* Always export the selected boot entry to the system in a volatile var. */
        (void) efivar_set(LOADER_GUID, L"LoaderEntrySelected", entry->id, 0);

        /* Do not save or delete if this was a oneshot boot. */
        if (streq_ptr(config->entry_oneshot, entry->id))
                return;

        if (config->use_saved_entry_efivar || (!config->entry_default_efivar && config->use_saved_entry)) {
                /* Avoid unnecessary NVRAM writes. */
                if (streq_ptr(config->entry_saved, entry->id))
                        return;

                (void) efivar_set(LOADER_GUID, L"LoaderEntryLastBooted", entry->id, EFI_VARIABLE_NON_VOLATILE);
        } else
                /* Delete the non-volatile var if not needed. */
                (void) efivar_set(LOADER_GUID, L"LoaderEntryLastBooted", NULL, EFI_VARIABLE_NON_VOLATILE);
}

static void export_variables(
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *loaded_image_path,
                UINT64 init_usec) {

        static const UINT64 loader_features =
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT |
                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                EFI_LOADER_FEATURE_ENTRY_ONESHOT |
                EFI_LOADER_FEATURE_BOOT_COUNTING |
                EFI_LOADER_FEATURE_XBOOTLDR |
                EFI_LOADER_FEATURE_RANDOM_SEED |
                EFI_LOADER_FEATURE_LOAD_DRIVER |
                0;

        _cleanup_freepool_ CHAR16 *infostr = NULL, *typestr = NULL;
        CHAR16 uuid[37];

        assert(loaded_image);
        assert(loaded_image_path);

        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeInitUSec", init_usec);
        efivar_set(LOADER_GUID, L"LoaderInfo", L"systemd-boot " GIT_VERSION, 0);

        infostr = xpool_print(L"%s %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        efivar_set(LOADER_GUID, L"LoaderFirmwareInfo", infostr, 0);

        typestr = xpool_print(L"UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        efivar_set(LOADER_GUID, L"LoaderFirmwareType", typestr, 0);

        (void) efivar_set_uint64_le(LOADER_GUID, L"LoaderFeatures", loader_features, 0);

        /* the filesystem path to this image, to prevent adding ourselves to the menu */
        efivar_set(LOADER_GUID, L"LoaderImageIdentifier", loaded_image_path, 0);

        /* export the device path this image is started from */
        if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                efivar_set(LOADER_GUID, L"LoaderDevicePartUUID", uuid, 0);
}

static void config_load_all_entries(
                Config *config,
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *loaded_image_path,
                EFI_FILE *root_dir) {

        assert(config);
        assert(loaded_image);
        assert(loaded_image_path);
        assert(root_dir);

        config_load_defaults(config, root_dir);

        /* scan /EFI/Linux/ directory */
        config_entry_add_linux(config, loaded_image->DeviceHandle, root_dir);

        /* scan /loader/entries/\*.conf files */
        config_load_entries(config, loaded_image->DeviceHandle, root_dir, loaded_image_path);

        /* Similar, but on any XBOOTLDR partition */
        config_load_xbootldr(config, loaded_image->DeviceHandle);

        /* sort entries after version number */
        sort_pointer_array((void **) config->entries, config->entry_count, (compare_pointer_func_t) config_entry_compare);

        /* if we find some well-known loaders, add them to the end of the list */
        config_entry_add_osx(config);
        config_entry_add_windows(config, loaded_image->DeviceHandle, root_dir);
        config_entry_add_loader_auto(config, loaded_image->DeviceHandle, root_dir, NULL,
                                     L"auto-efi-shell", 's', L"EFI Shell", L"\\shell" EFI_MACHINE_TYPE_NAME ".efi");
        config_entry_add_loader_auto(config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     L"auto-efi-default", '\0', L"EFI Default Loader", NULL);

        if (config->auto_firmware && FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI))
                config_entry_add_call(config,
                                      L"auto-reboot-to-firmware-setup",
                                      L"Reboot Into Firmware Interface",
                                      reboot_into_firmware);

        if (config->entry_count == 0)
                return;

        config_write_entries_to_variable(config);

        config_title_generate(config);

        /* select entry by configured pattern or EFI LoaderDefaultEntry= variable */
        config_default_entry_select(config);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        EFI_LOADED_IMAGE *loaded_image;
        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        _cleanup_(config_free) Config config = {};
        CHAR16 *loaded_image_path;
        EFI_STATUS err;
        UINT64 init_usec;
        BOOLEAN menu = FALSE;

        InitializeLib(image, sys_table);
        init_usec = time_usec();
        debug_hook(L"systemd-boot");
        /* Uncomment the next line if you need to wait for debugger. */
        // debug_break();

        err = BS->OpenProtocol(image,
                        &LoadedImageProtocol,
                        (void **)&loaded_image,
                        image,
                        NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error getting a LoadedImageProtocol handle: %r", err);

        loaded_image_path = DevicePathToStr(loaded_image->FilePath);
        if (!loaded_image_path)
                return log_oom();

        export_variables(loaded_image, loaded_image_path, init_usec);

        root_dir = LibOpenRoot(loaded_image->DeviceHandle);
        if (!root_dir)
                return log_error_status_stall(EFI_LOAD_ERROR, L"Unable to open root directory.", EFI_LOAD_ERROR);

        if (secure_boot_enabled() && shim_loaded()) {
                err = security_policy_install();
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error installing security policy: %r", err);
        }

        (void) load_drivers(image, loaded_image, root_dir);

        config_load_all_entries(&config, loaded_image, loaded_image_path, root_dir);

        if (config.entry_count == 0) {
                log_error_stall(L"No loader found. Configuration files in \\loader\\entries\\*.conf are needed.");
                goto out;
        }

        /* select entry or show menu when key is pressed or timeout is set */
        if (config.force_menu || config.timeout_sec > 0)
                menu = TRUE;
        else {
                UINT64 key;

                /* Block up to 100ms to give firmware time to get input working. */
                err = console_key_read(&key, 100 * 1000);
                if (!EFI_ERROR(err)) {
                        /* find matching key in config entries */
                        UINTN idx = entry_lookup_key(&config, config.idx_default, KEYCHAR(key));
                        if (idx != IDX_INVALID)
                                config.idx_default = idx;
                        else
                                menu = TRUE;
                }
        }

        for (;;) {
                ConfigEntry *entry;

                entry = config.entries[config.idx_default];
                if (menu) {
                        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeMenuUSec", 0);
                        if (!menu_run(&config, &entry, loaded_image_path))
                                break;
                }

                /* Run special entry like "reboot" now. Those that have a loader
                 * will be handled by image_start() instead. */
                if (entry->call && !entry->loader) {
                        entry->call();
                        continue;
                }

                config_entry_bump_counters(entry, root_dir);
                save_selected_entry(&config, entry);

                /* Optionally, read a random seed off the ESP and pass it to the OS */
                (void) process_random_seed(root_dir, config.random_seed_mode);

                err = image_start(image, entry);
                if (err != EFI_SUCCESS)
                        /* Not using EFI_ERROR here because positive values are also errors like with any
                         * other (userspace) program. */
                        goto out;

                menu = TRUE;
                config.timeout_sec = 0;
        }
        err = EFI_SUCCESS;
out:
        BS->CloseProtocol(image, &LoadedImageProtocol, image, NULL);
        return err;
}
