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
        LOADER_SECURE_BOOT_KEYS,
};

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

typedef struct {
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
        secure_boot_enroll secure_boot_enroll;
        bool force_menu;
        bool use_saved_entry;
        bool use_saved_entry_efivar;
        bool beep;
        int64_t console_mode;
        int64_t console_mode_efivar;
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

static bool line_edit(
                char16_t **line_in,
                UINTN x_max,
                UINTN y_pos) {

        _cleanup_free_ char16_t *line = NULL, *print = NULL;
        UINTN size, len, first = 0, cursor = 0, clear = 0;

        assert(line_in);

        len = strlen16(*line_in);
        size = len + 1024;
        line = xnew(char16_t, size);
        print = xnew(char16_t, x_max + 1);
        strcpy16(line, strempty(*line_in));

        for (;;) {
                EFI_STATUS err;
                uint64_t key;
                UINTN j;
                UINTN cursor_color = TEXT_ATTR_SWAP(COLOR_EDIT);

                j = MIN(len - first, x_max);
                memcpy(print, line + first, j * sizeof(char16_t));
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
                                return false;

                        print_at(cursor + 1, y_pos, COLOR_EDIT, print + cursor);
                } while (err != EFI_SUCCESS);

                switch (key) {
                case KEYPRESS(0, SCAN_ESC, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'c'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'g'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('c')):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('g')):
                        return false;

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

                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_DELETE, 0):
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
                case KEYPRESS(0, SCAN_F3, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, SCAN_F3, CHAR_CARRIAGE_RETURN): /* Teclast X98+ II firmware sends malformed events */
                        if (!streq16(line, *line_in)) {
                                free(*line_in);
                                *line_in = TAKE_PTR(line);
                        }
                        return true;

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

static UINTN entry_lookup_key(Config *config, UINTN start, char16_t key) {
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

static char16_t *update_timeout_efivar(uint32_t *t, bool inc) {
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
                return xstrdup16(u"Menu timeout defined by configuration file.");
        case TIMEOUT_MENU_FORCE:
                return xstrdup16(u"Timeout disabled, menu will always be shown.");
        case TIMEOUT_MENU_HIDDEN:
                return xstrdup16(u"Menu disabled. Hold down key at bootup to show menu.");
        default:
                return xpool_print(L"Menu timeout set to %u s.", *t);
        }
}

static bool unicode_supported(void) {
        static int cache = -1;

        if (cache < 0)
                /* Basic unicode box drawing support is mandated by the spec, but it does
                 * not hurt to make sure it works. */
                cache = ST->ConOut->TestString(ST->ConOut, (char16_t *) L"─") == EFI_SUCCESS;

        return cache;
}

static void ps_string(const char16_t *fmt, const void *value) {
        assert(fmt);
        if (value)
                Print(fmt, value);
}

static void ps_bool(const char16_t *fmt, bool value) {
        assert(fmt);
        Print(fmt, yes_no(value));
}

static bool ps_continue(void) {
        if (unicode_supported())
                Print(L"\n─── Press any key to continue, ESC or q to quit. ───\n\n");
        else
                Print(L"\n--- Press any key to continue, ESC or q to quit. ---\n\n");

        uint64_t key;
        return console_key_read(&key, UINT64_MAX) == EFI_SUCCESS &&
                        !IN_SET(key, KEYPRESS(0, SCAN_ESC, 0), KEYPRESS(0, 0, 'q'), KEYPRESS(0, 0, 'Q'));
}

static void print_status(Config *config, char16_t *loaded_image_path) {
        UINTN x_max, y_max;
        uint32_t screen_width = 0, screen_height = 0;
        SecureBootMode secure;
        _cleanup_free_ char16_t *device_part_uuid = NULL;

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

        switch (config->secure_boot_enroll) {
        case ENROLL_OFF:
                Print(L"    secure-boot-enroll: off\n"); break;
        case ENROLL_MANUAL:
                Print(L"    secure-boot-enroll: manual\n"); break;
        case ENROLL_FORCE:
                Print(L"    secure-boot-enroll: force\n"); break;
        default:
                assert_not_reached();
        }

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

                _cleanup_free_ char16_t *dp = NULL;
                if (entry->device)
                        (void) device_path_to_str(DevicePathFromHandle(entry->device), &dp);

                    Print(L"  config entry: %" PRIuN L"/%" PRIuN L"\n", i + 1, config->entry_count);
                ps_string(L"            id: %s\n", entry->id);
                ps_string(L"         title: %s\n", entry->title);
                ps_string(L"    title show: %s\n", streq16(entry->title, entry->title_show) ? NULL : entry->title_show);
                ps_string(L"      sort key: %s\n", entry->sort_key);
                ps_string(L"       version: %s\n", entry->version);
                ps_string(L"    machine-id: %s\n", entry->machine_id);
                ps_string(L"        device: %s\n", dp);
                ps_string(L"        loader: %s\n", entry->loader);
                STRV_FOREACH(initrd, entry->initrd)
                    Print(L"        initrd: %s\n", *initrd);
                ps_string(L"    devicetree: %s\n", entry->devicetree);
                ps_string(L"       options: %s\n", entry->options);
                  ps_bool(L" internal call: %s\n", !!entry->call);

                  ps_bool(L"counting boots: %s\n", entry->tries_left >= 0);
                if (entry->tries_left >= 0) {
                    Print(L"         tries: %u left, %u done\n", entry->tries_left, entry->tries_done);
                    Print(L"  current path: %s\\%s\n",  entry->path, entry->current_name);
                    Print(L"     next path: %s\\%s\n",  entry->path, entry->next_name);
                }

                if (!ps_continue())
                        return;
        }
}

static EFI_STATUS reboot_into_firmware(void) {
        uint64_t osind = 0;
        EFI_STATUS err;

        if (!FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI))
                return log_error_status_stall(EFI_UNSUPPORTED, L"Reboot to firmware interface not supported.");

        (void) efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", &osind);
        osind |= EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        err = efivar_set_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", osind, EFI_VARIABLE_NON_VOLATILE);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error setting OsIndications: %r", err);

        RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}

static bool menu_run(
                Config *config,
                ConfigEntry **chosen_entry,
                char16_t *loaded_image_path) {

        assert(config);
        assert(chosen_entry);
        assert(loaded_image_path);

        EFI_STATUS err;
        UINTN visible_max = 0;
        UINTN idx_highlight = config->idx_default;
        UINTN idx_highlight_prev = 0;
        UINTN idx, idx_first = 0, idx_last = 0;
        bool new_mode = true, clear = true;
        bool refresh = true, highlight = false;
        UINTN x_start = 0, y_start = 0, y_status = 0;
        UINTN x_max, y_max;
        _cleanup_(strv_freep) char16_t **lines = NULL;
        _cleanup_free_ char16_t *clearline = NULL, *separator = NULL, *status = NULL;
        uint32_t timeout_efivar_saved = config->timeout_sec_efivar;
        uint32_t timeout_remain = config->timeout_sec == TIMEOUT_MENU_FORCE ? 0 : config->timeout_sec;
        bool exit = false, run = true, firmware_setup = false;
        int64_t console_mode_initial = ST->ConOut->Mode->Mode, console_mode_efivar_saved = config->console_mode_efivar;
        UINTN default_efivar_saved = config->idx_default_efivar;

        graphics_mode(false);
        ST->ConIn->Reset(ST->ConIn, false);
        ST->ConOut->EnableCursor(ST->ConOut, false);

        /* draw a single character to make ClearScreen work on some firmware */
        Print(L" ");

        err = console_set_mode(config->console_mode_efivar != CONSOLE_MODE_KEEP ?
                               config->console_mode_efivar : config->console_mode);
        if (err != EFI_SUCCESS) {
                clear_screen(COLOR_NORMAL);
                log_error_stall(L"Error switching console mode: %r", err);
        }

        UINTN line_width = 0, entry_padding = 3;
        while (!exit) {
                uint64_t key;

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
                                line_width = MAX(line_width, strlen16(config->entries[i]->title_show));
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
                        lines = xnew(char16_t *, config->entry_count + 1);

                        for (UINTN i = 0; i < config->entry_count; i++) {
                                UINTN j, padding;

                                lines[i] = xnew(char16_t, line_width + 1);
                                padding = (line_width - MIN(strlen16(config->entries[i]->title_show), line_width)) / 2;

                                for (j = 0; j < padding; j++)
                                        lines[i][j] = ' ';

                                for (UINTN k = 0; config->entries[i]->title_show[k] != '\0' && j < line_width; j++, k++)
                                        lines[i][j] = config->entries[i]->title_show[k];

                                for (; j < line_width; j++)
                                        lines[i][j] = ' ';
                                lines[i][line_width] = '\0';
                        }
                        lines[config->entry_count] = NULL;

                        clearline = xnew(char16_t, x_max + 1);
                        separator = xnew(char16_t, x_max + 1);
                        for (UINTN i = 0; i < x_max; i++) {
                                clearline[i] = ' ';
                                separator[i] = unicode_supported() ? L'─' : L'-';
                        }
                        clearline[x_max] = 0;
                        separator[x_max] = 0;

                        new_mode = false;
                        clear = true;
                }

                if (clear) {
                        clear_screen(COLOR_NORMAL);
                        clear = false;
                        refresh = true;
                }

                if (refresh) {
                        for (UINTN i = idx_first; i <= idx_last && i < config->entry_count; i++) {
                                print_at(x_start, y_start + i - idx_first,
                                         i == idx_highlight ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                         lines[i]);
                                if (i == config->idx_default_efivar)
                                        print_at(x_start,
                                                 y_start + i - idx_first,
                                                 i == idx_highlight ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                                 unicode_supported() ? L" ►" : L"=>");
                        }
                        refresh = false;
                } else if (highlight) {
                        print_at(x_start, y_start + idx_highlight_prev - idx_first, COLOR_ENTRY, lines[idx_highlight_prev]);
                        print_at(x_start, y_start + idx_highlight - idx_first, COLOR_HIGHLIGHT, lines[idx_highlight]);
                        if (idx_highlight_prev == config->idx_default_efivar)
                                print_at(x_start,
                                         y_start + idx_highlight_prev - idx_first,
                                         COLOR_ENTRY,
                                         unicode_supported() ? L" ►" : L"=>");
                        if (idx_highlight == config->idx_default_efivar)
                                print_at(x_start,
                                         y_start + idx_highlight - idx_first,
                                         COLOR_HIGHLIGHT,
                                         unicode_supported() ? L" ►" : L"=>");
                        highlight = false;
                }

                if (timeout_remain > 0) {
                        free(status);
                        status = xpool_print(L"Boot in %u s.", timeout_remain);
                }

                if (status) {
                        /* If we draw the last char of the last line, the screen will scroll and break our
                         * input. Therefore, draw one less character then we could for the status message.
                         * Note that the same does not apply for the separator line as it will never be drawn
                         * on the last line. */
                        UINTN len = strnlen16(status, x_max - 1);
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
                                exit = true;
                                break;
                        }

                        /* update status */
                        continue;
                }
                if (err != EFI_SUCCESS) {
                        exit = true;
                        break;
                }

                timeout_remain = 0;

                /* clear status after keystroke */
                status = mfree(status);

                idx_highlight_prev = idx_highlight;

                if (firmware_setup) {
                        firmware_setup = false;
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
                                refresh = true;
                                idx_highlight = 0;
                        }
                        break;

                case KEYPRESS(0, SCAN_END, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '>'):
                        if (idx_highlight < config->entry_count-1) {
                                refresh = true;
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
                case KEYPRESS(0, SCAN_F3, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, SCAN_F3, CHAR_CARRIAGE_RETURN): /* Teclast X98+ II firmware sends malformed events */
                case KEYPRESS(0, SCAN_RIGHT, 0):
                        exit = true;
                        break;

                case KEYPRESS(0, SCAN_F1, 0):
                case KEYPRESS(0, 0, 'h'):
                case KEYPRESS(0, 0, 'H'):
                case KEYPRESS(0, 0, '?'):
                        /* This must stay below 80 characters! Q/v/Ctrl+l/f deliberately not advertised. */
                        status = xstrdup16(u"(d)efault (t/T)timeout (e)dit (r/R)resolution (p)rint (h)elp");
                        break;

                case KEYPRESS(0, 0, 'Q'):
                        exit = true;
                        run = false;
                        break;

                case KEYPRESS(0, 0, 'd'):
                case KEYPRESS(0, 0, 'D'):
                        if (config->idx_default_efivar != idx_highlight) {
                                free(config->entry_default_efivar);
                                config->entry_default_efivar = xstrdup16(config->entries[idx_highlight]->id);
                                config->idx_default_efivar = idx_highlight;
                                status = xstrdup16(u"Default boot entry selected.");
                        } else {
                                config->entry_default_efivar = mfree(config->entry_default_efivar);
                                config->idx_default_efivar = IDX_INVALID;
                                status = xstrdup16(u"Default boot entry cleared.");
                        }
                        config->use_saved_entry_efivar = false;
                        refresh = true;
                        break;

                case KEYPRESS(0, 0, '-'):
                case KEYPRESS(0, 0, 'T'):
                        status = update_timeout_efivar(&config->timeout_sec_efivar, false);
                        break;

                case KEYPRESS(0, 0, '+'):
                case KEYPRESS(0, 0, 't'):
                        status = update_timeout_efivar(&config->timeout_sec_efivar, true);
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
                        clear = true;
                        break;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'l'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('l')):
                        clear = true;
                        break;

                case KEYPRESS(0, 0, 'r'):
                        err = console_set_mode(CONSOLE_MODE_NEXT);
                        if (err != EFI_SUCCESS)
                                status = xpool_print(L"Error changing console mode: %r", err);
                        else {
                                config->console_mode_efivar = ST->ConOut->Mode->Mode;
                                status = xpool_print(L"Console mode changed to %ld.", config->console_mode_efivar);
                        }
                        new_mode = true;
                        break;

                case KEYPRESS(0, 0, 'R'):
                        config->console_mode_efivar = CONSOLE_MODE_KEEP;
                        err = console_set_mode(config->console_mode == CONSOLE_MODE_KEEP ?
                                               console_mode_initial : config->console_mode);
                        if (err != EFI_SUCCESS)
                                status = xpool_print(L"Error resetting console mode: %r", err);
                        else
                                status = xpool_print(L"Console mode reset to %s default.",
                                                     config->console_mode == CONSOLE_MODE_KEEP ? L"firmware" : L"configuration file");
                        new_mode = true;
                        break;

                case KEYPRESS(0, 0, 'f'):
                case KEYPRESS(0, 0, 'F'):
                case KEYPRESS(0, SCAN_F2, 0):     /* Most vendors. */
                case KEYPRESS(0, SCAN_F10, 0):    /* HP and Lenovo. */
                case KEYPRESS(0, SCAN_DELETE, 0): /* Same as F2. */
                case KEYPRESS(0, SCAN_ESC, 0):    /* HP. */
                        if (FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI)) {
                                firmware_setup = true;
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
                        refresh = true;
                }

                if (idx_highlight > idx_last) {
                        idx_last = idx_highlight;
                        idx_first = 1 + idx_highlight - visible_max;
                        refresh = true;
                } else if (idx_highlight < idx_first) {
                        idx_first = idx_highlight;
                        idx_last = idx_highlight + visible_max-1;
                        refresh = true;
                }

                if (!refresh && idx_highlight != idx_highlight_prev)
                        highlight = true;
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
                switch (config->timeout_sec_efivar) {
                case TIMEOUT_UNSET:
                        efivar_set(LOADER_GUID, L"LoaderConfigTimeout", NULL, EFI_VARIABLE_NON_VOLATILE);
                        break;
                case TIMEOUT_MENU_FORCE:
                        efivar_set(LOADER_GUID, u"LoaderConfigTimeout", u"menu-force", EFI_VARIABLE_NON_VOLATILE);
                        break;
                case TIMEOUT_MENU_HIDDEN:
                        efivar_set(LOADER_GUID, u"LoaderConfigTimeout", u"menu-hidden", EFI_VARIABLE_NON_VOLATILE);
                        break;
                default:
                        efivar_set_uint_string(LOADER_GUID, L"LoaderConfigTimeout",
                                               config->timeout_sec_efivar, EFI_VARIABLE_NON_VOLATILE);
                }
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
                config->entries = xrealloc(
                                config->entries,
                                sizeof(void *) * config->entry_count,
                                sizeof(void *) * (config->entry_count + 16));
        }
        config->entries[config->entry_count++] = entry;
}

static void config_entry_free(ConfigEntry *entry) {
        if (!entry)
                return;

        free(entry->id);
        free(entry->title_show);
        free(entry->title);
        free(entry->sort_key);
        free(entry->version);
        free(entry->machine_id);
        free(entry->loader);
        free(entry->devicetree);
        free(entry->options);
        strv_free(entry->initrd);
        free(entry->path);
        free(entry->current_name);
        free(entry->next_name);
        free(entry);
}

static inline void config_entry_freep(ConfigEntry **entry) {
        config_entry_free(*entry);
}

static char *line_get_key_value(
                char *content,
                const char *sep,
                UINTN *pos,
                char **key_ret,
                char **value_ret) {

        char *line, *value;
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
                while (line[linelen] && !strchr8("\n\r", line[linelen]))
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
                while (strchr8(" \t", *line)) {
                        line++;
                        linelen--;
                }

                /* remove trailing whitespace */
                while (linelen > 0 && strchr8(" \t", line[linelen - 1]))
                        linelen--;
                line[linelen] = '\0';

                if (*line == '#')
                        continue;

                /* split key/value */
                value = line;
                while (*value && !strchr8(sep, *value))
                        value++;
                if (*value == '\0')
                        continue;
                *value = '\0';
                value++;
                while (*value && strchr8(sep, *value))
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

static void config_defaults_load_from_file(Config *config, char *content) {
        char *line;
        UINTN pos = 0;
        char *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(content);

        while ((line = line_get_key_value(content, " \t", &pos, &key, &value))) {
                if (streq8(key, "timeout")) {
                        if (streq8( value, "menu-force"))
                                config->timeout_sec_config = TIMEOUT_MENU_FORCE;
                        else if (streq8(value, "menu-hidden"))
                                config->timeout_sec_config = TIMEOUT_MENU_HIDDEN;
                        else {
                                uint64_t u;
                                if (!parse_number8(value, &u, NULL) || u > TIMEOUT_TYPE_MAX) {
                                        log_error_stall(L"Error parsing 'timeout' config option: %a", value);
                                        continue;
                                }
                                config->timeout_sec_config = u;
                        }
                        config->timeout_sec = config->timeout_sec_config;
                        continue;
                }

                if (streq8(key, "default")) {
                        if (value[0] == '@' && !strcaseeq8(value, "@saved")) {
                                log_error_stall(L"Unsupported special entry identifier: %a", value);
                                continue;
                        }
                        free(config->entry_default_config);
                        config->entry_default_config = xstra_to_str(value);
                        continue;
                }

                if (streq8(key, "editor")) {
                        err = parse_boolean(value, &config->editor);
                        if (err != EFI_SUCCESS)
                                log_error_stall(L"Error parsing 'editor' config option: %a", value);
                        continue;
                }

                if (streq8(key, "auto-entries")) {
                        err = parse_boolean(value, &config->auto_entries);
                        if (err != EFI_SUCCESS)
                                log_error_stall(L"Error parsing 'auto-entries' config option: %a", value);
                        continue;
                }

                if (streq8(key, "auto-firmware")) {
                        err = parse_boolean(value, &config->auto_firmware);
                        if (err != EFI_SUCCESS)
                                log_error_stall(L"Error parsing 'auto-firmware' config option: %a", value);
                        continue;
                }

                if (streq8(key, "beep")) {
                        err = parse_boolean(value, &config->beep);
                        if (err != EFI_SUCCESS)
                                log_error_stall(L"Error parsing 'beep' config option: %a", value);
                        continue;
                }

                if (streq8(key, "reboot-for-bitlocker")) {
                        err = parse_boolean(value, &config->reboot_for_bitlocker);
                        if (err != EFI_SUCCESS)
                                log_error_stall(L"Error parsing 'reboot-for-bitlocker' config option: %a", value);
                }

                if (streq8(key, "secure-boot-enroll")) {
                        if (streq8(value, "manual"))
                                config->secure_boot_enroll = ENROLL_MANUAL;
                        else if (streq8(value, "force"))
                                config->secure_boot_enroll = ENROLL_FORCE;
                        else if (streq8(value, "off"))
                                config->secure_boot_enroll = ENROLL_OFF;
                        else
                                log_error_stall(L"Error parsing 'secure-boot-enroll' config option: %a", value);
                        continue;
                }

                if (streq8(key, "console-mode")) {
                        if (streq8(value, "auto"))
                                config->console_mode = CONSOLE_MODE_AUTO;
                        else if (streq8(value, "max"))
                                config->console_mode = CONSOLE_MODE_FIRMWARE_MAX;
                        else if (streq8(value, "keep"))
                                config->console_mode = CONSOLE_MODE_KEEP;
                        else {
                                uint64_t u;
                                if (!parse_number8(value, &u, NULL) || u > CONSOLE_MODE_RANGE_MAX) {
                                        log_error_stall(L"Error parsing 'console-mode' config option: %a", value);
                                        continue;
                                }
                                config->console_mode = u;
                        }
                        continue;
                }

                if (streq8(key, "random-seed-mode")) {
                        if (streq8(value, "off"))
                                config->random_seed_mode = RANDOM_SEED_OFF;
                        else if (streq8(value, "with-system-token"))
                                config->random_seed_mode = RANDOM_SEED_WITH_SYSTEM_TOKEN;
                        else if (streq8(value, "always"))
                                config->random_seed_mode = RANDOM_SEED_ALWAYS;
                        else {
                                bool on;

                                err = parse_boolean(value, &on);
                                if (err != EFI_SUCCESS) {
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
                const char16_t *path,
                const char16_t *file,
                const char16_t *suffix) {

        assert(entry);
        assert(path);
        assert(file);
        assert(suffix);

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

        const char16_t *counter = NULL;
        for (;;) {
                char16_t *plus = strchr16(counter ?: file, '+');
                if (plus) {
                        /* We want the last "+". */
                        counter = plus + 1;
                        continue;
                }
                if (counter)
                        break;

                /* No boot counter found. */
                return;
        }

        uint64_t tries_left, tries_done = 0;
        size_t prefix_len = counter - file;

        if (!parse_number16(counter, &tries_left, &counter) || tries_left > INT_MAX)
                return;

        /* Parse done counter only if present. */
        if (*counter == '-' && (!parse_number16(counter + 1, &tries_done, &counter) || tries_done > INT_MAX))
                return;

        /* Boot counter in the middle of the name? */
        if (!streq16(counter, suffix))
                return;

        entry->tries_left = tries_left;
        entry->tries_done = tries_done;
        entry->path = xstrdup16(path);
        entry->current_name = xstrdup16(file);
        entry->next_name = xpool_print(
                        L"%.*s%u-%u%s",
                        prefix_len,
                        file,
                        LESS_BY(tries_left, 1u),
                        MIN(tries_done + 1, (uint64_t) INT_MAX),
                        suffix);
}

static void config_entry_bump_counters(ConfigEntry *entry, EFI_FILE *root_dir) {
        _cleanup_free_ char16_t* old_path = NULL, *new_path = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ EFI_FILE_INFO *file_info = NULL;
        UINTN file_info_size;
        EFI_STATUS err;

        assert(entry);
        assert(root_dir);

        if (entry->tries_left < 0)
                return;

        if (!entry->path || !entry->current_name || !entry->next_name)
                return;

        old_path = xpool_print(L"%s\\%s", entry->path, entry->current_name);

        err = root_dir->Open(root_dir, &handle, old_path, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (err != EFI_SUCCESS)
                return;

        err = get_file_info_harder(handle, &file_info, &file_info_size);
        if (err != EFI_SUCCESS)
                return;

        /* And rename the file */
        strcpy16(file_info->FileName, entry->next_name);
        err = handle->SetInfo(handle, &GenericFileInfo, file_info_size, file_info);
        if (err != EFI_SUCCESS) {
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
        if (streq16(entry->loader, old_path)) {
                free(entry->loader);
                entry->loader = TAKE_PTR(new_path);
        }
}

static void config_entry_add_type1(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *path,
                const char16_t *file,
                char *content,
                const char16_t *loaded_image_path) {

        _cleanup_(config_entry_freep) ConfigEntry *entry = NULL;
        char *line;
        UINTN pos = 0, n_initrd = 0;
        char *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);
        assert(path);
        assert(file);
        assert(content);

        entry = xnew(ConfigEntry, 1);
        *entry = (ConfigEntry) {
                .tries_done = -1,
                .tries_left = -1,
        };

        while ((line = line_get_key_value(content, " \t", &pos, &key, &value))) {
                if (streq8(key, "title")) {
                        free(entry->title);
                        entry->title = xstra_to_str(value);
                        continue;
                }

                if (streq8(key, "sort-key")) {
                        free(entry->sort_key);
                        entry->sort_key = xstra_to_str(value);
                        continue;
                }

                if (streq8(key, "version")) {
                        free(entry->version);
                        entry->version = xstra_to_str(value);
                        continue;
                }

                if (streq8(key, "machine-id")) {
                        free(entry->machine_id);
                        entry->machine_id = xstra_to_str(value);
                        continue;
                }

                if (streq8(key, "linux")) {
                        free(entry->loader);
                        entry->type = LOADER_LINUX;
                        entry->loader = xstra_to_path(value);
                        entry->key = 'l';
                        continue;
                }

                if (streq8(key, "efi")) {
                        entry->type = LOADER_EFI;
                        free(entry->loader);
                        entry->loader = xstra_to_path(value);

                        /* do not add an entry for ourselves */
                        if (loaded_image_path && strcaseeq16(entry->loader, loaded_image_path)) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }
                        continue;
                }

                if (streq8(key, "architecture")) {
                        /* do not add an entry for an EFI image of architecture not matching with that of the image */
                        if (!streq8(value, EFI_MACHINE_TYPE_NAME)) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }
                        continue;
                }

                if (streq8(key, "devicetree")) {
                        free(entry->devicetree);
                        entry->devicetree = xstra_to_path(value);
                        continue;
                }

                if (streq8(key, "initrd")) {
                        entry->initrd = xrealloc(
                                entry->initrd,
                                n_initrd == 0 ? 0 : (n_initrd + 1) * sizeof(uint16_t *),
                                (n_initrd + 2) * sizeof(uint16_t *));
                        entry->initrd[n_initrd++] = xstra_to_path(value);
                        entry->initrd[n_initrd] = NULL;
                        continue;
                }

                if (streq8(key, "options")) {
                        _cleanup_free_ char16_t *new = NULL;

                        new = xstra_to_str(value);
                        if (entry->options) {
                                char16_t *s = xpool_print(L"%s %s", entry->options, new);
                                free(entry->options);
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
        if (err != EFI_SUCCESS)
                return;

        entry->device = device;
        entry->id = xstrdup16(file);
        strtolower16(entry->id);

        config_add_entry(config, entry);

        config_entry_parse_tries(entry, path, file, L".conf");
        TAKE_PTR(entry);
}

static EFI_STATUS efivar_get_timeout(const char16_t *var, uint32_t *ret_value) {
        _cleanup_free_ char16_t *value = NULL;
        EFI_STATUS err;

        assert(var);
        assert(ret_value);

        err = efivar_get(LOADER_GUID, var, &value);
        if (err != EFI_SUCCESS)
                return err;

        if (streq16(value, u"menu-force")) {
                *ret_value = TIMEOUT_MENU_FORCE;
                return EFI_SUCCESS;
        }
        if (streq16(value, u"menu-hidden")) {
                *ret_value = TIMEOUT_MENU_HIDDEN;
                return EFI_SUCCESS;
        }

        uint64_t timeout;
        if (!parse_number16(value, &timeout, NULL))
                return EFI_INVALID_PARAMETER;

        *ret_value = MIN(timeout, TIMEOUT_TYPE_MAX);
        return EFI_SUCCESS;
}

static void config_load_defaults(Config *config, EFI_FILE *root_dir) {
        _cleanup_free_ char *content = NULL;
        UINTN value;
        EFI_STATUS err;

        assert(root_dir);

        *config = (Config) {
                .editor = true,
                .auto_entries = true,
                .auto_firmware = true,
                .reboot_for_bitlocker = false,
                .secure_boot_enroll = ENROLL_MANUAL,
                .random_seed_mode = RANDOM_SEED_WITH_SYSTEM_TOKEN,
                .idx_default_efivar = IDX_INVALID,
                .console_mode = CONSOLE_MODE_KEEP,
                .console_mode_efivar = CONSOLE_MODE_KEEP,
                .timeout_sec_config = TIMEOUT_UNSET,
                .timeout_sec_efivar = TIMEOUT_UNSET,
        };

        err = file_read(root_dir, L"\\loader\\loader.conf", 0, 0, &content, NULL);
        if (err == EFI_SUCCESS)
                config_defaults_load_from_file(config, content);

        err = efivar_get_timeout(u"LoaderConfigTimeout", &config->timeout_sec_efivar);
        if (err == EFI_SUCCESS)
                config->timeout_sec = config->timeout_sec_efivar;
        else if (err != EFI_NOT_FOUND)
                log_error_stall(u"Error reading LoaderConfigTimeout EFI variable: %r", err);

        err = efivar_get_timeout(u"LoaderConfigTimeoutOneShot", &config->timeout_sec);
        if (err == EFI_SUCCESS) {
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_set(LOADER_GUID, L"LoaderConfigTimeoutOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);

                config->force_menu = true; /* force the menu when this is set */
        } else if (err != EFI_NOT_FOUND)
                log_error_stall(u"Error reading LoaderConfigTimeoutOneShot EFI variable: %r", err);

        err = efivar_get_uint_string(LOADER_GUID, L"LoaderConfigConsoleMode", &value);
        if (err == EFI_SUCCESS)
                config->console_mode_efivar = value;

        err = efivar_get(LOADER_GUID, L"LoaderEntryOneShot", &config->entry_oneshot);
        if (err == EFI_SUCCESS)
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_set(LOADER_GUID, L"LoaderEntryOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);

        (void) efivar_get(LOADER_GUID, L"LoaderEntryDefault", &config->entry_default_efivar);

        strtolower16(config->entry_default_config);
        strtolower16(config->entry_default_efivar);
        strtolower16(config->entry_oneshot);
        strtolower16(config->entry_saved);

        config->use_saved_entry = streq16(config->entry_default_config, L"@saved");
        config->use_saved_entry_efivar = streq16(config->entry_default_efivar, L"@saved");
        if (config->use_saved_entry || config->use_saved_entry_efivar)
                (void) efivar_get(LOADER_GUID, L"LoaderEntryLastBooted", &config->entry_saved);
}

static void config_load_entries(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *loaded_image_path) {

        _cleanup_(file_closep) EFI_FILE *entries_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *f = NULL;
        UINTN f_size = 0;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);

        /* Adds Boot Loader Type #1 entries (i.e. /loader/entries/….conf) */

        err = open_directory(root_dir, L"\\loader\\entries", &entries_dir);
        if (err != EFI_SUCCESS)
                return;

        for (;;) {
                _cleanup_free_ char *content = NULL;

                err = readdir_harder(entries_dir, &f, &f_size);
                if (err != EFI_SUCCESS || !f)
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
                if (err == EFI_SUCCESS)
                        config_entry_add_type1(config, device, root_dir, L"\\loader\\entries", f->FileName, content, loaded_image_path);
        }
}

static int config_entry_compare(const ConfigEntry *a, const ConfigEntry *b) {
        int r;

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
                r = strcmp16(a->sort_key, b->sort_key);
                if (r != 0)
                        return r;

                /* If multiple installations of the same OS are around, group by machine ID */
                r = strcmp16(a->machine_id, b->machine_id);
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

        if (a->tries_left < 0 || b->tries_left < 0)
                return 0;

        /* If both items have boot counting, and otherwise are identical, put the entry with more tries left first */
        r = -CMP(a->tries_left, b->tries_left);
        if (r != 0)
                return r;

        /* If they have the same number of tries left, then let the one win which was tried fewer times so far */
        return CMP(a->tries_done, b->tries_done);
}

static UINTN config_entry_find(Config *config, const char16_t *pattern) {
        assert(config);

        /* We expect pattern and entry IDs to be already case folded. */

        if (!pattern)
                return IDX_INVALID;

        for (UINTN i = 0; i < config->entry_count; i++)
                if (efi_fnmatch(pattern, config->entries[i]->id))
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

static bool entries_unique(ConfigEntry **entries, bool *unique, UINTN entry_count) {
        bool is_unique = true;

        assert(entries);
        assert(unique);

        for (UINTN i = 0; i < entry_count; i++)
                for (UINTN k = i + 1; k < entry_count; k++) {
                        if (!streq16(entries[i]->title_show, entries[k]->title_show))
                                continue;

                        is_unique = unique[i] = unique[k] = false;
                }

        return is_unique;
}

/* generate a unique title, avoiding non-distinguishable menu entries */
static void config_title_generate(Config *config) {
        assert(config);

        bool unique[config->entry_count];

        /* set title */
        for (UINTN i = 0; i < config->entry_count; i++) {
                assert(!config->entries[i]->title_show);
                unique[i] = true;
                config->entries[i]->title_show = xstrdup16(config->entries[i]->title ?: config->entries[i]->id);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add version to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->version)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(L"%s (%s)", t, config->entries[i]->version);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add machine-id to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->machine_id)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(
                        L"%s (%.*s)",
                        t,
                        strnlen16(config->entries[i]->machine_id, 8),
                        config->entries[i]->machine_id);
        }

        if (entries_unique(config->entries, unique, config->entry_count))
                return;

        /* add file name to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                if (unique[i])
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xpool_print(L"%s (%s)", t, config->entries[i]->id);
        }
}

static bool is_sd_boot(EFI_FILE *root_dir, const char16_t *loader_path) {
        EFI_STATUS err;
        static const char * const sections[] = {
                ".sdmagic",
                NULL
        };
        UINTN offset = 0, size = 0, read;
        _cleanup_free_ char *content = NULL;

        assert(root_dir);
        assert(loader_path);

        err = pe_file_locate_sections(root_dir, loader_path, sections, &offset, &size);
        if (err != EFI_SUCCESS || size != sizeof(magic))
                return false;

        err = file_read(root_dir, loader_path, offset, size, &content, &read);
        if (err != EFI_SUCCESS || size != read)
                return false;

        return memcmp(content, magic, sizeof(magic)) == 0;
}

static ConfigEntry *config_entry_add_loader_auto(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *loaded_image_path,
                const char16_t *id,
                char16_t key,
                const char16_t *title,
                const char16_t *loader) {

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
                if (strcaseeq16(loader, loaded_image_path) ||
                    is_sd_boot(root_dir, loader) ||
                    is_sd_boot(root_dir, L"\\EFI\\BOOT\\GRUB" EFI_MACHINE_TYPE_NAME L".EFI"))
                        return NULL;
        }

        /* check existence */
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        EFI_STATUS err = root_dir->Open(root_dir, &handle, (char16_t *) loader, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return NULL;

        ConfigEntry *entry = xnew(ConfigEntry, 1);
        *entry = (ConfigEntry) {
                .id = xstrdup16(id),
                .type = LOADER_AUTO,
                .title = xstrdup16(title),
                .device = device,
                .loader = xstrdup16(loader),
                .key = key,
                .tries_done = -1,
                .tries_left = -1,
        };

        config_add_entry(config, entry);
        return entry;
}

static void config_entry_add_osx(Config *config) {
        EFI_STATUS err;
        UINTN n_handles = 0;
        _cleanup_free_ EFI_HANDLE *handles = NULL;

        assert(config);

        if (!config->auto_entries)
                return;

        err = BS->LocateHandleBuffer(ByProtocol, &FileSystemProtocol, NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return;

        for (UINTN i = 0; i < n_handles; i++) {
                _cleanup_(file_closep) EFI_FILE *root = NULL;

                if (open_volume(handles[i], &root) != EFI_SUCCESS)
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
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        UINTN n_handles;
        EFI_STATUS err;

        // FIXME: Experimental for now. Should be generalized, and become a per-entry option that can be
        // enabled independently of BitLocker, and without a BootXXXX entry pre-existing.

        /* BitLocker key cannot be sealed without a TPM present. */
        if (!tpm_present())
                return EFI_NOT_FOUND;

        err = BS->LocateHandleBuffer(ByProtocol, &BlockIoProtocol, NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return err;

        /* Look for BitLocker magic string on all block drives. */
        bool found = false;
        for (UINTN i = 0; i < n_handles; i++) {
                EFI_BLOCK_IO_PROTOCOL *block_io;
                err = BS->HandleProtocol(handles[i], &BlockIoProtocol, (void **) &block_io);
                if (err != EFI_SUCCESS || block_io->Media->BlockSize < 512 || block_io->Media->BlockSize > 4096)
                        continue;

                char buf[4096];
                err = block_io->ReadBlocks(block_io, block_io->Media->MediaId, 0, sizeof(buf), buf);
                if (err != EFI_SUCCESS)
                        continue;

                if (memcmp(buf + 3, "-FVE-FS-", STRLEN("-FVE-FS-")) == 0) {
                        found = true;
                        break;
                }
        }

        /* If no BitLocker drive was found, we can just chainload bootmgfw.efi directly. */
        if (!found)
                return EFI_NOT_FOUND;

        _cleanup_free_ uint16_t *boot_order = NULL;
        UINTN boot_order_size;

        /* There can be gaps in Boot#### entries. Instead of iterating over the full
         * EFI var list or uint16_t namespace, just look for "Windows Boot Manager" in BootOrder. */
        err = efivar_get_raw(EFI_GLOBAL_GUID, L"BootOrder", (char **) &boot_order, &boot_order_size);
        if (err != EFI_SUCCESS || boot_order_size % sizeof(uint16_t) != 0)
                return err;

        for (UINTN i = 0; i < boot_order_size / sizeof(uint16_t); i++) {
                _cleanup_free_ char *buf = NULL;
                char16_t name[sizeof(L"Boot0000")];
                UINTN buf_size;

                SPrint(name, sizeof(name), L"Boot%04x", (uint32_t) boot_order[i]);
                err = efivar_get_raw(EFI_GLOBAL_GUID, name, &buf, &buf_size);
                if (err != EFI_SUCCESS)
                        continue;

                /* Boot#### are EFI_LOAD_OPTION. But we really are only interested
                 * for the description, which is at this offset. */
                UINTN offset = sizeof(uint32_t) + sizeof(uint16_t);
                if (buf_size < offset + sizeof(char16_t))
                        continue;

                if (streq16((char16_t *) (buf + offset), L"Windows Boot Manager")) {
                        err = efivar_set_raw(
                                EFI_GLOBAL_GUID,
                                L"BootNext",
                                boot_order + i,
                                sizeof(boot_order[i]),
                                EFI_VARIABLE_NON_VOLATILE);
                        if (err != EFI_SUCCESS)
                                return err;
                        RT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
                        assert_not_reached();
                }
        }

        return EFI_NOT_FOUND;
}

static void config_entry_add_windows(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
        _cleanup_free_ char *bcd = NULL;
        char16_t *title = NULL;
        EFI_STATUS err;
        UINTN len;

        assert(config);
        assert(device);
        assert(root_dir);

        if (!config->auto_entries)
                return;

        /* Try to find a better title. */
        err = file_read(root_dir, L"\\EFI\\Microsoft\\Boot\\BCD", 0, 100*1024, &bcd, &len);
        if (err == EFI_SUCCESS)
                title = get_bcd_title((uint8_t *) bcd, len);

        ConfigEntry *e = config_entry_add_loader_auto(config, device, root_dir, NULL,
                                                      L"auto-windows", 'w', title ?: L"Windows Boot Manager",
                                                      L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

        if (config->reboot_for_bitlocker)
                e->call = boot_windows_bitlocker;
#endif
}

static void config_entry_add_unified(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir) {

        _cleanup_(file_closep) EFI_FILE *linux_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *f = NULL;
        UINTN f_size = 0;
        EFI_STATUS err;

        /* Adds Boot Loader Type #2 entries (i.e. /EFI/Linux/….efi) */

        assert(config);
        assert(device);
        assert(root_dir);

        err = open_directory(root_dir, L"\\EFI\\Linux", &linux_dir);
        if (err != EFI_SUCCESS)
                return;

        for (;;) {
                enum {
                        SECTION_CMDLINE,
                        SECTION_OSREL,
                        _SECTION_MAX,
                };

                static const char * const sections[_SECTION_MAX + 1] = {
                        [SECTION_CMDLINE] = ".cmdline",
                        [SECTION_OSREL]   = ".osrel",
                        NULL,
                };

                _cleanup_free_ char16_t *os_pretty_name = NULL, *os_image_id = NULL, *os_name = NULL, *os_id = NULL,
                        *os_image_version = NULL, *os_version = NULL, *os_version_id = NULL, *os_build_id = NULL;
                const char16_t *good_name, *good_version, *good_sort_key;
                _cleanup_free_ char *content = NULL;
                UINTN offs[_SECTION_MAX] = {};
                UINTN szs[_SECTION_MAX] = {};
                char *line;
                UINTN pos = 0;
                char *key, *value;

                err = readdir_harder(linux_dir, &f, &f_size);
                if (err != EFI_SUCCESS || !f)
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
                err = pe_file_locate_sections(linux_dir, f->FileName, sections, offs, szs);
                if (err != EFI_SUCCESS || szs[SECTION_OSREL] == 0)
                        continue;

                err = file_read(linux_dir, f->FileName, offs[SECTION_OSREL], szs[SECTION_OSREL], &content, NULL);
                if (err != EFI_SUCCESS)
                        continue;

                /* read properties from the embedded os-release file */
                while ((line = line_get_key_value(content, "=", &pos, &key, &value))) {
                        if (streq8(key, "PRETTY_NAME")) {
                                free(os_pretty_name);
                                os_pretty_name = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "IMAGE_ID")) {
                                free(os_image_id);
                                os_image_id = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "NAME")) {
                                free(os_name);
                                os_name = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "ID")) {
                                free(os_id);
                                os_id = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "IMAGE_VERSION")) {
                                free(os_image_version);
                                os_image_version = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "VERSION")) {
                                free(os_version);
                                os_version = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "VERSION_ID")) {
                                free(os_version_id);
                                os_version_id = xstra_to_str(value);
                                continue;
                        }

                        if (streq8(key, "BUILD_ID")) {
                                free(os_build_id);
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

                ConfigEntry *entry = xnew(ConfigEntry, 1);
                *entry = (ConfigEntry) {
                        .id = xstrdup16(f->FileName),
                        .type = LOADER_UNIFIED_LINUX,
                        .title = xstrdup16(good_name),
                        .version = xstrdup16(good_version),
                        .device = device,
                        .loader = xpool_print(L"\\EFI\\Linux\\%s", f->FileName),
                        .sort_key = xstrdup16(good_sort_key),
                        .key = 'l',
                        .tries_done = -1,
                        .tries_left = -1,
                };

                strtolower16(entry->id);
                config_add_entry(config, entry);
                config_entry_parse_tries(entry, L"\\EFI\\Linux", f->FileName, L".efi");

                if (szs[SECTION_CMDLINE] == 0)
                        continue;

                content = mfree(content);

                /* read the embedded cmdline file */
                err = file_read(linux_dir, f->FileName, offs[SECTION_CMDLINE], szs[SECTION_CMDLINE], &content, NULL);
                if (err == EFI_SUCCESS) {
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
        if (err != EFI_SUCCESS)
                return;

        config_entry_add_unified(config, new_device, root_dir);
        config_load_entries(config, new_device, root_dir, NULL);
}

static EFI_STATUS initrd_prepare(
                EFI_FILE *root,
                const ConfigEntry *entry,
                char16_t **ret_options,
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
        _cleanup_free_ char16_t *options = NULL;

        EFI_STATUS err;
        UINTN size = 0;
        _cleanup_free_ uint8_t *initrd = NULL;

        STRV_FOREACH(i, entry->initrd) {
                _cleanup_free_ char16_t *o = options;
                if (o)
                        options = xpool_print(L"%s initrd=%s", o, *i);
                else
                        options = xpool_print(L"initrd=%s", *i);

                _cleanup_(file_closep) EFI_FILE *handle = NULL;
                err = root->Open(root, &handle, *i, EFI_FILE_MODE_READ, 0);
                if (err != EFI_SUCCESS)
                        return err;

                _cleanup_free_ EFI_FILE_INFO *info = NULL;
                err = get_file_info_harder(handle, &info, NULL);
                if (err != EFI_SUCCESS)
                        return err;

                UINTN new_size, read_size = info->FileSize;
                if (__builtin_add_overflow(size, read_size, &new_size))
                        return EFI_OUT_OF_RESOURCES;
                initrd = xrealloc(initrd, size, new_size);

                err = handle->Read(handle, &read_size, initrd + size);
                if (err != EFI_SUCCESS)
                        return err;

                /* Make sure the actual read size is what we expected. */
                assert(size + read_size == new_size);
                size = new_size;
        }

        if (entry->options) {
                _cleanup_free_ char16_t *o = options;
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
        _cleanup_free_ EFI_DEVICE_PATH *path = NULL;
        EFI_STATUS err;

        assert(entry);

        /* If this loader entry has a special way to boot, try that first. */
        if (entry->call)
                (void) entry->call();

        _cleanup_(file_closep) EFI_FILE *image_root = NULL;
        err = open_volume(entry->device, &image_root);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error opening root path: %r", err);

        err = make_file_device_path(entry->device, entry->loader, &path);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error making file device path: %r", err);

        UINTN initrd_size = 0;
        _cleanup_free_ void *initrd = NULL;
        _cleanup_free_ char16_t *options_initrd = NULL;
        err = initrd_prepare(image_root, entry, &options_initrd, &initrd, &initrd_size);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error preparing initrd: %r", err);

        err = shim_load_image(parent_image, path, &image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error loading %s: %r", entry->loader, err);

        if (entry->devicetree) {
                err = devicetree_install(&dtstate, image_root, entry->devicetree);
                if (err != EFI_SUCCESS)
                        return log_error_status_stall(err, L"Error loading %s: %r", entry->devicetree, err);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd, initrd_size, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error registering initrd: %r", err);

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        err = BS->HandleProtocol(image, &LoadedImageProtocol, (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error getting LoadedImageProtocol handle: %r", err);

        char16_t *options = options_initrd ?: entry->options;
        if (options) {
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = strsize16(options);

                /* Try to log any options to the TPM, especially to catch manually edited options */
                (void) tpm_log_load_options(options, NULL);
        }

        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeExecUSec", 0);
        err = BS->StartImage(image, NULL, NULL);
        graphics_mode(false);
        if (err == EFI_SUCCESS)
                return EFI_SUCCESS;

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && entry->type == LOADER_LINUX) {
                uint32_t compat_address;

                err = pe_kernel_info(loaded_image->ImageBase, &compat_address);
                if (err != EFI_SUCCESS) {
                        if (err != EFI_UNSUPPORTED)
                                return log_error_status_stall(err, L"Error finding kernel compat entry address: %r", err);
                } else if (compat_address > 0) {
                        EFI_IMAGE_ENTRY_POINT kernel_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);

                        err = kernel_entry(image, ST);
                        graphics_mode(false);
                        if (err == EFI_SUCCESS)
                                return EFI_SUCCESS;
                } else
                        err = EFI_UNSUPPORTED;
        }

        return log_error_status_stall(err, L"Failed to execute %s (%s): %r", entry->title_show, entry->loader, err);
}

static void config_free(Config *config) {
        assert(config);
        for (UINTN i = 0; i < config->entry_count; i++)
                config_entry_free(config->entries[i]);
        free(config->entries);
        free(config->entry_default_config);
        free(config->entry_oneshot);
}

static void config_write_entries_to_variable(Config *config) {
        _cleanup_free_ char *buffer = NULL;
        UINTN sz = 0;
        char *p;

        assert(config);

        for (UINTN i = 0; i < config->entry_count; i++)
                sz += strsize16(config->entries[i]->id);

        p = buffer = xmalloc(sz);

        for (UINTN i = 0; i < config->entry_count; i++)
                p = mempcpy(p, config->entries[i]->id, strsize16(config->entries[i]->id));

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
        if (streq16(config->entry_oneshot, entry->id))
                return;

        if (config->use_saved_entry_efivar || (!config->entry_default_efivar && config->use_saved_entry)) {
                /* Avoid unnecessary NVRAM writes. */
                if (streq16(config->entry_saved, entry->id))
                        return;

                (void) efivar_set(LOADER_GUID, L"LoaderEntryLastBooted", entry->id, EFI_VARIABLE_NON_VOLATILE);
        } else
                /* Delete the non-volatile var if not needed. */
                (void) efivar_set(LOADER_GUID, L"LoaderEntryLastBooted", NULL, EFI_VARIABLE_NON_VOLATILE);
}

static EFI_STATUS secure_boot_discover_keys(Config *config, EFI_FILE *root_dir) {
        EFI_STATUS err;
        _cleanup_(file_closep) EFI_FILE *keys_basedir = NULL;

        if (secure_boot_mode() != SECURE_BOOT_SETUP)
                return EFI_SUCCESS;

        /* the lack of a 'keys' directory is not fatal and is silently ignored */
        err = open_directory(root_dir, u"\\loader\\keys", &keys_basedir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return err;

        for (;;) {
                _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
                size_t dirent_size = 0;
                ConfigEntry *entry = NULL;

                err = readdir_harder(keys_basedir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS || !dirent)
                        return err;

                if (dirent->FileName[0] == '.')
                        continue;

                if (!FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;

                entry = xnew(ConfigEntry, 1);
                *entry = (ConfigEntry) {
                        .id = xpool_print(L"secure-boot-keys-%s", dirent->FileName),
                        .title = xpool_print(L"Enroll Secure Boot keys: %s", dirent->FileName),
                        .path = xpool_print(L"\\loader\\keys\\%s", dirent->FileName),
                        .type = LOADER_SECURE_BOOT_KEYS,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);

                if (config->secure_boot_enroll == ENROLL_FORCE && strcaseeq16(dirent->FileName, u"auto"))
                        /* if we auto enroll successfully this call does not return, if it fails we still
                         * want to add other potential entries to the menu */
                        secure_boot_enroll_at(root_dir, entry->path);
        }

        return EFI_SUCCESS;
}

static void export_variables(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *loaded_image_path,
                uint64_t init_usec) {

        static const uint64_t loader_features =
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT |
                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                EFI_LOADER_FEATURE_ENTRY_ONESHOT |
                EFI_LOADER_FEATURE_BOOT_COUNTING |
                EFI_LOADER_FEATURE_XBOOTLDR |
                EFI_LOADER_FEATURE_RANDOM_SEED |
                EFI_LOADER_FEATURE_LOAD_DRIVER |
                EFI_LOADER_FEATURE_SORT_KEY |
                EFI_LOADER_FEATURE_SAVED_ENTRY |
                EFI_LOADER_FEATURE_DEVICETREE |
                0;

        _cleanup_free_ char16_t *infostr = NULL, *typestr = NULL;
        char16_t uuid[37];

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
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *loaded_image_path,
                EFI_FILE *root_dir) {

        assert(config);
        assert(loaded_image);
        assert(loaded_image_path);
        assert(root_dir);

        config_load_defaults(config, root_dir);

        /* scan /EFI/Linux/ directory */
        config_entry_add_unified(config, loaded_image->DeviceHandle, root_dir);

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

        if (config->auto_firmware && FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI)) {
                ConfigEntry *entry = xnew(ConfigEntry, 1);
                *entry = (ConfigEntry) {
                        .id = xstrdup16(u"auto-reboot-to-firmware-setup"),
                        .title = xstrdup16(u"Reboot Into Firmware Interface"),
                        .call = reboot_into_firmware,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);
        }

        /* find if secure boot signing keys exist and autoload them if necessary
        otherwise creates menu entries so that the user can load them manually
        if the secure-boot-enroll variable is set to no (the default), we do not
        even search for keys on the ESP */
        if (config->secure_boot_enroll != ENROLL_OFF)
                secure_boot_discover_keys(config, root_dir);

        if (config->entry_count == 0)
                return;

        config_write_entries_to_variable(config);

        config_title_generate(config);

        /* select entry by configured pattern or EFI LoaderDefaultEntry= variable */
        config_default_entry_select(config);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        _cleanup_(config_free) Config config = {};
        char16_t *loaded_image_path;
        EFI_STATUS err;
        uint64_t init_usec;
        bool menu = false;

        InitializeLib(image, sys_table);
        init_usec = time_usec();
        debug_hook(L"systemd-boot");
        /* Uncomment the next line if you need to wait for debugger. */
        // debug_break();

        /* The firmware may skip initializing some devices for the sake of a faster boot. This is especially
         * true for fastboot enabled firmwares. But this means that things we use like input devices or the
         * xbootldr partition may not be available yet. Reconnect all drivers should hopefully make the
         * firmware initialize everything we need. */
        (void) reconnect_all_drivers();

        err = BS->OpenProtocol(image,
                        &LoadedImageProtocol,
                        (void **)&loaded_image,
                        image,
                        NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error getting a LoadedImageProtocol handle: %r", err);

        err = device_path_to_str(loaded_image->FilePath, &loaded_image_path);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Error getting loaded image path: %r", err);

        export_variables(loaded_image, loaded_image_path, init_usec);

        err = open_volume(loaded_image->DeviceHandle, &root_dir);
        if (err != EFI_SUCCESS)
                return log_error_status_stall(err, L"Unable to open root directory: %r", err);

        (void) load_drivers(image, loaded_image, root_dir);

        config_load_all_entries(&config, loaded_image, loaded_image_path, root_dir);

        if (config.entry_count == 0) {
                log_error_stall(L"No loader found. Configuration files in \\loader\\entries\\*.conf are needed.");
                goto out;
        }

        /* select entry or show menu when key is pressed or timeout is set */
        if (config.force_menu || config.timeout_sec > 0)
                menu = true;
        else {
                uint64_t key;

                /* Block up to 100ms to give firmware time to get input working. */
                err = console_key_read(&key, 100 * 1000);
                if (err == EFI_SUCCESS) {
                        /* find matching key in config entries */
                        UINTN idx = entry_lookup_key(&config, config.idx_default, KEYCHAR(key));
                        if (idx != IDX_INVALID)
                                config.idx_default = idx;
                        else
                                menu = true;
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

                /* if auto enrollment is activated, we try to load keys for the given entry. */
                if (entry->type == LOADER_SECURE_BOOT_KEYS && config.secure_boot_enroll != ENROLL_OFF) {
                        err = secure_boot_enroll_at(root_dir, entry->path);
                        if (err != EFI_SUCCESS)
                                return err;
                        continue;
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
                        goto out;

                menu = true;
                config.timeout_sec = 0;
        }
        err = EFI_SUCCESS;
out:
        BS->CloseProtocol(image, &LoadedImageProtocol, image, NULL);
        return err;
}
