/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efigpt.h>
#include <efilib.h>

#include "console.h"
#include "crc32.h"
#include "disk.h"
#include "efi-loader-features.h"
#include "graphics.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "random-seed.h"
#include "secure-boot.h"
#include "shim.h"
#include "util.h"

#ifndef EFI_OS_INDICATIONS_BOOT_TO_FW_UI
#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI 0x0000000000000001ULL
#endif

#define TEXT_ATTR_SWAP(c) EFI_TEXT_ATTR(((c) & 0b11110000) >> 4, (c) & 0b1111)

#define LAST_BOOTED_FILE L"\\loader\\last-booted"

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-boot " GIT_VERSION " ####";

enum loader_type {
        LOADER_UNDEFINED,
        LOADER_EFI,
        LOADER_LINUX,
};

typedef struct {
        CHAR16 *id; /* The unique identifier for this entry */
        CHAR16 *title_show;
        CHAR16 *title;
        CHAR16 *version;
        CHAR16 *machine_id;
        EFI_HANDLE *device;
        enum loader_type type;
        CHAR16 *loader;
        CHAR16 *options;
        CHAR16 key;
        EFI_STATUS (*call)(VOID);
        BOOLEAN no_autoselect;
        BOOLEAN non_unique;
        UINTN tries_done;
        UINTN tries_left;
        CHAR16 *path;
        CHAR16 *current_name;
        CHAR16 *next_name;
} ConfigEntry;

typedef struct {
        ConfigEntry **entries;
        UINTN entry_count;
        INTN idx_default;
        INTN idx_default_efivar;
        INTN timeout_sec;
        INTN timeout_sec_config;
        INTN timeout_sec_efivar;
        BOOLEAN save_default;
        CHAR16 *entry_default_pattern;
        CHAR16 *entry_oneshot;
        CHAR16 *options_edit;
        BOOLEAN editor;
        BOOLEAN box;
        BOOLEAN auto_entries;
        BOOLEAN auto_firmware;
        BOOLEAN force_menu;
        UINTN console_mode;
        INTN console_mode_efivar;
        enum console_mode_change_type console_mode_change;
        RandomSeedMode random_seed_mode;
} Config;

static VOID cursor_left(UINTN *cursor, UINTN *first) {
        assert(cursor);
        assert(first);

        if ((*cursor) > 0)
                (*cursor)--;
        else if ((*first) > 0)
                (*first)--;
}

static VOID cursor_right(
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
                const CHAR16 *line_in,
                CHAR16 **line_out,
                UINTN x_max,
                UINTN y_pos) {

        _cleanup_freepool_ CHAR16 *line = NULL, *print = NULL;
        UINTN size, len, first, cursor, clear;
        BOOLEAN exit, enter;

        assert(line_out);

        if (!line_in)
                line_in = L"";
        size = StrLen(line_in) + 1024;
        line = AllocatePool(size * sizeof(CHAR16));
        StrCpy(line, line_in);
        len = StrLen(line);
        print = AllocatePool((x_max+1) * sizeof(CHAR16));

        first = 0;
        cursor = 0;
        clear = 0;
        enter = FALSE;
        exit = FALSE;
        while (!exit) {
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
                        print_at(cursor + 1, y_pos, cursor_color, print+cursor);
                        cursor_color = TEXT_ATTR_SWAP(cursor_color);

                        err = console_key_read(&key, 750 * 1000);
                        print_at(cursor + 1, y_pos, COLOR_EDIT, print+cursor);
                } while (EFI_ERROR(err));

                switch (key) {
                case KEYPRESS(0, SCAN_ESC, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'c'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'g'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('c')):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('g')):
                        exit = TRUE;
                        break;

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
                        if (StrCmp(line, line_in) != 0)
                                *line_out = TAKE_PTR(line);
                        enter = TRUE;
                        exit = TRUE;
                        break;

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

        return enter;
}

static UINTN entry_lookup_key(Config *config, UINTN start, CHAR16 key) {
        assert(config);

        if (key == 0)
                return -1;

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

        return -1;
}

static CHAR16 *update_timeout_efivar(Config *config) {
        if (config->timeout_sec_efivar >= -1)
                efivar_set_int_string(LOADER_GUID,
                                      L"LoaderConfigTimeout",
                                      config->timeout_sec_efivar,
                                      EFI_VARIABLE_NON_VOLATILE);
        else {
                config->timeout_sec_efivar = -2;
                efivar_set(LOADER_GUID, L"LoaderConfigTimeout", NULL, EFI_VARIABLE_NON_VOLATILE);
        }

        if (config->timeout_sec_efivar > 0)
                return PoolPrint(L"Menu timeout set to %ds.", config->timeout_sec_efivar);
        else if (config->timeout_sec_efivar == 0)
                return StrDuplicate(L"Menu disabled. Hold down key at bootup to show menu.");
        else if (config->timeout_sec_efivar == -1)
                return StrDuplicate(L"Timeout disabled, menu will always be shown.");
        else
                return StrDuplicate(L"Menu timeout defined by configuration file.");
}

static VOID print_status(Config *config, CHAR16 *loaded_image_path) {
        UINT64 key, indvar;
        INTN value;
        BOOLEAN modevar;
        _cleanup_freepool_ CHAR16 *partstr = NULL, *defaultstr = NULL;
        UINTN x_max, y_max;
        const CHAR16 *random_seed_mode;
        const CHAR16 *console_mode;
        CHAR16 console_mode_value[32];
        UINTN padding = 26;

        assert(config);
        assert(loaded_image_path);

        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, COLOR);
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);

        console_query_mode(&x_max, &y_max);

        #define line(property, format, ...) ({ \
                if (format) { \
                        Print(L"%*s: ", padding, property); \
                        Print(format, ## __VA_ARGS__); \
                        Print(L"\n"); \
                } \
        })

        line(L"systemd-boot version", L""GIT_VERSION);
        line(L"architecture", L""EFI_MACHINE_TYPE_NAME);
        line(L"loaded image", loaded_image_path);
        line(L"UEFI specification", L"%d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        line(L"firmware vendor", ST->FirmwareVendor);
        line(L"firmware version", L"%d.%02d", ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        line(L"console mode", L"%d/%d", ST->ConOut->Mode->Mode, ST->ConOut->Mode->MaxMode - 1);
        line(L"console size", L"%d x %d", x_max, y_max);
        line(L"secure boot", yes_no(secure_boot_enabled()));
        if (!EFI_ERROR(efivar_get_boolean_u8(EFI_GLOBAL_GUID, L"SetupMode", &modevar)))
                line(L"secure boot setup mode", modevar ? L"setup" : L"user");
        line(L"shim", shim_loaded() ? L"present" : L"no");
        if (!EFI_ERROR(efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndicationsSupported", &indvar)))
                line(L"os indications supported", L"%d", indvar);

        Print(L"\n--- Press any key to continue. ---\n\n");
        console_key_read(&key, 0);

        line(L"timeout", L"%ld", config->timeout_sec_config);
        line(L"default pattern", config->save_default ? L"auto-last-booted" : config->entry_default_pattern);
        if (config->save_default)
                line(L"saved entry", config->entry_default_pattern);
        line(L"editor", yes_no(config->editor));
        line(L"box", yes_no(config->box));
        line(L"auto-entries", yes_no(config->auto_entries));
        line(L"auto-firmware", yes_no(config->auto_firmware));

        switch (config->random_seed_mode) {
        case RANDOM_SEED_OFF:
                random_seed_mode = L"off";
                break;
        case RANDOM_SEED_WITH_SYSTEM_TOKEN:
                random_seed_mode = L"with-system-token";
                break;
        case RANDOM_SEED_ALWAYS:
                random_seed_mode = L"always";
                break;
        default:
                _unreachable_;
        }
        line(L"random-seed-mode", random_seed_mode);

        switch (config->console_mode_change) {
        case CONSOLE_MODE_AUTO:
                console_mode = L"auto";
                break;
        case CONSOLE_MODE_KEEP:
                console_mode = L"keep";
                break;
        case CONSOLE_MODE_MAX:
                console_mode = L"max";
                break;
        case CONSOLE_MODE_SET:
                console_mode = console_mode_value;
                SPrint(console_mode_value, ELEMENTSOF(console_mode_value), L"%u", config->console_mode);
                break;
        default:
                _unreachable_;
        }
        line(L"console-mode", console_mode);

        if (!EFI_ERROR(efivar_get_int_string(LOADER_GUID, L"LoaderConfigTimeout", &value)))
                line(L"LoaderConfigTimeout", L"%ld", value);
        if (!EFI_ERROR(efivar_get_int_string(LOADER_GUID, L"LoaderConfigConsoleMode", &value)))
                line(L"LoaderConfigConsoleMode", L"%ld", value);
        line(L"LoaderEntryOneShot", config->entry_oneshot);
        if (!EFI_ERROR(efivar_get(LOADER_GUID, L"LoaderDevicePartUUID", &partstr)))
                line(L"LoaderDevicePartUUID", partstr);
        if (!EFI_ERROR(efivar_get(LOADER_GUID, L"LoaderEntryDefault", &defaultstr)))
                line(L"LoaderEntryDefault", defaultstr);

        Print(L"\n--- Press any key to continue. ---\n\n");
        console_key_read(&key, 0);

        line(L"config entry count", L"%d", config->entry_count);
        line(L"default entry id", L"%d", config->idx_default);
        if (config->idx_default_efivar >= 0)
                line(L"default entry id (EFI var)", L"%d", config->idx_default_efivar);
        Print(L"\n");

        padding = 14;
        for (UINTN i = 0; i < config->entry_count; i++) {
                ConfigEntry *entry = config->entries[i];

                line(L"config entry", L"%d/%d", i+1, config->entry_count);
                line(L"id", entry->id);
                line(L"title", entry->title);
                line(L"title show", entry->title_show);
                line(L"version", entry->version);
                line(L"machine-id", entry->machine_id);
                if (entry->device) {
                        EFI_DEVICE_PATH *device_path;

                        device_path = DevicePathFromHandle(entry->device);
                        if (device_path) {
                                _cleanup_freepool_ CHAR16 *str = NULL;

                                str = DevicePathToStr(device_path);
                                line(L"device handle", str);
                        }
                }
                line(L"loader", entry->loader);
                line(L"options", entry->options);
                line(L"auto-select", yes_no(!entry->no_autoselect));
                line(L"internal call", yes_no(!!entry->call));

                line(L"counting boots", yes_no(entry->tries_left != UINTN_MAX));
                if (entry->tries_left != UINTN_MAX) {
                        line(L"tries", L"%u of %u", entry->tries_done, entry->tries_left);
                        line(L"current path", L"%s\\%s", entry->path, entry->current_name);
                        line(L"next path", L"%s\\%s", entry->path, entry->next_name);
                }

                if (i == config->entry_count - 1) {
                        Print(L"\n--- Press any key to quit. ---\n\n");
                        console_key_read(&key, 0);
                } else {
                        Print(L"\n--- Press any key to continue, ESC or q to quit. ---\n\n");
                        console_key_read(&key, 0);

                        if (key == KEYPRESS(0, SCAN_ESC, 0) || key == KEYPRESS(0, 0, 'q'))
                                break;
                }
        }

        #undef line

        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
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
        UINTN visible_count = 0;
        UINTN idx_highlight = config->idx_default;
        UINTN idx_highlight_prev = 0;
        UINTN idx_first = 0;
        UINTN idx_last = 0;
        BOOLEAN new_mode = TRUE;
        BOOLEAN clear_screen = TRUE;
        BOOLEAN refresh = TRUE;
        BOOLEAN highlight = FALSE;
        UINTN line_width = 0;
        UINTN entry_padding = 3;
        CHAR16 **lines = NULL;
        UINTN x_start = 0;
        UINTN y_start = 0;
        UINTN y_status = 0;
        UINTN x_max;
        UINTN y_max;
        CHAR16 *status = NULL;
        CHAR16 *clearline = NULL;
        INTN timeout_remain = config->timeout_sec;
        INT16 idx;
        BOOLEAN exit = FALSE;
        BOOLEAN run = TRUE;

        graphics_mode(FALSE);
        uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
        uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);

        /* draw a single character to make ClearScreen work on some firmware */
        Print(L" ");

        if (config->console_mode_efivar >= 0)
                err = console_set_mode(config->console_mode_efivar, CONSOLE_MODE_SET);
        else
                err = console_set_mode(config->console_mode, config->console_mode_change);
        if (EFI_ERROR(err)) {
                uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
                PrintErrorStall(L"Error switching console mode: %r", err);
        }

        while (!exit) {
                UINT64 key;

                if (new_mode) {
                        console_query_mode(&x_max, &y_max);

                        /* account for box+status or padding+status */
                        visible_max = y_max - (config->box ? 3 : 2);

                        /* Drawing entries starts at idx_first until idx_last.
                        * We want to make sure that idx_highlight is centered,
                        * but not if that means that above/below it are no entries
                        * to draw anymore. */
                        if (config->entry_count < visible_max || idx_highlight < visible_max / 2)
                                idx_first = 0;
                        else if (idx_highlight >= config->entry_count - (visible_max / 2))
                                idx_first = config->entry_count - visible_max;
                        else
                                idx_first = idx_highlight - (visible_max / 2);
                        idx_last = idx_first + visible_max-1;

                        /* length of the longest entry */
                        line_width = 0;
                        for (UINTN i = 0; i < config->entry_count; i++)
                                line_width = MAX(line_width, StrLen(config->entries[i]->title_show));
                        line_width = MIN(line_width + 2 * entry_padding, x_max - (config->box ? 2 : 0));

                        /* offsets to center the entries on the screen */
                        x_start = (x_max - (line_width)) / 2;
                        if (config->entry_count < visible_max)
                                y_start = ((visible_max - config->entry_count) / 2) + 1;
                        else
                                y_start = 0;
                        if (config->box)
                                y_start++;
                        visible_count = MIN(visible_max, config->entry_count);

                        /* Put status right after the box if drawn, otherwise give it a bit more breathing room. */
                        if (config->box)
                                y_status = y_start + visible_count + 1;
                        else
                                y_status = MIN(y_start + visible_count + 5, y_max - 1);

                        if (lines) {
                                for (UINTN i = 0; i < config->entry_count; i++)
                                        FreePool(lines[i]);
                                FreePool(lines);
                                FreePool(clearline);
                        }

                        /* menu entries title lines */
                        lines = AllocatePool(sizeof(CHAR16 *) * config->entry_count);
                        for (UINTN i = 0; i < config->entry_count; i++) {
                                UINTN j;

                                lines[i] = AllocatePool(((line_width + 1) * sizeof(CHAR16)));
                                UINTN padding = (line_width - MIN(StrLen(config->entries[i]->title_show), line_width)) / 2;

                                for (j = 0; j < padding; j++)
                                        lines[i][j] = ' ';

                                for (UINTN k = 0; config->entries[i]->title_show[k] != '\0' && j < line_width; j++, k++)
                                        lines[i][j] = config->entries[i]->title_show[k];

                                for (; j < line_width; j++)
                                        lines[i][j] = ' ';
                                lines[i][line_width] = '\0';
                        }

                        clearline = AllocatePool((x_max+1) * sizeof(CHAR16));
                        for (UINTN i = 0; i < x_max; i++)
                                clearline[i] = ' ';
                        clearline[x_max] = 0;

                        new_mode = FALSE;
                        clear_screen = TRUE;
                }

                if (clear_screen) {
                        /* draw a single character to make ClearScreen work on some firmware */
                        Print(L" ");
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, COLOR);
                        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
                        if (config->box)
                                draw_box(x_start - 1, y_start - 1, line_width + 1, visible_count + 1, COLOR_BOX);
                        clear_screen = FALSE;
                        refresh = TRUE;
                }

                if (refresh) {
                        for (UINTN i = 0; i < config->entry_count; i++) {
                                if (i < idx_first || i > idx_last)
                                        continue;
                                print_at(x_start, y_start + i - idx_first,
                                         (i == idx_highlight) ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                         lines[i]);
                        }
                        refresh = FALSE;
                } else if (highlight) {
                        print_at(x_start, y_start + idx_highlight_prev - idx_first, COLOR_ENTRY, lines[idx_highlight_prev]);
                        print_at(x_start, y_start + idx_highlight - idx_first, COLOR_HIGHLIGHT, lines[idx_highlight]);
                        highlight = FALSE;
                }

                if (timeout_remain > 0) {
                        FreePool(status);
                        status = PoolPrint(L"Boot in %ds.", timeout_remain);
                }

                /* print status after entry list */
                if (status) {
                        UINTN len;
                        UINTN x;

                        /* center line */
                        len = StrLen(status);
                        if (len < x_max)
                                x = (x_max - len) / 2;
                        else
                                x = 0;
                        print_at(0, y_status, COLOR, clearline + (x_max - x));
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, status);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline+1 + x + len);
                }

                err = console_key_read(&key, timeout_remain > 0 ? 1000 * 1000 : 0);
                if (err == EFI_TIMEOUT) {
                        timeout_remain--;
                        if (timeout_remain == 0) {
                                exit = TRUE;
                                break;
                        }

                        /* update status */
                        continue;
                } else
                        timeout_remain = 0;

                /* clear status after keystroke */
                if (status) {
                        FreePool(status);
                        status = NULL;
                        print_at(0, y_status, COLOR, clearline + 1);
                }

                idx_highlight_prev = idx_highlight;

                switch (key) {
                case KEYPRESS(0, SCAN_UP, 0):
                case KEYPRESS(0, 0, 'k'):
                        if (idx_highlight > 0)
                                idx_highlight--;
                        break;

                case KEYPRESS(0, SCAN_DOWN, 0):
                case KEYPRESS(0, 0, 'j'):
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
                        /* This must stay below 80 characters! Q/v/Ctrl+l deliberately not advertised. */
                        status = StrDuplicate(L"(d)efault (t/T)timeout (e)dit (r)esolution (p)rint (h)elp");
                        break;

                case KEYPRESS(0, 0, 'Q'):
                        exit = TRUE;
                        run = FALSE;
                        break;

                case KEYPRESS(0, 0, 'd'):
                case KEYPRESS(0, 0, 'D'):
                        if (config->idx_default_efivar != (INTN)idx_highlight) {
                                /* store the selected entry in a persistent EFI variable */
                                efivar_set(
                                        LOADER_GUID,
                                        L"LoaderEntryDefault",
                                        config->entries[idx_highlight]->id,
                                        EFI_VARIABLE_NON_VOLATILE);
                                config->idx_default_efivar = idx_highlight;
                                status = StrDuplicate(L"Default boot entry selected.");
                        } else {
                                /* clear the default entry EFI variable */
                                efivar_set(LOADER_GUID, L"LoaderEntryDefault", NULL, EFI_VARIABLE_NON_VOLATILE);
                                config->idx_default_efivar = -1;
                                status = StrDuplicate(L"Default boot entry cleared.");
                        }
                        break;

                case KEYPRESS(0, 0, '-'):
                case KEYPRESS(0, 0, 'T'):
                        config->timeout_sec_efivar--;
                        status = update_timeout_efivar(config);
                        break;

                case KEYPRESS(0, 0, '+'):
                case KEYPRESS(0, 0, 't'):
                        config->timeout_sec_efivar++;
                        status = update_timeout_efivar(config);
                        break;

                case KEYPRESS(0, 0, 'e'):
                case KEYPRESS(0, 0, 'E'):
                        /* only the options of configured entries can be edited */
                        if (!config->editor || config->entries[idx_highlight]->type == LOADER_UNDEFINED)
                                break;
                        /* The edit line may end up on the last line of the screen. And even though we're
                         * not telling the firmware to advance the line, it still does in this one case,
                         * causing a scroll to happen that screws with our beautiful boot loader output.
                         * Since we cannot paint the last character of the edit line, we simply start
                         * at x-offset 1 for symmetry. */
                        print_at(1, y_status, COLOR_EDIT, clearline + 2);
                        exit = line_edit(config->entries[idx_highlight]->options, &config->options_edit, x_max-2, y_status);
                        print_at(1, y_status, COLOR, clearline + 2);
                        break;

                case KEYPRESS(0, 0, 'v'):
                        status = PoolPrint(L"systemd-boot " GIT_VERSION " (" EFI_MACHINE_TYPE_NAME "), UEFI Specification %d.%02d, Vendor %s %d.%02d",
                                           ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff,
                                           ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                        break;

                case KEYPRESS(0, 0, 'p'):
                case KEYPRESS(0, 0, 'P'):
                        print_status(config, loaded_image_path);
                        clear_screen = TRUE;
                        break;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'l'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('l')):
                        clear_screen = TRUE;
                        break;

                case KEYPRESS(0, 0, 'r'):
                case KEYPRESS(0, 0, 'R'):
                case KEYPRESS(0, SCAN_F4, 0):
                        if (config->console_mode_efivar >= 0 && ST->ConOut->Mode->Mode == ST->ConOut->Mode->MaxMode - 1) {
                                config->console_mode_efivar = -1;
                                efivar_set(LOADER_GUID, L"LoaderConfigConsoleMode", NULL, EFI_VARIABLE_NON_VOLATILE);
                                status = StrDuplicate(L"Console mode defined by configuration file.");
                        } else {
                                err = console_set_mode(0, CONSOLE_MODE_NEXT);
                                if (EFI_ERROR(err))
                                        status = PoolPrint(L"Error changing console mode: %r", err);
                                else {
                                        config->console_mode_efivar = ST->ConOut->Mode->Mode;
                                        efivar_set_int_string(LOADER_GUID,
                                                              L"LoaderConfigConsoleMode",
                                                              config->console_mode_efivar,
                                                              EFI_VARIABLE_NON_VOLATILE);
                                        status = PoolPrint(L"Console mode changed to %d.", config->console_mode_efivar);
                                }
                                new_mode = TRUE;
                        }
                        break;

                default:
                        /* jump with a hotkey directly to a matching entry */
                        idx = entry_lookup_key(config, idx_highlight+1, KEYCHAR(key));
                        if (idx < 0)
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

        for (UINTN i = 0; i < config->entry_count; i++)
                FreePool(lines[i]);
        FreePool(lines);
        FreePool(clearline);

        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, COLOR);
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
        return run;
}

static VOID config_add_entry(Config *config, ConfigEntry *entry) {
        assert(config);
        assert(entry);

        if ((config->entry_count & 15) == 0) {
                UINTN i;

                i = config->entry_count + 16;
                if (config->entry_count == 0)
                        config->entries = AllocatePool(sizeof(VOID *) * i);
                else
                        config->entries = ReallocatePool(config->entries,
                                                         sizeof(VOID *) * config->entry_count, sizeof(VOID *) * i);
        }
        config->entries[config->entry_count++] = entry;
}

static VOID config_entry_free(ConfigEntry *entry) {
        if (!entry)
                return;

        FreePool(entry->id);
        FreePool(entry->title_show);
        FreePool(entry->title);
        FreePool(entry->version);
        FreePool(entry->machine_id);
        FreePool(entry->loader);
        FreePool(entry->options);
        FreePool(entry->path);
        FreePool(entry->current_name);
        FreePool(entry->next_name);
        FreePool(entry);
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

skip:
        line = content + *pos;
        if (*line == '\0')
                return NULL;

        linelen = 0;
        while (line[linelen] && !strchra((CHAR8 *)"\n\r", line[linelen]))
               linelen++;

        /* move pos to next line */
        *pos += linelen;
        if (content[*pos])
                (*pos)++;

        /* empty line */
        if (linelen == 0)
                goto skip;

        /* terminate line */
        line[linelen] = '\0';

        /* remove leading whitespace */
        while (strchra((CHAR8 *)" \t", *line)) {
                line++;
                linelen--;
        }

        /* remove trailing whitespace */
        while (linelen > 0 && strchra((CHAR8 *)" \t", line[linelen-1]))
                linelen--;
        line[linelen] = '\0';

        if (*line == '#')
                goto skip;

        /* split key/value */
        value = line;
        while (*value && !strchra(sep, *value))
                value++;
        if (*value == '\0')
                goto skip;
        *value = '\0';
        value++;
        while (*value && strchra(sep, *value))
                value++;

        /* unquote */
        if (value[0] == '"' && line[linelen-1] == '"') {
                value++;
                line[linelen-1] = '\0';
        }

        *key_ret = line;
        *value_ret = value;
        return line;
}

static VOID config_defaults_load_from_file(Config *config, CHAR8 *content) {
        CHAR8 *line;
        UINTN pos = 0;
        CHAR8 *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(content);

        while ((line = line_get_key_value(content, (CHAR8 *)" \t", &pos, &key, &value))) {
                if (strcmpa((CHAR8 *)"timeout", key) == 0) {
                        _cleanup_freepool_ CHAR16 *s = NULL;

                        s = stra_to_str(value);
                        err = parse_int(s, &config->timeout_sec_config);
                        if (EFI_ERROR(err))
                                PrintErrorStall(L"Error parsing 'timeout' config option: %r", err);
                        else
                                config->timeout_sec = config->timeout_sec_config;
                        continue;
                }

                if (strcmpa((CHAR8 *)"default", key) == 0) {
                        FreePool(config->entry_default_pattern);
                        if (strcmpa((CHAR8 *)"auto-last-booted", value) == 0) {
                                config->save_default = TRUE;
                                config->entry_default_pattern = NULL;
                        } else {
                                config->save_default = FALSE;
                                config->entry_default_pattern = stra_to_str(value);
                                StrLwr(config->entry_default_pattern);
                        }
                        continue;
                }

                if (strcmpa((CHAR8 *)"editor", key) == 0) {
                        err = parse_boolean(value, &config->editor);
                        if (EFI_ERROR(err))
                                PrintErrorStall(L"Error parsing 'editor' config option: %r", err);
                        continue;
                }

                if (strcmpa((CHAR8 *)"box", key) == 0) {
                        err = parse_boolean(value, &config->box);
                        if (EFI_ERROR(err))
                                PrintErrorStall(L"Error parsing 'box' config option: %r", err);
                        continue;
                }

                if (strcmpa((CHAR8 *)"auto-entries", key) == 0) {
                        err = parse_boolean(value, &config->auto_entries);
                        if (EFI_ERROR(err))
                                PrintErrorStall(L"Error parsing 'auto-entries' config option: %r", err);
                        continue;
                }

                if (strcmpa((CHAR8 *)"auto-firmware", key) == 0) {
                        err = parse_boolean(value, &config->auto_firmware);
                        if (EFI_ERROR(err))
                                PrintErrorStall(L"Error parsing 'auto-firmware' config option: %r", err);
                        continue;
                }

                if (strcmpa((CHAR8 *)"console-mode", key) == 0) {
                        if (strcmpa((CHAR8 *)"auto", value) == 0)
                                config->console_mode_change = CONSOLE_MODE_AUTO;
                        else if (strcmpa((CHAR8 *)"max", value) == 0)
                                config->console_mode_change = CONSOLE_MODE_MAX;
                        else if (strcmpa((CHAR8 *)"keep", value)  == 0)
                                config->console_mode_change = CONSOLE_MODE_KEEP;
                        else {
                                _cleanup_freepool_ CHAR16 *s = NULL;

                                s = stra_to_str(value);
                                config->console_mode = Atoi(s);
                                config->console_mode_change = CONSOLE_MODE_SET;
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
                                        PrintErrorStall(L"Error parsing 'random-seed-mode' config option: %r", err);
                                        continue;
                                }
                                config->random_seed_mode = on ? RANDOM_SEED_ALWAYS : RANDOM_SEED_OFF;
                        }
                }
        }
}

static VOID config_entry_parse_tries(
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

        entry->path = StrDuplicate(path);
        entry->current_name = StrDuplicate(file);

        next_left = left <= 0 ? 0 : left - 1;
        next_done = done >= (UINTN) -2 ? (UINTN) -2 : done + 1;

        prefix = StrDuplicate(file);
        prefix[i] = 0;

        entry->next_name = PoolPrint(L"%s+%u-%u%s", prefix, next_left, next_done, suffix ?: L"");
}

static VOID config_entry_bump_counters(
                ConfigEntry *entry,
                EFI_FILE_HANDLE root_dir) {

        _cleanup_freepool_ CHAR16* old_path = NULL, *new_path = NULL;
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        static EFI_GUID EfiFileInfoGuid = EFI_FILE_INFO_ID;
        _cleanup_freepool_ EFI_FILE_INFO *file_info = NULL;
        UINTN file_info_size, a, b;
        EFI_STATUS r;

        assert(entry);
        assert(root_dir);

        if (entry->tries_left == UINTN_MAX)
                return;

        if (!entry->path || !entry->current_name || !entry->next_name)
                return;

        old_path = PoolPrint(L"%s\\%s", entry->path, entry->current_name);

        r = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, old_path, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (EFI_ERROR(r))
                return;

        a = StrLen(entry->current_name);
        b = StrLen(entry->next_name);

        file_info_size = OFFSETOF(EFI_FILE_INFO, FileName) + (a > b ? a : b) + 1;

        for (;;) {
                file_info = AllocatePool(file_info_size);

                r = uefi_call_wrapper(handle->GetInfo, 4, handle, &EfiFileInfoGuid, &file_info_size, file_info);
                if (!EFI_ERROR(r))
                        break;

                if (r != EFI_BUFFER_TOO_SMALL || file_info_size * 2 < file_info_size) {
                        PrintErrorStall(L"Failed to get file info for '%s': %r", old_path, r);
                        return;
                }

                file_info_size *= 2;
                FreePool(file_info);
        }

        /* And rename the file */
        StrCpy(file_info->FileName, entry->next_name);
        r = uefi_call_wrapper(handle->SetInfo, 4, handle, &EfiFileInfoGuid, file_info_size, file_info);
        if (EFI_ERROR(r)) {
                PrintErrorStall(L"Failed to rename '%s' to '%s', ignoring: %r", old_path, entry->next_name, r);
                return;
        }

        /* Flush everything to disk, just in case… */
        (void) uefi_call_wrapper(handle->Flush, 1, handle);

        /* Let's tell the OS that we renamed this file, so that it knows what to rename to the counter-less name on
         * success */
        new_path = PoolPrint(L"%s\\%s", entry->path, entry->next_name);
        efivar_set(LOADER_GUID, L"LoaderBootCountPath", new_path, 0);

        /* If the file we just renamed is the loader path, then let's update that. */
        if (StrCmp(entry->loader, old_path) == 0) {
                FreePool(entry->loader);
                entry->loader = TAKE_PTR(new_path);
        }
}

static VOID config_entry_add_from_file(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const CHAR16 *path,
                const CHAR16 *file,
                CHAR8 *content,
                const CHAR16 *loaded_image_path) {

        ConfigEntry *entry;
        CHAR8 *line;
        UINTN pos = 0;
        CHAR8 *key, *value;
        EFI_STATUS err;
        EFI_FILE_HANDLE handle;
        _cleanup_freepool_ CHAR16 *initrd = NULL;

        assert(config);
        assert(root_dir);
        assert(path);
        assert(file);
        assert(content);
        assert(loaded_image_path);

        entry = AllocatePool(sizeof(ConfigEntry));

        *entry = (ConfigEntry) {
                .tries_done = UINTN_MAX,
                .tries_left = UINTN_MAX,
        };

        while ((line = line_get_key_value(content, (CHAR8 *)" \t", &pos, &key, &value))) {
                if (strcmpa((CHAR8 *)"title", key) == 0) {
                        FreePool(entry->title);
                        entry->title = stra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"version", key) == 0) {
                        FreePool(entry->version);
                        entry->version = stra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"machine-id", key) == 0) {
                        FreePool(entry->machine_id);
                        entry->machine_id = stra_to_str(value);
                        continue;
                }

                if (strcmpa((CHAR8 *)"linux", key) == 0) {
                        FreePool(entry->loader);
                        entry->type = LOADER_LINUX;
                        entry->loader = stra_to_path(value);
                        entry->key = 'l';
                        continue;
                }

                if (strcmpa((CHAR8 *)"efi", key) == 0) {
                        entry->type = LOADER_EFI;
                        FreePool(entry->loader);
                        entry->loader = stra_to_path(value);

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

                if (strcmpa((CHAR8 *)"initrd", key) == 0) {
                        _cleanup_freepool_ CHAR16 *new = NULL;

                        new = stra_to_path(value);
                        if (initrd) {
                                CHAR16 *s;

                                s = PoolPrint(L"%s initrd=%s", initrd, new);
                                FreePool(initrd);
                                initrd = s;
                        } else
                                initrd = PoolPrint(L"initrd=%s", new);

                        continue;
                }

                if (strcmpa((CHAR8 *)"options", key) == 0) {
                        _cleanup_freepool_ CHAR16 *new = NULL;

                        new = stra_to_str(value);
                        if (entry->options) {
                                CHAR16 *s;

                                s = PoolPrint(L"%s %s", entry->options, new);
                                FreePool(entry->options);
                                entry->options = s;
                        } else
                                entry->options = TAKE_PTR(new);

                        continue;
                }
        }

        if (entry->type == LOADER_UNDEFINED) {
                config_entry_free(entry);
                return;
        }

        /* check existence */
        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, entry->loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err)) {
                config_entry_free(entry);
                return;
        }
        uefi_call_wrapper(handle->Close, 1, handle);

        /* add initrd= to options */
        if (entry->type == LOADER_LINUX && initrd) {
                if (entry->options) {
                        CHAR16 *s;

                        s = PoolPrint(L"%s %s", initrd, entry->options);
                        FreePool(entry->options);
                        entry->options = s;
                } else
                        entry->options = TAKE_PTR(initrd);
        }

        entry->device = device;
        entry->id = StrDuplicate(file);
        StrLwr(entry->id);

        config_add_entry(config, entry);

        config_entry_parse_tries(entry, path, file, L".conf");
}

static VOID config_load_defaults(Config *config, EFI_FILE *root_dir) {
        _cleanup_freepool_ CHAR8 *content = NULL;
        EFI_STATUS err;

        assert(root_dir);

        *config = (Config) {
                .editor = TRUE,
                .auto_entries = TRUE,
                .auto_firmware = TRUE,
                .random_seed_mode = RANDOM_SEED_WITH_SYSTEM_TOKEN,
                .console_mode_efivar = -1,
                .timeout_sec_efivar = -2
        };

        err = file_read(root_dir, L"\\loader\\loader.conf", 0, 0, &content, NULL);
        if (!EFI_ERROR(err))
                config_defaults_load_from_file(config, content);

        err = efivar_get_int_string(LOADER_GUID, L"LoaderConfigTimeout", &config->timeout_sec_efivar);
        if (!EFI_ERROR(err))
                config->timeout_sec = config->timeout_sec_efivar;

        err = efivar_get_int_string(LOADER_GUID, L"LoaderConfigTimeoutOneShot", &config->timeout_sec);
        if (!EFI_ERROR(err)) {
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_set(LOADER_GUID, L"LoaderConfigTimeoutOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);
                config->force_menu = TRUE; /* force the menu when this is set */
        }

        efivar_get_int_string(LOADER_GUID, L"LoaderConfigConsoleMode", &config->console_mode_efivar);

        if (config->save_default) {
                CHAR8 *saved;
                err = file_read(root_dir, LAST_BOOTED_FILE, 0, 0, &saved, NULL);
                if (!EFI_ERROR(err))
                        config->entry_default_pattern = (CHAR16*)saved;
        }
}

static VOID config_load_entries(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                CHAR16 *loaded_image_path) {

        EFI_FILE_HANDLE entries_dir;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);
        assert(loaded_image_path);

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &entries_dir, (CHAR16*) L"\\loader\\entries", EFI_FILE_MODE_READ, 0ULL);
        if (!EFI_ERROR(err)) {
                for (;;) {
                        CHAR16 buf[256];
                        UINTN bufsize;
                        EFI_FILE_INFO *f;
                        _cleanup_freepool_ CHAR8 *content = NULL;

                        bufsize = sizeof(buf);
                        err = uefi_call_wrapper(entries_dir->Read, 3, entries_dir, &bufsize, buf);
                        if (bufsize == 0 || EFI_ERROR(err))
                                break;

                        f = (EFI_FILE_INFO *) buf;
                        if (f->FileName[0] == '.')
                                continue;
                        if (f->Attribute & EFI_FILE_DIRECTORY)
                                continue;

                        if (!endswith_no_case(f->FileName, L".conf"))
                                continue;
                        if (startswith(f->FileName, L"auto-"))
                                continue;

                        err = file_read(entries_dir, f->FileName, 0, 0, &content, NULL);
                        if (!EFI_ERROR(err))
                                config_entry_add_from_file(config, device, root_dir, L"\\loader\\entries", f->FileName, content, loaded_image_path);
                }
                uefi_call_wrapper(entries_dir->Close, 1, entries_dir);
        }
}

static INTN config_entry_compare(ConfigEntry *a, ConfigEntry *b) {
        INTN r;

        assert(a);
        assert(b);

        /* Order entries that have no tries left to the beginning of the list */
        if (a->tries_left != 0 && b->tries_left == 0)
                return 1;
        if (a->tries_left == 0 && b->tries_left != 0)
                return -1;

        r = strverscmp_improved(a->id, b->id);
        if (r != 0)
                return r;

        if (a->tries_left == UINTN_MAX ||
            b->tries_left == UINTN_MAX)
                return 0;

        /* If both items have boot counting, and otherwise are identical, put the entry with more tries left last */
        if (a->tries_left > b->tries_left)
                return 1;
        if (a->tries_left < b->tries_left)
                return -1;

        /* If they have the same number of tries left, then let the one win which was tried fewer times so far */
        if (a->tries_done < b->tries_done)
                return 1;
        if (a->tries_done > b->tries_done)
                return -1;

        return 0;
}

static VOID config_sort_entries(Config *config) {
        assert(config);

        for (UINTN i = 1; i < config->entry_count; i++) {
                BOOLEAN more;

                more = FALSE;
                for (UINTN k = 0; k < config->entry_count - i; k++) {
                        ConfigEntry *entry;

                        if (config_entry_compare(config->entries[k], config->entries[k+1]) <= 0)
                                continue;

                        entry = config->entries[k];
                        config->entries[k] = config->entries[k+1];
                        config->entries[k+1] = entry;
                        more = TRUE;
                }
                if (!more)
                        break;
        }
}

static INTN config_entry_find(Config *config, CHAR16 *id) {
        assert(config);
        assert(id);

        for (UINTN i = 0; i < config->entry_count; i++)
                if (StrCmp(config->entries[i]->id, id) == 0)
                        return (INTN) i;

        return -1;
}

static VOID config_default_entry_select(Config *config) {
        _cleanup_freepool_ CHAR16 *entry_oneshot = NULL, *entry_default = NULL;
        EFI_STATUS err;
        INTN i;

        assert(config);

        /*
         * The EFI variable to specify a boot entry for the next, and only the
         * next reboot. The variable is always cleared directly after it is read.
         */
        err = efivar_get(LOADER_GUID, L"LoaderEntryOneShot", &entry_oneshot);
        if (!EFI_ERROR(err)) {

                config->entry_oneshot = StrDuplicate(entry_oneshot);
                efivar_set(LOADER_GUID, L"LoaderEntryOneShot", NULL, EFI_VARIABLE_NON_VOLATILE);

                i = config_entry_find(config, entry_oneshot);
                if (i >= 0) {
                        config->idx_default = i;
                        return;
                }
        }

        /*
         * The EFI variable to select the default boot entry overrides the
         * configured pattern. The variable can be set and cleared by pressing
         * the 'd' key in the loader selection menu.
         */
        err = efivar_get(LOADER_GUID, L"LoaderEntryDefault", &entry_default);
        if (!EFI_ERROR(err)) {

                i = config_entry_find(config, entry_default);
                if (i >= 0) {
                        config->idx_default = i;
                        config->idx_default_efivar = i;
                        return;
                }
        }
        config->idx_default_efivar = -1;

        if (config->entry_count == 0)
                return;

        /*
         * Match the pattern from the end of the list to the start, find last
         * entry (largest number) matching the given pattern.
         */
        if (config->entry_default_pattern) {
                i = config->entry_count;
                while (i--) {
                        if (MetaiMatch(config->entries[i]->id, config->entry_default_pattern)) {
                                config->idx_default = i;
                                return;
                        }
                }
        }

        /* select the last suitable entry */
        i = config->entry_count;
        while (i--) {
                if (config->entries[i]->no_autoselect)
                        continue;
                config->idx_default = i;
                return;
        }

        /* no entry found */
        config->idx_default = -1;
}

static BOOLEAN find_nonunique(ConfigEntry **entries, UINTN entry_count) {
        BOOLEAN non_unique = FALSE;

        assert(entries);

        for (UINTN i = 0; i < entry_count; i++)
                entries[i]->non_unique = FALSE;

        for (UINTN i = 0; i < entry_count; i++)
                for (UINTN k = 0; k < entry_count; k++) {
                        if (i == k)
                                continue;
                        if (StrCmp(entries[i]->title_show, entries[k]->title_show) != 0)
                                continue;

                        non_unique = entries[i]->non_unique = entries[k]->non_unique = TRUE;
                }

        return non_unique;
}

/* generate a unique title, avoiding non-distinguishable menu entries */
static VOID config_title_generate(Config *config) {
        assert(config);

        /* set title */
        for (UINTN i = 0; i < config->entry_count; i++) {
                CHAR16 *title;

                FreePool(config->entries[i]->title_show);
                title = config->entries[i]->title;
                if (!title)
                        title = config->entries[i]->id;
                config->entries[i]->title_show = StrDuplicate(title);
        }

        if (!find_nonunique(config->entries, config->entry_count))
                return;

        /* add version to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                CHAR16 *s;

                if (!config->entries[i]->non_unique)
                        continue;
                if (!config->entries[i]->version)
                        continue;

                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, config->entries[i]->version);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
        }

        if (!find_nonunique(config->entries, config->entry_count))
                return;

        /* add machine-id to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                CHAR16 *s;
                _cleanup_freepool_ CHAR16 *m = NULL;

                if (!config->entries[i]->non_unique)
                        continue;
                if (!config->entries[i]->machine_id)
                        continue;

                m = StrDuplicate(config->entries[i]->machine_id);
                m[8] = '\0';
                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, m);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
        }

        if (!find_nonunique(config->entries, config->entry_count))
                return;

        /* add file name to non-unique titles */
        for (UINTN i = 0; i < config->entry_count; i++) {
                CHAR16 *s;

                if (!config->entries[i]->non_unique)
                        continue;
                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, config->entries[i]->id);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
                config->entries[i]->non_unique = FALSE;
        }
}

static BOOLEAN config_entry_add_call(
                Config *config,
                const CHAR16 *id,
                const CHAR16 *title,
                EFI_STATUS (*call)(VOID)) {

        ConfigEntry *entry;

        assert(config);
        assert(id);
        assert(title);

        entry = AllocatePool(sizeof(ConfigEntry));
        *entry = (ConfigEntry) {
                .id = StrDuplicate(id),
                .title = StrDuplicate(title),
                .call = call,
                .no_autoselect = TRUE,
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
                const CHAR16 *version) {

        ConfigEntry *entry;

        assert(config);
        assert(id);
        assert(title);
        assert(loader);

        entry = AllocatePool(sizeof(ConfigEntry));
        *entry = (ConfigEntry) {
                .type = type,
                .title = StrDuplicate(title),
                .version = version ? StrDuplicate(version) : NULL,
                .device = device,
                .loader = StrDuplicate(loader),
                .id = StrDuplicate(id),
                .key = key,
                .tries_done = UINTN_MAX,
                .tries_left = UINTN_MAX,
        };

        StrLwr(entry->id);

        config_add_entry(config, entry);
        return entry;
}

static BOOLEAN is_sd_boot(EFI_FILE *root_dir, const CHAR16 *loader, const CHAR16 *loaded_image_path) {
        EFI_STATUS err;
        UINTN read_size = 100 * 1024;
        _cleanup_freepool_ CHAR8 *loader_content = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *loader_info = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *loaded_image_info = NULL;
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE loader_handle = NULL;
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE loaded_image_handle = NULL;

        assert(root_dir);
        assert(loader);
        assert(loaded_image_path);

        if (StriCmp(loader, loaded_image_path) == 0)
                return TRUE;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &loader_handle, (CHAR16*) loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return FALSE;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &loaded_image_handle, (CHAR16*) loaded_image_path, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return FALSE;

        loader_info = LibFileInfo(loader_handle);
        if (!loader_info)
                return FALSE;

        loaded_image_info = LibFileInfo(loaded_image_handle);
        if (!loaded_image_info)
                return FALSE;

        if (loader_info->FileSize != loaded_image_info->FileSize)
                return FALSE;

        loader_content = AllocatePool(read_size);
        if (!loader_content)
                return FALSE;

        err = uefi_call_wrapper(root_dir->Read, 3, loader_handle, &read_size, loader_content);
        if (EFI_ERROR(err) || read_size < sizeof(magic))
                return FALSE;

        return !!FindMem(loader_content, read_size, magic, sizeof(magic));
}

static BOOLEAN config_entry_add_loader_auto(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const CHAR16 *loaded_image_path,
                const CHAR16 *id,
                CHAR16 key,
                const CHAR16 *title,
                const CHAR16 *loader) {

        EFI_FILE_HANDLE handle;
        ConfigEntry *entry;
        EFI_STATUS err;

        assert(config);
        assert(root_dir);

        if (!config->auto_entries)
                return FALSE;

        /* do not add an entry for ourselves */
        if (loaded_image_path) {
                assert(StriCmp(L"\\EFI\\BOOT\\BOOT" EFI_MACHINE_TYPE_NAME L".EFI", loader) == 0);
                if (is_sd_boot(root_dir, loader, loaded_image_path))
                        return FALSE;
                /* If the default loader is not us, it might be shim.
                 * It would chainload GRUBX64.EFI in that case, which might be us.*/
                if (is_sd_boot(root_dir, L"\\EFI\\BOOT\\GRUB" EFI_MACHINE_TYPE_NAME L".EFI", loaded_image_path))
                        return FALSE;
        }

        /* check existence */
        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, (CHAR16*) loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return FALSE;
        uefi_call_wrapper(handle->Close, 1, handle);

        entry = config_entry_add_loader(config, device, LOADER_UNDEFINED, id, key, title, loader, NULL);
        if (!entry)
                return FALSE;

        /* do not boot right away into auto-detected entries */
        entry->no_autoselect = TRUE;

        return TRUE;
}

static VOID config_entry_add_osx(Config *config) {
        EFI_STATUS err;
        UINTN handle_count = 0;
        _cleanup_freepool_ EFI_HANDLE *handles = NULL;

        assert(config);

        if (!config->auto_entries)
                return;

        err = LibLocateHandle(ByProtocol, &FileSystemProtocol, NULL, &handle_count, &handles);
        if (!EFI_ERROR(err)) {
                for (UINTN i = 0; i < handle_count; i++) {
                        EFI_FILE *root;
                        BOOLEAN found;

                        root = LibOpenRoot(handles[i]);
                        if (!root)
                                continue;
                        found = config_entry_add_loader_auto(config, handles[i], root, NULL, L"auto-osx", 'a', L"macOS",
                                                             L"\\System\\Library\\CoreServices\\boot.efi");
                        uefi_call_wrapper(root->Close, 1, root);
                        if (found)
                                break;
                }
        }
}


static VOID config_entry_add_windows(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir) {
        EFI_STATUS err;
        UINTN len;
        const CHAR16 *title = NULL;
        _cleanup_freepool_ CHAR8 *bcd = NULL;

        assert(config);
        assert(device);
        assert(root_dir);

        if (!config->auto_entries)
                return;

        /* Try to find a better title. */
        err = file_read(root_dir, L"\\EFI\\Microsoft\\Boot\\BCD", 0, 100*1024, &bcd, &len);
        if (!EFI_ERROR(err)) {
                const struct {
                        const CHAR16 *title;
                        const UINTN version_len;
                } versions[] = {
                        { L"Windows 11",    STRLEN(L"11")+1 },
                        { L"Windows 10",    STRLEN(L"10")+1 },
                        { L"Windows 8.1",   STRLEN(L"8.1")+1 },
                        { L"Windows 8",     STRLEN(L"8")+1 },
                        { L"Windows 7",     STRLEN(L"7")+1 },
                        { L"Windows Vista", STRLEN(L"Vista")+1 },
                };

                CHAR8 *p = bcd;
                while (!title) {
                        CHAR8 *v = FindMem(p, len, versions[0].title, STRLEN(L"Windows "));
                        if (!v)
                                break;

                        v += STRLEN(L"Windows ");
                        len -= v - p;
                        p = v;

                        /* We found the prefix, now try all the version strings. */
                        for (UINTN i = 0; i < ELEMENTSOF(versions); i++) {
                                if (CompareMem(p, versions[i].title + (STRLEN(L"Windows ") / sizeof(CHAR16)), versions[i].version_len) == 0) {
                                        title = versions[i].title;
                                        break;
                                }
                        }
                }
        }

        if (!title)
                title = L"Windows Boot Manager";

        config_entry_add_loader_auto(config, device, root_dir, NULL, L"auto-windows",
                                     'w', title, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
}

static VOID config_entry_add_linux(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir) {

        EFI_FILE_HANDLE linux_dir;
        EFI_STATUS err;
        ConfigEntry *entry;

        assert(config);
        assert(device);
        assert(root_dir);

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &linux_dir, (CHAR16*) L"\\EFI\\Linux", EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return;

        for (;;) {
                CHAR16 buf[256];
                UINTN bufsize = sizeof buf;
                EFI_FILE_INFO *f;
                CHAR8 *sections[] = {
                        (CHAR8 *)".osrel",
                        (CHAR8 *)".cmdline",
                        NULL
                };
                UINTN offs[ELEMENTSOF(sections)-1] = {};
                UINTN szs[ELEMENTSOF(sections)-1] = {};
                UINTN addrs[ELEMENTSOF(sections)-1] = {};
                CHAR8 *content = NULL;
                CHAR8 *line;
                UINTN pos = 0;
                CHAR8 *key, *value;
                CHAR16 *os_name_pretty = NULL;
                CHAR16 *os_name = NULL;
                CHAR16 *os_id = NULL;
                CHAR16 *os_version = NULL;
                CHAR16 *os_version_id = NULL;
                CHAR16 *os_build_id = NULL;

                err = uefi_call_wrapper(linux_dir->Read, 3, linux_dir, &bufsize, buf);
                if (bufsize == 0 || EFI_ERROR(err))
                        break;

                f = (EFI_FILE_INFO *) buf;
                if (f->FileName[0] == '.')
                        continue;
                if (f->Attribute & EFI_FILE_DIRECTORY)
                        continue;
                if (!endswith_no_case(f->FileName, L".efi"))
                        continue;
                if (startswith(f->FileName, L"auto-"))
                        continue;

                /* look for .osrel and .cmdline sections in the .efi binary */
                err = pe_file_locate_sections(linux_dir, f->FileName, sections, addrs, offs, szs);
                if (EFI_ERROR(err))
                        continue;

                err = file_read(linux_dir, f->FileName, offs[0], szs[0], &content, NULL);
                if (EFI_ERROR(err))
                        continue;

                /* read properties from the embedded os-release file */
                while ((line = line_get_key_value(content, (CHAR8 *)"=", &pos, &key, &value))) {
                        if (strcmpa((CHAR8 *)"PRETTY_NAME", key) == 0) {
                                FreePool(os_name_pretty);
                                os_name_pretty = stra_to_str(value);
                                continue;
                        }

                        if (strcmpa((CHAR8 *)"NAME", key) == 0) {
                                FreePool(os_name);
                                os_name = stra_to_str(value);
                                continue;
                        }

                        if (strcmpa((CHAR8 *)"ID", key) == 0) {
                                FreePool(os_id);
                                os_id = stra_to_str(value);
                                continue;
                        }

                        if (strcmpa((CHAR8 *)"VERSION", key) == 0) {
                                FreePool(os_version);
                                os_version = stra_to_str(value);
                                continue;
                        }

                        if (strcmpa((CHAR8 *)"VERSION_ID", key) == 0) {
                                FreePool(os_version_id);
                                os_version_id = stra_to_str(value);
                                continue;
                        }

                        if (strcmpa((CHAR8 *)"BUILD_ID", key) == 0) {
                                FreePool(os_build_id);
                                os_build_id = stra_to_str(value);
                                continue;
                        }
                }

                if ((os_name_pretty || os_name) && os_id && (os_version || os_version_id || os_build_id)) {
                        _cleanup_freepool_ CHAR16 *path = NULL;

                        path = PoolPrint(L"\\EFI\\Linux\\%s", f->FileName);

                        entry = config_entry_add_loader(config, device, LOADER_LINUX, f->FileName, 'l',
                                                        os_name_pretty ?: os_name, path,
                                                        os_version ?: (os_version_id ? : os_build_id));

                        FreePool(content);
                        content = NULL;

                        /* read the embedded cmdline file */
                        err = file_read(linux_dir, f->FileName, offs[1], szs[1], &content, NULL);
                        if (!EFI_ERROR(err)) {

                                /* chomp the newline */
                                if (content[szs[1]-1] == '\n')
                                        content[szs[1]-1] = '\0';

                                entry->options = stra_to_str(content);
                        }

                        config_entry_parse_tries(entry, L"\\EFI\\Linux", f->FileName, L".efi");
                }

                FreePool(os_name_pretty);
                FreePool(os_name);
                FreePool(os_id);
                FreePool(os_version);
                FreePool(os_version_id);
                FreePool(os_build_id);
                FreePool(content);
        }

        uefi_call_wrapper(linux_dir->Close, 1, linux_dir);
}

#define XBOOTLDR_GUID \
        &(const EFI_GUID) { 0xbc13c2ff, 0x59e6, 0x4262, { 0xa3, 0x52, 0xb2, 0x75, 0xfd, 0x6f, 0x71, 0x72 } }

static EFI_DEVICE_PATH *path_parent(EFI_DEVICE_PATH *path, EFI_DEVICE_PATH *node) {
        EFI_DEVICE_PATH *parent;
        UINTN len;

        assert(path);
        assert(node);

        len = (UINT8*) NextDevicePathNode(node) - (UINT8*) path;
        parent = (EFI_DEVICE_PATH*) AllocatePool(len + sizeof(EFI_DEVICE_PATH));
        CopyMem(parent, path, len);
        CopyMem((UINT8*) parent + len, EndDevicePath, sizeof(EFI_DEVICE_PATH));

        return parent;
}

static VOID config_load_xbootldr(
                Config *config,
                EFI_HANDLE *device) {

        EFI_DEVICE_PATH *partition_path, *disk_path, *copy;
        UINT32 found_partition_number = UINT32_MAX;
        UINT64 found_partition_start = UINT64_MAX;
        UINT64 found_partition_size = UINT64_MAX;
        UINT8 found_partition_signature[16] = {};
        EFI_HANDLE new_device;
        EFI_FILE *root_dir;
        EFI_STATUS r;

        assert(config);
        assert(device);

        partition_path = DevicePathFromHandle(device);
        if (!partition_path)
                return;

        for (EFI_DEVICE_PATH *node = partition_path; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                EFI_HANDLE disk_handle;
                EFI_BLOCK_IO *block_io;
                EFI_DEVICE_PATH *p;

                /* First, Let's look for the SCSI/SATA/USB/… device path node, i.e. one above the media
                 * devices */
                if (DevicePathType(node) != MESSAGING_DEVICE_PATH)
                        continue;

                /* Determine the device path one level up */
                disk_path = path_parent(partition_path, node);
                p = disk_path;
                r = uefi_call_wrapper(BS->LocateDevicePath, 3, &BlockIoProtocol, &p, &disk_handle);
                if (EFI_ERROR(r))
                        continue;

                r = uefi_call_wrapper(BS->HandleProtocol, 3, disk_handle, &BlockIoProtocol, (VOID **)&block_io);
                if (EFI_ERROR(r))
                        continue;

                /* Filter out some block devices early. (We only care about block devices that aren't
                 * partitions themselves — we look for GPT partition tables to parse after all —, and only
                 * those which contain a medium and have at least 2 blocks.) */
                if (block_io->Media->LogicalPartition ||
                    !block_io->Media->MediaPresent ||
                    block_io->Media->LastBlock <= 1)
                        continue;

                /* Try both copies of the GPT header, in case one is corrupted */
                for (UINTN nr = 0; nr < 2; nr++) {
                        _cleanup_freepool_ EFI_PARTITION_ENTRY* entries = NULL;
                        union {
                                EFI_PARTITION_TABLE_HEADER gpt_header;
                                uint8_t space[((sizeof(EFI_PARTITION_TABLE_HEADER) + 511) / 512) * 512];
                        } gpt_header_buffer;
                        const EFI_PARTITION_TABLE_HEADER *h = &gpt_header_buffer.gpt_header;
                        UINT64 where;
                        UINTN sz;
                        UINT32 c;

                        if (nr == 0)
                                /* Read the first copy at LBA 1 */
                                where = 1;
                        else
                                /* Read the second copy at the very last LBA of this block device */
                                where = block_io->Media->LastBlock;

                        /* Read the GPT header */
                        r = uefi_call_wrapper(block_io->ReadBlocks, 5,
                                              block_io,
                                              block_io->Media->MediaId,
                                              where,
                                              sizeof(gpt_header_buffer), &gpt_header_buffer);
                        if (EFI_ERROR(r))
                                continue;

                        /* Some superficial validation of the GPT header */
                        c = CompareMem(&h->Header.Signature, "EFI PART", sizeof(h->Header.Signature));
                        if (c != 0)
                                continue;

                        if (h->Header.HeaderSize < 92 ||
                            h->Header.HeaderSize > 512)
                                continue;

                        if (h->Header.Revision != 0x00010000U)
                                continue;

                        /* Calculate CRC check */
                        c = ~crc32_exclude_offset(UINT32_MAX,
                                                  (const UINT8*) &gpt_header_buffer,
                                                  h->Header.HeaderSize,
                                                  OFFSETOF(EFI_PARTITION_TABLE_HEADER, Header.CRC32),
                                                  sizeof(h->Header.CRC32));
                        if (c != h->Header.CRC32)
                                continue;

                        if (h->MyLBA != where)
                                continue;

                        if (h->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))
                                continue;

                        if (h->NumberOfPartitionEntries <= 0 ||
                            h->NumberOfPartitionEntries > 1024)
                                continue;

                        if (h->SizeOfPartitionEntry > UINTN_MAX / h->NumberOfPartitionEntries) /* overflow check */
                                continue;

                        /* Now load the GPT entry table */
                        sz = ALIGN_TO((UINTN) h->SizeOfPartitionEntry * (UINTN) h->NumberOfPartitionEntries, 512);
                        entries = AllocatePool(sz);

                        r = uefi_call_wrapper(block_io->ReadBlocks, 5,
                                              block_io,
                                              block_io->Media->MediaId,
                                              h->PartitionEntryLBA,
                                              sz, entries);
                        if (EFI_ERROR(r))
                                continue;

                        /* Calculate CRC of entries array, too */
                        c = ~crc32(UINT32_MAX, entries, sz);
                        if (c != h->PartitionEntryArrayCRC32)
                                continue;

                        for (UINTN i = 0; i < h->NumberOfPartitionEntries; i++) {
                                EFI_PARTITION_ENTRY *entry;

                                entry = (EFI_PARTITION_ENTRY*) ((UINT8*) entries + h->SizeOfPartitionEntry * i);

                                if (CompareMem(&entry->PartitionTypeGUID, XBOOTLDR_GUID, 16) == 0) {
                                        UINT64 end;

                                        /* Let's use memcpy(), in case the structs are not aligned (they really should be though) */
                                        CopyMem(&found_partition_start, &entry->StartingLBA, sizeof(found_partition_start));
                                        CopyMem(&end, &entry->EndingLBA, sizeof(end));

                                        if (end < found_partition_start) /* Bogus? */
                                                continue;

                                        found_partition_size = end - found_partition_start + 1;
                                        CopyMem(found_partition_signature, &entry->UniquePartitionGUID, sizeof(found_partition_signature));

                                        found_partition_number = i + 1;
                                        goto found;
                                }
                        }

                        break; /* This GPT was fully valid, but we didn't find what we are looking for. This
                                * means there's no reason to check the second copy of the GPT header */
                }
        }

        return; /* Not found */

found:
        copy = DuplicateDevicePath(partition_path);

        /* Patch in the data we found */
        for (EFI_DEVICE_PATH *node = copy; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
                HARDDRIVE_DEVICE_PATH *hd;

                if (DevicePathType(node) != MEDIA_DEVICE_PATH)
                        continue;

                if (DevicePathSubType(node) != MEDIA_HARDDRIVE_DP)
                        continue;

                hd = (HARDDRIVE_DEVICE_PATH*) node;
                hd->PartitionNumber = found_partition_number;
                hd->PartitionStart = found_partition_start;
                hd->PartitionSize = found_partition_size;
                CopyMem(hd->Signature, found_partition_signature, sizeof(hd->Signature));
                hd->MBRType = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
                hd->SignatureType = SIGNATURE_TYPE_GUID;
        }

        r = uefi_call_wrapper(BS->LocateDevicePath, 3, &BlockIoProtocol, &copy, &new_device);
        if (EFI_ERROR(r))
                return;

        root_dir = LibOpenRoot(new_device);
        if (!root_dir)
                return;

        config_entry_add_linux(config, new_device, root_dir);
        config_load_entries(config, new_device, root_dir, NULL);
}

static EFI_STATUS image_start(
                EFI_HANDLE parent_image,
                const Config *config,
                const ConfigEntry *entry) {

        EFI_HANDLE image;
        _cleanup_freepool_ EFI_DEVICE_PATH *path = NULL;
        CHAR16 *options;
        EFI_STATUS err;

        assert(config);
        assert(entry);

        path = FileDevicePath(entry->device, entry->loader);
        if (!path) {
                PrintErrorStall(L"Error getting device path.");
                return EFI_INVALID_PARAMETER;
        }

        err = uefi_call_wrapper(BS->LoadImage, 6, FALSE, parent_image, path, NULL, 0, &image);
        if (EFI_ERROR(err)) {
                PrintErrorStall(L"Error loading %s: %r", entry->loader, err);
                return err;
        }

        if (config->options_edit)
                options = config->options_edit;
        else if (entry->options)
                options = entry->options;
        else
                options = NULL;
        if (options) {
                EFI_LOADED_IMAGE *loaded_image;

                err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                        parent_image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
                if (EFI_ERROR(err)) {
                        PrintErrorStall(L"Error getting LoadedImageProtocol handle: %r", err);
                        goto out_unload;
                }
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = (StrLen(loaded_image->LoadOptions)+1) * sizeof(CHAR16);

#if ENABLE_TPM
                /* Try to log any options to the TPM, especially to catch manually edited options */
                err = tpm_log_event(SD_TPM_PCR,
                                    (EFI_PHYSICAL_ADDRESS) (UINTN) loaded_image->LoadOptions,
                                    loaded_image->LoadOptionsSize, loaded_image->LoadOptions);
                if (EFI_ERROR(err))
                        PrintErrorStall(L"Unable to add image options measurement: %r", err);
#endif
        }

        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeExecUSec", 0);
        err = uefi_call_wrapper(BS->StartImage, 3, image, NULL, NULL);
out_unload:
        uefi_call_wrapper(BS->UnloadImage, 1, image);
        return err;
}

static EFI_STATUS reboot_into_firmware(VOID) {
        UINT64 old, new;
        EFI_STATUS err;

        new = EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        err = efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", &old);
        if (!EFI_ERROR(err))
                new |= old;

        err = efivar_set_uint64_le(EFI_GLOBAL_GUID, L"OsIndications", new, EFI_VARIABLE_NON_VOLATILE);
        if (EFI_ERROR(err))
                return err;

        err = uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS, 0, NULL);
        PrintErrorStall(L"Error calling ResetSystem: %r", err);
        return err;
}

static VOID config_free(Config *config) {
        assert(config);
        for (UINTN i = 0; i < config->entry_count; i++)
                config_entry_free(config->entries[i]);
        FreePool(config->entries);
        FreePool(config->entry_default_pattern);
        FreePool(config->options_edit);
        FreePool(config->entry_oneshot);
}

static VOID config_write_entries_to_variable(Config *config) {
        _cleanup_freepool_ CHAR16 *buffer = NULL;
        UINTN sz = 0;
        CHAR16 *p;

        assert(config);

        for (UINTN i = 0; i < config->entry_count; i++)
                sz += StrLen(config->entries[i]->id) + 1;

        p = buffer = AllocatePool(sz * sizeof(CHAR16));

        for (UINTN i = 0; i < config->entry_count; i++) {
                UINTN l;

                l = StrLen(config->entries[i]->id) + 1;
                CopyMem(p, config->entries[i]->id, l * sizeof(CHAR16));

                p += l;
        }

        /* Store the full list of discovered entries. */
        (void) efivar_set_raw(LOADER_GUID, L"LoaderEntries", buffer, (UINT8 *) p - (UINT8 *) buffer, 0);
}

static VOID save_default(EFI_FILE *root_dir, Config *config, const CHAR16 *entry) {
        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE handle = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *info = NULL;
        EFI_STATUS err;
        UINTN size;

        assert(root_dir);
        assert(config);
        assert(entry);

        if (!config->save_default || StriCmp(config->entry_default_pattern, entry) == 0)
                return;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, (CHAR16*)LAST_BOOTED_FILE, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (EFI_ERROR(err)) {
                PrintErrorStall(L"Failed to open " LAST_BOOTED_FILE ": %r", err);
                return;
        }

        info = LibFileInfo(handle);
        if (!info) {
                log_oom();
                return;
        }

        size = StrSize(entry);
        if (info->FileSize < size) {
                PrintErrorStall(L"Cannot write to " LAST_BOOTED_FILE ": File is too short.");
                return;
        }

        err = uefi_call_wrapper(handle->Write, 3, handle, &size, (CHAR16*)entry);
        if (EFI_ERROR(err)) {
                PrintErrorStall(L"Failed to write to " LAST_BOOTED_FILE ": %r", err);
                return;
        }

        err = uefi_call_wrapper(handle->Flush, 1, handle);
        if (EFI_ERROR(err)) {
                PrintErrorStall(L"Failed to flush " LAST_BOOTED_FILE ": %r", err);
                return;
        }
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        static const UINT64 loader_features =
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT |
                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                EFI_LOADER_FEATURE_ENTRY_ONESHOT |
                EFI_LOADER_FEATURE_BOOT_COUNTING |
                EFI_LOADER_FEATURE_XBOOTLDR |
                EFI_LOADER_FEATURE_RANDOM_SEED |
                0;

        _cleanup_freepool_ CHAR16 *infostr = NULL, *typestr = NULL;
        UINT64 osind = 0;
        EFI_LOADED_IMAGE *loaded_image;
        EFI_FILE *root_dir;
        CHAR16 *loaded_image_path;
        EFI_STATUS err;
        Config config;
        UINT64 init_usec;
        BOOLEAN menu = FALSE;
        CHAR16 uuid[37];

        assert(sys_table);

        InitializeLib(image, sys_table);
        init_usec = time_usec();
        efivar_set_time_usec(LOADER_GUID, L"LoaderTimeInitUSec", init_usec);
        efivar_set(LOADER_GUID, L"LoaderInfo", L"systemd-boot " GIT_VERSION, 0);

        infostr = PoolPrint(L"%s %d.%02d", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        efivar_set(LOADER_GUID, L"LoaderFirmwareInfo", infostr, 0);

        typestr = PoolPrint(L"UEFI %d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        efivar_set(LOADER_GUID, L"LoaderFirmwareType", typestr, 0);

        (void) efivar_set_uint64_le(LOADER_GUID, L"LoaderFeatures", loader_features, 0);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
                PrintErrorStall(L"Error getting a LoadedImageProtocol handle: %r", err);
                return err;
        }

        /* export the device path this image is started from */
        if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                efivar_set(LOADER_GUID, L"LoaderDevicePartUUID", uuid, 0);

        root_dir = LibOpenRoot(loaded_image->DeviceHandle);
        if (!root_dir) {
                PrintErrorStall(L"Unable to open root directory.");
                return EFI_LOAD_ERROR;
        }

        if (secure_boot_enabled() && shim_loaded()) {
                err = security_policy_install();
                if (EFI_ERROR(err)) {
                        PrintErrorStall(L"Error installing security policy: %r", err);
                        return err;
                }
        }

        /* the filesystem path to this image, to prevent adding ourselves to the menu */
        loaded_image_path = DevicePathToStr(loaded_image->FilePath);
        efivar_set(LOADER_GUID, L"LoaderImageIdentifier", loaded_image_path, 0);

        config_load_defaults(&config, root_dir);

        /* scan /EFI/Linux/ directory */
        config_entry_add_linux(&config, loaded_image->DeviceHandle, root_dir);

        /* scan /loader/entries/\*.conf files */
        config_load_entries(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path);

        /* Similar, but on any XBOOTLDR partition */
        config_load_xbootldr(&config, loaded_image->DeviceHandle);

        /* sort entries after version number */
        config_sort_entries(&config);

        /* if we find some well-known loaders, add them to the end of the list */
        config_entry_add_osx(&config);
        config_entry_add_windows(&config, loaded_image->DeviceHandle, root_dir);
        config_entry_add_loader_auto(&config, loaded_image->DeviceHandle, root_dir, NULL,
                                     L"auto-efi-shell", 's', L"EFI Shell", L"\\shell" EFI_MACHINE_TYPE_NAME ".efi");
        config_entry_add_loader_auto(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     L"auto-efi-default", '\0', L"EFI Default Loader", L"\\EFI\\BOOT\\BOOT" EFI_MACHINE_TYPE_NAME ".EFI");

        if (config.auto_firmware && efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndicationsSupported", &osind) == EFI_SUCCESS) {
                if (osind & EFI_OS_INDICATIONS_BOOT_TO_FW_UI)
                        config_entry_add_call(&config,
                                              L"auto-reboot-to-firmware-setup",
                                              L"Reboot Into Firmware Interface",
                                              reboot_into_firmware);
        }

        if (config.entry_count == 0) {
                PrintErrorStall(L"No loader found. Configuration files in \\loader\\entries\\*.conf are needed.");
                goto out;
        }

        config_write_entries_to_variable(&config);

        config_title_generate(&config);

        /* select entry by configured pattern or EFI LoaderDefaultEntry= variable */
        config_default_entry_select(&config);

        /* if no configured entry to select from was found, enable the menu */
        if (config.idx_default == -1) {
                config.idx_default = 0;
                if (config.timeout_sec == 0)
                        config.timeout_sec = 10;
        }

        /* select entry or show menu when key is pressed or timeout is set */
        if (config.force_menu || config.timeout_sec != 0)
                menu = TRUE;
        else {
                UINT64 key;

                err = console_key_read(&key, 100 * 1000);
                if (!EFI_ERROR(err)) {
                        INT16 idx;

                        /* find matching key in config entries */
                        idx = entry_lookup_key(&config, config.idx_default, KEYCHAR(key));
                        if (idx >= 0)
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
                        uefi_call_wrapper(BS->SetWatchdogTimer, 4, 0, 0x10000, 0, NULL);
                        if (!menu_run(&config, &entry, loaded_image_path))
                                break;
                }

                /* run special entry like "reboot" */
                if (entry->call) {
                        entry->call();
                        continue;
                }

                config_entry_bump_counters(entry, root_dir);

                /* Export the selected boot entry to the system */
                (VOID) efivar_set(LOADER_GUID, L"LoaderEntrySelected", entry->id, 0);

                /* Optionally, read a random seed off the ESP and pass it to the OS */
                (VOID) process_random_seed(root_dir, config.random_seed_mode);

                save_default(root_dir, &config, entry->id);

                uefi_call_wrapper(BS->SetWatchdogTimer, 4, 5 * 60, 0x10000, 0, NULL);
                err = image_start(image, &config, entry);
                if (EFI_ERROR(err)) {
                        graphics_mode(FALSE);
                        PrintErrorStall(L"Failed to execute %s (%s): %r", entry->title, entry->loader, err);
                        goto out;
                }

                menu = TRUE;
                config.timeout_sec = 0;
        }
        err = EFI_SUCCESS;
out:
        FreePool(loaded_image_path);
        config_free(&config);
        uefi_call_wrapper(root_dir->Close, 1, root_dir);
        uefi_call_wrapper(BS->CloseProtocol, 4, image, &LoadedImageProtocol, image, NULL);
        return err;
}
