/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2012-2015 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2012-2015 Harald Hoyer <harald@redhat.com>
 */

#include <efi.h>
#include <efilib.h>

#include "util.h"
#include "console.h"
#include "graphics.h"
#include "pefile.h"
#include "disk.h"
#include "linux.h"

#ifndef EFI_OS_INDICATIONS_BOOT_TO_FW_UI
#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI 0x0000000000000001ULL
#endif

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-boot " VERSION " ####";

static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

enum loader_type {
        LOADER_UNDEFINED,
        LOADER_EFI,
        LOADER_LINUX
};

typedef struct {
        CHAR16 *file;
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
} ConfigEntry;

typedef struct {
        ConfigEntry **entries;
        UINTN entry_count;
        INTN idx_default;
        INTN idx_default_efivar;
        UINTN timeout_sec;
        UINTN timeout_sec_config;
        INTN timeout_sec_efivar;
        CHAR16 *entry_default_pattern;
        CHAR16 *entry_oneshot;
        CHAR16 *options_edit;
        BOOLEAN no_editor;
} Config;

static VOID cursor_left(UINTN *cursor, UINTN *first) {
        if ((*cursor) > 0)
                (*cursor)--;
        else if ((*first) > 0)
                (*first)--;
}

static VOID cursor_right(UINTN *cursor, UINTN *first, UINTN x_max, UINTN len) {
        if ((*cursor)+1 < x_max)
                (*cursor)++;
        else if ((*first) + (*cursor) < len)
                (*first)++;
}

static BOOLEAN line_edit(CHAR16 *line_in, CHAR16 **line_out, UINTN x_max, UINTN y_pos) {
        CHAR16 *line;
        UINTN size;
        UINTN len;
        UINTN first;
        CHAR16 *print;
        UINTN cursor;
        UINTN clear;
        BOOLEAN exit;
        BOOLEAN enter;

        if (!line_in)
                line_in = L"";
        size = StrLen(line_in) + 1024;
        line = AllocatePool(size * sizeof(CHAR16));
        StrCpy(line, line_in);
        len = StrLen(line);
        print = AllocatePool((x_max+1) * sizeof(CHAR16));

        uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, TRUE);

        first = 0;
        cursor = 0;
        clear = 0;
        enter = FALSE;
        exit = FALSE;
        while (!exit) {
                EFI_STATUS err;
                UINT64 key;
                UINTN i;

                i = len - first;
                if (i >= x_max-1)
                        i = x_max-1;
                CopyMem(print, line + first, i * sizeof(CHAR16));
                while (clear > 0 && i < x_max-1) {
                        clear--;
                        print[i++] = ' ';
                }
                print[i] = '\0';

                uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_pos);
                uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, print);
                uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);

                err = console_key_read(&key, TRUE);
                if (EFI_ERROR(err))
                        continue;

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
                        while (line[first + cursor] && line[first + cursor] == ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        while (line[first + cursor] && line[first + cursor] != ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);
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
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);
                        continue;

                case KEYPRESS(0, SCAN_RIGHT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'f'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('f')):
                        /* forward-char */
                        if (first + cursor == len)
                                continue;
                        cursor_right(&cursor, &first, x_max, len);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);
                        continue;

                case KEYPRESS(0, SCAN_LEFT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'b'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('b')):
                        /* backward-char */
                        cursor_left(&cursor, &first);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);
                        continue;

                case KEYPRESS(EFI_ALT_PRESSED, 0, 'd'):
                        /* kill-word */
                        clear = 0;
                        for (i = first + cursor; i < len && line[i] == ' '; i++)
                                clear++;
                        for (; i < len && line[i] != ' '; i++)
                                clear++;

                        for (i = first + cursor; i + clear < len; i++)
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
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, cursor, y_pos);

                        for (i = first + cursor; i + clear < len; i++)
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
                        for (i = first + cursor; i < len; i++)
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
                        if (StrCmp(line, line_in) != 0) {
                                *line_out = line;
                                line = NULL;
                        }
                        enter = TRUE;
                        exit = TRUE;
                        break;

                case KEYPRESS(0, 0, CHAR_BACKSPACE):
                        if (len == 0)
                                continue;
                        if (first == 0 && cursor == 0)
                                continue;
                        for (i = first + cursor-1; i < len; i++)
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
                        for (i = len; i > first + cursor; i--)
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

        uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);
        FreePool(print);
        FreePool(line);
        return enter;
}

static UINTN entry_lookup_key(Config *config, UINTN start, CHAR16 key) {
        UINTN i;

        if (key == 0)
                return -1;

        /* select entry by number key */
        if (key >= '1' && key <= '9') {
                i = key - '0';
                if (i > config->entry_count)
                        i = config->entry_count;
                return i-1;
        }

        /* find matching key in config entries */
        for (i = start; i < config->entry_count; i++)
                if (config->entries[i]->key == key)
                        return i;

        for (i = 0; i < start; i++)
                if (config->entries[i]->key == key)
                        return i;

        return -1;
}

static VOID print_status(Config *config, CHAR16 *loaded_image_path) {
        UINT64 key;
        UINTN i;
        CHAR16 *s;
        CHAR8 *b;
        UINTN x;
        UINTN y;
        UINTN size;

        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);

        Print(L"systemd-boot version:   " VERSION "\n");
        Print(L"architecture:           " EFI_MACHINE_TYPE_NAME "\n");
        Print(L"loaded image:           %s\n", loaded_image_path);
        Print(L"UEFI specification:     %d.%02d\n", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        Print(L"firmware vendor:        %s\n", ST->FirmwareVendor);
        Print(L"firmware version:       %d.%02d\n", ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);

        if (uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, ST->ConOut->Mode->Mode, &x, &y) == EFI_SUCCESS)
                Print(L"console size:           %d x %d\n", x, y);

        if (efivar_get_raw(&global_guid, L"SecureBoot", &b, &size) == EFI_SUCCESS) {
                Print(L"SecureBoot:             %s\n", yes_no(*b > 0));
                FreePool(b);
        }

        if (efivar_get_raw(&global_guid, L"SetupMode", &b, &size) == EFI_SUCCESS) {
                Print(L"SetupMode:              %s\n", *b > 0 ? L"setup" : L"user");
                FreePool(b);
        }

        if (efivar_get_raw(&global_guid, L"OsIndicationsSupported", &b, &size) == EFI_SUCCESS) {
                Print(L"OsIndicationsSupported: %d\n", (UINT64)*b);
                FreePool(b);
        }
        Print(L"\n");

        Print(L"timeout:                %d\n", config->timeout_sec);
        if (config->timeout_sec_efivar >= 0)
                Print(L"timeout (EFI var):      %d\n", config->timeout_sec_efivar);
        Print(L"timeout (config):       %d\n", config->timeout_sec_config);
        if (config->entry_default_pattern)
                Print(L"default pattern:        '%s'\n", config->entry_default_pattern);
        Print(L"editor:                 %s\n", yes_no(!config->no_editor));
        Print(L"\n");

        Print(L"config entry count:     %d\n", config->entry_count);
        Print(L"entry selected idx:     %d\n", config->idx_default);
        if (config->idx_default_efivar >= 0)
                Print(L"entry EFI var idx:      %d\n", config->idx_default_efivar);
        Print(L"\n");

        if (efivar_get_int(L"LoaderConfigTimeout", &i) == EFI_SUCCESS)
                Print(L"LoaderConfigTimeout:    %d\n", i);
        if (config->entry_oneshot)
                Print(L"LoaderEntryOneShot:     %s\n", config->entry_oneshot);
        if (efivar_get(L"LoaderDevicePartUUID", &s) == EFI_SUCCESS) {
                Print(L"LoaderDevicePartUUID:   %s\n", s);
                FreePool(s);
        }
        if (efivar_get(L"LoaderEntryDefault", &s) == EFI_SUCCESS) {
                Print(L"LoaderEntryDefault:     %s\n", s);
                FreePool(s);
        }

        Print(L"\n--- press key ---\n\n");
        console_key_read(&key, TRUE);

        for (i = 0; i < config->entry_count; i++) {
                ConfigEntry *entry;

                if (key == KEYPRESS(0, SCAN_ESC, 0) || key == KEYPRESS(0, 0, 'q'))
                        break;

                entry = config->entries[i];
                Print(L"config entry:           %d/%d\n", i+1, config->entry_count);
                if (entry->file)
                        Print(L"file                    '%s'\n", entry->file);
                Print(L"title show              '%s'\n", entry->title_show);
                if (entry->title)
                        Print(L"title                   '%s'\n", entry->title);
                if (entry->version)
                        Print(L"version                 '%s'\n", entry->version);
                if (entry->machine_id)
                        Print(L"machine-id              '%s'\n", entry->machine_id);
                if (entry->device) {
                        EFI_DEVICE_PATH *device_path;
                        CHAR16 *str;

                        device_path = DevicePathFromHandle(entry->device);
                        if (device_path) {
                                str = DevicePathToStr(device_path);
                                Print(L"device handle           '%s'\n", str);
                                FreePool(str);
                        }
                }
                if (entry->loader)
                        Print(L"loader                  '%s'\n", entry->loader);
                if (entry->options)
                        Print(L"options                 '%s'\n", entry->options);
                Print(L"auto-select             %s\n", yes_no(!entry->no_autoselect));
                if (entry->call)
                        Print(L"internal call           yes\n");

                Print(L"\n--- press key ---\n\n");
                console_key_read(&key, TRUE);
        }

        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
}

static BOOLEAN menu_run(Config *config, ConfigEntry **chosen_entry, CHAR16 *loaded_image_path) {
        EFI_STATUS err;
        UINTN visible_max;
        UINTN idx_highlight;
        UINTN idx_highlight_prev;
        UINTN idx_first;
        UINTN idx_last;
        BOOLEAN refresh;
        BOOLEAN highlight;
        UINTN i;
        UINTN line_width;
        CHAR16 **lines;
        UINTN x_start;
        UINTN y_start;
        UINTN x_max;
        UINTN y_max;
        CHAR16 *status;
        CHAR16 *clearline;
        INTN timeout_remain;
        INT16 idx;
        BOOLEAN exit = FALSE;
        BOOLEAN run = TRUE;
        BOOLEAN wait = FALSE;

        graphics_mode(FALSE);
        uefi_call_wrapper(ST->ConIn->Reset, 2, ST->ConIn, FALSE);
        uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);
        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);

        /* draw a single character to make ClearScreen work on some firmware */
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L" ");
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);

        err = uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, ST->ConOut->Mode->Mode, &x_max, &y_max);
        if (EFI_ERROR(err)) {
                x_max = 80;
                y_max = 25;
        }

        /* we check 10 times per second for a keystroke */
        if (config->timeout_sec > 0)
                timeout_remain = config->timeout_sec * 10;
        else
                timeout_remain = -1;

        idx_highlight = config->idx_default;
        idx_highlight_prev = 0;

        visible_max = y_max - 2;

        if ((UINTN)config->idx_default >= visible_max)
                idx_first = config->idx_default-1;
        else
                idx_first = 0;

        idx_last = idx_first + visible_max-1;

        refresh = TRUE;
        highlight = FALSE;

        /* length of the longest entry */
        line_width = 5;
        for (i = 0; i < config->entry_count; i++) {
                UINTN entry_len;

                entry_len = StrLen(config->entries[i]->title_show);
                if (line_width < entry_len)
                        line_width = entry_len;
        }
        if (line_width > x_max-6)
                line_width = x_max-6;

        /* offsets to center the entries on the screen */
        x_start = (x_max - (line_width)) / 2;
        if (config->entry_count < visible_max)
                y_start = ((visible_max - config->entry_count) / 2) + 1;
        else
                y_start = 0;

        /* menu entries title lines */
        lines = AllocatePool(sizeof(CHAR16 *) * config->entry_count);
        for (i = 0; i < config->entry_count; i++) {
                UINTN j, k;

                lines[i] = AllocatePool(((x_max+1) * sizeof(CHAR16)));
                for (j = 0; j < x_start; j++)
                        lines[i][j] = ' ';

                for (k = 0; config->entries[i]->title_show[k] != '\0' && j < x_max; j++, k++)
                        lines[i][j] = config->entries[i]->title_show[k];

                for (; j < x_max; j++)
                        lines[i][j] = ' ';
                lines[i][x_max] = '\0';
        }

        status = NULL;
        clearline = AllocatePool((x_max+1) * sizeof(CHAR16));
        for (i = 0; i < x_max; i++)
                clearline[i] = ' ';
        clearline[i] = 0;

        while (!exit) {
                UINT64 key;

                if (refresh) {
                        for (i = 0; i < config->entry_count; i++) {
                                if (i < idx_first || i > idx_last)
                                        continue;
                                uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_start + i - idx_first);
                                if (i == idx_highlight)
                                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
                                                          EFI_BLACK|EFI_BACKGROUND_LIGHTGRAY);
                                else
                                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut,
                                                          EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
                                uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, lines[i]);
                                if ((INTN)i == config->idx_default_efivar) {
                                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, x_start-3, y_start + i - idx_first);
                                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"=>");
                                }
                        }
                        refresh = FALSE;
                } else if (highlight) {
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_start + idx_highlight_prev - idx_first);
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, lines[idx_highlight_prev]);
                        if ((INTN)idx_highlight_prev == config->idx_default_efivar) {
                                uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, x_start-3, y_start + idx_highlight_prev - idx_first);
                                uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"=>");
                        }

                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_start + idx_highlight - idx_first);
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_BLACK|EFI_BACKGROUND_LIGHTGRAY);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, lines[idx_highlight]);
                        if ((INTN)idx_highlight == config->idx_default_efivar) {
                                uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, x_start-3, y_start + idx_highlight - idx_first);
                                uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"=>");
                        }
                        highlight = FALSE;
                }

                if (timeout_remain > 0) {
                        FreePool(status);
                        status = PoolPrint(L"Boot in %d sec.", (timeout_remain + 5) / 10);
                }

                /* print status at last line of screen */
                if (status) {
                        UINTN len;
                        UINTN x;

                        /* center line */
                        len = StrLen(status);
                        if (len < x_max)
                                x = (x_max - len) / 2;
                        else
                                x = 0;
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_max-1);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline + (x_max - x));
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, status);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline+1 + x + len);
                }

                err = console_key_read(&key, wait);
                if (EFI_ERROR(err)) {
                        /* timeout reached */
                        if (timeout_remain == 0) {
                                exit = TRUE;
                                break;
                        }

                        /* sleep and update status */
                        if (timeout_remain > 0) {
                                uefi_call_wrapper(BS->Stall, 1, 100 * 1000);
                                timeout_remain--;
                                continue;
                        }

                        /* timeout disabled, wait for next key */
                        wait = TRUE;
                        continue;
                }

                timeout_remain = -1;

                /* clear status after keystroke */
                if (status) {
                        FreePool(status);
                        status = NULL;
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_max-1);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline+1);
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
                        exit = TRUE;
                        break;

                case KEYPRESS(0, SCAN_F1, 0):
                case KEYPRESS(0, 0, 'h'):
                case KEYPRESS(0, 0, '?'):
                        status = StrDuplicate(L"(d)efault, (t/T)timeout, (e)dit, (v)ersion (Q)uit (P)rint (h)elp");
                        break;

                case KEYPRESS(0, 0, 'Q'):
                        exit = TRUE;
                        run = FALSE;
                        break;

                case KEYPRESS(0, 0, 'd'):
                        if (config->idx_default_efivar != (INTN)idx_highlight) {
                                /* store the selected entry in a persistent EFI variable */
                                efivar_set(L"LoaderEntryDefault", config->entries[idx_highlight]->file, TRUE);
                                config->idx_default_efivar = idx_highlight;
                                status = StrDuplicate(L"Default boot entry selected.");
                        } else {
                                /* clear the default entry EFI variable */
                                efivar_set(L"LoaderEntryDefault", NULL, TRUE);
                                config->idx_default_efivar = -1;
                                status = StrDuplicate(L"Default boot entry cleared.");
                        }
                        refresh = TRUE;
                        break;

                case KEYPRESS(0, 0, '-'):
                case KEYPRESS(0, 0, 'T'):
                        if (config->timeout_sec_efivar > 0) {
                                config->timeout_sec_efivar--;
                                efivar_set_int(L"LoaderConfigTimeout", config->timeout_sec_efivar, TRUE);
                                if (config->timeout_sec_efivar > 0)
                                        status = PoolPrint(L"Menu timeout set to %d sec.", config->timeout_sec_efivar);
                                else
                                        status = StrDuplicate(L"Menu disabled. Hold down key at bootup to show menu.");
                        } else if (config->timeout_sec_efivar <= 0){
                                config->timeout_sec_efivar = -1;
                                efivar_set(L"LoaderConfigTimeout", NULL, TRUE);
                                if (config->timeout_sec_config > 0)
                                        status = PoolPrint(L"Menu timeout of %d sec is defined by configuration file.",
                                                           config->timeout_sec_config);
                                else
                                        status = StrDuplicate(L"Menu disabled. Hold down key at bootup to show menu.");
                        }
                        break;

                case KEYPRESS(0, 0, '+'):
                case KEYPRESS(0, 0, 't'):
                        if (config->timeout_sec_efivar == -1 && config->timeout_sec_config == 0)
                                config->timeout_sec_efivar++;
                        config->timeout_sec_efivar++;
                        efivar_set_int(L"LoaderConfigTimeout", config->timeout_sec_efivar, TRUE);
                        if (config->timeout_sec_efivar > 0)
                                status = PoolPrint(L"Menu timeout set to %d sec.",
                                                   config->timeout_sec_efivar);
                        else
                                status = StrDuplicate(L"Menu disabled. Hold down key at bootup to show menu.");
                        break;

                case KEYPRESS(0, 0, 'e'):
                        /* only the options of configured entries can be edited */
                        if (config->no_editor || config->entries[idx_highlight]->type == LOADER_UNDEFINED)
                                break;
                        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTGRAY|EFI_BACKGROUND_BLACK);
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_max-1);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline+1);
                        if (line_edit(config->entries[idx_highlight]->options, &config->options_edit, x_max-1, y_max-1))
                                exit = TRUE;
                        uefi_call_wrapper(ST->ConOut->SetCursorPosition, 3, ST->ConOut, 0, y_max-1);
                        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, clearline+1);
                        break;

                case KEYPRESS(0, 0, 'v'):
                        status = PoolPrint(L"systemd-boot " VERSION " (" EFI_MACHINE_TYPE_NAME "), UEFI Specification %d.%02d, Vendor %s %d.%02d",
                                           ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff,
                                           ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
                        break;

                case KEYPRESS(0, 0, 'P'):
                        print_status(config, loaded_image_path);
                        refresh = TRUE;
                        break;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'l'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('l')):
                        refresh = TRUE;
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

        for (i = 0; i < config->entry_count; i++)
                FreePool(lines[i]);
        FreePool(lines);
        FreePool(clearline);

        uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_WHITE|EFI_BACKGROUND_BLACK);
        uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
        return run;
}

static VOID config_add_entry(Config *config, ConfigEntry *entry) {
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
        FreePool(entry->title_show);
        FreePool(entry->title);
        FreePool(entry->machine_id);
        FreePool(entry->loader);
        FreePool(entry->options);
}

static BOOLEAN is_digit(CHAR16 c) {
        return (c >= '0') && (c <= '9');
}

static UINTN c_order(CHAR16 c) {
        if (c == '\0')
                return 0;
        if (is_digit(c))
                return 0;
        else if ((c >= 'a') && (c <= 'z'))
                return c;
        else
                return c + 0x10000;
}

static INTN str_verscmp(CHAR16 *s1, CHAR16 *s2) {
        CHAR16 *os1 = s1;
        CHAR16 *os2 = s2;

        while (*s1 || *s2) {
                INTN first;

                while ((*s1 && !is_digit(*s1)) || (*s2 && !is_digit(*s2))) {
                        INTN order;

                        order = c_order(*s1) - c_order(*s2);
                        if (order)
                                return order;
                        s1++;
                        s2++;
                }

                while (*s1 == '0')
                        s1++;
                while (*s2 == '0')
                        s2++;

                first = 0;
                while (is_digit(*s1) && is_digit(*s2)) {
                        if (first == 0)
                                first = *s1 - *s2;
                        s1++;
                        s2++;
                }

                if (is_digit(*s1))
                        return 1;
                if (is_digit(*s2))
                        return -1;

                if (first)
                        return first;
        }

        return StrCmp(os1, os2);
}

static CHAR8 *line_get_key_value(CHAR8 *content, CHAR8 *sep, UINTN *pos, CHAR8 **key_ret, CHAR8 **value_ret) {
        CHAR8 *line;
        UINTN linelen;
        CHAR8 *value;

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
        while (linelen > 0 && strchra(sep, line[linelen-1]))
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
        if (value[0] == '\"' && line[linelen-1] == '\"') {
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

        line = content;
        while ((line = line_get_key_value(content, (CHAR8 *)" \t", &pos, &key, &value))) {
                if (strcmpa((CHAR8 *)"timeout", key) == 0) {
                        CHAR16 *s;

                        s = stra_to_str(value);
                        config->timeout_sec_config = Atoi(s);
                        config->timeout_sec = config->timeout_sec_config;
                        FreePool(s);
                        continue;
                }

                if (strcmpa((CHAR8 *)"default", key) == 0) {
                        FreePool(config->entry_default_pattern);
                        config->entry_default_pattern = stra_to_str(value);
                        StrLwr(config->entry_default_pattern);
                        continue;
                }

                if (strcmpa((CHAR8 *)"editor", key) == 0) {
                        BOOLEAN on;

                        if (EFI_ERROR(parse_boolean(value, &on)))
                                continue;
                        config->no_editor = !on;
                }
        }
}

static VOID config_entry_add_from_file(Config *config, EFI_HANDLE *device, CHAR16 *file, CHAR8 *content, CHAR16 *loaded_image_path) {
        ConfigEntry *entry;
        CHAR8 *line;
        UINTN pos = 0;
        CHAR8 *key, *value;
        UINTN len;
        CHAR16 *initrd = NULL;

        entry = AllocateZeroPool(sizeof(ConfigEntry));

        line = content;
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
                        if (StriCmp(entry->loader, loaded_image_path) == 0) {
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
                        CHAR16 *new;

                        new = stra_to_path(value);
                        if (initrd) {
                                CHAR16 *s;

                                s = PoolPrint(L"%s initrd=%s", initrd, new);
                                FreePool(initrd);
                                initrd = s;
                        } else
                                initrd = PoolPrint(L"initrd=%s", new);
                        FreePool(new);
                        continue;
                }

                if (strcmpa((CHAR8 *)"options", key) == 0) {
                        CHAR16 *new;

                        new = stra_to_str(value);
                        if (entry->options) {
                                CHAR16 *s;

                                s = PoolPrint(L"%s %s", entry->options, new);
                                FreePool(entry->options);
                                entry->options = s;
                        } else {
                                entry->options = new;
                                new = NULL;
                        }
                        FreePool(new);
                        continue;
                }
        }

        if (entry->type == LOADER_UNDEFINED) {
                config_entry_free(entry);
                FreePool(initrd);
                FreePool(entry);
                return;
        }

        /* add initrd= to options */
        if (entry->type == LOADER_LINUX && initrd) {
                if (entry->options) {
                        CHAR16 *s;

                        s = PoolPrint(L"%s %s", initrd, entry->options);
                        FreePool(entry->options);
                        entry->options = s;
                } else {
                        entry->options = initrd;
                        initrd = NULL;
                }
        }
        FreePool(initrd);

        entry->device = device;
        entry->file = StrDuplicate(file);
        len = StrLen(entry->file);
        /* remove ".conf" */
        if (len > 5)
                entry->file[len - 5] = '\0';
        StrLwr(entry->file);

        config_add_entry(config, entry);
}

static VOID config_load_defaults(Config *config, EFI_FILE *root_dir) {
        CHAR8 *content = NULL;
        UINTN sec;
        UINTN len;
        EFI_STATUS err;

        len = file_read(root_dir, L"\\loader\\loader.conf", 0, 0, &content);
        if (len > 0)
                config_defaults_load_from_file(config, content);
        FreePool(content);

        err = efivar_get_int(L"LoaderConfigTimeout", &sec);
        if (!EFI_ERROR(err)) {
                config->timeout_sec_efivar = sec;
                config->timeout_sec = sec;
        } else
                config->timeout_sec_efivar = -1;
}

static VOID config_load_entries(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir, CHAR16 *loaded_image_path) {
        EFI_FILE_HANDLE entries_dir;
        EFI_STATUS err;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &entries_dir, L"\\loader\\entries", EFI_FILE_MODE_READ, 0ULL);
        if (!EFI_ERROR(err)) {
                for (;;) {
                        CHAR16 buf[256];
                        UINTN bufsize;
                        EFI_FILE_INFO *f;
                        CHAR8 *content = NULL;
                        UINTN len;

                        bufsize = sizeof(buf);
                        err = uefi_call_wrapper(entries_dir->Read, 3, entries_dir, &bufsize, buf);
                        if (bufsize == 0 || EFI_ERROR(err))
                                break;

                        f = (EFI_FILE_INFO *) buf;
                        if (f->FileName[0] == '.')
                                continue;
                        if (f->Attribute & EFI_FILE_DIRECTORY)
                                continue;

                        len = StrLen(f->FileName);
                        if (len < 6)
                                continue;
                        if (StriCmp(f->FileName + len - 5, L".conf") != 0)
                                continue;
                        if (StrnCmp(f->FileName, L"auto-", 5) == 0)
                                continue;

                        len = file_read(entries_dir, f->FileName, 0, 0, &content);
                        if (len > 0)
                                config_entry_add_from_file(config, device, f->FileName, content, loaded_image_path);
                        FreePool(content);
                }
                uefi_call_wrapper(entries_dir->Close, 1, entries_dir);
        }
}

static VOID config_sort_entries(Config *config) {
        UINTN i;

        for (i = 1; i < config->entry_count; i++) {
                BOOLEAN more;
                UINTN k;

                more = FALSE;
                for (k = 0; k < config->entry_count - i; k++) {
                        ConfigEntry *entry;

                        if (str_verscmp(config->entries[k]->file, config->entries[k+1]->file) <= 0)
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

static VOID config_default_entry_select(Config *config) {
        CHAR16 *var;
        EFI_STATUS err;
        UINTN i;

        /*
         * The EFI variable to specify a boot entry for the next, and only the
         * next reboot. The variable is always cleared directly after it is read.
         */
        err = efivar_get(L"LoaderEntryOneShot", &var);
        if (!EFI_ERROR(err)) {
                BOOLEAN found = FALSE;

                for (i = 0; i < config->entry_count; i++) {
                        if (StrCmp(config->entries[i]->file, var) == 0) {
                                config->idx_default = i;
                                found = TRUE;
                                break;
                        }
                }

                config->entry_oneshot = StrDuplicate(var);
                efivar_set(L"LoaderEntryOneShot", NULL, TRUE);
                FreePool(var);
                if (found)
                        return;
        }

        /*
         * The EFI variable to select the default boot entry overrides the
         * configured pattern. The variable can be set and cleared by pressing
         * the 'd' key in the loader selection menu, the entry is marked with
         * an '*'.
         */
        err = efivar_get(L"LoaderEntryDefault", &var);
        if (!EFI_ERROR(err)) {
                BOOLEAN found = FALSE;

                for (i = 0; i < config->entry_count; i++) {
                        if (StrCmp(config->entries[i]->file, var) == 0) {
                                config->idx_default = i;
                                config->idx_default_efivar = i;
                                found = TRUE;
                                break;
                        }
                }
                FreePool(var);
                if (found)
                        return;
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
                        if (config->entries[i]->no_autoselect)
                                continue;
                        if (MetaiMatch(config->entries[i]->file, config->entry_default_pattern)) {
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

/* generate a unique title, avoiding non-distinguishable menu entries */
static VOID config_title_generate(Config *config) {
        UINTN i, k;
        BOOLEAN unique;

        /* set title */
        for (i = 0; i < config->entry_count; i++) {
                CHAR16 *title;

                FreePool(config->entries[i]->title_show);
                title = config->entries[i]->title;
                if (!title)
                        title = config->entries[i]->file;
                config->entries[i]->title_show = StrDuplicate(title);
        }

        unique = TRUE;
        for (i = 0; i < config->entry_count; i++) {
                for (k = 0; k < config->entry_count; k++) {
                        if (i == k)
                                continue;
                        if (StrCmp(config->entries[i]->title_show, config->entries[k]->title_show) != 0)
                                continue;

                        unique = FALSE;
                        config->entries[i]->non_unique = TRUE;
                        config->entries[k]->non_unique = TRUE;
                }
        }
        if (unique)
                return;

        /* add version to non-unique titles */
        for (i = 0; i < config->entry_count; i++) {
                CHAR16 *s;

                if (!config->entries[i]->non_unique)
                        continue;
                if (!config->entries[i]->version)
                        continue;

                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, config->entries[i]->version);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
                config->entries[i]->non_unique = FALSE;
        }

        unique = TRUE;
        for (i = 0; i < config->entry_count; i++) {
                for (k = 0; k < config->entry_count; k++) {
                        if (i == k)
                                continue;
                        if (StrCmp(config->entries[i]->title_show, config->entries[k]->title_show) != 0)
                                continue;

                        unique = FALSE;
                        config->entries[i]->non_unique = TRUE;
                        config->entries[k]->non_unique = TRUE;
                }
        }
        if (unique)
                return;

        /* add machine-id to non-unique titles */
        for (i = 0; i < config->entry_count; i++) {
                CHAR16 *s;
                CHAR16 *m;

                if (!config->entries[i]->non_unique)
                        continue;
                if (!config->entries[i]->machine_id)
                        continue;

                m = StrDuplicate(config->entries[i]->machine_id);
                m[8] = '\0';
                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, m);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
                config->entries[i]->non_unique = FALSE;
                FreePool(m);
        }

        unique = TRUE;
        for (i = 0; i < config->entry_count; i++) {
                for (k = 0; k < config->entry_count; k++) {
                        if (i == k)
                                continue;
                        if (StrCmp(config->entries[i]->title_show, config->entries[k]->title_show) != 0)
                                continue;

                        unique = FALSE;
                        config->entries[i]->non_unique = TRUE;
                        config->entries[k]->non_unique = TRUE;
                }
        }
        if (unique)
                return;

        /* add file name to non-unique titles */
        for (i = 0; i < config->entry_count; i++) {
                CHAR16 *s;

                if (!config->entries[i]->non_unique)
                        continue;
                s = PoolPrint(L"%s (%s)", config->entries[i]->title_show, config->entries[i]->file);
                FreePool(config->entries[i]->title_show);
                config->entries[i]->title_show = s;
                config->entries[i]->non_unique = FALSE;
        }
}

static BOOLEAN config_entry_add_call(Config *config, CHAR16 *title, EFI_STATUS (*call)(VOID)) {
        ConfigEntry *entry;

        entry = AllocateZeroPool(sizeof(ConfigEntry));
        entry->title = StrDuplicate(title);
        entry->call = call;
        entry->no_autoselect = TRUE;
        config_add_entry(config, entry);
        return TRUE;
}

static ConfigEntry *config_entry_add_loader(Config *config, EFI_HANDLE *device,
                                            enum loader_type type,CHAR16 *file, CHAR16 key, CHAR16 *title, CHAR16 *loader) {
        ConfigEntry *entry;

        entry = AllocateZeroPool(sizeof(ConfigEntry));
        entry->type = type;
        entry->title = StrDuplicate(title);
        entry->device = device;
        entry->loader = StrDuplicate(loader);
        entry->file = StrDuplicate(file);
        StrLwr(entry->file);
        entry->key = key;
        config_add_entry(config, entry);

        return entry;
}

static BOOLEAN config_entry_add_loader_auto(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir, CHAR16 *loaded_image_path,
                                         CHAR16 *file, CHAR16 key, CHAR16 *title, CHAR16 *loader) {
        EFI_FILE_HANDLE handle;
        ConfigEntry *entry;
        EFI_STATUS err;

        /* do not add an entry for ourselves */
        if (loaded_image_path && StriCmp(loader, loaded_image_path) == 0)
                return FALSE;

        /* check existence */
        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &handle, loader, EFI_FILE_MODE_READ, 0ULL);
        if (EFI_ERROR(err))
                return FALSE;
        uefi_call_wrapper(handle->Close, 1, handle);

        entry = config_entry_add_loader(config, device, LOADER_UNDEFINED, file, key, title, loader);
        if (!entry)
                return FALSE;

        /* do not boot right away into auto-detected entries */
        entry->no_autoselect = TRUE;

        return TRUE;
}

static VOID config_entry_add_osx(Config *config) {
        EFI_STATUS err;
        UINTN handle_count = 0;
        EFI_HANDLE *handles = NULL;

        err = LibLocateHandle(ByProtocol, &FileSystemProtocol, NULL, &handle_count, &handles);
        if (!EFI_ERROR(err)) {
                UINTN i;

                for (i = 0; i < handle_count; i++) {
                        EFI_FILE *root;
                        BOOLEAN found;

                        root = LibOpenRoot(handles[i]);
                        if (!root)
                                continue;
                        found = config_entry_add_loader_auto(config, handles[i], root, NULL, L"auto-osx", 'a', L"OS X",
                                                             L"\\System\\Library\\CoreServices\\boot.efi");
                        uefi_call_wrapper(root->Close, 1, root);
                        if (found)
                                break;
                }

                FreePool(handles);
        }
}

static VOID config_entry_add_linux( Config *config, EFI_LOADED_IMAGE *loaded_image, EFI_FILE *root_dir) {
        EFI_FILE_HANDLE linux_dir;
        EFI_STATUS err;
        ConfigEntry *entry;

        err = uefi_call_wrapper(root_dir->Open, 5, root_dir, &linux_dir, L"\\EFI\\Linux", EFI_FILE_MODE_READ, 0ULL);
        if (!EFI_ERROR(err)) {
                for (;;) {
                        CHAR16 buf[256];
                        UINTN bufsize;
                        EFI_FILE_INFO *f;
                        CHAR8 *sections[] = {
                                (UINT8 *)".osrel",
                                (UINT8 *)".cmdline",
                                NULL
                        };
                        UINTN offs[ELEMENTSOF(sections)-1] = {};
                        UINTN szs[ELEMENTSOF(sections)-1] = {};
                        UINTN addrs[ELEMENTSOF(sections)-1] = {};
                        CHAR8 *content = NULL;
                        UINTN len;
                        CHAR8 *line;
                        UINTN pos = 0;
                        CHAR8 *key, *value;
                        CHAR16 *os_name = NULL;
                        CHAR16 *os_id = NULL;
                        CHAR16 *os_version = NULL;
                        CHAR16 *os_build = NULL;

                        bufsize = sizeof(buf);
                        err = uefi_call_wrapper(linux_dir->Read, 3, linux_dir, &bufsize, buf);
                        if (bufsize == 0 || EFI_ERROR(err))
                                break;

                        f = (EFI_FILE_INFO *) buf;
                        if (f->FileName[0] == '.')
                                continue;
                        if (f->Attribute & EFI_FILE_DIRECTORY)
                                continue;
                        len = StrLen(f->FileName);
                        if (len < 5)
                                continue;
                        if (StriCmp(f->FileName + len - 4, L".efi") != 0)
                                continue;

                        /* look for .osrel and .cmdline sections in the .efi binary */
                        err = pefile_locate_sections(linux_dir, f->FileName, sections, addrs, offs, szs);
                        if (EFI_ERROR(err))
                                continue;

                        len = file_read(linux_dir, f->FileName, offs[0], szs[0], &content);
                        if (len <= 0)
                                continue;

                        /* read properties from the embedded os-release file */
                        line = content;
                        while ((line = line_get_key_value(content, (CHAR8 *)"=", &pos, &key, &value))) {
                                if (strcmpa((CHAR8 *)"PRETTY_NAME", key) == 0) {
                                        FreePool(os_name);
                                        os_name = stra_to_str(value);
                                        continue;
                                }

                                if (strcmpa((CHAR8 *)"ID", key) == 0) {
                                        FreePool(os_id);
                                        os_id = stra_to_str(value);
                                        continue;
                                }

                                if (strcmpa((CHAR8 *)"VERSION_ID", key) == 0) {
                                        FreePool(os_version);
                                        os_version = stra_to_str(value);
                                        continue;
                                }

                                if (strcmpa((CHAR8 *)"BUILD_ID", key) == 0) {
                                        FreePool(os_build);
                                        os_build = stra_to_str(value);
                                        continue;
                                }
                        }

                        if (os_name && os_id && (os_version || os_build)) {
                                CHAR16 *conf;
                                CHAR16 *path;
                                CHAR16 *cmdline;

                                conf = PoolPrint(L"%s-%s", os_id, os_version ? : os_build);
                                path = PoolPrint(L"\\EFI\\Linux\\%s", f->FileName);
                                entry = config_entry_add_loader(config, loaded_image->DeviceHandle, LOADER_LINUX, conf, 'l', os_name, path);

                                FreePool(content);
                                /* read the embedded cmdline file */
                                len = file_read(linux_dir, f->FileName, offs[1], szs[1] - 1 , &content);
                                if (len > 0) {
                                        cmdline = stra_to_str(content);
                                        entry->options = cmdline;
                                        cmdline = NULL;
                                }
                                FreePool(cmdline);
                                FreePool(conf);
                                FreePool(path);
                        }

                        FreePool(os_name);
                        FreePool(os_id);
                        FreePool(os_version);
                        FreePool(os_build);
                        FreePool(content);
                }
                uefi_call_wrapper(linux_dir->Close, 1, linux_dir);
        }
}

static EFI_STATUS image_start(EFI_HANDLE parent_image, const Config *config, const ConfigEntry *entry) {
        EFI_HANDLE image;
        EFI_DEVICE_PATH *path;
        CHAR16 *options;
        EFI_STATUS err;

        path = FileDevicePath(entry->device, entry->loader);
        if (!path) {
                Print(L"Error getting device path.");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return EFI_INVALID_PARAMETER;
        }

        err = uefi_call_wrapper(BS->LoadImage, 6, FALSE, parent_image, path, NULL, 0, &image);
        if (EFI_ERROR(err)) {
                Print(L"Error loading %s: %r", entry->loader, err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                goto out;
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
                        Print(L"Error getting LoadedImageProtocol handle: %r", err);
                        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                        goto out_unload;
                }
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = (StrLen(loaded_image->LoadOptions)+1) * sizeof(CHAR16);
        }

        efivar_set_time_usec(L"LoaderTimeExecUSec", 0);
        err = uefi_call_wrapper(BS->StartImage, 3, image, NULL, NULL);
out_unload:
        uefi_call_wrapper(BS->UnloadImage, 1, image);
out:
        FreePool(path);
        return err;
}

static EFI_STATUS reboot_into_firmware(VOID) {
        CHAR8 *b;
        UINTN size;
        UINT64 osind;
        EFI_STATUS err;

        osind = EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        err = efivar_get_raw(&global_guid, L"OsIndications", &b, &size);
        if (!EFI_ERROR(err))
                osind |= (UINT64)*b;
        FreePool(b);

        err = efivar_set_raw(&global_guid, L"OsIndications", (CHAR8 *)&osind, sizeof(UINT64), TRUE);
        if (EFI_ERROR(err))
                return err;

        err = uefi_call_wrapper(RT->ResetSystem, 4, EfiResetCold, EFI_SUCCESS, 0, NULL);
        Print(L"Error calling ResetSystem: %r", err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
}

static VOID config_free(Config *config) {
        UINTN i;

        for (i = 0; i < config->entry_count; i++)
                config_entry_free(config->entries[i]);
        FreePool(config->entries);
        FreePool(config->entry_default_pattern);
        FreePool(config->options_edit);
        FreePool(config->entry_oneshot);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        CHAR16 *s;
        CHAR8 *b;
        UINTN size;
        EFI_LOADED_IMAGE *loaded_image;
        EFI_FILE *root_dir;
        CHAR16 *loaded_image_path;
        EFI_STATUS err;
        Config config;
        UINT64 init_usec;
        BOOLEAN menu = FALSE;
        CHAR16 uuid[37];

        InitializeLib(image, sys_table);
        init_usec = time_usec();
        efivar_set_time_usec(L"LoaderTimeInitUSec", init_usec);
        efivar_set(L"LoaderInfo", L"systemd-boot " VERSION, FALSE);
        s = PoolPrint(L"%s %d.%02d", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        efivar_set(L"LoaderFirmwareInfo", s, FALSE);
        FreePool(s);
        s = PoolPrint(L"UEFI %d.%02d", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        efivar_set(L"LoaderFirmwareType", s, FALSE);
        FreePool(s);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
                Print(L"Error getting a LoadedImageProtocol handle: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        /* export the device path this image is started from */
        if (disk_get_part_uuid(loaded_image->DeviceHandle, uuid) == EFI_SUCCESS)
                efivar_set(L"LoaderDevicePartUUID", uuid, FALSE);

        root_dir = LibOpenRoot(loaded_image->DeviceHandle);
        if (!root_dir) {
                Print(L"Unable to open root directory: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return EFI_LOAD_ERROR;
        }


        /* the filesystem path to this image, to prevent adding ourselves to the menu */
        loaded_image_path = DevicePathToStr(loaded_image->FilePath);
        efivar_set(L"LoaderImageIdentifier", loaded_image_path, FALSE);

        ZeroMem(&config, sizeof(Config));
        config_load_defaults(&config, root_dir);

        /* scan /EFI/Linux/ directory */
        config_entry_add_linux(&config, loaded_image, root_dir);

        /* scan /loader/entries/\*.conf files */
        config_load_entries(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path);

        /* sort entries after version number */
        config_sort_entries(&config);

        /* if we find some well-known loaders, add them to the end of the list */
        config_entry_add_loader_auto(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     L"auto-windows", 'w', L"Windows Boot Manager", L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        config_entry_add_loader_auto(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     L"auto-efi-shell", 's', L"EFI Shell", L"\\shell" EFI_MACHINE_TYPE_NAME ".efi");
        config_entry_add_loader_auto(&config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     L"auto-efi-default", '\0', L"EFI Default Loader", L"\\EFI\\Boot\\boot" EFI_MACHINE_TYPE_NAME ".efi");
        config_entry_add_osx(&config);

        if (efivar_get_raw(&global_guid, L"OsIndicationsSupported", &b, &size) == EFI_SUCCESS) {
                UINT64 osind = (UINT64)*b;

                if (osind & EFI_OS_INDICATIONS_BOOT_TO_FW_UI)
                        config_entry_add_call(&config, L"Reboot Into Firmware Interface", reboot_into_firmware);
                FreePool(b);
        }

        if (config.entry_count == 0) {
                Print(L"No loader found. Configuration files in \\loader\\entries\\*.conf are needed.");
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                goto out;
        }

        config_title_generate(&config);

        /* select entry by configured pattern or EFI LoaderDefaultEntry= variable*/
        config_default_entry_select(&config);

        /* if no configured entry to select from was found, enable the menu */
        if (config.idx_default == -1) {
                config.idx_default = 0;
                if (config.timeout_sec == 0)
                        config.timeout_sec = 10;
        }

        /* select entry or show menu when key is pressed or timeout is set */
        if (config.timeout_sec == 0) {
                UINT64 key;

                err = console_key_read(&key, FALSE);
                if (!EFI_ERROR(err)) {
                        INT16 idx;

                        /* find matching key in config entries */
                        idx = entry_lookup_key(&config, config.idx_default, KEYCHAR(key));
                        if (idx >= 0)
                                config.idx_default = idx;
                        else
                                menu = TRUE;
                }
        } else
                menu = TRUE;

        for (;;) {
                ConfigEntry *entry;

                entry = config.entries[config.idx_default];
                if (menu) {
                        efivar_set_time_usec(L"LoaderTimeMenuUSec", 0);
                        uefi_call_wrapper(BS->SetWatchdogTimer, 4, 0, 0x10000, 0, NULL);
                        if (!menu_run(&config, &entry, loaded_image_path))
                                break;

                        /* run special entry like "reboot" */
                        if (entry->call) {
                                entry->call();
                                continue;
                        }
                }

                /* export the selected boot entry to the system */
                efivar_set(L"LoaderEntrySelected", entry->file, FALSE);

                uefi_call_wrapper(BS->SetWatchdogTimer, 4, 5 * 60, 0x10000, 0, NULL);
                err = image_start(image, &config, entry);
                if (EFI_ERROR(err)) {
                        graphics_mode(FALSE);
                        Print(L"\nFailed to execute %s (%s): %r\n", entry->title, entry->loader, err);
                        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
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
