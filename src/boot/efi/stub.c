/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2015 Kay Sievers <kay@vrfy.org>
 */

#include <efi.h>
#include <efilib.h>

#include "util.h"
#include "pefile.h"
#include "graphics.h"
#include "splash.h"
#include "linux.h"

/* magic string to find in the binary image */
static const char __attribute__((used)) magic[] = "#### LoaderInfo: systemd-stub " VERSION " ####";

static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *sys_table) {
        EFI_LOADED_IMAGE *loaded_image;
        EFI_FILE *root_dir;
        CHAR16 *loaded_image_path;
        CHAR8 *b;
        UINTN size;
        BOOLEAN secure = FALSE;
        CHAR8 *sections[] = {
                (UINT8 *)".cmdline",
                (UINT8 *)".linux",
                (UINT8 *)".initrd",
                (UINT8 *)".splash",
                NULL
        };
        UINTN addrs[ELEMENTSOF(sections)-1] = {};
        UINTN offs[ELEMENTSOF(sections)-1] = {};
        UINTN szs[ELEMENTSOF(sections)-1] = {};
        CHAR8 *cmdline = NULL;
        UINTN cmdline_len;
        EFI_STATUS err;

        InitializeLib(image, sys_table);

        err = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol, (VOID **)&loaded_image,
                                image, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(err)) {
                Print(L"Error getting a LoadedImageProtocol handle: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        root_dir = LibOpenRoot(loaded_image->DeviceHandle);
        if (!root_dir) {
                Print(L"Unable to open root directory: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return EFI_LOAD_ERROR;
        }

        loaded_image_path = DevicePathToStr(loaded_image->FilePath);

        if (efivar_get_raw(&global_guid, L"SecureBoot", &b, &size) == EFI_SUCCESS) {
                if (*b > 0)
                        secure = TRUE;
                FreePool(b);
        }

        err = pefile_locate_sections(root_dir, loaded_image_path, sections, addrs, offs, szs);
        if (EFI_ERROR(err)) {
                Print(L"Unable to locate embedded .linux section: %r ", err);
                uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
                return err;
        }

        if (szs[0] > 0)
                cmdline = (CHAR8 *)(loaded_image->ImageBase + addrs[0]);

        cmdline_len = szs[0];

        /* if we are not in secure boot mode, accept a custom command line and replace the built-in one */
        if (!secure && loaded_image->LoadOptionsSize > 0) {
                CHAR16 *options;
                CHAR8 *line;
                UINTN i;

                options = (CHAR16 *)loaded_image->LoadOptions;
                cmdline_len = (loaded_image->LoadOptionsSize / sizeof(CHAR16)) * sizeof(CHAR8);
                line = AllocatePool(cmdline_len);
                for (i = 0; i < cmdline_len; i++)
                        line[i] = options[i];
                cmdline = line;
        }

        if (szs[3] > 0)
                graphics_splash((UINT8 *)((UINTN)loaded_image->ImageBase + addrs[3]), szs[3], NULL);

        err = linux_exec(image, cmdline, cmdline_len,
                         (UINTN)loaded_image->ImageBase + addrs[1],
                         (UINTN)loaded_image->ImageBase + addrs[2], szs[2]);

        graphics_mode(FALSE);
        Print(L"Execution of embedded linux image failed: %r\n", err);
        uefi_call_wrapper(BS->Stall, 1, 3 * 1000 * 1000);
        return err;
}
