/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright © 2013 Intel Corporation
 *   Authored by Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
 */

#include <efi.h>
#include <efilib.h>

#include "graphics.h"
#include "missing_efi.h"
#include "util.h"

EFI_STATUS graphics_mode(bool on) {
        EFI_CONSOLE_CONTROL_PROTOCOL *ConsoleControl = NULL;
        EFI_CONSOLE_CONTROL_SCREEN_MODE new;
        EFI_CONSOLE_CONTROL_SCREEN_MODE current;
        BOOLEAN uga_exists;
        BOOLEAN stdin_locked;
        EFI_STATUS err;

        err = BS->LocateProtocol((EFI_GUID *) EFI_CONSOLE_CONTROL_GUID, NULL, (void **) &ConsoleControl);
        if (err != EFI_SUCCESS)
                /* console control protocol is nonstandard and might not exist. */
                return err == EFI_NOT_FOUND ? EFI_SUCCESS : err;

        /* check current mode */
        err =ConsoleControl->GetMode(ConsoleControl, &current, &uga_exists, &stdin_locked);
        if (err != EFI_SUCCESS)
                return err;

        /* do not touch the mode */
        new  = on ? EfiConsoleControlScreenGraphics : EfiConsoleControlScreenText;
        if (new == current)
                return EFI_SUCCESS;

        err =ConsoleControl->SetMode(ConsoleControl, new);

        /* some firmware enables the cursor when switching modes */
        ST->ConOut->EnableCursor(ST->ConOut, false);

        return err;
}
