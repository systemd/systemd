/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright © 2013 Intel Corporation
 *   Authored by Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
 */

#include "graphics.h"
#include "proto/console-control.h"
#include "proto/simple-text-io.h"
#include "util.h"

EFI_STATUS graphics_mode(bool on) {
        EFI_CONSOLE_CONTROL_PROTOCOL *ConsoleControl = NULL;
        EFI_CONSOLE_CONTROL_SCREEN_MODE new;
        EFI_CONSOLE_CONTROL_SCREEN_MODE current;
        bool uga_exists, stdin_locked;
        EFI_STATUS err;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_CONSOLE_CONTROL_PROTOCOL), NULL, (void **) &ConsoleControl);
        if (err != EFI_SUCCESS)
                /* console control protocol is nonstandard and might not exist. */
                return err == EFI_NOT_FOUND ? EFI_SUCCESS : err;

        /* check current mode */
        err = ConsoleControl->GetMode(ConsoleControl, &current, &uga_exists, &stdin_locked);
        if (err != EFI_SUCCESS)
                return err;

        /* do not touch the mode */
        new = on ? EfiConsoleControlScreenGraphics : EfiConsoleControlScreenText;
        if (new == current)
                return EFI_SUCCESS;

        log_wait();
        err = ConsoleControl->SetMode(ConsoleControl, new);

        /* some firmware enables the cursor when switching modes */
        ST->ConOut->EnableCursor(ST->ConOut, false);

        return err;
}
