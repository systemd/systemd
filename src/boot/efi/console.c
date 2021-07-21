/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "console.h"
#include "util.h"

#define SYSTEM_FONT_WIDTH 8
#define SYSTEM_FONT_HEIGHT 19
#define HORIZONTAL_MAX_OK 1920
#define VERTICAL_MAX_OK 1080
#define VIEWPORT_RATIO 10

#define EFI_SIMPLE_TEXT_INPUT_EX_GUID &(EFI_GUID) EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID

EFI_STATUS console_key_read(UINT64 *key, BOOLEAN wait) {
        static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *TextInputEx;
        static BOOLEAN checked;
        UINTN index;
        EFI_INPUT_KEY k;
        EFI_STATUS err;

        if (!checked) {
                err = LibLocateProtocol(EFI_SIMPLE_TEXT_INPUT_EX_GUID, (VOID **)&TextInputEx);
                if (EFI_ERROR(err))
                        TextInputEx = NULL;

                checked = TRUE;
        }

        /* wait until key is pressed */
        if (wait)
                uefi_call_wrapper(BS->WaitForEvent, 3, 1, &ST->ConIn->WaitForKey, &index);

        if (TextInputEx) {
                EFI_KEY_DATA keydata;
                UINT64 keypress;

                err = uefi_call_wrapper(TextInputEx->ReadKeyStrokeEx, 2, TextInputEx, &keydata);
                if (!EFI_ERROR(err)) {
                        UINT32 shift = 0;

                        /* do not distinguish between left and right keys */
                        if (keydata.KeyState.KeyShiftState & EFI_SHIFT_STATE_VALID) {
                                if (keydata.KeyState.KeyShiftState & (EFI_RIGHT_CONTROL_PRESSED|EFI_LEFT_CONTROL_PRESSED))
                                        shift |= EFI_CONTROL_PRESSED;
                                if (keydata.KeyState.KeyShiftState & (EFI_RIGHT_ALT_PRESSED|EFI_LEFT_ALT_PRESSED))
                                        shift |= EFI_ALT_PRESSED;
                        };

                        /* 32 bit modifier keys + 16 bit scan code + 16 bit unicode */
                        keypress = KEYPRESS(shift, keydata.Key.ScanCode, keydata.Key.UnicodeChar);
                        if (keypress > 0) {
                                *key = keypress;
                                return 0;
                        }
                }
        }

        /* fallback for firmware which does not support SimpleTextInputExProtocol
         *
         * This is also called in case ReadKeyStrokeEx did not return a key, because
         * some broken firmwares offer SimpleTextInputExProtocol, but never actually
         * handle any key. */
        err  = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &k);
        if (EFI_ERROR(err))
                return err;

        *key = KEYPRESS(0, k.ScanCode, k.UnicodeChar);
        return 0;
}

static EFI_STATUS change_mode(UINTN mode) {
        EFI_STATUS err;
        UINTN old_mode = ST->ConOut->Mode->Mode;

        err = uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, mode);
        if (!EFI_ERROR(err))
                return EFI_SUCCESS;

        /* Something went wrong. Output is probably borked, so try to revert to previous mode. */
        if (!EFI_ERROR(uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, old_mode)))
                return err;

        /* Maybe the device is on fire? */
        uefi_call_wrapper(ST->ConOut->Reset, 2, ST->ConOut, TRUE);
        uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, (UINTN)0);
        return err;
}

static UINTN get_auto_mode(void) {
        EFI_GUID GraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput;
        EFI_STATUS err;
        BOOLEAN keep = FALSE;

        err = LibLocateProtocol(&GraphicsOutputProtocolGuid, (VOID **)&GraphicsOutput);
        if (!EFI_ERROR(err) && GraphicsOutput->Mode && GraphicsOutput->Mode->Info) {
                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info = GraphicsOutput->Mode->Info;

                /* Start verifying if we are in a resolution larger than Full HD
                 * (1920x1080). If we're not, assume we're in a good mode and do not
                 * try to change it. */
                if (Info->HorizontalResolution <= HORIZONTAL_MAX_OK && Info->VerticalResolution <= VERTICAL_MAX_OK)
                        keep = TRUE;
                /* For larger resolutions, calculate the ratio of the total screen
                 * area to the text viewport area. If it's less than 10 times bigger,
                 * then assume the text is readable and keep the text mode. */
                else {
                        UINT64 screen_area = (UINT64)Info->HorizontalResolution * (UINT64)Info->VerticalResolution;
                        UINT64 x_max, y_max, text_area;

                        console_query_mode(&x_max, &y_max);
                        text_area = SYSTEM_FONT_WIDTH * SYSTEM_FONT_HEIGHT * x_max * y_max;

                        if (text_area != 0 && screen_area/text_area < VIEWPORT_RATIO)
                                keep = TRUE;
                }
        }

        if (keep)
                return ST->ConOut->Mode->Mode;

        /* If we reached here, then we have a high resolution screen and the text
         * viewport is less than 10% the screen area, so the firmware developer
         * screwed up. Try to switch to a better mode. Mode number 2 is first non
         * standard mode, which is provided by the device manufacturer, so it should
         * be a good mode.
         * Note: MaxMode is the number of modes, not the last mode. */
        if (ST->ConOut->Mode->MaxMode > 2)
                return 2;

        /* Try again with mode different than zero (assume user requests
         * auto mode due to some problem with mode zero). */
        if (ST->ConOut->Mode->MaxMode == 2)
                return 1;

        /* Else force mode change to zero. */
        return 0;
}

EFI_STATUS console_set_mode(UINTN mode, enum console_mode_change_type how) {
        EFI_STATUS err;

        switch (how) {
        case CONSOLE_MODE_KEEP:
                return EFI_SUCCESS;

        case CONSOLE_MODE_AUTO:
                return change_mode(get_auto_mode());

        case CONSOLE_MODE_NEXT:
                if (ST->ConOut->Mode->MaxMode <= 0)
                        return EFI_UNSUPPORTED;

                mode = ST->ConOut->Mode->Mode;
                do {
                        mode = (mode + 1) % ST->ConOut->Mode->MaxMode;
                        err = change_mode(mode);
                        /* Try the next mode if this one does not work. If
                         * this is mode 0, we wrapped around and should stop. */
                } while (EFI_ERROR(err) && mode > 0);
                return err;

        case CONSOLE_MODE_MAX:
                if (ST->ConOut->Mode->MaxMode > 0)
                        mode = ST->ConOut->Mode->MaxMode - 1;
                else
                        mode = 0;
                _fallthrough_;

        case CONSOLE_MODE_SET:
        default:
                return change_mode(mode);
        }
}

EFI_STATUS console_query_mode(UINTN *x_max, UINTN *y_max) {
        EFI_STATUS err = uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, ST->ConOut->Mode->Mode, x_max, y_max);
        if (EFI_ERROR(err)) {
                *x_max = 80;
                *y_max = 25;
        }
        return err;
}
