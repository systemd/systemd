/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "console.h"
#include "util.h"

#define SYSTEM_FONT_WIDTH 8
#define SYSTEM_FONT_HEIGHT 19

#define EFI_SIMPLE_TEXT_INPUT_EX_GUID                           \
        &(const EFI_GUID) EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID

static inline void EventClosep(EFI_EVENT *event) {
        if (!*event)
                return;

        uefi_call_wrapper(BS->CloseEvent, 1, *event);
}

/*
 * Reading input from the console sounds like an easy task to do, but thanks to broken
 * firmware it is actually a nightmare.
 *
 * There is a ConIn and TextInputEx API for this. Ideally we want to use TextInputEx,
 * because that gives us Ctrl/Alt/Shift key state information. Unfortunately, it is not
 * always available and sometimes just non-functional.
 *
 * On the other hand we have ConIn, where some firmware likes to just freeze on us
 * if we call ReadKeyStroke on it.
 *
 * Therefore, we use WaitForEvent on both ConIn and TextInputEx (if available) along
 * with a timer event. The timer ensures there is no need to call into functions
 * that might freeze on us, while still allowing us to show a timeout counter.
 */
EFI_STATUS console_key_read(UINT64 *key, UINT64 timeout_usec) {
        static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *TextInputEx;
        static BOOLEAN checked;
        UINTN index;
        EFI_INPUT_KEY k;
        EFI_STATUS err;
        _cleanup_(EventClosep) EFI_EVENT timer = NULL;
        EFI_EVENT events[3] = { ST->ConIn->WaitForKey };
        UINTN n_events = 1;

        assert(key);

        if (!checked) {
                err = LibLocateProtocol((EFI_GUID*) EFI_SIMPLE_TEXT_INPUT_EX_GUID, (VOID **)&TextInputEx);
                if (EFI_ERROR(err) ||
                    uefi_call_wrapper(BS->CheckEvent, 1, TextInputEx->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        /* If WaitForKeyEx fails here, the firmware pretends it talks this
                         * protocol, but it really doesn't. */
                        TextInputEx = NULL;
                else
                        events[n_events++] = TextInputEx->WaitForKeyEx;

                checked = TRUE;
        }

        if (timeout_usec > 0) {
                err = uefi_call_wrapper(BS->CreateEvent, 5, EVT_TIMER, 0, NULL, NULL, &timer);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error creating timer event: %r", err);

                /* SetTimer expects 100ns units for some reason. */
                err = uefi_call_wrapper(BS->SetTimer, 3, timer, TimerRelative, timeout_usec * 10);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error arming timer event: %r", err);

                events[n_events++] = timer;
        }

        err = uefi_call_wrapper(BS->WaitForEvent, 3, n_events, events, &index);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error waiting for events: %r", err);

        if (timeout_usec > 0 && timer == events[index])
                return EFI_TIMEOUT;

        /* TextInputEx might be ready too even if ConIn got to signal first. */
        if (TextInputEx && !EFI_ERROR(uefi_call_wrapper(BS->CheckEvent, 1, TextInputEx->WaitForKeyEx))) {
                EFI_KEY_DATA keydata;
                UINT64 keypress;
                UINT32 shift = 0;

                err = uefi_call_wrapper(TextInputEx->ReadKeyStrokeEx, 2, TextInputEx, &keydata);
                if (EFI_ERROR(err))
                        return err;

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
                        return EFI_SUCCESS;
                }

                return EFI_NOT_READY;
        }

        err  = uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &k);
        if (EFI_ERROR(err))
                return err;

        *key = KEYPRESS(0, k.ScanCode, k.UnicodeChar);
        return EFI_SUCCESS;
}

static EFI_STATUS change_mode(UINTN mode) {
        EFI_STATUS err;

        err = uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, mode);

        /* Special case mode 1: when using OVMF and qemu, setting it returns error
         * and breaks console output. */
        if (EFI_ERROR(err) && mode == 1)
                uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, (UINTN)0);

        return err;
}

static UINT64 text_area_from_font_size(void) {
        EFI_STATUS err;
        UINT64 text_area;
        UINTN rows, columns;

        err = uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, ST->ConOut->Mode->Mode, &columns, &rows);
        if (EFI_ERROR(err)) {
                columns = 80;
                rows = 25;
        }

        text_area = SYSTEM_FONT_WIDTH * SYSTEM_FONT_HEIGHT * (UINT64)rows * (UINT64)columns;

        return text_area;
}

static EFI_STATUS mode_auto(UINTN *mode) {
        const UINT32 HORIZONTAL_MAX_OK = 1920;
        const UINT32 VERTICAL_MAX_OK = 1080;
        const UINT64 VIEWPORT_RATIO = 10;
        UINT64 screen_area, text_area;
        static const EFI_GUID GraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput;
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
        EFI_STATUS err;
        BOOLEAN keep = FALSE;

        assert(mode);

        err = LibLocateProtocol((EFI_GUID*) &GraphicsOutputProtocolGuid, (VOID **)&GraphicsOutput);
        if (!EFI_ERROR(err) && GraphicsOutput->Mode && GraphicsOutput->Mode->Info) {
                Info = GraphicsOutput->Mode->Info;

                /* Start verifying if we are in a resolution larger than Full HD
                 * (1920x1080). If we're not, assume we're in a good mode and do not
                 * try to change it. */
                if (Info->HorizontalResolution <= HORIZONTAL_MAX_OK && Info->VerticalResolution <= VERTICAL_MAX_OK)
                        keep = TRUE;
                /* For larger resolutions, calculate the ratio of the total screen
                 * area to the text viewport area. If it's less than 10 times bigger,
                 * then assume the text is readable and keep the text mode. */
                else {
                        screen_area = (UINT64)Info->HorizontalResolution * (UINT64)Info->VerticalResolution;
                        text_area = text_area_from_font_size();

                        if (text_area != 0 && screen_area/text_area < VIEWPORT_RATIO)
                                keep = TRUE;
                }
        }

        if (keep) {
                /* Just clear the screen instead of changing the mode and return. */
                *mode = ST->ConOut->Mode->Mode;
                uefi_call_wrapper(ST->ConOut->ClearScreen, 1, ST->ConOut);
                return EFI_SUCCESS;
        }

        /* If we reached here, then we have a high resolution screen and the text
         * viewport is less than 10% the screen area, so the firmware developer
         * screwed up. Try to switch to a better mode. Mode number 2 is first non
         * standard mode, which is provided by the device manufacturer, so it should
         * be a good mode.
         * Note: MaxMode is the number of modes, not the last mode. */
        if (ST->ConOut->Mode->MaxMode > 2)
                *mode = 2;
        /* Try again with mode different than zero (assume user requests
         * auto mode due to some problem with mode zero). */
        else if (ST->ConOut->Mode->MaxMode == 2)
                *mode = 1;
        /* Else force mode change to zero. */
        else
                *mode = 0;

        return change_mode(*mode);
}

EFI_STATUS console_set_mode(UINTN *mode, enum console_mode_change_type how) {
        assert(mode);

        if (how == CONSOLE_MODE_AUTO)
                return mode_auto(mode);

        if (how == CONSOLE_MODE_MAX) {
                /* Note: MaxMode is the number of modes, not the last mode. */
                if (ST->ConOut->Mode->MaxMode > 0)
                        *mode = ST->ConOut->Mode->MaxMode-1;
                else
                        *mode = 0;
        }

        return change_mode(*mode);
}
