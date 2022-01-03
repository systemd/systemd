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

static inline void event_closep(EFI_EVENT *event) {
        if (!*event)
                return;

        BS->CloseEvent(*event);
}

/*
 * Reading input from the console sounds like an easy task to do, but thanks to broken
 * firmware it is actually a nightmare.
 *
 * There is a SimpleTextInput and SimpleTextInputEx API for this. Ideally we want to use
 * TextInputEx, because that gives us Ctrl/Alt/Shift key state information. Unfortunately,
 * it is not always available and sometimes just non-functional.
 *
 * On some firmware, calling ReadKeyStroke or ReadKeyStrokeEx on the default console input
 * device will just freeze no matter what (even though it *reported* being ready).
 * Also, multiple input protocols can be backed by the same device, but they can be out of
 * sync. Falling back on a different protocol can end up with double input.
 *
 * Therefore, we will preferably use TextInputEx for ConIn if that is available. Additionally,
 * we look for the first TextInputEx device the firmware gives us as a fallback option. It
 * will replace ConInEx permanently if it ever reports a key press.
 * Lastly, a timer event allows us to provide a input timeout without having to call into
 * any input functions that can freeze on us or using a busy/stall loop. */
EFI_STATUS console_key_read(UINT64 *key, UINT64 timeout_usec) {
        static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *conInEx = NULL, *extraInEx = NULL;
        static BOOLEAN checked = FALSE;
        UINTN index;
        EFI_STATUS err;
        _cleanup_(event_closep) EFI_EVENT timer = NULL;

        assert(key);

        if (!checked) {
                /* Get the *first* TextInputEx device.*/
                err = LibLocateProtocol(&SimpleTextInputExProtocol, (void **) &extraInEx);
                if (EFI_ERROR(err) || BS->CheckEvent(extraInEx->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        /* If WaitForKeyEx fails here, the firmware pretends it talks this
                         * protocol, but it really doesn't. */
                        extraInEx = NULL;

                /* Get the TextInputEx version of ST->ConIn. */
                err = BS->HandleProtocol(ST->ConsoleInHandle, &SimpleTextInputExProtocol, (void **) &conInEx);
                if (EFI_ERROR(err) || BS->CheckEvent(conInEx->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        conInEx = NULL;

                if (conInEx == extraInEx)
                        extraInEx = NULL;

                checked = TRUE;
        }

        err = BS->CreateEvent(EVT_TIMER, 0, NULL, NULL, &timer);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error creating timer event: %r", err);

        EFI_EVENT events[] = {
                timer,
                conInEx ? conInEx->WaitForKeyEx : ST->ConIn->WaitForKey,
                extraInEx ? extraInEx->WaitForKeyEx : NULL,
        };
        UINTN n_events = extraInEx ? 3 : 2;

        /* Watchdog rearming loop in case the user never provides us with input or some
         * broken firmware never returns from WaitForEvent. */
        for (;;) {
                UINT64 watchdog_timeout_sec = 5 * 60,
                       watchdog_ping_usec = watchdog_timeout_sec / 2 * 1000 * 1000;

                /* SetTimer expects 100ns units for some reason. */
                err = BS->SetTimer(
                                timer,
                                TimerRelative,
                                MIN(timeout_usec, watchdog_ping_usec) * 10);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error arming timer event: %r", err);

                (void) BS->SetWatchdogTimer(watchdog_timeout_sec, 0x10000, 0, NULL);
                err = BS->WaitForEvent(n_events, events, &index);
                (void) BS->SetWatchdogTimer(watchdog_timeout_sec, 0x10000, 0, NULL);

                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error waiting for events: %r", err);

                /* We have keyboard input, process it after this loop. */
                if (timer != events[index])
                        break;

                /* The EFI timer fired instead. If this was a watchdog timeout, loop again. */
                if (timeout_usec == UINT64_MAX)
                        continue;
                else if (timeout_usec > watchdog_ping_usec) {
                        timeout_usec -= watchdog_ping_usec;
                        continue;
                }

                /* The caller requested a timeout? They shall have one! */
                return EFI_TIMEOUT;
        }

        /* If the extra input device we found returns something, always use that instead
         * to work around broken firmware freezing on ConIn/ConInEx. */
        if (extraInEx && !EFI_ERROR(BS->CheckEvent(extraInEx->WaitForKeyEx))) {
                conInEx = extraInEx;
                extraInEx = NULL;
        }

        /* Do not fall back to ConIn if we have a ConIn that supports TextInputEx.
         * The two may be out of sync on some firmware, giving us double input. */
        if (conInEx) {
                EFI_KEY_DATA keydata;
                UINT64 keypress;
                UINT32 shift = 0;

                err = conInEx->ReadKeyStrokeEx(conInEx, &keydata);
                if (EFI_ERROR(err))
                        return err;

                /* do not distinguish between left and right keys */
                if (keydata.KeyState.KeyShiftState & EFI_SHIFT_STATE_VALID) {
                        if (keydata.KeyState.KeyShiftState & (EFI_RIGHT_CONTROL_PRESSED|EFI_LEFT_CONTROL_PRESSED))
                                shift |= EFI_CONTROL_PRESSED;
                        if (keydata.KeyState.KeyShiftState & (EFI_RIGHT_ALT_PRESSED|EFI_LEFT_ALT_PRESSED))
                                shift |= EFI_ALT_PRESSED;
                }

                /* 32 bit modifier keys + 16 bit scan code + 16 bit unicode */
                keypress = KEYPRESS(shift, keydata.Key.ScanCode, keydata.Key.UnicodeChar);
                if (keypress > 0) {
                        *key = keypress;
                        return EFI_SUCCESS;
                }

                return EFI_NOT_READY;
        } else if (BS->CheckEvent(ST->ConIn->WaitForKey)) {
                EFI_INPUT_KEY k;

                err = ST->ConIn->ReadKeyStroke(ST->ConIn, &k);
                if (EFI_ERROR(err))
                        return err;

                *key = KEYPRESS(0, k.ScanCode, k.UnicodeChar);
                return EFI_SUCCESS;
        }

        return EFI_NOT_READY;
}

static EFI_STATUS change_mode(INT64 mode) {
        EFI_STATUS err;
        INT32 old_mode;

        /* SetMode expects a UINTN, so make sure these values are sane. */
        mode = CLAMP(mode, CONSOLE_MODE_RANGE_MIN, CONSOLE_MODE_RANGE_MAX);
        old_mode = MAX(CONSOLE_MODE_RANGE_MIN, ST->ConOut->Mode->Mode);

        err = ST->ConOut->SetMode(ST->ConOut, mode);
        if (!EFI_ERROR(err))
                return EFI_SUCCESS;

        /* Something went wrong. Output is probably borked, so try to revert to previous mode. */
        if (!EFI_ERROR(ST->ConOut->SetMode(ST->ConOut, old_mode)))
                return err;

        /* Maybe the device is on fire? */
        ST->ConOut->Reset(ST->ConOut, TRUE);
        ST->ConOut->SetMode(ST->ConOut, CONSOLE_MODE_RANGE_MIN);
        return err;
}

static INT64 get_auto_mode(void) {
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput;
        EFI_STATUS err;

        err = LibLocateProtocol(&GraphicsOutputProtocol, (void **)&GraphicsOutput);
        if (!EFI_ERROR(err) && GraphicsOutput->Mode && GraphicsOutput->Mode->Info) {
                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info = GraphicsOutput->Mode->Info;
                BOOLEAN keep = FALSE;

                /* Start verifying if we are in a resolution larger than Full HD
                 * (1920x1080). If we're not, assume we're in a good mode and do not
                 * try to change it. */
                if (Info->HorizontalResolution <= HORIZONTAL_MAX_OK && Info->VerticalResolution <= VERTICAL_MAX_OK)
                        keep = TRUE;
                /* For larger resolutions, calculate the ratio of the total screen
                 * area to the text viewport area. If it's less than 10 times bigger,
                 * then assume the text is readable and keep the text mode. */
                else {
                        UINT64 text_area;
                        UINTN x_max, y_max;
                        UINT64 screen_area = (UINT64)Info->HorizontalResolution * (UINT64)Info->VerticalResolution;

                        console_query_mode(&x_max, &y_max);
                        text_area = SYSTEM_FONT_WIDTH * SYSTEM_FONT_HEIGHT * (UINT64)x_max * (UINT64)y_max;

                        if (text_area != 0 && screen_area/text_area < VIEWPORT_RATIO)
                                keep = TRUE;
                }

                if (keep)
                        return ST->ConOut->Mode->Mode;
        }

        /* If we reached here, then we have a high resolution screen and the text
         * viewport is less than 10% the screen area, so the firmware developer
         * screwed up. Try to switch to a better mode. Mode number 2 is first non
         * standard mode, which is provided by the device manufacturer, so it should
         * be a good mode.
         * Note: MaxMode is the number of modes, not the last mode. */
        if (ST->ConOut->Mode->MaxMode > CONSOLE_MODE_FIRMWARE_FIRST)
                return CONSOLE_MODE_FIRMWARE_FIRST;

        /* Try again with mode different than zero (assume user requests
         * auto mode due to some problem with mode zero). */
        if (ST->ConOut->Mode->MaxMode > CONSOLE_MODE_80_50)
                return CONSOLE_MODE_80_50;

        return CONSOLE_MODE_80_25;
}

EFI_STATUS console_set_mode(INT64 mode) {
        switch (mode) {
        case CONSOLE_MODE_KEEP:
                /* If the firmware indicates the current mode is invalid, change it anyway. */
                if (ST->ConOut->Mode->Mode < CONSOLE_MODE_RANGE_MIN)
                        return change_mode(CONSOLE_MODE_RANGE_MIN);
                return EFI_SUCCESS;

        case CONSOLE_MODE_NEXT:
                if (ST->ConOut->Mode->MaxMode <= CONSOLE_MODE_RANGE_MIN)
                        return EFI_UNSUPPORTED;

                mode = MAX(CONSOLE_MODE_RANGE_MIN, ST->ConOut->Mode->Mode);
                do {
                        mode = (mode + 1) % ST->ConOut->Mode->MaxMode;
                        if (!EFI_ERROR(change_mode(mode)))
                                break;
                        /* If this mode is broken/unsupported, try the next.
                         * If mode is 0, we wrapped around and should stop. */
                } while (mode > CONSOLE_MODE_RANGE_MIN);

                return EFI_SUCCESS;

        case CONSOLE_MODE_AUTO:
                return change_mode(get_auto_mode());

        case CONSOLE_MODE_FIRMWARE_MAX:
                /* Note: MaxMode is the number of modes, not the last mode. */
                return change_mode(ST->ConOut->Mode->MaxMode - 1LL);

        default:
                return change_mode(mode);
        }
}

EFI_STATUS console_query_mode(UINTN *x_max, UINTN *y_max) {
        EFI_STATUS err;

        assert(x_max);
        assert(y_max);

        err = ST->ConOut->QueryMode(ST->ConOut, ST->ConOut->Mode->Mode, x_max, y_max);
        if (EFI_ERROR(err)) {
                /* Fallback values mandated by UEFI spec. */
                switch (ST->ConOut->Mode->Mode) {
                case CONSOLE_MODE_80_50:
                        *x_max = 80;
                        *y_max = 50;
                        break;
                case CONSOLE_MODE_80_25:
                default:
                        *x_max = 80;
                        *y_max = 25;
                }
        }

        return err;
}
