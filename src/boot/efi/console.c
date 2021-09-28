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

        err = uefi_call_wrapper(BS->CreateEvent, 5, EVT_TIMER, 0, NULL, NULL, &timer);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Error creating timer event: %r", err);
        events[n_events++] = timer;

        /* Watchdog rearming loop in case the user never provides us with input or some
         * broken firmware never returns from WaitForEvent. */
        for (;;) {
                UINT64 watchdog_timeout_sec = 5 * 60,
                       watchdog_ping_usec = watchdog_timeout_sec / 2 * 1000 * 1000;

                /* SetTimer expects 100ns units for some reason. */
                err = uefi_call_wrapper(
                                BS->SetTimer, 3,
                                timer,
                                TimerRelative,
                                MIN(timeout_usec, watchdog_ping_usec) * 10);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Error arming timer event: %r", err);

                (void) uefi_call_wrapper(BS->SetWatchdogTimer, 4, watchdog_timeout_sec, 0x10000, 0, NULL);
                err = uefi_call_wrapper(BS->WaitForEvent, 3, n_events, events, &index);
                (void) uefi_call_wrapper(BS->SetWatchdogTimer, 4, watchdog_timeout_sec, 0x10000, 0, NULL);

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

static EFI_STATUS change_mode(INT64 mode) {
        EFI_STATUS err;
        INT32 old_mode;

        /* SetMode expects a UINTN, so make sure these values are sane. */
        mode = CLAMP(mode, CONSOLE_MODE_RANGE_MIN, CONSOLE_MODE_RANGE_MAX);
        old_mode = MAX(CONSOLE_MODE_RANGE_MIN, ST->ConOut->Mode->Mode);

        err = uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, mode);
        if (!EFI_ERROR(err))
                return EFI_SUCCESS;

        /* Something went wrong. Output is probably borked, so try to revert to previous mode. */
        if (!EFI_ERROR(uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, old_mode)))
                return err;

        /* Maybe the device is on fire? */
        uefi_call_wrapper(ST->ConOut->Reset, 2, ST->ConOut, TRUE);
        uefi_call_wrapper(ST->ConOut->SetMode, 2, ST->ConOut, CONSOLE_MODE_RANGE_MIN);
        return err;
}

static INT64 get_auto_mode(void) {
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput;
        EFI_STATUS err;

        err = LibLocateProtocol(&GraphicsOutputProtocol, (VOID **)&GraphicsOutput);
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

        err = uefi_call_wrapper(ST->ConOut->QueryMode, 4, ST->ConOut, ST->ConOut->Mode->Mode, x_max, y_max);
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
