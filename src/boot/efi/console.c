/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "proto/graphics-output.h"
#include "util.h"

#define SYSTEM_FONT_WIDTH 8
#define SYSTEM_FONT_HEIGHT 19
#define HORIZONTAL_MAX_OK 1920
#define VERTICAL_MAX_OK 1080
#define VIEWPORT_RATIO 10

static void event_closep(EFI_EVENT *event) {
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
EFI_STATUS console_key_read(uint64_t *key, uint64_t timeout_usec) {
        static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *conInEx = NULL, *extraInEx = NULL;
        static bool checked = false;
        size_t index;
        EFI_STATUS err;
        _cleanup_(event_closep) EFI_EVENT timer = NULL;

        assert(key);

        if (!checked) {
                void *extraInExRaw, *conInExRaw;
                /* Get the *first* TextInputEx device. */
                err = BS->LocateProtocol(
                                MAKE_GUID_PTR(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL), NULL, &extraInExRaw);
                if (err != EFI_SUCCESS || BS->CheckEvent(((EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *)extraInExRaw)->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        /* If WaitForKeyEx fails here, the firmware pretends it talks this
                         * protocol, but it really doesn't. */
                        extraInExRaw = NULL;
                
                extraInEx = extraInExRaw;
                /* Get the TextInputEx version of ST->ConIn. */
                err = BS->HandleProtocol(
                                ST->ConsoleInHandle,
                                MAKE_GUID_PTR(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL),
                                &conInExRaw);
                if (err != EFI_SUCCESS || BS->CheckEvent((EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *)conInExRaw)->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        conInExRaw = NULL;
                
                conInEx = conInExRaw;
                if (conInEx == extraInEx)
                        extraInEx = NULL;

                checked = true;
        }

        err = BS->CreateEvent(EVT_TIMER, 0, NULL, NULL, &timer);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error creating timer event: %m");

        EFI_EVENT events[] = {
                timer,
                conInEx ? conInEx->WaitForKeyEx : ST->ConIn->WaitForKey,
                extraInEx ? extraInEx->WaitForKeyEx : NULL,
        };
        size_t n_events = extraInEx ? 3 : 2;

        /* Watchdog rearming loop in case the user never provides us with input or some
         * broken firmware never returns from WaitForEvent. */
        for (;;) {
                uint64_t watchdog_timeout_sec = 5 * 60,
                       watchdog_ping_usec = watchdog_timeout_sec / 2 * 1000 * 1000;

                /* SetTimer expects 100ns units for some reason. */
                err = BS->SetTimer(
                                timer,
                                TimerRelative,
                                MIN(timeout_usec, watchdog_ping_usec) * 10);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error arming timer event: %m");

                (void) BS->SetWatchdogTimer(watchdog_timeout_sec, 0x10000, 0, NULL);
                err = BS->WaitForEvent(n_events, events, &index);
                (void) BS->SetWatchdogTimer(watchdog_timeout_sec, 0x10000, 0, NULL);

                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error waiting for events: %m");

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
        if (extraInEx && BS->CheckEvent(extraInEx->WaitForKeyEx) == EFI_SUCCESS) {
                conInEx = extraInEx;
                extraInEx = NULL;
        }

        /* Do not fall back to ConIn if we have a ConIn that supports TextInputEx.
         * The two may be out of sync on some firmware, giving us double input. */
        if (conInEx) {
                EFI_KEY_DATA keydata;
                uint32_t shift = 0;

                err = conInEx->ReadKeyStrokeEx(conInEx, &keydata);
                if (err != EFI_SUCCESS)
                        return err;

                if (FLAGS_SET(keydata.KeyState.KeyShiftState, EFI_SHIFT_STATE_VALID)) {
                        /* Do not distinguish between left and right keys (set both flags). */
                        if (keydata.KeyState.KeyShiftState & EFI_CONTROL_PRESSED)
                                shift |= EFI_CONTROL_PRESSED;
                        if (keydata.KeyState.KeyShiftState & EFI_ALT_PRESSED)
                                shift |= EFI_ALT_PRESSED;
                        if (keydata.KeyState.KeyShiftState & EFI_LOGO_PRESSED)
                                shift |= EFI_LOGO_PRESSED;

                        /* Shift is not supposed to be reported for keys that can be represented as uppercase
                         * unicode chars (Shift+f is reported as F instead). Some firmware does it anyway, so
                         * filter those out. */
                        if ((keydata.KeyState.KeyShiftState & EFI_SHIFT_PRESSED) &&
                            keydata.Key.UnicodeChar == 0)
                                shift |= EFI_SHIFT_PRESSED;
                }

                /* 32 bit modifier keys + 16 bit scan code + 16 bit unicode */
                *key = KEYPRESS(shift, keydata.Key.ScanCode, keydata.Key.UnicodeChar);
                return EFI_SUCCESS;
        } else if (BS->CheckEvent(ST->ConIn->WaitForKey) == EFI_SUCCESS) {
                EFI_INPUT_KEY k;

                err = ST->ConIn->ReadKeyStroke(ST->ConIn, &k);
                if (err != EFI_SUCCESS)
                        return err;

                *key = KEYPRESS(0, k.ScanCode, k.UnicodeChar);
                return EFI_SUCCESS;
        }

        return EFI_NOT_READY;
}

static EFI_STATUS change_mode(int64_t mode) {
        EFI_STATUS err;
        int32_t old_mode;

        /* SetMode expects a size_t, so make sure these values are sane. */
        mode = CLAMP(mode, CONSOLE_MODE_RANGE_MIN, CONSOLE_MODE_RANGE_MAX);
        old_mode = MAX(CONSOLE_MODE_RANGE_MIN, ST->ConOut->Mode->Mode);

        log_wait();
        err = ST->ConOut->SetMode(ST->ConOut, mode);
        if (err == EFI_SUCCESS)
                return EFI_SUCCESS;

        /* Something went wrong. Output is probably borked, so try to revert to previous mode. */
        if (ST->ConOut->SetMode(ST->ConOut, old_mode) == EFI_SUCCESS)
                return err;

        /* Maybe the device is on fire? */
        ST->ConOut->Reset(ST->ConOut, true);
        ST->ConOut->SetMode(ST->ConOut, CONSOLE_MODE_RANGE_MIN);
        return err;
}

EFI_STATUS query_screen_resolution(uint32_t *ret_w, uint32_t *ret_h) {
        EFI_STATUS err;
        EFI_GRAPHICS_OUTPUT_PROTOCOL *go;
        void *go_raw;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL), NULL, &go_raw);
        if (err != EFI_SUCCESS)
                return err;
        
        go = go_raw;
        if (!go->Mode || !go->Mode->Info)
                return EFI_DEVICE_ERROR;

        *ret_w = go->Mode->Info->HorizontalResolution;
        *ret_h = go->Mode->Info->VerticalResolution;
        return EFI_SUCCESS;
}

static int64_t get_auto_mode(void) {
        uint32_t screen_width, screen_height;

        if (query_screen_resolution(&screen_width, &screen_height) == EFI_SUCCESS) {
                bool keep = false;

                /* Start verifying if we are in a resolution larger than Full HD
                 * (1920x1080). If we're not, assume we're in a good mode and do not
                 * try to change it. */
                if (screen_width <= HORIZONTAL_MAX_OK && screen_height <= VERTICAL_MAX_OK)
                        keep = true;
                /* For larger resolutions, calculate the ratio of the total screen
                 * area to the text viewport area. If it's less than 10 times bigger,
                 * then assume the text is readable and keep the text mode. */
                else {
                        uint64_t text_area;
                        size_t x_max, y_max;
                        uint64_t screen_area = (uint64_t)screen_width * (uint64_t)screen_height;

                        console_query_mode(&x_max, &y_max);
                        text_area = SYSTEM_FONT_WIDTH * SYSTEM_FONT_HEIGHT * (uint64_t)x_max * (uint64_t)y_max;

                        if (text_area != 0 && screen_area/text_area < VIEWPORT_RATIO)
                                keep = true;
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

EFI_STATUS console_set_mode(int64_t mode) {
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
                        if (change_mode(mode) == EFI_SUCCESS)
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

EFI_STATUS console_query_mode(size_t *x_max, size_t *y_max) {
        EFI_STATUS err;

        assert(x_max);
        assert(y_max);

        err = ST->ConOut->QueryMode(ST->ConOut, ST->ConOut->Mode->Mode, x_max, y_max);
        if (err != EFI_SUCCESS) {
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
