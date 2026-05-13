/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "device-path-util.h"
#include "efi-log.h"
#include "efi-string.h"
#include "proto/graphics-output.h"
#include "proto/pci-io.h"
#include "string-util-fundamental.h"
#include "util.h"

#define SYSTEM_FONT_WIDTH 8
#define SYSTEM_FONT_HEIGHT 19
#define HORIZONTAL_MAX_OK 1920
#define VERTICAL_MAX_OK 1080
#define VIEWPORT_RATIO 10

static void event_closep(EFI_EVENT *event) {
        assert(event);

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
EFI_STATUS console_key_read(uint64_t *ret_key, uint64_t timeout_usec) {
        static EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *conInEx = NULL, *extraInEx = NULL;
        static bool checked = false;
        size_t index;
        EFI_STATUS err;
        _cleanup_(event_closep) EFI_EVENT timer = NULL;

        if (!checked) {
                /* Get the *first* TextInputEx device. */
                err = BS->LocateProtocol(
                                MAKE_GUID_PTR(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL), NULL, (void **) &extraInEx);
                if (err != EFI_SUCCESS || BS->CheckEvent(extraInEx->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        /* If WaitForKeyEx fails here, the firmware pretends it talks this
                         * protocol, but it really doesn't. */
                        extraInEx = NULL;

                /* Get the TextInputEx version of ST->ConIn. */
                err = BS->HandleProtocol(
                                ST->ConsoleInHandle,
                                MAKE_GUID_PTR(EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL),
                                (void **) &conInEx);
                if (err != EFI_SUCCESS || BS->CheckEvent(conInEx->WaitForKeyEx) == EFI_INVALID_PARAMETER)
                        conInEx = NULL;

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
        if (extraInEx && BS->CheckEvent(extraInEx->WaitForKeyEx) == EFI_SUCCESS)
                conInEx = TAKE_PTR(extraInEx);

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
                if (ret_key)
                        *ret_key = KEYPRESS(shift, keydata.Key.ScanCode, keydata.Key.UnicodeChar);
                return EFI_SUCCESS;
        } else if (BS->CheckEvent(ST->ConIn->WaitForKey) == EFI_SUCCESS) {
                EFI_INPUT_KEY k;

                err = ST->ConIn->ReadKeyStroke(ST->ConIn, &k);
                if (err != EFI_SUCCESS)
                        return err;

                if (ret_key)
                        *ret_key = KEYPRESS(0, k.ScanCode, k.UnicodeChar);
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

        assert(ret_w);
        assert(ret_h);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL), NULL, (void **) &go);
        if (err != EFI_SUCCESS)
                return err;

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

static int next_mode(int64_t mode, int64_t direction) {
        assert(IN_SET(direction, 1, -1));
        assert(ST->ConOut->Mode->MaxMode > 0);

        /* Always start at the beginning if we are out of range or reached the last mode already */
        if (direction > 0) {
                if (mode < CONSOLE_MODE_RANGE_MIN || mode >= ST->ConOut->Mode->MaxMode-1)
                        return CONSOLE_MODE_RANGE_MIN;
        } else if (direction < 0) {
                if (mode <= CONSOLE_MODE_RANGE_MIN || mode > ST->ConOut->Mode->MaxMode-1)
                        return ST->ConOut->Mode->MaxMode-1;
        } else
                assert_not_reached();

        return mode + direction;
}

EFI_STATUS console_set_mode(int64_t mode) {
        EFI_STATUS r;

        /* If there are no modes defined, fail immediately */
        if (ST->ConOut->Mode->MaxMode <= 0)
                return mode == CONSOLE_MODE_KEEP ? EFI_SUCCESS : EFI_UNSUPPORTED;

        int64_t target, direction = 1;
        switch (mode) {
        case CONSOLE_MODE_KEEP:
                /* If the firmware indicates the current mode is invalid, change it anyway. */
                if (ST->ConOut->Mode->Mode >= CONSOLE_MODE_RANGE_MIN &&
                    ST->ConOut->Mode->Mode < ST->ConOut->Mode->MaxMode)
                        return EFI_SUCCESS;

                target = CONSOLE_MODE_RANGE_MIN;
                break;

        case CONSOLE_MODE_NEXT:
                target = next_mode(ST->ConOut->Mode->Mode, direction);
                break;

        case CONSOLE_MODE_AUTO:
                target = get_auto_mode();
                break;

        case CONSOLE_MODE_FIRMWARE_MAX:
                /* Note: MaxMode is the number of modes, not the last mode. */
                target = ST->ConOut->Mode->MaxMode - 1;
                direction = -1; /* search backwards for a working mode */
                break;

        case CONSOLE_MODE_RANGE_MIN...CONSOLE_MODE_RANGE_MAX:
                target = mode;
                break;

        default:
                assert_not_reached();
        }

        for (int64_t attempt = 0;; attempt++) {
                r = change_mode(target);
                if (r == EFI_SUCCESS)
                        return EFI_SUCCESS;
                if (attempt >= ST->ConOut->Mode->MaxMode-1) /* give up, once we tried them all */
                        return r;

                /* If this mode is broken/unsupported, try the next. */
                target = next_mode(target, direction);
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

static bool has_virtio_console_pci_device(void) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles = 0;

        EFI_STATUS err = BS->LocateHandleBuffer(
                        ByProtocol,
                        MAKE_GUID_PTR(EFI_PCI_IO_PROTOCOL),
                        NULL,
                        &n_handles,
                        &handles);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Failed to locate PCI I/O protocol handles, assuming no VirtIO console: %m");
                return false;
        }

        if (n_handles == 0) {
                log_debug("No PCI devices found, not scanning for VirtIO console.");
                return false;
        }

        log_debug("Found %zu PCI devices, scanning for VirtIO console...", n_handles);

        size_t n_virtio_console = 0;

        for (size_t i = 0; i < n_handles; i++) {
                EFI_PCI_IO_PROTOCOL *pci_io = NULL;

                if (BS->HandleProtocol(handles[i], MAKE_GUID_PTR(EFI_PCI_IO_PROTOCOL), (void **) &pci_io) != EFI_SUCCESS)
                        continue;

                /* Read PCI vendor ID and device ID (at offsets 0x00 and 0x02 in PCI config space) */
                uint16_t pci_id[2] = {};
                if (pci_io->Pci.Read(pci_io, EfiPciIoWidthUint16, /* offset= */ 0x00, /* count= */ 2, pci_id) != EFI_SUCCESS)
                        continue;

                log_debug("PCI device %zu: vendor=%04x device=%04x", i, pci_id[0], pci_id[1]);

                if (pci_id[0] == PCI_VENDOR_ID_REDHAT && pci_id[1] == PCI_DEVICE_ID_VIRTIO_CONSOLE)
                        n_virtio_console++;

                if (n_virtio_console > 1) {
                        log_debug("There is more than one VirtIO console PCI device, cannot determine which one is the console.");
                        return false;
                }
        }

        if (n_virtio_console == 0) {
                log_debug("No VirtIO console PCI device found.");
                return false;
        }

        log_debug("Found exactly one VirtIO console PCI device.");
        return true;
}

static bool has_graphics_output(void) {
        EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
        EFI_STATUS err;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL), NULL, (void **) &gop);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "No EFI Graphics Output Protocol found: %m");
                return false;
        }

        log_debug("EFI Graphics Output Protocol found.");
        return true;
}

#if defined(__i386__) || defined(__x86_64__)

/* Walk the device path looking for a UART console and determine the COM port index from the
 * ACPI device path node. On x86, the Linux kernel assigns fixed ttyS indices based on I/O port
 * addresses (see arch/x86/include/asm/serial.h):
 *
 *   ttyS0=0x3F8, ttyS1=0x2F8, ttyS2=0x3E8, ttyS3=0x2E8
 *
 * On standard PC firmware, the ACPI UID for PNP0501 (16550 UART) maps directly to the COM port
 * index: UID 0 = COM1 (0x3F8) = ttyS0, UID 1 = COM2 (0x2F8) = ttyS1, etc.
 *
 * Returns EFI_SUCCESS and sets *ret_index on success, or EFI_NOT_FOUND if no PNP0501 UART
 * was found. */
static EFI_STATUS device_path_get_uart_index(const EFI_DEVICE_PATH *dp, uint32_t *ret_index) {
        assert(ret_index);

        for (const EFI_DEVICE_PATH *node = dp; !device_path_is_end(node); node = device_path_next_node(node))
                if (node->Type == ACPI_DEVICE_PATH &&
                    node->SubType == ACPI_DP &&
                    node->Length >= sizeof(ACPI_HID_DEVICE_PATH)) {
                        const ACPI_HID_DEVICE_PATH *acpi = (const ACPI_HID_DEVICE_PATH *) node;
                        if (acpi->HID == EISA_PNP_ID(0x0501)) {
                                *ret_index = acpi->UID;
                                return EFI_SUCCESS;
                        }
                }

        return EFI_NOT_FOUND;
}

/* Check if the console output is a serial UART. If so, determine the COM port index from the
 * ACPI device path so we can pass the correct console= device to the kernel. */
static EFI_STATUS find_serial_console_index(uint32_t *ret_index) {
        assert(ret_index);

        /* First try the ConOut handle directly. */
        EFI_DEVICE_PATH *dp = NULL;
        if (BS->HandleProtocol(ST->ConsoleOutHandle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp) == EFI_SUCCESS) {
                _cleanup_free_ char16_t *dp_str = NULL;
                (void) device_path_to_str(dp, &dp_str);
                log_debug("ConOut device path: %ls", strempty(dp_str));

                if (device_path_get_uart_index(dp, ret_index) == EFI_SUCCESS) {
                        log_debug("ConOut is a serial console (port index %u).", *ret_index);
                        return EFI_SUCCESS;
                }

                log_debug("ConOut device path does not contain a PNP0501 UART node.");
                return EFI_NOT_FOUND;
        }

        /* ConOut handle has no device path (e.g. ConSplitter virtual handle). Enumerate all
         * text output handles and check if any of them is a serial console. */
        log_debug("ConOut handle has no device path, enumerating text output handles...");

        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles = 0;
        if (BS->LocateHandleBuffer(
                        ByProtocol,
                        MAKE_GUID_PTR(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL),
                        NULL,
                        &n_handles,
                        &handles) != EFI_SUCCESS) {
                log_debug("Failed to enumerate text output handles.");
                return EFI_NOT_FOUND;
        }

        bool found = false;

        for (size_t i = 0; i < n_handles; i++) {
                dp = NULL;
                if (BS->HandleProtocol(handles[i], MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp) != EFI_SUCCESS)
                        continue;

                _cleanup_free_ char16_t *dp_str = NULL;
                (void) device_path_to_str(dp, &dp_str);
                log_debug("Text output handle %zu device path: %ls", i, strempty(dp_str));

                uint32_t index;
                if (device_path_get_uart_index(dp, &index) != EFI_SUCCESS)
                        continue;

                log_debug("Text output handle %zu is a serial console (port index %u).", i, index);

                if (found && *ret_index != index) {
                        log_debug("Multiple serial consoles with different port indices found, cannot determine which one to use.");
                        return EFI_NOT_FOUND;
                }

                *ret_index = index;
                found = true;
        }

        if (!found) {
                log_debug("No serial console found among text output handles.");
                return EFI_NOT_FOUND;
        }

        return EFI_SUCCESS;
}

static const char16_t *serial_console_arg(uint32_t index) {
        /* Use the uart I/O port address format (see Documentation/admin-guide/kernel-parameters.txt)
         * instead of ttyS names. This addresses the 8250/16550 UART at the specified I/O port
         * directly and switches to the matching ttyS device later. The I/O port addresses for
         * the standard COM ports are fixed (see arch/x86/include/asm/serial.h), and the ACPI UID
         * for PNP0501 maps directly to the COM port index. */
        static const char16_t *const table[] = {
                u"console=uart,io,0x3f8",  /* COM1 */
                u"console=uart,io,0x2f8",  /* COM2 */
                u"console=uart,io,0x3e8",  /* COM3 */
                u"console=uart,io,0x2e8",  /* COM4 */
        };

        if (index >= ELEMENTSOF(table))
                return NULL;

        return table[index];
}

#endif /* __i386__ || __x86_64__ */

/* If there's no console= in the command line yet, try to detect the appropriate console device.
 *
 * Detection order:
 * 1. If exactly one VirtIO console PCI device exists -> console=hvc0
 * 2. If there's graphical output (GOP) -> don't add console=, the kernel defaults are fine
 * 3. On x86, if exactly one serial console exists -> console=uart,io,<addr>
 * 4. Otherwise -> don't add console=, let the user handle it
 *
 * VirtIO console takes priority since it's explicitly configured by the VMM. Graphics is
 * checked before serial to avoid accidentally redirecting output away from a graphical
 * console by adding a serial console= argument.
 *
 * Serial console auto-detection is restricted to x86 where ACPI PNP0501 UIDs map to fixed
 * I/O port addresses for 8250/16550 UARTs. On non-x86 (e.g. ARM), serial device indices are
 * assigned dynamically, and the kernel has its own console auto-detection mechanisms
 * (DT stdout-path, etc.).
 *
 * Not TPM-measured because the value is deterministically derived from firmware-reported
 * hardware state (PCI device enumeration, GOP presence, serial device paths). */
void cmdline_append_console(char16_t **cmdline) {
        assert(cmdline);

        if (*cmdline && (efi_fnmatch(u"console=*", *cmdline) || efi_fnmatch(u"* console=*", *cmdline))) {
                log_debug("Kernel command line already contains console=, not adding one.");
                return;
        }

        const char16_t *console_arg = NULL;

        if (has_virtio_console_pci_device())
                console_arg = u"console=hvc0";
        else if (has_graphics_output()) {
                log_debug("Graphical output available, not adding console= to kernel command line.");
                return;
        }
#if defined(__i386__) || defined(__x86_64__)
        else {
                uint32_t serial_index;
                if (find_serial_console_index(&serial_index) == EFI_SUCCESS)
                        console_arg = serial_console_arg(serial_index);
        }
#endif

        if (!console_arg) {
                log_debug("Cannot determine console type, not adding console= to kernel command line.");
                return;
        }

        log_debug("Appending %ls to kernel command line.", console_arg);

        _cleanup_free_ char16_t *old = TAKE_PTR(*cmdline);
        if (isempty(old))
                *cmdline = xstrdup16(console_arg);
        else
                *cmdline = xasprintf("%ls %ls", old, console_arg);
}
