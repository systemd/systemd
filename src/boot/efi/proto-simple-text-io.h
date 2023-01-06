/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID \
        GUID_DEF(0x387477c1, 0x69c7, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
#define EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID \
        GUID_DEF(0xdd9e7534, 0x7762, 0x4698, 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa)
#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID \
        GUID_DEF(0x387477c2, 0x69c7, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_SHIFT_STATE_VALID     0x80000000
#define EFI_RIGHT_SHIFT_PRESSED   0x00000001
#define EFI_LEFT_SHIFT_PRESSED    0x00000002
#define EFI_RIGHT_CONTROL_PRESSED 0x00000004
#define EFI_LEFT_CONTROL_PRESSED  0x00000008
#define EFI_RIGHT_ALT_PRESSED     0x00000010
#define EFI_LEFT_ALT_PRESSED      0x00000020
#define EFI_RIGHT_LOGO_PRESSED    0x00000040
#define EFI_LEFT_LOGO_PRESSED     0x00000080
#define EFI_MENU_KEY_PRESSED      0x00000100
#define EFI_SYS_REQ_PRESSED       0x00000200

#define EFI_TOGGLE_STATE_VALID 0x80
#define EFI_KEY_STATE_EXPOSED  0x40
#define EFI_SCROLL_LOCK_ACTIVE 0x01
#define EFI_NUM_LOCK_ACTIVE    0x02
#define EFI_CAPS_LOCK_ACTIVE   0x04

enum {
        EFI_BLACK        = 0x00,
        EFI_BLUE         = 0x01,
        EFI_GREEN        = 0x02,
        EFI_CYAN         = EFI_BLUE | EFI_GREEN,
        EFI_RED          = 0x04,
        EFI_MAGENTA      = EFI_BLUE | EFI_RED,
        EFI_BROWN        = EFI_GREEN | EFI_RED,
        EFI_LIGHTGRAY    = EFI_BLUE | EFI_GREEN | EFI_RED,
        EFI_BRIGHT       = 0x08,
        EFI_DARKGRAY     = EFI_BLACK | EFI_BRIGHT,
        EFI_LIGHTBLUE    = EFI_BLUE | EFI_BRIGHT,
        EFI_LIGHTGREEN   = EFI_GREEN | EFI_BRIGHT,
        EFI_LIGHTCYAN    = EFI_CYAN | EFI_BRIGHT,
        EFI_LIGHTRED     = EFI_RED | EFI_BRIGHT,
        EFI_LIGHTMAGENTA = EFI_MAGENTA | EFI_BRIGHT,
        EFI_YELLOW       = EFI_BROWN | EFI_BRIGHT,
        EFI_WHITE        = EFI_BLUE | EFI_GREEN | EFI_RED | EFI_BRIGHT,
};

#define EFI_TEXT_ATTR(fg, bg) ((fg) | ((bg) << 4))
#define EFI_TEXT_ATTR_SWAP(c) EFI_TEXT_ATTR(((c) & 0xf0) >> 4, (c) & 0xf)

enum {
        SCAN_NULL = 0x00,
        SCAN_UP = 0x01,
        SCAN_DOWN = 0x02,
        SCAN_RIGHT = 0x03,
        SCAN_LEFT = 0x04,
        SCAN_HOME = 0x05,
        SCAN_END = 0x06,
        SCAN_INSERT = 0x07,
        SCAN_DELETE = 0x08,
        SCAN_PAGE_UP = 0x09,
        SCAN_PAGE_DOWN = 0x0A,
        SCAN_F1 = 0x0B,
        SCAN_F2 = 0x0C,
        SCAN_F3 = 0x0D,
        SCAN_F4 = 0x0E,
        SCAN_F5 = 0x0F,
        SCAN_F6 = 0x10,
        SCAN_F7 = 0x11,
        SCAN_F8 = 0x12,
        SCAN_F9 = 0x13,
        SCAN_F10 = 0x14,
        SCAN_F11 = 0x15,
        SCAN_F12 = 0x16,
        SCAN_ESC = 0x17,
        SCAN_PAUSE = 0x48,
        SCAN_F13 = 0x68,
        SCAN_F14 = 0x69,
        SCAN_F15 = 0x6A,
        SCAN_F16 = 0x6B,
        SCAN_F17 = 0x6C,
        SCAN_F18 = 0x6D,
        SCAN_F19 = 0x6E,
        SCAN_F20 = 0x6F,
        SCAN_F21 = 0x70,
        SCAN_F22 = 0x71,
        SCAN_F23 = 0x72,
        SCAN_F24 = 0x73,
        SCAN_MUTE = 0x7F,
        SCAN_VOLUME_UP = 0x80,
        SCAN_VOLUME_DOWN = 0x81,
        SCAN_BRIGHTNESS_UP = 0x100,
        SCAN_BRIGHTNESS_DOWN = 0x101,
        SCAN_SUSPEND = 0x102,
        SCAN_HIBERNATE = 0x103,
        SCAN_TOGGLE_DISPLAY = 0x104,
        SCAN_RECOVERY = 0x105,
        SCAN_EJECT = 0x106,
};

typedef struct {
        uint16_t ScanCode;
        char16_t UnicodeChar;
} EFI_INPUT_KEY;

typedef struct {
        uint32_t KeyShiftState;
        uint8_t KeyToggleState;
} EFI_KEY_STATE;

typedef struct {
        EFI_INPUT_KEY Key;
        EFI_KEY_STATE KeyState;
} EFI_KEY_DATA;

struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
        EFI_STATUS (EFIAPI *Reset)(
                        EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                        bool ExtendedVerification);
        EFI_STATUS (EFIAPI *ReadKeyStroke)(
                        EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                        EFI_INPUT_KEY *Key);
        EFI_EVENT WaitForKey;
};

typedef struct EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;
struct EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL {
        EFI_STATUS (EFIAPI *Reset)(
                        EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                        bool ExtendedVerification);
        EFI_STATUS (EFIAPI *ReadKeyStrokeEx)(
                        EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
                        EFI_KEY_DATA *KeyData);
        EFI_EVENT WaitForKeyEx;
        void *SetState;
        void *RegisterKeyNotify;
        void *UnregisterKeyNotify;
};

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
        EFI_STATUS (EFIAPI *Reset)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        bool ExtendedVerification);
        EFI_STATUS (EFIAPI *OutputString)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        char16_t *String);
        EFI_STATUS (EFIAPI *TestString)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        char16_t *String);
        EFI_STATUS (EFIAPI *QueryMode)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        size_t ModeNumber,
                        size_t *Columns,
                        size_t *Rows);
        EFI_STATUS (EFIAPI *SetMode)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        size_t ModeNumber);
        EFI_STATUS (EFIAPI *SetAttribute)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        size_t Attribute);
        EFI_STATUS (EFIAPI *ClearScreen)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);
        EFI_STATUS (EFIAPI *SetCursorPosition)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        size_t Column,
                        size_t Row);
        EFI_STATUS (EFIAPI *EnableCursor)(
                        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                        bool Visible);
        struct {
                int32_t MaxMode;
                int32_t Mode;
                int32_t Attribute;
                int32_t CursorColumn;
                int32_t CursorRow;
                bool CursorVisible;
        } *Mode;
};
