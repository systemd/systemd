/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID \
        GUID_DEF(0x387477c1, 0x69c7, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
#define EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID \
        GUID_DEF(0xdd9e7534, 0x7762, 0x4698, 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa)
#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID \
        GUID_DEF(0x387477c2, 0x69c7, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_SHIFT_STATE_VALID     0x80000000U
#define EFI_RIGHT_SHIFT_PRESSED   0x00000001U
#define EFI_LEFT_SHIFT_PRESSED    0x00000002U
#define EFI_RIGHT_CONTROL_PRESSED 0x00000004U
#define EFI_LEFT_CONTROL_PRESSED  0x00000008U
#define EFI_RIGHT_ALT_PRESSED     0x00000010U
#define EFI_LEFT_ALT_PRESSED      0x00000020U
#define EFI_RIGHT_LOGO_PRESSED    0x00000040U
#define EFI_LEFT_LOGO_PRESSED     0x00000080U
#define EFI_MENU_KEY_PRESSED      0x00000100U
#define EFI_SYS_REQ_PRESSED       0x00000200U

#define EFI_TOGGLE_STATE_VALID 0x80U
#define EFI_KEY_STATE_EXPOSED  0x40U
#define EFI_SCROLL_LOCK_ACTIVE 0x01U
#define EFI_NUM_LOCK_ACTIVE    0x02U
#define EFI_CAPS_LOCK_ACTIVE   0x04U

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
#define EFI_TEXT_ATTR_SWAP(c) EFI_TEXT_ATTR(((c) & 0xF0U) >> 4, (c) & 0xFU)

enum {
        SCAN_NULL            = 0x000,
        SCAN_UP              = 0x001,
        SCAN_DOWN            = 0x002,
        SCAN_RIGHT           = 0x003,
        SCAN_LEFT            = 0x004,
        SCAN_HOME            = 0x005,
        SCAN_END             = 0x006,
        SCAN_INSERT          = 0x007,
        SCAN_DELETE          = 0x008,
        SCAN_PAGE_UP         = 0x009,
        SCAN_PAGE_DOWN       = 0x00A,
        SCAN_F1              = 0x00B,
        SCAN_F2              = 0x00C,
        SCAN_F3              = 0x00D,
        SCAN_F4              = 0x00E,
        SCAN_F5              = 0x00F,
        SCAN_F6              = 0x010,
        SCAN_F7              = 0x011,
        SCAN_F8              = 0x012,
        SCAN_F9              = 0x013,
        SCAN_F10             = 0x014,
        SCAN_F11             = 0x015,
        SCAN_F12             = 0x016,
        SCAN_ESC             = 0x017,
        SCAN_PAUSE           = 0x048,
        SCAN_F13             = 0x068,
        SCAN_F14             = 0x069,
        SCAN_F15             = 0x06A,
        SCAN_F16             = 0x06B,
        SCAN_F17             = 0x06C,
        SCAN_F18             = 0x06D,
        SCAN_F19             = 0x06E,
        SCAN_F20             = 0x06F,
        SCAN_F21             = 0x070,
        SCAN_F22             = 0x071,
        SCAN_F23             = 0x072,
        SCAN_F24             = 0x073,
        SCAN_MUTE            = 0x07F,
        SCAN_VOLUME_UP       = 0x080,
        SCAN_VOLUME_DOWN     = 0x081,
        SCAN_BRIGHTNESS_UP   = 0x100,
        SCAN_BRIGHTNESS_DOWN = 0x101,
        SCAN_SUSPEND         = 0x102,
        SCAN_HIBERNATE       = 0x103,
        SCAN_TOGGLE_DISPLAY  = 0x104,
        SCAN_RECOVERY        = 0x105,
        SCAN_EJECT           = 0x106,
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
