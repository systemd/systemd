/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_HII_DATABASE_PROTOCOL_GUID \
        GUID_DEF(0xef9fc172, 0xa1b2, 0x4693, 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42)

typedef void *EFI_HII_HANDLE;

typedef struct {
        EFI_GUID PackageListGuid;
        uint32_t PackageLength;
} EFI_HII_PACKAGE_LIST_HEADER;

typedef struct _packed_ {
        uint32_t LengthAndType; /* Length:24 | Type:8 (little-endian) */
} EFI_HII_PACKAGE_HEADER;

typedef size_t EFI_HII_DATABASE_NOTIFY_TYPE;

typedef EFI_STATUS (EFIAPI *EFI_HII_DATABASE_NOTIFY)(
                uint8_t PackageType,
                EFI_GUID *PackageGuid,
                EFI_HII_PACKAGE_HEADER *Package,
                EFI_HII_HANDLE Handle,
                EFI_HII_DATABASE_NOTIFY_TYPE NotifyType);

typedef struct EFI_HII_DATABASE_PROTOCOL EFI_HII_DATABASE_PROTOCOL;

struct EFI_HII_DATABASE_PROTOCOL {
        EFI_STATUS (EFIAPI *NewPackageList)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HII_PACKAGE_LIST_HEADER *PackageList,
                        EFI_HANDLE DriverHandle,
                        EFI_HII_HANDLE *Handle);

        EFI_STATUS (EFIAPI *RemovePackageList)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HII_HANDLE Handle);

        EFI_STATUS (EFIAPI *UpdatePackageList)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HII_HANDLE Handle,
                        EFI_HII_PACKAGE_LIST_HEADER *PackageList);

        EFI_STATUS (EFIAPI *ListPackageLists)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        uint8_t PackageType,
                        EFI_GUID *PackageGuid,
                        size_t *HandleBufferLength,
                        EFI_HII_HANDLE *Handle);

        EFI_STATUS (EFIAPI *ExportPackageLists)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HII_HANDLE Handle,
                        size_t *BufferSize,
                        EFI_HII_PACKAGE_LIST_HEADER *Buffer);

        EFI_STATUS (EFIAPI *RegisterPackageNotify)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        uint8_t PackageType,
                        EFI_GUID *PackageGuid,
                        EFI_HII_DATABASE_NOTIFY PackageNotifyFn,
                        EFI_HII_DATABASE_NOTIFY_TYPE NotifyType,
                        EFI_HANDLE *NotifyHandle);

        EFI_STATUS (EFIAPI *UnregisterPackageNotify)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HANDLE NotificationHandle);

        EFI_STATUS (EFIAPI *FindKeyboardLayouts)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        uint16_t *KeyGuidBufferLength,
                        EFI_GUID *KeyGuidBuffer);

        EFI_STATUS (EFIAPI *GetKeyboardLayout)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_GUID *KeyGuid,
                        uint16_t *KeyboardLayoutLength,
                        void *KeyboardLayout);

        EFI_STATUS (EFIAPI *SetKeyboardLayout)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_GUID *KeyGuid);

        EFI_STATUS (EFIAPI *GetPackageListHandle)(
                        EFI_HII_DATABASE_PROTOCOL *This,
                        EFI_HII_HANDLE PackageListHandle,
                        EFI_HANDLE *DriverHandle);
};

/* EFI_HII_KEYBOARD_LAYOUT and EFI_KEY_DESCRIPTOR are packed: LayoutDescriptorStringOffset follows
 * a 16-byte EFI_GUID at offset 2, so it is at offset 18 — *not* a natural 4-byte alignment. */
typedef struct _packed_ {
        uint16_t LayoutLength;
        EFI_GUID Guid;
        uint32_t LayoutDescriptorStringOffset;
        uint8_t DescriptorCount;
        /* EFI_KEY_DESCRIPTOR Descriptors[DescriptorCount] follows here, then at
         * LayoutDescriptorStringOffset (from the start of this struct) the description-string bundle. */
} EFI_HII_KEYBOARD_LAYOUT;

typedef struct _packed_ {
        uint32_t Key;
        char16_t Unicode;
        char16_t ShiftedUnicode;
        char16_t AltGrUnicode;
        char16_t ShiftedAltGrUnicode;
        uint16_t Modifier;
        uint16_t AffectedAttribute;
} EFI_KEY_DESCRIPTOR;

/* The description-string bundle that LayoutDescriptorStringOffset points to. After DescriptionCount,
 * each of the DescriptionCount entries is laid out as:
 *
 *   CHAR16 Language[];           // RFC 4646 tag, terminated by the Space below (no NUL)
 *   CHAR16 Space;                // U+0020
 *   CHAR16 DescriptionString[];  // NUL-terminated UTF-16 description
 *
 * Despite what the UEFI spec text says, Language is encoded as UTF-16 (CHAR16) in practice — see EDK2
 * MdeModulePkg/Bus/Usb/UsbKbDxe/KeyBoard.h USB_KEYBOARD_LAYOUT_PACK_BIN. */
typedef struct _packed_ {
        uint16_t DescriptionCount;
        char16_t Strings[];
} EFI_DESCRIPTION_STRING_BUNDLE;
