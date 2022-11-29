/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efi.h>

#include "macro-fundamental.h"

/* gnu-efi 3.0.13 */
#ifndef EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID

#define EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID \
    { 0xdd9e7534, 0x7762, 0x4698, {0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa} }
#define SimpleTextInputExProtocol ((EFI_GUID)EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID)

#define EFI_SHIFT_STATE_VALID           0x80000000
#define EFI_RIGHT_SHIFT_PRESSED         0x00000001
#define EFI_LEFT_SHIFT_PRESSED          0x00000002
#define EFI_RIGHT_CONTROL_PRESSED       0x00000004
#define EFI_LEFT_CONTROL_PRESSED        0x00000008
#define EFI_RIGHT_ALT_PRESSED           0x00000010
#define EFI_LEFT_ALT_PRESSED            0x00000020
#define EFI_RIGHT_LOGO_PRESSED          0x00000040
#define EFI_LEFT_LOGO_PRESSED           0x00000080

struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_INPUT_RESET_EX)(
        struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
        BOOLEAN ExtendedVerification
);

typedef UINT8 EFI_KEY_TOGGLE_STATE;

typedef struct {
        UINT32 KeyShiftState;
        EFI_KEY_TOGGLE_STATE KeyToggleState;
} EFI_KEY_STATE;

typedef struct {
        EFI_INPUT_KEY Key;
        EFI_KEY_STATE KeyState;
} EFI_KEY_DATA;

typedef EFI_STATUS (EFIAPI *EFI_INPUT_READ_KEY_EX)(
        struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
        EFI_KEY_DATA *KeyData
);

typedef EFI_STATUS (EFIAPI *EFI_SET_STATE)(
        struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
        EFI_KEY_TOGGLE_STATE *KeyToggleState
);

typedef EFI_STATUS (EFIAPI *EFI_KEY_NOTIFY_FUNCTION)(
        EFI_KEY_DATA *KeyData
);

typedef EFI_STATUS (EFIAPI *EFI_REGISTER_KEYSTROKE_NOTIFY)(
        struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
        EFI_KEY_DATA KeyData,
        EFI_KEY_NOTIFY_FUNCTION KeyNotificationFunction,
        VOID **NotifyHandle
);

typedef EFI_STATUS (EFIAPI *EFI_UNREGISTER_KEYSTROKE_NOTIFY)(
        struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
        VOID *NotificationHandle
);

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL {
        EFI_INPUT_RESET_EX Reset;
        EFI_INPUT_READ_KEY_EX ReadKeyStrokeEx;
        EFI_EVENT WaitForKeyEx;
        EFI_SET_STATE SetState;
        EFI_REGISTER_KEYSTROKE_NOTIFY RegisterKeyNotify;
        EFI_UNREGISTER_KEYSTROKE_NOTIFY UnregisterKeyNotify;
} EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;

#endif

/* gnu-efi 3.0.14 */
#ifndef EFI_IMAGE_MACHINE_RISCV64
        #define EFI_IMAGE_MACHINE_RISCV64 0x5064
#endif

/* gnu-efi 3.0.14 */
#ifndef EFI_DTB_TABLE_GUID
#define EFI_DTB_TABLE_GUID \
        { 0xb1b621d5, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0} }
#define EfiDtbTableGuid ((EFI_GUID)EFI_DTB_TABLE_GUID)
#endif

#ifndef EFI_DT_FIXUP_PROTOCOL_GUID
#define EFI_DT_FIXUP_PROTOCOL_GUID \
        { 0xe617d64c, 0xfe08, 0x46da, {0xf4, 0xdc, 0xbb, 0xd5, 0x87, 0x0c, 0x73, 0x00} }
#define EfiDtFixupProtocol ((EFI_GUID)EFI_DT_FIXUP_PROTOCOL_GUID)

#define EFI_DT_FIXUP_PROTOCOL_REVISION 0x00010000

/* Add nodes and update properties */
#define EFI_DT_APPLY_FIXUPS    0x00000001
/*
 * Reserve memory according to the /reserved-memory node
 * and the memory reservation block
 */
#define EFI_DT_RESERVE_MEMORY  0x00000002

typedef struct _EFI_DT_FIXUP_PROTOCOL EFI_DT_FIXUP_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_DT_FIXUP) (
        IN EFI_DT_FIXUP_PROTOCOL *This,
        IN VOID                  *Fdt,
        IN OUT UINTN             *BufferSize,
        IN UINT32                Flags);

struct _EFI_DT_FIXUP_PROTOCOL {
        UINT64         Revision;
        EFI_DT_FIXUP   Fixup;
};

#endif

/* TCG EFI Protocol Specification */
#ifndef EFI_TCG_GUID

#define EFI_TCG_GUID \
        &(const EFI_GUID) { 0xf541796d, 0xa62e, 0x4954, { 0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd } }

typedef struct _TCG_VERSION {
        UINT8 Major;
        UINT8 Minor;
        UINT8 RevMajor;
        UINT8 RevMinor;
} TCG_VERSION;

typedef struct tdEFI_TCG2_VERSION {
        UINT8 Major;
        UINT8 Minor;
} EFI_TCG2_VERSION;

typedef struct _TCG_BOOT_SERVICE_CAPABILITY {
        UINT8 Size;
        struct _TCG_VERSION StructureVersion;
        struct _TCG_VERSION ProtocolSpecVersion;
        UINT8 HashAlgorithmBitmap;
        BOOLEAN TPMPresentFlag;
        BOOLEAN TPMDeactivatedFlag;
} TCG_BOOT_SERVICE_CAPABILITY;

typedef struct tdTREE_BOOT_SERVICE_CAPABILITY {
        UINT8 Size;
        EFI_TCG2_VERSION StructureVersion;
        EFI_TCG2_VERSION ProtocolVersion;
        UINT32 HashAlgorithmBitmap;
        UINT32 SupportedEventLogs;
        BOOLEAN TrEEPresentFlag;
        UINT16 MaxCommandSize;
        UINT16 MaxResponseSize;
        UINT32 ManufacturerID;
} TREE_BOOT_SERVICE_CAPABILITY;

typedef UINT32 TCG_ALGORITHM_ID;
#define TCG_ALG_SHA 0x00000004  // The SHA1 algorithm

#define SHA1_DIGEST_SIZE 20

typedef struct _TCG_DIGEST {
        UINT8 Digest[SHA1_DIGEST_SIZE];
} TCG_DIGEST;

#define EV_IPL 13

typedef struct _TCG_PCR_EVENT {
        UINT32 PCRIndex;
        UINT32 EventType;
        struct _TCG_DIGEST digest;
        UINT32 EventSize;
        UINT8 Event[1];
} TCG_PCR_EVENT;

INTERFACE_DECL(_EFI_TCG);

typedef EFI_STATUS(EFIAPI * EFI_TCG_STATUS_CHECK) (IN struct _EFI_TCG * This,
                                                   OUT struct _TCG_BOOT_SERVICE_CAPABILITY * ProtocolCapability,
                                                   OUT UINT32 * TCGFeatureFlags,
                                                   OUT EFI_PHYSICAL_ADDRESS * EventLogLocation,
                                                   OUT EFI_PHYSICAL_ADDRESS * EventLogLastEntry);

typedef EFI_STATUS(EFIAPI * EFI_TCG_HASH_ALL) (IN struct _EFI_TCG * This,
                                               IN UINT8 * HashData,
                                               IN UINT64 HashDataLen,
                                               IN TCG_ALGORITHM_ID AlgorithmId,
                                               IN OUT UINT64 * HashedDataLen, IN OUT UINT8 ** HashedDataResult);

typedef EFI_STATUS(EFIAPI * EFI_TCG_LOG_EVENT) (IN struct _EFI_TCG * This,
                                                IN struct _TCG_PCR_EVENT * TCGLogData,
                                                IN OUT UINT32 * EventNumber, IN UINT32 Flags);

typedef EFI_STATUS(EFIAPI * EFI_TCG_PASS_THROUGH_TO_TPM) (IN struct _EFI_TCG * This,
                                                          IN UINT32 TpmInputParameterBlockSize,
                                                          IN UINT8 * TpmInputParameterBlock,
                                                          IN UINT32 TpmOutputParameterBlockSize,
                                                          IN UINT8 * TpmOutputParameterBlock);

typedef EFI_STATUS(EFIAPI * EFI_TCG_HASH_LOG_EXTEND_EVENT) (IN struct _EFI_TCG * This,
                                                            IN EFI_PHYSICAL_ADDRESS HashData,
                                                            IN UINT64 HashDataLen,
                                                            IN TCG_ALGORITHM_ID AlgorithmId,
                                                            IN struct _TCG_PCR_EVENT * TCGLogData,
                                                            IN OUT UINT32 * EventNumber,
                                                            OUT EFI_PHYSICAL_ADDRESS * EventLogLastEntry);

typedef struct _EFI_TCG {
        EFI_TCG_STATUS_CHECK StatusCheck;
        EFI_TCG_HASH_ALL HashAll;
        EFI_TCG_LOG_EVENT LogEvent;
        EFI_TCG_PASS_THROUGH_TO_TPM PassThroughToTPM;
        EFI_TCG_HASH_LOG_EXTEND_EVENT HashLogExtendEvent;
} EFI_TCG;

#endif

/* TCG EFI Protocol Specification */
#ifndef EFI_TCG2_GUID

#define EFI_TCG2_GUID \
        &(const EFI_GUID) { 0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } }

typedef struct tdEFI_TCG2_PROTOCOL EFI_TCG2_PROTOCOL;

typedef UINT32 EFI_TCG2_EVENT_LOG_BITMAP;
typedef UINT32 EFI_TCG2_EVENT_LOG_FORMAT;
typedef UINT32 EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY {
        UINT8 Size;
        EFI_TCG2_VERSION StructureVersion;
        EFI_TCG2_VERSION ProtocolVersion;
        EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
        EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
        BOOLEAN TPMPresentFlag;
        UINT16 MaxCommandSize;
        UINT16 MaxResponseSize;
        UINT32 ManufacturerID;
        UINT32 NumberOfPCRBanks;
        EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;

#define EFI_TCG2_EVENT_HEADER_VERSION  1

typedef struct {
        UINT32 HeaderSize;
        UINT16 HeaderVersion;
        UINT32 PCRIndex;
        UINT32 EventType;
} _packed_ EFI_TCG2_EVENT_HEADER;

typedef struct tdEFI_TCG2_EVENT {
        UINT32 Size;
        EFI_TCG2_EVENT_HEADER Header;
        UINT8 Event[1];
} _packed_ EFI_TCG2_EVENT;

typedef EFI_STATUS(EFIAPI * EFI_TCG2_GET_CAPABILITY) (IN EFI_TCG2_PROTOCOL * This,
                                                      IN OUT EFI_TCG2_BOOT_SERVICE_CAPABILITY * ProtocolCapability);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_GET_EVENT_LOG) (IN EFI_TCG2_PROTOCOL * This,
                                                     IN EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
                                                     OUT EFI_PHYSICAL_ADDRESS * EventLogLocation,
                                                     OUT EFI_PHYSICAL_ADDRESS * EventLogLastEntry,
                                                     OUT BOOLEAN * EventLogTruncated);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_HASH_LOG_EXTEND_EVENT) (IN EFI_TCG2_PROTOCOL * This,
                                                             IN UINT64 Flags,
                                                             IN EFI_PHYSICAL_ADDRESS DataToHash,
                                                             IN UINT64 DataToHashLen, IN EFI_TCG2_EVENT * EfiTcgEvent);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_SUBMIT_COMMAND) (IN EFI_TCG2_PROTOCOL * This,
                                                      IN UINT32 InputParameterBlockSize,
                                                      IN UINT8 * InputParameterBlock,
                                                      IN UINT32 OutputParameterBlockSize, IN UINT8 * OutputParameterBlock);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_GET_ACTIVE_PCR_BANKS) (IN EFI_TCG2_PROTOCOL * This, OUT UINT32 * ActivePcrBanks);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_SET_ACTIVE_PCR_BANKS) (IN EFI_TCG2_PROTOCOL * This, IN UINT32 ActivePcrBanks);

typedef EFI_STATUS(EFIAPI * EFI_TCG2_GET_RESULT_OF_SET_ACTIVE_PCR_BANKS) (IN EFI_TCG2_PROTOCOL * This,
                                                                          OUT UINT32 * OperationPresent, OUT UINT32 * Response);

typedef struct tdEFI_TCG2_PROTOCOL {
        EFI_TCG2_GET_CAPABILITY GetCapability;
        EFI_TCG2_GET_EVENT_LOG GetEventLog;
        EFI_TCG2_HASH_LOG_EXTEND_EVENT HashLogExtendEvent;
        EFI_TCG2_SUBMIT_COMMAND SubmitCommand;
        EFI_TCG2_GET_ACTIVE_PCR_BANKS GetActivePcrBanks;
        EFI_TCG2_SET_ACTIVE_PCR_BANKS SetActivePcrBanks;
        EFI_TCG2_GET_RESULT_OF_SET_ACTIVE_PCR_BANKS GetResultOfSetActivePcrBanks;
} EFI_TCG2;

#endif

#ifndef EFI_LOAD_FILE2_PROTOCOL_GUID
#define EFI_LOAD_FILE2_PROTOCOL_GUID \
        {0x4006c0c1, 0xfcb3, 0x403e, {0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d} }
#define EfiLoadFile2Protocol ((EFI_GUID)EFI_LOAD_FILE2_PROTOCOL_GUID)
#endif

#define LINUX_INITRD_MEDIA_GUID \
        {0x5568e427, 0x68fc, 0x4f3d, {0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68} }

/* UEFI Platform Initialization (Vol2: DXE) */
#ifndef EFI_SECURITY_ARCH_PROTOCOL_GUID

#define EFI_SECURITY_ARCH_PROTOCOL_GUID \
        { 0xa46423e3, 0x4617, 0x49f1, { 0xb9, 0xff, 0xd1, 0xbf, 0xa9, 0x11, 0x58, 0x39 } }
#define EFI_SECURITY2_ARCH_PROTOCOL_GUID \
        { 0x94ab2f58, 0x1438, 0x4ef1, { 0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68 } }

typedef struct EFI_SECURITY_ARCH_PROTOCOL EFI_SECURITY_ARCH_PROTOCOL;
typedef struct EFI_SECURITY2_ARCH_PROTOCOL EFI_SECURITY2_ARCH_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_SECURITY_FILE_AUTHENTICATION_STATE)(
                const EFI_SECURITY_ARCH_PROTOCOL *This,
                uint32_t AuthenticationStatus,
                const EFI_DEVICE_PATH *File);

struct EFI_SECURITY_ARCH_PROTOCOL {
        EFI_SECURITY_FILE_AUTHENTICATION_STATE FileAuthenticationState;
};

typedef EFI_STATUS (EFIAPI *EFI_SECURITY2_FILE_AUTHENTICATION)(
                const EFI_SECURITY2_ARCH_PROTOCOL *This,
                const EFI_DEVICE_PATH *DevicePath,
                void *FileBuffer,
                UINTN FileSize,
                BOOLEAN BootPolicy);

struct EFI_SECURITY2_ARCH_PROTOCOL {
        EFI_SECURITY2_FILE_AUTHENTICATION FileAuthentication;
};

#endif

#ifndef EFI_CONSOLE_CONTROL_GUID

#define EFI_CONSOLE_CONTROL_GUID \
        &(const EFI_GUID) { 0xf42f7782, 0x12e, 0x4c12, { 0x99, 0x56, 0x49, 0xf9, 0x43, 0x4, 0xf7, 0x21 } }

struct _EFI_CONSOLE_CONTROL_PROTOCOL;

typedef enum {
        EfiConsoleControlScreenText,
        EfiConsoleControlScreenGraphics,
        EfiConsoleControlScreenMaxValue,
} EFI_CONSOLE_CONTROL_SCREEN_MODE;

typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE)(
        struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
        EFI_CONSOLE_CONTROL_SCREEN_MODE *Mode,
        BOOLEAN *UgaExists,
        BOOLEAN *StdInLocked
);

typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE)(
        struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
        EFI_CONSOLE_CONTROL_SCREEN_MODE Mode
);

typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN)(
        struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
        CHAR16 *Password
);

typedef struct _EFI_CONSOLE_CONTROL_PROTOCOL {
        EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE GetMode;
        EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE SetMode;
        EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN LockStdIn;
} EFI_CONSOLE_CONTROL_PROTOCOL;

#endif

#ifndef EFI_IMAGE_SECURITY_DATABASE_VARIABLE

#define EFI_IMAGE_SECURITY_DATABASE_VARIABLE \
        { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }}

#endif

#ifndef EFI_SHELL_PARAMETERS_PROTOCOL_GUID
#  define EFI_SHELL_PARAMETERS_PROTOCOL_GUID \
        { 0x752f3136, 0x4e16, 0x4fdc, { 0xa2, 0x2a, 0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca } }

typedef struct {
        CHAR16 **Argv;
        UINTN Argc;
        void *StdIn;
        void *StdOut;
        void *StdErr;
} EFI_SHELL_PARAMETERS_PROTOCOL;
#endif

#ifndef EFI_BOOT_MANAGER_POLICY_PROTOCOL_GUID
#define EFI_BOOT_MANAGER_POLICY_PROTOCOL_GUID \
        { 0xFEDF8E0C, 0xE147, 0x11E3, { 0x99, 0x03, 0xB8, 0xE8, 0x56, 0x2C, 0xBA, 0xFA } }
#define EFI_BOOT_MANAGER_POLICY_CONSOLE_GUID \
        { 0xCAB0E94C, 0xE15F, 0x11E3, { 0x91, 0x8D, 0xB8, 0xE8, 0x56, 0x2C, 0xBA, 0xFA } }

typedef struct EFI_BOOT_MANAGER_POLICY_PROTOCOL EFI_BOOT_MANAGER_POLICY_PROTOCOL;
struct EFI_BOOT_MANAGER_POLICY_PROTOCOL {
        UINT64 Revision;
        EFI_STATUS (EFIAPI *ConnectDevicePath)(
                EFI_BOOT_MANAGER_POLICY_PROTOCOL *This,
                EFI_DEVICE_PATH *DevicePath,
                BOOLEAN Recursive);
        EFI_STATUS (EFIAPI *ConnectDeviceClass)(
                EFI_BOOT_MANAGER_POLICY_PROTOCOL *This,
                EFI_GUID *Class);
};
#endif
