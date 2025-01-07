/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "efi-fundamental.h"
#include "macro-fundamental.h"

#if SD_BOOT
/* uchar.h/wchar.h are not suitable for freestanding environments. */
typedef __WCHAR_TYPE__ wchar_t;
typedef __CHAR16_TYPE__ char16_t;
typedef __CHAR32_TYPE__ char32_t;

/* Let's be paranoid and do some sanity checks. */
assert_cc(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
assert_cc(__STDC_HOSTED__ == 0);
assert_cc(sizeof(bool) == 1);
assert_cc(sizeof(uint8_t) == 1);
assert_cc(sizeof(uint16_t) == 2);
assert_cc(sizeof(uint32_t) == 4);
assert_cc(sizeof(uint64_t) == 8);
assert_cc(sizeof(wchar_t) == 2);
assert_cc(sizeof(char16_t) == 2);
assert_cc(sizeof(char32_t) == 4);
assert_cc(sizeof(size_t) == sizeof(void *));
assert_cc(sizeof(size_t) == sizeof(uintptr_t));
assert_cc(alignof(bool) == 1);
assert_cc(alignof(uint8_t) == 1);
assert_cc(alignof(uint16_t) == 2);
assert_cc(alignof(uint32_t) == 4);
assert_cc(alignof(uint64_t) == 8);
assert_cc(alignof(wchar_t) == 2);
assert_cc(alignof(char16_t) == 2);
assert_cc(alignof(char32_t) == 4);

#  if defined(__x86_64__) && defined(__ILP32__)
#    error Building for x64 requires -m64 on x32 ABI.
#  endif
#else
#  include <uchar.h>
#  include <wchar.h>
#endif

/* We use size_t/ssize_t to represent UEFI UINTN/INTN. */
typedef size_t EFI_STATUS;
typedef intptr_t ssize_t;

typedef void* EFI_HANDLE;
typedef void* EFI_EVENT;
typedef size_t EFI_TPL;
typedef uint64_t EFI_LBA;
typedef uint64_t EFI_PHYSICAL_ADDRESS;

#if defined(__x86_64__) && !defined(__ILP32__)
#  define EFIAPI __attribute__((ms_abi))
#else
#  define EFIAPI
#endif

#if __SIZEOF_POINTER__ == 8
#  define EFI_ERROR_MASK 0x8000000000000000ULL
#elif __SIZEOF_POINTER__ == 4
#  define EFI_ERROR_MASK 0x80000000ULL
#else
#  error Unsupported pointer size
#endif

#define EFI_STATUS_IS_ERROR(s) (((s) & EFI_ERROR_MASK) != 0)

#define EFIWARN(s) ((EFI_STATUS) s)
#define EFIERR(s) ((EFI_STATUS) (s | EFI_ERROR_MASK))

#define EFI_SUCCESS               EFIWARN(0)
#define EFI_WARN_UNKNOWN_GLYPH    EFIWARN(1)
#define EFI_WARN_DELETE_FAILURE   EFIWARN(2)
#define EFI_WARN_WRITE_FAILURE    EFIWARN(3)
#define EFI_WARN_BUFFER_TOO_SMALL EFIWARN(4)
#define EFI_WARN_STALE_DATA       EFIWARN(5)
#define EFI_WARN_FILE_SYSTEM      EFIWARN(6)
#define EFI_WARN_RESET_REQUIRED   EFIWARN(7)

#define EFI_LOAD_ERROR           EFIERR(1)
#define EFI_INVALID_PARAMETER    EFIERR(2)
#define EFI_UNSUPPORTED          EFIERR(3)
#define EFI_BAD_BUFFER_SIZE      EFIERR(4)
#define EFI_BUFFER_TOO_SMALL     EFIERR(5)
#define EFI_NOT_READY            EFIERR(6)
#define EFI_DEVICE_ERROR         EFIERR(7)
#define EFI_WRITE_PROTECTED      EFIERR(8)
#define EFI_OUT_OF_RESOURCES     EFIERR(9)
#define EFI_VOLUME_CORRUPTED     EFIERR(10)
#define EFI_VOLUME_FULL          EFIERR(11)
#define EFI_NO_MEDIA             EFIERR(12)
#define EFI_MEDIA_CHANGED        EFIERR(13)
#define EFI_NOT_FOUND            EFIERR(14)
#define EFI_ACCESS_DENIED        EFIERR(15)
#define EFI_NO_RESPONSE          EFIERR(16)
#define EFI_NO_MAPPING           EFIERR(17)
#define EFI_TIMEOUT              EFIERR(18)
#define EFI_NOT_STARTED          EFIERR(19)
#define EFI_ALREADY_STARTED      EFIERR(20)
#define EFI_ABORTED              EFIERR(21)
#define EFI_ICMP_ERROR           EFIERR(22)
#define EFI_TFTP_ERROR           EFIERR(23)
#define EFI_PROTOCOL_ERROR       EFIERR(24)
#define EFI_INCOMPATIBLE_VERSION EFIERR(25)
#define EFI_SECURITY_VIOLATION   EFIERR(26)
#define EFI_CRC_ERROR            EFIERR(27)
#define EFI_END_OF_MEDIA         EFIERR(28)
#define EFI_ERROR_RESERVED_29    EFIERR(29)
#define EFI_ERROR_RESERVED_30    EFIERR(30)
#define EFI_END_OF_FILE          EFIERR(31)
#define EFI_INVALID_LANGUAGE     EFIERR(32)
#define EFI_COMPROMISED_DATA     EFIERR(33)
#define EFI_IP_ADDRESS_CONFLICT  EFIERR(34)
#define EFI_HTTP_ERROR           EFIERR(35)

/* These allow MAKE_GUID_PTR() to work without requiring an extra _GUID in the passed name. We want to
 * keep the GUID definitions in line with the UEFI spec. */
#define EFI_GLOBAL_VARIABLE_GUID EFI_GLOBAL_VARIABLE
#define EFI_FILE_INFO_GUID EFI_FILE_INFO_ID

#define EFI_CUSTOM_MODE_ENABLE_GUID \
        GUID_DEF(0xc076ec0c, 0x7028, 0x4399, 0xa0, 0x72, 0x71, 0xee, 0x5c, 0x44, 0x8b, 0x9f)

#define EVT_TIMER                         0x80000000U
#define EVT_RUNTIME                       0x40000000U
#define EVT_NOTIFY_WAIT                   0x00000100U
#define EVT_NOTIFY_SIGNAL                 0x00000200U
#define EVT_SIGNAL_EXIT_BOOT_SERVICES     0x00000201U
#define EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE 0x60000202U

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x01U
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x02U
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL       0x04U
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x08U
#define EFI_OPEN_PROTOCOL_BY_DRIVER           0x10U
#define EFI_OPEN_PROTOCOL_EXCLUSIVE           0x20U

#define EFI_VARIABLE_NON_VOLATILE                          0x01U
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x02U
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x04U
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                 0x08U
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            0x10U
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x20U
#define EFI_VARIABLE_APPEND_WRITE                          0x40U
#define EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS         0x80U

#define EFI_TIME_ADJUST_DAYLIGHT 0x001U
#define EFI_TIME_IN_DAYLIGHT     0x002U
#define EFI_UNSPECIFIED_TIMEZONE 0x7FFU

#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI                   0x01U
#define EFI_OS_INDICATIONS_TIMESTAMP_REVOCATION            0x02U
#define EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED 0x04U
#define EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED           0x08U
#define EFI_OS_INDICATIONS_CAPSULE_RESULT_VAR_SUPPORTED    0x10U
#define EFI_OS_INDICATIONS_START_OS_RECOVERY               0x20U
#define EFI_OS_INDICATIONS_START_PLATFORM_RECOVERY         0x40U
#define EFI_OS_INDICATIONS_JSON_CONFIG_DATA_REFRESH        0x80U

#define EFI_PAGE_SIZE 4096U
#define EFI_SIZE_TO_PAGES(s) (((s) + 0xFFFU) >> 12U)

/* These are common enough to warrant forward declaration. We also give them a
 * shorter name for convenience. */
typedef struct EFI_FILE_PROTOCOL EFI_FILE;
typedef struct EFI_DEVICE_PATH_PROTOCOL EFI_DEVICE_PATH;

typedef struct EFI_SIMPLE_TEXT_INPUT_PROTOCOL EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef enum {
        TimerCancel,
        TimerPeriodic,
        TimerRelative,
} EFI_TIMER_DELAY;

typedef enum {
        AllocateAnyPages,
        AllocateMaxAddress,
        AllocateAddress,
        MaxAllocateType,
} EFI_ALLOCATE_TYPE;

typedef enum {
        EfiReservedMemoryType,
        EfiLoaderCode,
        EfiLoaderData,
        EfiBootServicesCode,
        EfiBootServicesData,
        EfiRuntimeServicesCode,
        EfiRuntimeServicesData,
        EfiConventionalMemory,
        EfiUnusableMemory,
        EfiACPIReclaimMemory,
        EfiACPIMemoryNVS,
        EfiMemoryMappedIO,
        EfiMemoryMappedIOPortSpace,
        EfiPalCode,
        EfiPersistentMemory,
        EfiUnacceptedMemoryType,
        EfiMaxMemoryType,
} EFI_MEMORY_TYPE;

typedef enum {
        AllHandles,
        ByRegisterNotify,
        ByProtocol,
} EFI_LOCATE_SEARCH_TYPE;

typedef enum {
        EfiResetCold,
        EfiResetWarm,
        EfiResetShutdown,
        EfiResetPlatformSpecific,
} EFI_RESET_TYPE;

typedef struct {
        uint32_t Resolution;
        uint32_t Accuracy;
        bool SetsToZero;
} EFI_TIME_CAPABILITIES;

typedef struct {
        uint64_t Signature;
        uint32_t Revision;
        uint32_t HeaderSize;
        uint32_t CRC32;
        uint32_t Reserved;
} EFI_TABLE_HEADER;

typedef struct {
        EFI_TABLE_HEADER Hdr;
        void *RaiseTPL;
        void *RestoreTPL;
        EFI_STATUS (EFIAPI *AllocatePages)(
                        EFI_ALLOCATE_TYPE Type,
                        EFI_MEMORY_TYPE MemoryType,
                        size_t Pages,
                        EFI_PHYSICAL_ADDRESS *Memory);
        EFI_STATUS (EFIAPI *FreePages)(
                        EFI_PHYSICAL_ADDRESS Memory,
                        size_t Pages);
        void *GetMemoryMap;
        EFI_STATUS (EFIAPI *AllocatePool)(
                        EFI_MEMORY_TYPE PoolType,
                        size_t Size,
                        void **Buffer);
        EFI_STATUS (EFIAPI *FreePool)(void *Buffer);
        EFI_STATUS (EFIAPI *CreateEvent)(
                        uint32_t Type,
                        EFI_TPL NotifyTpl,
                        void *NotifyFunction,
                        void *NotifyContext,
                        EFI_EVENT *Event);
        EFI_STATUS (EFIAPI *SetTimer)(
                        EFI_EVENT Event,
                        EFI_TIMER_DELAY Type,
                        uint64_t TriggerTime);
        EFI_STATUS (EFIAPI *WaitForEvent)(
                        size_t NumberOfEvents,
                        EFI_EVENT *Event,
                        size_t *Index);
        void *SignalEvent;
        EFI_STATUS (EFIAPI *CloseEvent)(EFI_EVENT Event);
        EFI_STATUS (EFIAPI *CheckEvent)(EFI_EVENT Event);
        void *InstallProtocolInterface;
        EFI_STATUS (EFIAPI *ReinstallProtocolInterface)(
                        EFI_HANDLE Handle,
                        EFI_GUID *Protocol,
                        void *OldInterface,
                        void *NewInterface);
        void *UninstallProtocolInterface;
        EFI_STATUS (EFIAPI *HandleProtocol)(
                        EFI_HANDLE Handle,
                        EFI_GUID *Protocol,
                        void **Interface);
        void *Reserved;
        void *RegisterProtocolNotify;
        EFI_STATUS (EFIAPI *LocateHandle)(
                        EFI_LOCATE_SEARCH_TYPE SearchType,
                        EFI_GUID *Protocol,
                        void *SearchKey,
                        size_t *BufferSize,
                        EFI_HANDLE *Buffer);
        EFI_STATUS (EFIAPI *LocateDevicePath)(
                        EFI_GUID *Protocol,
                        EFI_DEVICE_PATH **DevicePath,
                        EFI_HANDLE *Device);
        EFI_STATUS (EFIAPI *InstallConfigurationTable)(
                        EFI_GUID *Guid,
                        void *Table);
        EFI_STATUS (EFIAPI *LoadImage)(
                        bool BootPolicy,
                        EFI_HANDLE ParentImageHandle,
                        EFI_DEVICE_PATH *DevicePath,
                        void *SourceBuffer,
                        size_t SourceSize,
                        EFI_HANDLE *ImageHandle);
        EFI_STATUS (EFIAPI *StartImage)(
                        EFI_HANDLE ImageHandle,
                        size_t *ExitDataSize,
                        char16_t **ExitData);
        EFI_STATUS (EFIAPI *Exit)(
                        EFI_HANDLE ImageHandle,
                        EFI_STATUS ExitStatus,
                        size_t ExitDataSize,
                        char16_t *ExitData);
        EFI_STATUS (EFIAPI *UnloadImage)(EFI_HANDLE ImageHandle);
        void *ExitBootServices;
        EFI_STATUS (EFIAPI *GetNextMonotonicCount)(uint64_t *Count);
        EFI_STATUS (EFIAPI *Stall)(size_t Microseconds);
        EFI_STATUS (EFIAPI *SetWatchdogTimer)(
                        size_t Timeout,
                        uint64_t WatchdogCode,
                        size_t DataSize,
                        char16_t *WatchdogData);
        EFI_STATUS (EFIAPI *ConnectController)(
                        EFI_HANDLE ControllerHandle,
                        EFI_HANDLE *DriverImageHandle,
                        EFI_DEVICE_PATH *RemainingDevicePath,
                        bool Recursive);
        EFI_STATUS (EFIAPI *DisconnectController)(
                        EFI_HANDLE ControllerHandle,
                        EFI_HANDLE DriverImageHandle,
                        EFI_HANDLE ChildHandle);
        EFI_STATUS (EFIAPI *OpenProtocol)(
                        EFI_HANDLE Handle,
                        EFI_GUID *Protocol,
                        void **Interface,
                        EFI_HANDLE AgentHandle,
                        EFI_HANDLE ControllerHandle,
                        uint32_t Attributes);
        EFI_STATUS (EFIAPI *CloseProtocol)(
                        EFI_HANDLE Handle,
                        EFI_GUID *Protocol,
                        EFI_HANDLE AgentHandle,
                        EFI_HANDLE ControllerHandle);
        void *OpenProtocolInformation;
        EFI_STATUS (EFIAPI *ProtocolsPerHandle)(
                        EFI_HANDLE Handle,
                        EFI_GUID ***ProtocolBuffer,
                        size_t *ProtocolBufferCount);
        EFI_STATUS (EFIAPI *LocateHandleBuffer)(
                        EFI_LOCATE_SEARCH_TYPE SearchType,
                        EFI_GUID *Protocol,
                        void *SearchKey,
                        size_t *NoHandles,
                        EFI_HANDLE **Buffer);
        EFI_STATUS (EFIAPI *LocateProtocol)(
                        EFI_GUID *Protocol,
                        void *Registration,
                        void **Interface);
        EFI_STATUS (EFIAPI *InstallMultipleProtocolInterfaces)(EFI_HANDLE *Handle, ...);
        EFI_STATUS (EFIAPI *UninstallMultipleProtocolInterfaces)(EFI_HANDLE Handle, ...);
        EFI_STATUS (EFIAPI *CalculateCrc32)(
                        void *Data,
                        size_t DataSize,
                        uint32_t *Crc32);
        void (EFIAPI *CopyMem)(
                        void *Destination,
                        void *Source,
                        size_t Length);
        void (EFIAPI *SetMem)(
                        void *Buffer,
                        size_t Size,
                        uint8_t Value);
        void *CreateEventEx;
} EFI_BOOT_SERVICES;

typedef struct {
        EFI_TABLE_HEADER Hdr;
        EFI_STATUS (EFIAPI *GetTime)(
                        EFI_TIME *Time,
                        EFI_TIME_CAPABILITIES *Capabilities);
        EFI_STATUS (EFIAPI *SetTime)(EFI_TIME *Time);
        void *GetWakeupTime;
        void *SetWakeupTime;
        void *SetVirtualAddressMap;
        void *ConvertPointer;
        EFI_STATUS (EFIAPI *GetVariable)(
                        char16_t *VariableName,
                        EFI_GUID *VendorGuid,
                        uint32_t *Attributes,
                        size_t *DataSize,
                        void *Data);
        void *GetNextVariableName;
        EFI_STATUS (EFIAPI *SetVariable)(
                        char16_t *VariableName,
                        EFI_GUID *VendorGuid,
                        uint32_t Attributes,
                        size_t  DataSize,
                        void *Data);
        EFI_STATUS (EFIAPI *GetNextHighMonotonicCount)(uint32_t *HighCount);
        void (EFIAPI *ResetSystem)(
                        EFI_RESET_TYPE ResetType,
                        EFI_STATUS ResetStatus,
                        size_t DataSize,
                        void *ResetData);
        void *UpdateCapsule;
        void *QueryCapsuleCapabilities;
        void *QueryVariableInfo;
} EFI_RUNTIME_SERVICES;

typedef struct {
        EFI_TABLE_HEADER Hdr;
        char16_t *FirmwareVendor;
        uint32_t FirmwareRevision;
        EFI_HANDLE ConsoleInHandle;
        EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;
        EFI_HANDLE ConsoleOutHandle;
        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
        EFI_HANDLE StandardErrorHandle;
        EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
        EFI_RUNTIME_SERVICES *RuntimeServices;
        EFI_BOOT_SERVICES *BootServices;
        size_t NumberOfTableEntries;
        struct {
                EFI_GUID VendorGuid;
                void *VendorTable;
        } *ConfigurationTable;
} EFI_SYSTEM_TABLE;

extern EFI_SYSTEM_TABLE *ST;
extern EFI_BOOT_SERVICES *BS;
extern EFI_RUNTIME_SERVICES *RT;
