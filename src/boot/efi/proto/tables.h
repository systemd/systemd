/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_GLOBAL_VARIABLE \
        GUID_DEF(0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c)
#define EFI_IMAGE_SECURITY_DATABASE_GUID \
        GUID_DEF(0xd719b2cb, 0x3d3a, 0x4596, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f)

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
#define EFI_SIZE_TO_PAGES(s) ((s) + 0xFFFU) >> 12U

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
        uint16_t Year;
        uint8_t Month;
        uint8_t Day;
        uint8_t Hour;
        uint8_t Minute;
        uint8_t Second;
        uint8_t Pad1;
        uint32_t Nanosecond;
        int16_t TimeZone;
        uint8_t Daylight;
        uint8_t Pad2;
} EFI_TIME;

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
