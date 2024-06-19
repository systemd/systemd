/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <uchar.h>

#include "tpm2-util.h"

/* Definitions as per "TCG PC Client Specific Platform Firmware Profile Specification"
 * (https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/),
 * section 10.4.1 "Event Types" (at least in version 1.05 Revision 23 of the spec) */
#ifndef EV_PREBOOT_CERT
#define EV_PREBOOT_CERT                  UINT32_C(0x00000000)
#define EV_POST_CODE                     UINT32_C(0x00000001)
#define EV_NO_ACTION                     UINT32_C(0x00000003)
#define EV_SEPARATOR                     UINT32_C(0x00000004)
#define EV_ACTION                        UINT32_C(0x00000005)
#define EV_EVENT_TAG                     UINT32_C(0x00000006)
#define EV_S_CRTM_CONTENTS               UINT32_C(0x00000007)
#define EV_S_CRTM_VERSION                UINT32_C(0x00000008)
#define EV_CPU_MICROCODE                 UINT32_C(0x00000009)
#define EV_PLATFORM_CONFIG_FLAGS         UINT32_C(0x0000000a)
#define EV_TABLE_OF_DEVICES              UINT32_C(0x0000000b)
#define EV_COMPACT_HASH                  UINT32_C(0x0000000c)
#define EV_IPL                           UINT32_C(0x0000000d)
#define EV_IPL_PARTITION_DATA            UINT32_C(0x0000000e)
#define EV_NONHOST_CODE                  UINT32_C(0x0000000f)
#define EV_NONHOST_CONFIG                UINT32_C(0x00000010)
#define EV_NONHOST_INFO                  UINT32_C(0x00000011)
#define EV_OMIT_BOOT_DEVICE_EVENTS       UINT32_C(0x00000012)
#define EV_EFI_EVENT_BASE                UINT32_C(0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG    UINT32_C(0x80000001)
#define EV_EFI_VARIABLE_BOOT             UINT32_C(0x80000002)
#define EV_EFI_BOOT_SERVICES_APPLICATION UINT32_C(0x80000003)
#define EV_EFI_BOOT_SERVICES_DRIVER      UINT32_C(0x80000004)
#define EV_EFI_RUNTIME_SERVICES_DRIVER   UINT32_C(0x80000005)
#define EV_EFI_GPT_EVENT                 UINT32_C(0x80000006)
#define EV_EFI_ACTION                    UINT32_C(0x80000007)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB    UINT32_C(0x80000008)
#define EV_EFI_HANDOFF_TABLES            UINT32_C(0x80000009)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB2   UINT32_C(0x8000000A)
#define EV_EFI_HANDOFF_TABLES2           UINT32_C(0x8000000B)
#define EV_EFI_VARIABLE_BOOT2            UINT32_C(0x8000000C)
#define EV_EFI_HCRTM_EVENT               UINT32_C(0x80000010)
#define EV_EFI_VARIABLE_AUTHORITY        UINT32_C(0x800000E0)
#define EV_EFI_SPDM_FIRMWARE_BLOB        UINT32_C(0x800000E1)
#define EV_EFI_SPDM_FIRMWARE_CONFIG      UINT32_C(0x800000E2)
#endif

/* Defined in drivers/firmware/efi/libstub/efistub.h in the Linux kernel sources */
#ifndef INITRD_EVENT_TAG_ID
#define INITRD_EVENT_TAG_ID UINT32_C(0x8F3B22EC)
#endif

#ifndef LOAD_OPTIONS_EVENT_TAG_ID
#define LOAD_OPTIONS_EVENT_TAG_ID UINT32_C(0x8F3B22ED)
#endif

const char* tpm2_log_event_type_to_string(uint32_t type) _const_;

#if HAVE_TPM2

/* UEFI event log data structures */
typedef struct _packed_ TCG_PCClientPCREvent {
        uint32_t pcrIndex;
        uint32_t eventType;
        uint8_t digest[20];
        uint32_t eventDataSize;
        uint32_t event[];
} TCG_PCClientPCREvent;

typedef struct _packed_ packed_TPMT_HA {
        uint16_t hashAlg;
        TPMU_HA digest;
} packed_TPMT_HA;

typedef struct _packed_ packed_TPML_DIGEST_VALUES {
        uint32_t count;
        packed_TPMT_HA digests[];
} packed_TPML_DIGEST_VALUES;

typedef struct _packed_ TCG_PCR_EVENT2 {
        uint32_t pcrIndex;
        uint32_t eventType;
        packed_TPML_DIGEST_VALUES digests;
        /* … */
} TCG_PCR_EVENT2;

typedef struct _packed_ TCG_EfiSpecIdEventAlgorithmSize {
        uint16_t algorithmId;
        uint16_t digestSize;
} TCG_EfiSpecIdEventAlgorithmSize;

typedef struct _packed_ tdTCG_EfiSpecIdEvent {
        uint8_t signature[16];
        uint32_t platformClass;
        uint8_t specVersionMinor;
        uint8_t specVersionMajor;
        uint8_t specErrata;
        uint8_t uintnSize;
        uint32_t numberOfAlgorithms;
        TCG_EfiSpecIdEventAlgorithmSize digestSizes[];
        /* … */
} TCG_EfiSpecIDEvent;

typedef struct _packed_ UEFI_VARIABLE_DATA {
        uint8_t variableName[16];
        uint64_t unicodeNameLength;
        uint64_t variableDataLength;
        char16_t unicodeName[];
        /* … */
} UEFI_VARIABLE_DATA;

typedef struct _packed_ TCG_PCClientTaggedEvent{
        uint32_t taggedEventID;
        uint32_t taggedEventDataSize;
        uint8_t taggedEventData[];
} TCG_PCClientTaggedEvent;

typedef struct _packed_ packed_EFI_DEVICE_PATH {
        uint8_t type;
        uint8_t subType;
        uint16_t length;
        uint8_t path[];
} packed_EFI_DEVICE_PATH;

typedef struct _packed_ UEFI_IMAGE_LOAD_EVENT {
        uint64_t imageLocationInMemory;
        uint64_t imageLengthInMemory;
        uint64_t imageLinkTimeAddress;
        uint64_t lengthOfDevicePath;
        packed_EFI_DEVICE_PATH devicePath[];
} UEFI_IMAGE_LOAD_EVENT;

typedef struct _packed_ UEFI_PLATFORM_FIRMWARE_BLOB {
        uint64_t blobBase;
        uint64_t blobLength;
} UEFI_PLATFORM_FIRMWARE_BLOB;

#endif
