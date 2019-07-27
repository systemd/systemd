/* SPDX-License-Identifier: LGPL-2.1+ */

#if ENABLE_TPM

#include <efi.h>
#include <efilib.h>
#include "measure.h"

#define EFI_TCG_PROTOCOL_GUID { 0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd} }

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

#define EFI_TCG2_PROTOCOL_GUID {0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }}

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
} __attribute__((packed)) EFI_TCG2_EVENT_HEADER;

typedef struct tdEFI_TCG2_EVENT {
        UINT32 Size;
        EFI_TCG2_EVENT_HEADER Header;
        UINT8 Event[1];
} __attribute__((packed)) EFI_TCG2_EVENT;

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

static EFI_STATUS tpm1_measure_to_pcr_and_event_log(const EFI_TCG *tcg, UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer,
                                                    UINTN buffer_size, const CHAR16 *description) {
        EFI_STATUS status;
        TCG_PCR_EVENT *tcg_event;
        UINT32 event_number;
        EFI_PHYSICAL_ADDRESS event_log_last;
        UINTN desc_len;

        desc_len = (StrLen(description) + 1) * sizeof(CHAR16);

        tcg_event = AllocateZeroPool(desc_len + sizeof(TCG_PCR_EVENT));

        if (!tcg_event)
                return EFI_OUT_OF_RESOURCES;

        tcg_event->EventSize = desc_len;
        CopyMem((VOID *) & tcg_event->Event[0], (VOID *) description, desc_len);

        tcg_event->PCRIndex = pcrindex;
        tcg_event->EventType = EV_IPL;

        event_number = 1;
        status = uefi_call_wrapper(tcg->HashLogExtendEvent, 7,
                                   (EFI_TCG *) tcg, buffer, buffer_size, TCG_ALG_SHA, tcg_event, &event_number, &event_log_last);

        if (EFI_ERROR(status))
                return status;

        uefi_call_wrapper(BS->FreePool, 1, tcg_event);

        return EFI_SUCCESS;
}

static EFI_STATUS tpm2_measure_to_pcr_and_event_log(const EFI_TCG2 *tcg, UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer,
                                                    UINT64 buffer_size, const CHAR16 *description) {
        EFI_STATUS status;
        EFI_TCG2_EVENT *tcg_event;
        UINTN desc_len;

        desc_len = StrLen(description) * sizeof(CHAR16);

        tcg_event = AllocateZeroPool(sizeof(*tcg_event) - sizeof(tcg_event->Event) + desc_len + 1);

        if (!tcg_event)
                return EFI_OUT_OF_RESOURCES;

        tcg_event->Size = sizeof(*tcg_event) - sizeof(tcg_event->Event) + desc_len + 1;
        tcg_event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
        tcg_event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
        tcg_event->Header.PCRIndex = pcrindex;
        tcg_event->Header.EventType = EV_IPL;

        CopyMem((VOID *) tcg_event->Event, (VOID *) description, desc_len);

        status = uefi_call_wrapper(tcg->HashLogExtendEvent, 5, (EFI_TCG2 *) tcg, 0, buffer, (UINT64) buffer_size, tcg_event);

        uefi_call_wrapper(BS->FreePool, 1, tcg_event);

        if (EFI_ERROR(status))
                return status;

        return EFI_SUCCESS;
}

static EFI_TCG * tcg1_interface_check(void) {
        EFI_GUID tpm_guid = EFI_TCG_PROTOCOL_GUID;
        EFI_STATUS status;
        EFI_TCG *tcg;
        TCG_BOOT_SERVICE_CAPABILITY capability;
        UINT32 features;
        EFI_PHYSICAL_ADDRESS event_log_location;
        EFI_PHYSICAL_ADDRESS event_log_last_entry;

        status = LibLocateProtocol(&tpm_guid, (void **) &tcg);

        if (EFI_ERROR(status))
                return NULL;

        capability.Size = (UINT8) sizeof(capability);
        status = uefi_call_wrapper(tcg->StatusCheck, 5, tcg, &capability, &features, &event_log_location, &event_log_last_entry);

        if (EFI_ERROR(status))
                return NULL;

        if (capability.TPMDeactivatedFlag)
                return NULL;

        if (!capability.TPMPresentFlag)
                return NULL;

        return tcg;
}

static EFI_TCG2 * tcg2_interface_check() {
        EFI_GUID tpm2_guid = EFI_TCG2_PROTOCOL_GUID;
        EFI_STATUS status;
        EFI_TCG2 *tcg;
        EFI_TCG2_BOOT_SERVICE_CAPABILITY capability;

        status = LibLocateProtocol(&tpm2_guid, (void **) &tcg);

        if (EFI_ERROR(status))
                return NULL;

        capability.Size = (UINT8) sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY);
        status = uefi_call_wrapper(tcg->GetCapability, 2, tcg, &capability);

        if (EFI_ERROR(status))
                return NULL;

        if (capability.StructureVersion.Major == 1 &&
            capability.StructureVersion.Minor == 0) {
                TCG_BOOT_SERVICE_CAPABILITY *caps_1_0;
                caps_1_0 = (TCG_BOOT_SERVICE_CAPABILITY *)&capability;
                if (caps_1_0->TPMPresentFlag)
                        return tcg;
        }

        if (!capability.TPMPresentFlag)
                return NULL;

        return tcg;
}

EFI_STATUS tpm_log_event(UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer, UINTN buffer_size, const CHAR16 *description) {
        EFI_TCG *tpm1;
        EFI_TCG2 *tpm2;

        tpm2 = tcg2_interface_check();
        if (tpm2) {
                return tpm2_measure_to_pcr_and_event_log(tpm2, pcrindex, buffer, buffer_size, description);
        }

        tpm1 = tcg1_interface_check();
        if (tpm1)
                return tpm1_measure_to_pcr_and_event_log(tpm1, pcrindex, buffer, buffer_size, description);

        /* No active TPM found, so don't return an error */
        return EFI_SUCCESS;
}

#endif
