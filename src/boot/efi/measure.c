/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if ENABLE_TPM

#include <efi.h>
#include <efilib.h>

#include "macro-fundamental.h"
#include "measure.h"
#include "missing_efi.h"

static EFI_STATUS tpm1_measure_to_pcr_and_event_log(const EFI_TCG *tcg, UINT32 pcrindex, const EFI_PHYSICAL_ADDRESS buffer,
                                                    UINTN buffer_size, const CHAR16 *description) {
        EFI_STATUS status;
        TCG_PCR_EVENT *tcg_event;
        UINT32 event_number;
        EFI_PHYSICAL_ADDRESS event_log_last;
        UINTN desc_len;

        assert(tcg);
        assert(description);

        desc_len = StrSize(description);
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

        assert(tcg);
        assert(description);

        desc_len = StrSize(description);
        tcg_event = AllocateZeroPool(sizeof(*tcg_event) - sizeof(tcg_event->Event) + desc_len);

        if (!tcg_event)
                return EFI_OUT_OF_RESOURCES;

        tcg_event->Size = sizeof(*tcg_event) - sizeof(tcg_event->Event) + desc_len;
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
        EFI_STATUS status;
        EFI_TCG *tcg;
        TCG_BOOT_SERVICE_CAPABILITY capability;
        UINT32 features;
        EFI_PHYSICAL_ADDRESS event_log_location;
        EFI_PHYSICAL_ADDRESS event_log_last_entry;

        status = LibLocateProtocol((EFI_GUID*) EFI_TCG_GUID, (void **) &tcg);

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

static EFI_TCG2 * tcg2_interface_check(void) {
        EFI_STATUS status;
        EFI_TCG2 *tcg;
        EFI_TCG2_BOOT_SERVICE_CAPABILITY capability;

        status = LibLocateProtocol((EFI_GUID*) EFI_TCG2_GUID, (void **) &tcg);

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

        assert(description);

        tpm2 = tcg2_interface_check();
        if (tpm2)
                return tpm2_measure_to_pcr_and_event_log(tpm2, pcrindex, buffer, buffer_size, description);

        tpm1 = tcg1_interface_check();
        if (tpm1)
                return tpm1_measure_to_pcr_and_event_log(tpm1, pcrindex, buffer, buffer_size, description);

        /* No active TPM found, so don't return an error */
        return EFI_SUCCESS;
}

#endif
