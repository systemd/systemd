/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if ENABLE_TPM

#include <efi.h>
#include <efilib.h>

#include "macro-fundamental.h"
#include "measure.h"
#include "missing_efi.h"
#include "util.h"

static EFI_STATUS tpm1_measure_to_pcr_and_event_log(
                const EFI_TCG *tcg,
                UINT32 pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                UINTN buffer_size,
                const CHAR16 *description) {

        _cleanup_freepool_ TCG_PCR_EVENT *tcg_event = NULL;
        EFI_PHYSICAL_ADDRESS event_log_last;
        UINT32 event_number = 1;
        UINTN desc_len;

        assert(tcg);
        assert(description);

        desc_len = StrSize(description);
        tcg_event = AllocateZeroPool(OFFSETOF(TCG_PCR_EVENT, Event) + desc_len);
        if (!tcg_event)
                return EFI_OUT_OF_RESOURCES;

        *tcg_event = (TCG_PCR_EVENT) {
                .EventSize = desc_len,
                .PCRIndex = pcrindex,
                .EventType = EV_IPL,
        };
        CopyMem(tcg_event->Event, description, desc_len);

        return tcg->HashLogExtendEvent(
                        (EFI_TCG *) tcg,
                        buffer, buffer_size,
                        TCG_ALG_SHA,
                        tcg_event,
                        &event_number,
                        &event_log_last);
}

static EFI_STATUS tpm2_measure_to_pcr_and_event_log(
                EFI_TCG2 *tcg,
                UINT32 pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                UINT64 buffer_size,
                const CHAR16 *description) {

        _cleanup_freepool_ EFI_TCG2_EVENT *tcg_event = NULL;
        UINTN desc_len;

        assert(tcg);
        assert(description);

        desc_len = StrSize(description);
        tcg_event = AllocateZeroPool(OFFSETOF(EFI_TCG2_EVENT, Event) + desc_len);
        if (!tcg_event)
                return EFI_OUT_OF_RESOURCES;

        *tcg_event = (EFI_TCG2_EVENT) {
                .Size = OFFSETOF(EFI_TCG2_EVENT, Event) + desc_len,
                .Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER),
                .Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION,
                .Header.PCRIndex = pcrindex,
                .Header.EventType = EV_IPL,
        };

        CopyMem(tcg_event->Event, description, desc_len);

        return tcg->HashLogExtendEvent(
                        tcg,
                        0,
                        buffer, buffer_size,
                        tcg_event);
}

static EFI_TCG *tcg1_interface_check(void) {
        EFI_PHYSICAL_ADDRESS event_log_location, event_log_last_entry;
        TCG_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        EFI_STATUS status;
        UINT32 features;
        EFI_TCG *tcg;

        status = LibLocateProtocol((EFI_GUID*) EFI_TCG_GUID, (void **) &tcg);
        if (EFI_ERROR(status))
                return NULL;

        status = tcg->StatusCheck(
                        tcg,
                        &capability,
                        &features,
                        &event_log_location,
                        &event_log_last_entry);
        if (EFI_ERROR(status))
                return NULL;

        if (capability.TPMDeactivatedFlag)
                return NULL;

        if (!capability.TPMPresentFlag)
                return NULL;

        return tcg;
}

static EFI_TCG2 * tcg2_interface_check(void) {
        EFI_TCG2_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        EFI_STATUS status;
        EFI_TCG2 *tcg;

        status = LibLocateProtocol((EFI_GUID*) EFI_TCG2_GUID, (void **) &tcg);
        if (EFI_ERROR(status))
                return NULL;

        status = tcg->GetCapability(tcg, &capability);
        if (EFI_ERROR(status))
                return NULL;

        if (capability.StructureVersion.Major == 1 &&
            capability.StructureVersion.Minor == 0) {
                TCG_BOOT_SERVICE_CAPABILITY *caps_1_0 =
                        (TCG_BOOT_SERVICE_CAPABILITY*) &capability;
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

EFI_STATUS tpm_log_load_options(const CHAR16 *load_options) {
        EFI_STATUS err;

        /* Measures a load options string into the TPM2, i.e. the kernel command line */

        err = tpm_log_event(TPM_PCR_INDEX_KERNEL_PARAMETERS,
                            POINTER_TO_PHYSICAL_ADDRESS(load_options),
                            StrSize(load_options), load_options);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Unable to add load options (i.e. kernel command) line measurement: %r", err);

        return EFI_SUCCESS;
}

#endif
