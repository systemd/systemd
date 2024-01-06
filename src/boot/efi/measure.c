/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if ENABLE_TPM

#include "macro-fundamental.h"
#include "measure.h"
#include "memory-util-fundamental.h"
#include "proto/tcg.h"
#include "tpm2-pcr.h"
#include "util.h"

static EFI_STATUS tpm1_measure_to_pcr_and_event_log(
                const EFI_TCG_PROTOCOL *tcg,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                size_t buffer_size,
                const char16_t *description) {

        _cleanup_free_ TCG_PCR_EVENT *tcg_event = NULL;
        EFI_PHYSICAL_ADDRESS event_log_last;
        uint32_t event_number = 1;
        size_t desc_len;

        assert(tcg);
        assert(description);

        desc_len = strsize16(description);
        tcg_event = xmalloc(offsetof(TCG_PCR_EVENT, Event) + desc_len);
        *tcg_event = (TCG_PCR_EVENT) {
                .EventSize = desc_len,
                .PCRIndex = pcrindex,
                .EventType = EV_IPL,
        };
        memcpy(tcg_event->Event, description, desc_len);

        return tcg->HashLogExtendEvent(
                        (EFI_TCG_PROTOCOL *) tcg,
                        buffer, buffer_size,
                        TCG_ALG_SHA,
                        tcg_event,
                        &event_number,
                        &event_log_last);
}

static EFI_STATUS tpm2_measure_to_pcr_and_tagged_event_log(
                EFI_TCG2_PROTOCOL *tcg,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                uint64_t buffer_size,
                uint32_t event_id,
                const char16_t *description) {

        _cleanup_free_ struct event {
                EFI_TCG2_EVENT tcg_event;
                EFI_TCG2_TAGGED_EVENT tcg_tagged_event;
        } _packed_ *event = NULL;
        size_t desc_len, event_size;

        assert(tcg);
        assert(description);

        desc_len = strsize16(description);
        event_size = offsetof(EFI_TCG2_EVENT, Event) + offsetof(EFI_TCG2_TAGGED_EVENT, Event) + desc_len;

        event = xmalloc(event_size);
        *event = (struct event) {
                .tcg_event = (EFI_TCG2_EVENT) {
                        .Size = event_size,
                        .Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER),
                        .Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION,
                        .Header.PCRIndex = pcrindex,
                        .Header.EventType = EV_EVENT_TAG,
                },
                .tcg_tagged_event = {
                        .EventId = event_id,
                        .EventSize = desc_len,
                },
        };
        memcpy(event->tcg_tagged_event.Event, description, desc_len);

        return tcg->HashLogExtendEvent(
                        tcg,
                        0,
                        buffer, buffer_size,
                        &event->tcg_event);
}

static EFI_STATUS tpm2_measure_to_pcr_and_event_log(
                EFI_TCG2_PROTOCOL *tcg,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                uint64_t buffer_size,
                const char16_t *description) {

        _cleanup_free_ EFI_TCG2_EVENT *tcg_event = NULL;
        size_t desc_len;

        assert(tcg);
        assert(description);

        /* NB: We currently record everything as EV_IPL. Which sucks, because it makes it hard to
         * recognize from the event log which of the events are ours. Measurement logs are kinda API hence
         * this is hard to change for existing, established events. But for future additions, let's use
         * EV_EVENT_TAG instead, with a tag of our choosing that makes clear what precisely we are measuring
         * here. */

        desc_len = strsize16(description);
        tcg_event = xmalloc(offsetof(EFI_TCG2_EVENT, Event) + desc_len);
        *tcg_event = (EFI_TCG2_EVENT) {
                .Size = offsetof(EFI_TCG2_EVENT, Event) + desc_len,
                .Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER),
                .Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION,
                .Header.PCRIndex = pcrindex,
                .Header.EventType = EV_IPL,
        };

        memcpy(tcg_event->Event, description, desc_len);

        return tcg->HashLogExtendEvent(
                        tcg,
                        0,
                        buffer, buffer_size,
                        tcg_event);
}

static EFI_TCG_PROTOCOL *tcg1_interface_check(void) {
        EFI_PHYSICAL_ADDRESS event_log_location, event_log_last_entry;
        EFI_TCG_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        EFI_STATUS err;
        uint32_t features;
        EFI_TCG_PROTOCOL *tcg;
        void *tcg_raw;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_TCG_PROTOCOL), NULL, &tcg_raw);
        if (err != EFI_SUCCESS)
                return NULL;
        
        tcg = tcg_raw;
        err = tcg->StatusCheck(
                        tcg,
                        &capability,
                        &features,
                        &event_log_location,
                        &event_log_last_entry);
        if (err != EFI_SUCCESS)
                return NULL;

        if (capability.TPMDeactivatedFlag)
                return NULL;

        if (!capability.TPMPresentFlag)
                return NULL;

        return tcg;
}

static EFI_TCG2_PROTOCOL *tcg2_interface_check(void) {
        EFI_TCG2_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        EFI_STATUS err;
        EFI_TCG2_PROTOCOL *tcg;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_TCG2_PROTOCOL), NULL, (void **) &tcg);
        if (err != EFI_SUCCESS)
                return NULL;

        err = tcg->GetCapability(tcg, &capability);
        if (err != EFI_SUCCESS)
                return NULL;

        if (capability.StructureVersion.Major == 1 &&
            capability.StructureVersion.Minor == 0) {
                EFI_TCG_BOOT_SERVICE_CAPABILITY *caps_1_0 =
                        (EFI_TCG_BOOT_SERVICE_CAPABILITY*) &capability;
                if (caps_1_0->TPMPresentFlag)
                        return tcg;
        }

        if (!capability.TPMPresentFlag)
                return NULL;

        return tcg;
}

bool tpm_present(void) {
        return tcg2_interface_check() || tcg1_interface_check();
}

EFI_STATUS tpm_log_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        EFI_TCG2_PROTOCOL *tpm2;
        EFI_STATUS err;

        assert(description || pcrindex == UINT32_MAX);

        /* If EFI_SUCCESS is returned, will initialize ret_measured to true if we actually measured
         * something, or false if measurement was turned off. */

        if (pcrindex == UINT32_MAX) { /* PCR disabled? */
                if (ret_measured)
                        *ret_measured = false;

                return EFI_SUCCESS;
        }

        tpm2 = tcg2_interface_check();
        if (tpm2)
                err = tpm2_measure_to_pcr_and_event_log(tpm2, pcrindex, buffer, buffer_size, description);
        else {
                EFI_TCG_PROTOCOL *tpm1;

                tpm1 = tcg1_interface_check();
                if (tpm1)
                        err = tpm1_measure_to_pcr_and_event_log(tpm1, pcrindex, buffer, buffer_size, description);
                else {
                        /* No active TPM found, so don't return an error */

                        if (ret_measured)
                                *ret_measured = false;

                        return EFI_SUCCESS;
                }
        }

        if (err == EFI_SUCCESS && ret_measured)
                *ret_measured = true;

        return err;
}

EFI_STATUS tpm_log_tagged_event(
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                size_t buffer_size,
                uint32_t event_id,
                const char16_t *description,
                bool *ret_measured) {

        EFI_TCG2_PROTOCOL *tpm2;
        EFI_STATUS err;

        assert(description || pcrindex == UINT32_MAX);
        assert(event_id > 0);

        /* If EFI_SUCCESS is returned, will initialize ret_measured to true if we actually measured
         * something, or false if measurement was turned off. */

        tpm2 = tcg2_interface_check();
        if (!tpm2 || pcrindex == UINT32_MAX) { /* PCR disabled? */
                if (ret_measured)
                        *ret_measured = false;

                return EFI_SUCCESS;
        }

        err = tpm2_measure_to_pcr_and_tagged_event_log(tpm2, pcrindex, buffer, buffer_size, event_id, description);
        if (err == EFI_SUCCESS && ret_measured)
                *ret_measured = true;

        return err;
}

EFI_STATUS tpm_log_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char *description, bool *ret_measured) {
        _cleanup_free_ char16_t *c = NULL;

        if (description)
                c = xstr8_to_16(description);

        return tpm_log_event(pcrindex, buffer, buffer_size, c, ret_measured);
}

EFI_STATUS tpm_log_load_options(const char16_t *load_options, bool *ret_measured) {
        bool measured = false;
        EFI_STATUS err;

        /* Measures a load options string into the TPM2, i.e. the kernel command line */

        err = tpm_log_event(
                        TPM2_PCR_KERNEL_CONFIG,
                        POINTER_TO_PHYSICAL_ADDRESS(load_options),
                        strsize16(load_options),
                        load_options,
                        &measured);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err,
                                "Unable to add load options (i.e. kernel command) line measurement to PCR %i: %m",
                                TPM2_PCR_KERNEL_CONFIG);

        if (ret_measured)
                *ret_measured = measured;

        return EFI_SUCCESS;
}

#endif
