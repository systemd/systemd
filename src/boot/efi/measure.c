/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if ENABLE_TPM

#include "macro-fundamental.h"
#include "measure.h"
#include "memory-util-fundamental.h"
#include "proto/cc-measurement.h"
#include "proto/tcg.h"
#include "tpm2-pcr.h"
#include "util.h"

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

        /* New style stuff we log as EV_EVENT_TAG with a recognizable event tag. */

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

static EFI_STATUS tpm2_measure_to_pcr_and_ipl_event_log(
                EFI_TCG2_PROTOCOL *tcg,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                uint64_t buffer_size,
                const char16_t *description) {

        _cleanup_free_ EFI_TCG2_EVENT *tcg_event = NULL;
        size_t desc_len;

        assert(tcg);
        assert(description);

        /* We record older stuff as EV_IPL. Which sucks, because it makes it hard to recognize from the event
         * log which of the events are ours. Measurement logs are kinda API hence this is hard to change for
         * existing, established events. But for future additions, let's use EV_EVENT_TAG instead, with a tag
         * of our choosing that makes clear what precisely we are measuring here. See above. */

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

static EFI_STATUS cc_measure_to_mr_and_ipl_event_log(
                EFI_CC_MEASUREMENT_PROTOCOL *cc,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                uint64_t buffer_size,
                const char16_t *description) {

        _cleanup_free_ EFI_CC_EVENT *event = NULL;
        uint32_t mr;
        EFI_STATUS err;
        size_t desc_len;

        assert(cc);
        assert(description);

        /* MapPcrToMrIndex service provides callers information on
         * how the TPM PCR registers are mapped to the CC measurement
         * registers (MR) in the vendor implementation. */
        err = cc->MapPcrToMrIndex(cc, pcrindex, &mr);
        if (err != EFI_SUCCESS)
                return EFI_NOT_FOUND;

        desc_len = strsize16(description);
        event = xmalloc(offsetof(EFI_CC_EVENT, Event) + desc_len);
        *event = (EFI_CC_EVENT) {
                .Size = offsetof(EFI_CC_EVENT, Event) + desc_len,
                .Header.HeaderSize = sizeof(EFI_CC_EVENT_HEADER),
                .Header.HeaderVersion = EFI_CC_EVENT_HEADER_VERSION,
                .Header.MrIndex = mr,
                .Header.EventType = EV_IPL,
        };

        memcpy(event->Event, description, desc_len);

        return cc->HashLogExtendEvent(
                        cc,
                        0,
                        buffer,
                        buffer_size,
                        event);
}

static EFI_CC_MEASUREMENT_PROTOCOL *cc_interface_check(void) {
        EFI_CC_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        EFI_STATUS err;
        EFI_CC_MEASUREMENT_PROTOCOL *cc;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_CC_MEASUREMENT_PROTOCOL), NULL, (void **) &cc);
        if (err != EFI_SUCCESS)
                return NULL;

        err = cc->GetCapability(cc, &capability);
        if (err != EFI_SUCCESS)
                return NULL;

        if (!(capability.SupportedEventLogs & EFI_CC_EVENT_LOG_FORMAT_TCG_2))
                return NULL;

        return cc;
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
        return tcg2_interface_check();
}

static EFI_STATUS tcg2_log_ipl_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        EFI_TCG2_PROTOCOL *tpm2;
        EFI_STATUS err = EFI_SUCCESS;

        assert(ret_measured);

        tpm2 = tcg2_interface_check();
        if (!tpm2) {
                *ret_measured = false;
                return EFI_SUCCESS;
        }

        err = tpm2_measure_to_pcr_and_ipl_event_log(tpm2, pcrindex, buffer, buffer_size, description);
        if (err != EFI_SUCCESS)
                return err;

        *ret_measured = true;
        return EFI_SUCCESS;
}

static EFI_STATUS cc_log_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        EFI_CC_MEASUREMENT_PROTOCOL *cc;
        EFI_STATUS err = EFI_SUCCESS;

        assert(ret_measured);

        cc = cc_interface_check();
        if (!cc) {
                *ret_measured = false;
                return EFI_SUCCESS;
        }

        err = cc_measure_to_mr_and_ipl_event_log(cc, pcrindex, buffer, buffer_size, description);
        if (err != EFI_SUCCESS)
                return err;

        *ret_measured = true;
        return EFI_SUCCESS;
}

EFI_STATUS tpm_log_ipl_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        EFI_STATUS err;
        bool tpm_ret_measured, cc_ret_measured;

        assert(description || pcrindex == UINT32_MAX);

        /* If EFI_SUCCESS is returned, will initialize ret_measured to true if we actually measured
         * something, or false if measurement was turned off. */

        if (pcrindex == UINT32_MAX) { /* PCR disabled? */
                if (ret_measured)
                        *ret_measured = false;

                return EFI_SUCCESS;
        }

        /* Measure into both CC and TPM if both are available to avoid a problem like CVE-2021-42299 */
        err = cc_log_event(pcrindex, buffer, buffer_size, description, &cc_ret_measured);
        if (err != EFI_SUCCESS)
                return err;

        err = tcg2_log_ipl_event(pcrindex, buffer, buffer_size, description, &tpm_ret_measured);
        if (err != EFI_SUCCESS)
                return err;

        if (ret_measured)
                *ret_measured = tpm_ret_measured || cc_ret_measured;

        return EFI_SUCCESS;
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
        if (!err)
                return err;

        *ret_measured = true;
        return EFI_SUCCESS;
}

EFI_STATUS tpm_log_ipl_event_ascii(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char *description, bool *ret_measured) {
        _cleanup_free_ char16_t *c = NULL;

        if (description)
                c = xstr8_to_16(description);

        return tpm_log_ipl_event(pcrindex, buffer, buffer_size, c, ret_measured);
}

EFI_STATUS tpm_log_load_options(const char16_t *load_options, bool *ret_measured) {
        EFI_STATUS err;

        /* Measures a load options string into the TPM2, i.e. the kernel command line */

        err = tpm_log_ipl_event(
                        TPM2_PCR_KERNEL_CONFIG,
                        POINTER_TO_PHYSICAL_ADDRESS(load_options),
                        strsize16(load_options),
                        load_options,
                        ret_measured);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err,
                                "Unable to add load options (i.e. kernel command) line measurement to PCR %i: %m",
                                TPM2_PCR_KERNEL_CONFIG);

        return EFI_SUCCESS;
}

#endif
