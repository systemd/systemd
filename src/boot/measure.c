/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if ENABLE_TPM

#include "efi-log.h"
#include "iovec-util.h"
#include "measure.h"
#include "proto/cc-measurement.h"
#include "proto/tcg.h"
#include "sha256.h"
#include "tpm2-pcr.h"
#include "util.h"

static EFI_STATUS tpm2_measure_to_pcr_and_tagged_event_log(
                EFI_TCG2_PROTOCOL *tcg,
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                uint64_t buffer_size,
                uint32_t event_id,
                const char16_t *description) {

        _cleanup_free_ union event {
                EFI_TCG2_EVENT tcg_event;
                EFI_TCG2_TAGGED_EVENT tcg_tagged_event;
        } *event = NULL;
        size_t desc_len, event_size;

        assert(tcg);
        assert(description);

        /* New style stuff we log as EV_EVENT_TAG with a recognizable event tag. */

        desc_len = strsize16(description);
        event_size = offsetof(EFI_TCG2_TAGGED_EVENT, Event) + desc_len;

        event = xmalloc(event_size);
        event->tcg_tagged_event = (EFI_TCG2_TAGGED_EVENT) {
                .Size = event_size,
                .Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER),
                .Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION,
                .Header.PCRIndex = pcrindex,
                .Header.EventType = EV_EVENT_TAG,
                .EventId = event_id,
                .EventSize = desc_len,
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

static EFI_TCG2_PROTOCOL* tcg2_interface_check(EFI_TCG2_VERSION *ret_version) {
        EFI_STATUS err;

        EFI_TCG2_PROTOCOL *tcg;
        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_TCG2_PROTOCOL), NULL, (void **) &tcg);
        if (err != EFI_SUCCESS)
                return NULL;

        EFI_TCG2_BOOT_SERVICE_CAPABILITY capability = {
                .Size = sizeof(capability),
        };
        err = tcg->GetCapability(tcg, &capability);
        if (err != EFI_SUCCESS)
                return NULL;

        assert(capability.Size >= endoffsetof_field(EFI_TCG2_BOOT_SERVICE_CAPABILITY, Size));

        /* This is a paranoia check, given these fields existed from day one of the spec. But the spec also
         * suggests checking the structure size before accessing any fields, hence let's do so, for extra
         * paranoia. */
        if (capability.Size < CONST_MAX(endoffsetof_field(EFI_TCG2_BOOT_SERVICE_CAPABILITY, TPMPresentFlag),
                                        endoffsetof_field(EFI_TCG2_BOOT_SERVICE_CAPABILITY, ProtocolVersion)))
                return NULL;

        if (!capability.TPMPresentFlag)
                return NULL;

        if (ret_version)
                *ret_version = capability.ProtocolVersion;

        return tcg;
}

bool tpm_present(void) {
        return tcg2_interface_check(/* ret_version= */ NULL);
}

bool runtime_measurement_available(void) {
        return tpm_present() || cc_interface_check();
}

uint32_t tpm_get_active_pcr_banks(void) {
        EFI_STATUS err;

        EFI_TCG2_PROTOCOL *tpm2;
        EFI_TCG2_VERSION version;
        tpm2 = tcg2_interface_check(&version);
        if (!tpm2)
                return 0;

        /* GetActivePcrBanks() was added only in version 1.1 of the spec */
        if (version.Major < 1 || (version.Major == 1 && version.Minor < 1)) {
                log_debug("TCG protocol too old for GetActivePcrBanks(), returning wildcard bank information.");
                return UINT32_MAX;
        }

        uint32_t active_pcr_banks = 0;
        err = tpm2->GetActivePcrBanks(tpm2, &active_pcr_banks);
        if (err != EFI_SUCCESS) {
                log_warning_status(err, "Failed to get TPM2 active PCR banks, assuming none: %m");
                return 0;
        }

        return active_pcr_banks;
}

static EFI_STATUS tcg2_log_ipl_event(uint32_t pcrindex, EFI_PHYSICAL_ADDRESS buffer, size_t buffer_size, const char16_t *description, bool *ret_measured) {
        EFI_TCG2_PROTOCOL *tpm2;
        EFI_STATUS err = EFI_SUCCESS;

        assert(ret_measured);

        tpm2 = tcg2_interface_check(/* ret_version= */ NULL);
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

static EFI_STATUS tcg2_log_tagged_event(
                uint32_t pcrindex,
                EFI_PHYSICAL_ADDRESS buffer,
                size_t buffer_size,
                uint32_t event_id,
                const char16_t *description,
                bool *ret_measured) {

        EFI_TCG2_PROTOCOL *tpm2;
        EFI_STATUS err = EFI_SUCCESS;

        assert(ret_measured);

        tpm2 = tcg2_interface_check(/* ret_version= */ NULL);
        if (!tpm2) {
                *ret_measured = false;
                return EFI_SUCCESS;
        }

        err = tpm2_measure_to_pcr_and_tagged_event_log(tpm2, pcrindex, buffer, buffer_size, event_id, description);
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

/* Without a TPM, nothing keeps track of what we would have measured. Hence record it ourselves, so that
 * the OS can replay it into a software TPM. The records use the format of the TCG crypto agile event log
 * (TCG_PCR_EVENT2) with a single SHA-256 digest. Only the PCRs owned by the OS are recorded, i.e., PCRs 11,
 * 12 and 13, as the firmware ones can't be replayed consistently anyway.
 * This is opt-in via systemd.tpm2_measured_os=1 on the kernel command line, to not hash the UKI when
 * not needed. The command line is only settled after the UKI sections were measured, hence until then the
 * events are only kept pending. Data inside the UKI image, which stays in memory, is only referenced and
 * hashed once the decision is made. Everything else is copied, as the caller might free it before. */
typedef enum ReplayLogState {
        REPLAY_LOG_OFF,
        REPLAY_LOG_PENDING,
        REPLAY_LOG_ON,
} ReplayLogState;

typedef struct PendingEvent {
        uint32_t pcrindex;
        uint32_t event_type;   /* EV_IPL or EV_EVENT_TAG */
        uint32_t event_id;     /* Only used for EV_EVENT_TAG */
        const void *data;      /* Not owned, points to 'copy' or into the UKI image */
        size_t size;
        void *copy;            /* Owned copy of data outside the UKI image, NULL if 'data' points into it */
        char16_t *description; /* Owned */
} PendingEvent;

static void pending_event_done(PendingEvent *e) {
        assert(e);

        /* 'data' might point to 'copy', hence reset it too */
        e->data = NULL;
        e->size = 0;
        e->copy = mfree(e->copy);
        e->description = mfree(e->description);
}

static DEFINE_ARRAY_FREE_FUNC(pending_event_free_array, PendingEvent, pending_event_done);

/* TCG_PCR_EVENT2 with a single SHA-256 digest, followed by the event data */
typedef struct ReplayLogRecord {
        uint32_t pcr_index;
        uint32_t event_type;
        uint32_t digest_count;
        uint16_t hash_alg;
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint32_t event_size;
} _packed_ ReplayLogRecord;

/* TCG_PCClientTaggedEvent, followed by the tagged event data */
typedef struct ReplayLogTag {
        uint32_t event_id;
        uint32_t event_data_size;
} _packed_ ReplayLogTag;

static ReplayLogState replay_log_state = REPLAY_LOG_OFF;
static PendingEvent *pending_events = NULL;
static size_t n_pending_events = 0;
static struct iovec replay_log = {};
static uintptr_t replay_log_image = 0;
static size_t replay_log_image_size = 0;

static bool replay_log_in_image(const void *data, size_t size) {
        uintptr_t p = (uintptr_t) data;

        return replay_log_image != 0 &&
                p >= replay_log_image &&
                size <= replay_log_image_size &&
                p - replay_log_image <= replay_log_image_size - size;
}

static void replay_log_record(
                uint32_t pcrindex,
                uint32_t event_type,
                uint32_t event_id,
                const void *data,
                size_t size,
                const char16_t *description) {

        assert(description);
        assert(IN_SET(event_type, EV_IPL, EV_EVENT_TAG));

        size_t description_size = strsize16(description);
        size_t event_size = description_size;
        if (event_type == EV_EVENT_TAG)
                event_size += sizeof(ReplayLogTag);

        ReplayLogRecord record = {
                .pcr_index = pcrindex,
                .event_type = event_type,
                .digest_count = 1,
                .hash_alg = 0x000B, /* TPM2_ALG_SHA256 */
                .event_size = event_size,
        };
        sha256_direct(data, size, record.digest);

        size_t record_size = sizeof(record) + event_size;
        replay_log.iov_base = xrealloc(replay_log.iov_base, replay_log.iov_len, replay_log.iov_len + record_size);
        uint8_t *p = (uint8_t*) replay_log.iov_base + replay_log.iov_len;

        p = mempcpy(p, &record, sizeof(record));
        if (event_type == EV_EVENT_TAG) {
                ReplayLogTag tag = {
                        .event_id = event_id,
                        .event_data_size = description_size,
                };
                p = mempcpy(p, &tag, sizeof(tag));
        }
        memcpy(p, description, description_size);

        replay_log.iov_len += record_size;
}

static void replay_log_append(
                uint32_t pcrindex,
                uint32_t event_type,
                uint32_t event_id,
                EFI_PHYSICAL_ADDRESS buffer,
                size_t buffer_size,
                const char16_t *description) {

        /* PCRs 0…7 belong to the firmware and can't be replayed consistently. This skips our SMBIOS
         * measurement into PCR 1. */
        if (pcrindex < 8)
                return;

        switch (replay_log_state) {

        case REPLAY_LOG_OFF:
                return;

        case REPLAY_LOG_PENDING: {
                PendingEvent e = {
                        .pcrindex = pcrindex,
                        .event_type = event_type,
                        .event_id = event_id,
                        .data = PHYSICAL_ADDRESS_TO_POINTER(buffer),
                        .size = buffer_size,
                        .description = xstrdup16(description),
                };
                if (!replay_log_in_image(e.data, buffer_size))
                        e.data = e.copy = xmemdup(e.data, buffer_size);

                pending_events = xrealloc(
                                pending_events,
                                n_pending_events * sizeof(PendingEvent),
                                (n_pending_events + 1) * sizeof(PendingEvent));
                pending_events[n_pending_events++] = e;
                return;
        }

        case REPLAY_LOG_ON:
                replay_log_record(pcrindex, event_type, event_id, PHYSICAL_ADDRESS_TO_POINTER(buffer), buffer_size, description);
                return;

        default:
                assert_not_reached();
        }
}

void tpm_replay_log_start(const void *image, size_t image_size) {
        assert(image);

        replay_log_image = (uintptr_t) image;
        replay_log_image_size = image_size;
        replay_log_state = REPLAY_LOG_PENDING;
}

void tpm_replay_log_settle(bool enable) {
        if (replay_log_state != REPLAY_LOG_PENDING)
                return;

        if (enable)
                FOREACH_ARRAY(e, pending_events, n_pending_events)
                        replay_log_record(e->pcrindex, e->event_type, e->event_id, e->data, e->size, e->description);

        pending_event_free_array(pending_events, n_pending_events);
        pending_events = NULL;
        n_pending_events = 0;

        replay_log_state = enable ? REPLAY_LOG_ON : REPLAY_LOG_OFF;
}

const struct iovec* tpm_replay_log(void) {
        return &replay_log;
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

        if (!tpm_ret_measured)
                replay_log_append(pcrindex, EV_IPL, /* event_id= */ 0, buffer, buffer_size, description);

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

        EFI_STATUS err;
        bool tpm_ret_measured, cc_ret_measured;

        assert(description || pcrindex == UINT32_MAX);
        assert(event_id > 0);

        /* If EFI_SUCCESS is returned, will initialize ret_measured to true if we actually measured
         * something, or false if measurement was turned off. */

        if (pcrindex == UINT32_MAX) { /* PCR disabled? */
                if (ret_measured)
                        *ret_measured = false;

                return EFI_SUCCESS;
        }

        /* Measure into both CC and TPM if both are available to avoid a problem like CVE-2021-42299.
         * The CC protocol has no tagged-event concept, hence use the IPL event log there. */
        err = cc_log_event(pcrindex, buffer, buffer_size, description, &cc_ret_measured);
        if (err != EFI_SUCCESS)
                return err;

        err = tcg2_log_tagged_event(pcrindex, buffer, buffer_size, event_id, description, &tpm_ret_measured);
        if (err != EFI_SUCCESS)
                return err;

        if (!tpm_ret_measured)
                replay_log_append(pcrindex, EV_EVENT_TAG, event_id, buffer, buffer_size, description);

        if (ret_measured)
                *ret_measured = tpm_ret_measured || cc_ret_measured;

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
