/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <openssl/evp.h>

#include "pcrlock-firmware.h"
#include "unaligned.h"

static int tcg_pcr_event2_digests_size(
                const TCG_EfiSpecIdEventAlgorithmSize *algorithms,
                size_t n_algorithms,
                size_t *ret) {

        size_t m = 0;

        assert(algorithms || n_algorithms == 0);
        assert(ret);

        FOREACH_ARRAY(a, algorithms, n_algorithms) {

                if (a->digestSize > UINT32_MAX - offsetof(TPMT_HA, digest) - m)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Accumulated hash size too large");

                m += offsetof(TPMT_HA, digest) + a->digestSize;
        }

        *ret = m;
        return 0;
}

int validate_firmware_event(
                const TCG_PCR_EVENT2 *event,
                size_t left,
                const TCG_EfiSpecIdEventAlgorithmSize *algorithms,
                size_t n_algorithms,
                const TCG_PCR_EVENT2 **ret_next_event,
                size_t *ret_left,
                const void **ret_payload,
                size_t *ret_payload_size) {

        size_t digests_size;
        int r;

        assert(event);
        assert(algorithms || n_algorithms == 0);
        assert(ret_next_event);
        assert(ret_left);

        if (left == 0) {
                *ret_next_event = NULL;
                *ret_left = 0;
                return 0;
        }

        r = tcg_pcr_event2_digests_size(algorithms, n_algorithms, &digests_size);
        if (r < 0)
                return r;

        if (left < (uint64_t) offsetof(TCG_PCR_EVENT2, digests.digests) + (uint64_t) digests_size + sizeof(uint32_t))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event header too short.");

        if (event->digests.count != n_algorithms)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Number of digests in event doesn't match log.");

        uint32_t eventSize = unaligned_read_ne32((const uint8_t*) &event->digests.digests + digests_size);
        uint64_t size = (uint64_t) offsetof(TCG_PCR_EVENT2, digests.digests) + (uint64_t) digests_size + sizeof(uint32_t) + eventSize;

        if (size > left)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event header too short.");

        *ret_next_event = (const TCG_PCR_EVENT2*) ((const uint8_t*) event + size);
        *ret_left = left - size;

        if (ret_payload)
                *ret_payload = (const uint8_t*) &event->digests.digests + digests_size + sizeof(uint32_t);
        if (ret_payload_size)
                *ret_payload_size = eventSize;

        return 1;
}

int validate_firmware_header(
                const void *start,
                size_t size,
                const TCG_EfiSpecIdEventAlgorithmSize **ret_algorithms,
                size_t *ret_n_algorithms,
                const TCG_PCR_EVENT2 **ret_first,
                size_t *ret_left) {

        assert(start || size == 0);
        assert(ret_algorithms);
        assert(ret_n_algorithms);
        assert(ret_first);
        assert(ret_left);

        if (size < offsetof(TCG_PCClientPCREvent, event))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log too short for TCG_PCClientPCREvent.");

        const TCG_PCClientPCREvent *h = start;

        if (size < (uint64_t) offsetof(TCG_PCClientPCREvent, event) + (uint64_t) h->eventDataSize)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log too short for TCG_PCClientPCREvent events data.");

        if (h->eventType != EV_NO_ACTION)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header has unexpected event type 0x%08" PRIx32 ". (Probably not a TPM2 event log?)", h->eventType);
        if (h->pcrIndex != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header has unexpected PCR index %" PRIu32 ". (Probably not a TPM2 event log?)", h->pcrIndex);
        if (!memeqzero(h->digest, sizeof(h->digest)))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header has unexpected non-zero digest. (Probably not a TPM2 event log?)");

        if (h->eventDataSize < offsetof(TCG_EfiSpecIDEvent, digestSizes))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header too short for TCG_EfiSpecIdEvent.");

        const TCG_EfiSpecIDEvent *id = (const TCG_EfiSpecIDEvent*) h->event;

        /* Signature as per "TCG PC Client Specific Platform Firmware Profile Specification"
         * (https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/),
         * section 10.4.5.1 "Specification ID Version Event" (at least in version 1.05 Revision 23 of the
         * spec) */
        if (memcmp(id->signature,
                   (const uint8_t[]) { 0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x00 },
                   sizeof(id->signature)) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Missing TPM2 event log signature.");

        if (id->numberOfAlgorithms <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Number of advertised hash algorithms is zero.");
        if (id->numberOfAlgorithms > UINT32_MAX / sizeof(TCG_EfiSpecIdEventAlgorithmSize))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Number of advertised hash algorithms too large.");

        log_debug("TPM PC Client Platform Firmware Profile: family %u.%u, revision %u.%u",
                  id->specVersionMajor, id->specVersionMinor,
                  id->specErrata / 100U, id->specErrata % 100U);

        if (h->eventDataSize < (uint64_t) offsetof(TCG_EfiSpecIDEvent, digestSizes) + (uint64_t) (id->numberOfAlgorithms * sizeof(TCG_EfiSpecIdEventAlgorithmSize)) + 1U)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header doesn't fit all algorithms.");

        uint8_t vendorInfoSize = *((const uint8_t*) id + offsetof(TCG_EfiSpecIDEvent, digestSizes) + (id->numberOfAlgorithms * sizeof(TCG_EfiSpecIdEventAlgorithmSize)));
        if (h->eventDataSize != offsetof(TCG_EfiSpecIDEvent, digestSizes) + (id->numberOfAlgorithms * sizeof(TCG_EfiSpecIdEventAlgorithmSize)) + 1U + vendorInfoSize)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log header doesn't fit vendor info.");

        for (size_t i = 0; i < id->numberOfAlgorithms; i++) {
                const EVP_MD *implementation;
                const char *a;

                a = tpm2_hash_alg_to_string(id->digestSizes[i].algorithmId);
                if (!a) {
                        log_notice("Event log advertises unknown hash algorithm 0x%4x, can't validate.", id->digestSizes[i].algorithmId);
                        continue;
                }

                implementation = EVP_get_digestbyname(a);
                if (!implementation) {
                        log_notice("Event log advertises hash algorithm '%s' we don't implement, can't validate.", a);
                        continue;
                }

                if (EVP_MD_size(implementation) !=  id->digestSizes[i].digestSize)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Advertised digest size for '%s' is wrong, refusing.", a);
        }

        *ret_algorithms = id->digestSizes;
        *ret_n_algorithms = id->numberOfAlgorithms;

        size_t offset = offsetof(TCG_PCClientPCREvent, event) + h->eventDataSize;
        *ret_first = (TCG_PCR_EVENT2*) ((const uint8_t*) h + offset);
        *ret_left = size - offset;

        return 0;
}
