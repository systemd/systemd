/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "crypto-util.h"
#include "log.h"
#include "measurement-log.h"
#include "runtime-measure.h"
#include "tdx-rtmr.h"
#include "tpm2-util.h"

static int rtmr_calculate_digest(
                const struct iovec *data,
                const struct iovec *secret,
                struct iovec *ret) {
#if HAVE_OPENSSL
        _cleanup_free_ void *d = NULL;
        size_t size;
        int r;

        /* Mirror the per-bank digest rule of tpm2_pcr_extend_bytes(): secrets
         * are measured as an HMAC keyed by them, never as a literal hash. */
        if (iovec_is_set(secret))
                r = openssl_hmac_many("SHA384", secret->iov_base, secret->iov_len,
                                      data, 1, &d, &size);
        else
                r = openssl_digest_many("SHA384", data, 1, &d, &size);
        if (r < 0)
                return r;

        assert(size == TDX_RTMR_DIGEST_SIZE);

        *ret = IOVEC_MAKE(TAKE_PTR(d), size);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

bool runtime_measurements_supported(void) {
#if HAVE_TPM2
        if (tpm2_is_mostly_supported())
                return true;
#endif
        return tdx_rtmr_supported();
}

int runtime_measurement_extend_bytes(
                const RuntimeMeasureBackends *backends,
                unsigned pcr,
                const struct iovec *data,
                const struct iovec *secret,
                UserspaceMeasurementEventType event,
                const char *description) {

        bool measured = false;
        int r;

        assert(backends);
        assert(iovec_is_valid(data));
        assert(iovec_is_valid(secret));

#if HAVE_TPM2
        if (backends->tpm2) {
                r = tpm2_pcr_extend_bytes(backends->tpm2, backends->tpm2_banks, pcr,
                                          data, secret, event, description);
                if (r < 0)
                        return r;

                measured = true;
        }
#endif

        if (tdx_rtmr_supported()) {
                r = tdx_pcr_to_rtmr_index(pcr);
                if (r == -EOPNOTSUPP)
                        log_debug("PCR %u has no RTMR equivalent, not measuring into RTMR.", pcr);
                else if (r < 0)
                        return r;
                else {
                        _cleanup_(iovec_done) struct iovec digest = {};
                        unsigned rtmr = r;

                        r = rtmr_calculate_digest(data, secret, &digest);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to calculate digest for RTMR measurement: %m");

                        r = tdx_rtmr_extend_digest(rtmr, &digest, pcr,
                                                   /* nv_index_name= */ NULL, event, description);
                        if (r < 0)
                                return r;

                        measured = true;
                }
        }

        if (!measured)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No measurement backend available for PCR %u measurement.", pcr);

        return 0;
}

int runtime_measurement_extend_nvpcr(
                const RuntimeMeasureBackends *backends,
                const char *name,
                const struct iovec *data,
                const struct iovec *secret,
                UserspaceMeasurementEventType event,
                const char *description) {

        bool measured = false;
        int r;

        assert(backends);
        assert(name);
        assert(iovec_is_valid(data));
        assert(iovec_is_valid(secret));

#if HAVE_TPM2
        if (backends->tpm2) {
                r = tpm2_nvpcr_extend_bytes(backends->tpm2, /* session= */ NULL, name, data, secret,
                                            backends->tpm2_sync_secondary_anchor, event, description);
                if (r < 0)
                        return r;

                measured = true;
        }
#endif

        if (tdx_rtmr_supported()) {
                _cleanup_(iovec_done) struct iovec digest = {};

                r = rtmr_calculate_digest(data, secret, &digest);
                if (r < 0)
                        return log_debug_errno(r, "Failed to calculate digest for RTMR measurement: %m");

                r = tdx_rtmr_extend_digest(TDX_NVPCR_RTMR, &digest, /* pcr_index= */ UINT_MAX,
                                           name, event, description);
                if (r < 0)
                        return r;

                measured = true;
        }

        if (!measured)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "No measurement backend available for NvPCR '%s' measurement.", name);

        return 0;
}
