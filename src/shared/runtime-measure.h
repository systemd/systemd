/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "measurement-log.h"

/* Dispatches userspace measurements to all available runtime measurement backends: TPM2 PCRs/NvPCRs and
 * TDX RTMRs. This mirrors what sd-stub does at boot, which measures via both the TCG2 and the CC
 * measurement protocol (see src/boot/measure.c). */

typedef struct RuntimeMeasureBackends {
        Tpm2Context *tpm2;                 /* NULL = no TPM2 backend */
        char **tpm2_banks;                 /* PCR measurements only */
        bool tpm2_sync_secondary_anchor;   /* NvPCR measurements only: passed to tpm2_nvpcr_extend_bytes()
                                            * for lazy anchoring; keep false when /var may be unavailable */
} RuntimeMeasureBackends;

/* Returns true if at least one measurement backend is available. */
bool runtime_measurements_supported(void);

/* Measures the data into the given PCR of the TPM2 (if any) and into the RTMR the PCR maps to (if any).
 * If secret is given, an HMAC keyed by it is measured instead of a plain hash. The TPM2 leg runs first,
 * and the first failing backend aborts the measurement. Returns -EOPNOTSUPP if no backend measured. */
int runtime_measurement_extend_bytes(const RuntimeMeasureBackends *backends,
                unsigned pcr, const struct iovec *data, const struct iovec *secret,
                UserspaceMeasurementEventType event, const char *description);

/* Measures the data into the given NvPCR of the TPM2 (if any) and into TDX_NVPCR_RTMR (if any). If secret
 * is given, an HMAC keyed by it is measured instead of a plain hash. The TPM2 leg runs first, and the
 * first failing backend aborts the measurement. Returns -EOPNOTSUPP if no backend measured. Note that
 * NvPCR anchor initialization happens on the TPM2 only, it is never mirrored to RTMRs (see tdx-rtmr.h). */
int runtime_measurement_extend_nvpcr(const RuntimeMeasureBackends *backends,
                const char *name, const struct iovec *data, const struct iovec *secret,
                UserspaceMeasurementEventType event, const char *description);
