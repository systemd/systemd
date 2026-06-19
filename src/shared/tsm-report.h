/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

#include "shared-forward.h"

/* Optional knobs. Mirrors the write-only attributes other than inblob.
 * Zero-initialize ({}) and set only what you need. NULL options == all defaults. */
typedef struct TsmReportOptions {
        unsigned privlevel;                  /* e.g. SEV-SNP VMPL */
        bool privlevel_set;                  /* privlevel_floor is used when unset */
        /* service_provider currently not supported. */
} TsmReportOptions;

/* Result. Mirrors the read-only attributes. */
typedef struct TsmReport {
        char *provider;             /* e.g. "sev_guest", "tdx_guest" */
        struct iovec outblob;       /* the attestation report */
        struct iovec auxblob;       /* optional, unset if empty (e.g. SEV cert_table) */
        struct iovec manifestblob;  /* optional, unset if empty */
} TsmReport;

TsmReport *tsm_report_free(TsmReport *report);
DEFINE_TRIVIAL_CLEANUP_FUNC(TsmReport*, tsm_report_free);

/* Returns >0 if the configfs-tsm report interface is present, 0 if not, <0 on error. */
int tsm_report_supported(void);

/* Acquire an attestation report via configs-tsm.
 *   report_data: mandatory inblob to include in the report, 1..64 bytes
 *   options:     optional, NULL for defaults
 *   ret:         result, freed with tsm_report_free() */
int tsm_report_acquire(
        const struct iovec *report_data,
        const TsmReportOptions *options,
        TsmReport **ret);
