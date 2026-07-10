/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_TPM2

#include <tss2/tss2_tpm2_types.h>

typedef struct Tpm2ReportOptions {
        uint32_t pcr_mask;
        char **nv_pcrs;
} Tpm2ReportOptions;

void tpm2_report_options_done(Tpm2ReportOptions *opts);

typedef enum Tpm2ReportComponentType {
        TPM2_REPORT_TYPE_PCR,
        TPM2_REPORT_TYPE_NVPCR,
        TPM2_REPORT_TYPE_SESSION_AUDIT,

        _TPM2_REPORT_TYPE_MAX,
        _TPM2_REPORT_TYPE_INVALID = -EINVAL,
} Tpm2ReportComponentType;

DECLARE_STRING_TABLE_LOOKUP(tpm2_report_component_type, Tpm2ReportComponentType);

typedef struct Tpm2ReportComponent {
        Tpm2ReportComponentType type;

        /* For NvPCRs only */
        char *nv_pcr_name;
        TPM2B_NV_PUBLIC nv_public;

        /* Currently NvPCRs only but could be used in the future
         * for other types, except session audit where the qualifying
         * data is the report digest we get. */
        char *authenticated_data;

        /* Common fields */
        struct iovec attest_info;
        TPMT_SIGNATURE signature;
} Tpm2ReportComponent;

typedef struct Tpm2Report {
        sd_json_variant *event_log;

        TPM2B_PUBLIC public_key;

        Tpm2ReportComponent *components;
        size_t n_components;
} Tpm2Report;

Tpm2Report *tpm2_report_free(Tpm2Report *report);
DEFINE_TRIVIAL_CLEANUP_FUNC(Tpm2Report*, tpm2_report_free);

int tpm2_generate_report(
                Tpm2Context *c,
                const Tpm2ReportOptions *options,
                const Tpm2Handle *key,
                const TPM2B_DATA *external_data,
                Tpm2Report **ret);

#endif
