/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "sd-json.h"
#include "sd-varlink.h"
#include "string-table.h"
#include "strv.h"
#include "tpm2-report.h"
#include "tpm2-util.h"

void tpm2_report_options_done(Tpm2ReportOptions *opts) {
        assert(opts);

        opts->nv_pcrs = strv_free(opts->nv_pcrs);
}

static const char* const tpm2_report_component_type_table[_TPM2_REPORT_TYPE_MAX] = {
        [TPM2_REPORT_TYPE_PCR]           = "pcr",
        [TPM2_REPORT_TYPE_NVPCR]         = "nvcpr",
        [TPM2_REPORT_TYPE_SESSION_AUDIT] = "session-audit",
};
DEFINE_STRING_TABLE_LOOKUP(tpm2_report_component_type, Tpm2ReportComponentType);

static void tpm2_report_component_done(Tpm2ReportComponent *c) {
        assert(c);

        c->nv_pcr_name = mfree(c->nv_pcr_name);
        c->nv_public = mfree(c->nv_public);

        c->authenticated_data = mfree(c->authenticated_data);

        c->attestation = mfree(c->attestation);
        sym_Esys_Free(c->signature);
        c->signature = NULL;
}

static void tpm2_report_component_array_free(Tpm2ReportComponent *comps, size_t n_comps) {
        assert(comps || n_comps == 0);

        FOREACH_ARRAY(c, comps, n_comps)
                tpm2_report_component_done(c);
        free(comps);
}

Tpm2Report *tpm2_report_free(Tpm2Report *r) {
        if (!r)
                return NULL;

        r->event_log = sd_json_variant_unref(r->event_log);
        r->public_key = mfree(r->public_key);
        tpm2_report_component_array_free(r->components, r->n_components);
        r->components = NULL;
        r->n_components = 0;

        return mfree(r);
}

#if HAVE_OPENSSL

typedef struct NvPCRReportRequest {
        char *name;

        TPM2B_NV_PUBLIC *public;
        Tpm2Handle *handle;

        char *authenticated_data;
} NvPCRReportRequest;

static void nvpcr_report_request_done(NvPCRReportRequest *r) {
        assert(r);

        r->name = mfree(r->name);
        sym_Esys_Free(r->public);
        r->public = NULL;
        r->handle = tpm2_handle_free(r->handle);
        r->authenticated_data = mfree(r->authenticated_data);
}

static void nvpcr_report_request_array_free(NvPCRReportRequest *reqs, size_t n_reqs) {
        assert(reqs || n_reqs == 0);

        FOREACH_ARRAY(r, reqs, n_reqs)
                nvpcr_report_request_done(r);
        mfree(reqs);
}

static int make_qualifying_data(TPMI_ALG_HASH alg, const char *authenticated_data, TPM2B_DATA *ret) {
        int r;

        assert(authenticated_data);
        assert(ret);

        const char *md_alg = tpm2_hash_alg_to_string(alg);
        if (!md_alg)
                return -EINVAL;

        _cleanup_free_ void *digest = NULL;
        size_t digest_sz;
        r = openssl_digest(md_alg, authenticated_data, strlen(authenticated_data), &digest, &digest_sz);
        if (r < 0)
                return r;

        TPM2B_DATA digest_data;
        r = tpm2_digest_buf_to_data(alg, digest, digest_sz, &digest_data);
        if (r < 0)
                return r;

        *ret = digest_data;
        return 0;
}

static int make_nvpcr_report_authenticated_data(const char *name, uint64_t priority, char **ret) {
        int r;

        assert(name);
        assert(ret);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_buildo(
                &v,
                SD_JSON_BUILD_PAIR_STRING("name", name),
                SD_JSON_BUILD_PAIR_UNSIGNED("priority", priority));
        if (r < 0)
                return r;

        _cleanup_free_ char *data = NULL;
        r = sd_json_variant_format(v, /* flags= */ 0, &data);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(data);
        return 0;
}

static int tpm2_generate_report_try(
                Tpm2Context *c,
                const Tpm2Handle *key,
                const TPML_PCR_SELECTION *pcrs,
                NvPCRReportRequest *nv_pcrs,
                size_t n_nv_pcrs,
                const TPM2B_DATA *external_data,
                sd_json_variant **ret_event_log,
                Tpm2ReportComponent **ret_components,
                size_t *ret_n_components) {

        int r;

        assert(c);
        assert(pcrs);
        assert(nv_pcrs);
        assert(ret_event_log);
        assert(ret_components);
        assert(ret_n_components);

        /* This generates a PCR quote and a NV certification per NvPCR index, all inside an audit session.
         * Audit session exclusivity provides evidence that the sequence of attestations reflects a single
         * and consistent snapshot of the machine's state. */

        _cleanup_(tpm2_handle_freep) Tpm2Handle *audit_session = NULL;
        r = tpm2_make_exclusive_audit_session(c, &audit_session);
        if (r < 0)
                return r;

        Tpm2ReportComponent *components = NULL;
        size_t n_components = 0;
        CLEANUP_ARRAY(components, n_components, tpm2_report_component_array_free);

        /* First obtain a PCR quote. */
        _cleanup_free_ TPMS_ATTEST *quoted = NULL;
        _cleanup_(Esys_Freep) TPMT_SIGNATURE *quote_signature = NULL;
        r = tpm2_quote(
                        c,
                        /* sign_session= */ NULL,
                        audit_session,
                        key,
                        /* qualifying_data= */ NULL,
                        pcrs,
                        &quoted,
                        &quote_signature);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(components, n_components + 1))
                return log_oom_debug();
        components[n_components++] = (Tpm2ReportComponent) {
                .type = TPM2_REPORT_TYPE_PCR,
                .attestation = TAKE_PTR(quoted),
                .signature = TAKE_PTR(quote_signature),
        };

        /* Obtain NvPCR reports. */
        FOREACH_ARRAY(n, nv_pcrs, n_nv_pcrs) {
                log_debug("Fetching TPM attestation for NvPCR '%s'.", n->name);

                TPM2B_DATA qualifying_data;
                r = make_qualifying_data(n->public->nvPublic.nameAlg, n->authenticated_data, &qualifying_data);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create qualifying data for NvPCR attestation");

                _cleanup_free_ TPMS_ATTEST *certify_info = NULL;
                _cleanup_(Esys_Freep) TPMT_SIGNATURE *signature = NULL;
                r = tpm2_nv_certify(
                                c,
                                /* sign_session= */ NULL,
                                /* auth_session= */ NULL,
                                audit_session,
                                key,
                                &n->public->nvPublic,
                                n->handle,
                                &qualifying_data,
                                &certify_info,
                                &signature);
                if (r < 0)
                        return log_debug_errno(r, "Failed to fetch TPM attestation for NvPCR '%s'", n->name);

                _cleanup_free_ char *name_dup = strdup(n->name);
                if (!name_dup)
                        return log_oom_debug();

                _cleanup_free_ TPMS_NV_PUBLIC *nv_public = new0(TPMS_NV_PUBLIC, 1);
                if (!nv_public)
                        return log_oom_debug();
                memcpy(nv_public, &n->public->nvPublic, sizeof(TPMS_NV_PUBLIC));

                _cleanup_free_ char *authenticated_data = strdup(n->authenticated_data);
                if (!authenticated_data)
                        return log_oom_debug();

                if (!GREEDY_REALLOC(components, n_components + 1))
                        return log_oom_debug();
                components[n_components++] = (Tpm2ReportComponent) {
                        .type = TPM2_REPORT_TYPE_NVPCR,
                        .nv_pcr_name = TAKE_PTR(name_dup),
                        .nv_public = TAKE_PTR(nv_public),
                        .authenticated_data = TAKE_PTR(authenticated_data),
                        .attestation = TAKE_PTR(certify_info),
                        .signature = TAKE_PTR(signature),
                };
        }

        /* Read the event log before checking the audit session below. As tpm2_pcr_extend_bytes and
         * tpm2_nvpcr_extend_bytes touch the log after performing a TPM measurement, this ensures that we
         * get a log that is consistent with the previously obtained TPM quote and NV certifications. If
         * the log is appended to before we read it here, the audit session exclusivity check will fail
         * below because the TPM extend commands will have marked the session as no longer exclusive in
         * the TPM. */
        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.PCRLock");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to pcrlock: %m");

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_collect(vl, "io.systemd.PCRLock.ReadEventLog", /* parameters= */ NULL, &reply, &error_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to issue io.systemd.PCRLock.ReadEventLog varlink call: %m");
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                if (r != -EBADR)
                        return log_debug_errno(r, "Failed to issue io.systemd.PCRLock.ReadEventLog varlink call: %m");

                return log_debug_errno(r, "Failed to issue io.systemd.PCRLock.ReadEventLog varlink call: %s", error_id);
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *event_log = NULL;
        sd_json_variant *i;
        JSON_VARIANT_ARRAY_FOREACH(i, reply) {
                sd_json_variant *record = sd_json_variant_by_key(i, "record");
                if (!record)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Reply from io.systemd.PCRLock.ReadEventLog lacks 'record' field.");

                r = sd_json_variant_append_array(&event_log, record);
                if (r < 0)
                        return r;
        }

        if (!event_log) {
                r = sd_json_variant_new_array(&event_log, /* array= */ NULL, /* n= */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate empty event log array: %m");
        }

        _cleanup_free_ TPMS_ATTEST *audit_info = NULL;
        _cleanup_(Esys_Freep) TPMT_SIGNATURE *audit_signature = NULL;
        r = tpm2_get_session_audit_digest(
                        c,
                        /* eh_session= */ NULL,
                        /* sign_session= */ NULL,
                        audit_session,
                        key,
                        external_data,
                        &audit_info,
                        &audit_signature);
        if (r < 0)
                return r;

        if (audit_info->type != TPM2_ST_ATTEST_SESSION_AUDIT)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Unexpected audit session attestation tag 0x%" PRIx16, audit_info->type);
        if (audit_info->attested.sessionAudit.exclusiveSession == TPM2_NO)
                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "Audit session did not remain exclusive");

        if (!GREEDY_REALLOC(components, n_components + 1))
                return log_oom_debug();
        components[n_components++] = (Tpm2ReportComponent) {
                .type = TPM2_REPORT_TYPE_SESSION_AUDIT,
                .attestation = TAKE_PTR(audit_info),
                .signature = TAKE_PTR(audit_signature),
        };

        *ret_event_log = TAKE_PTR(event_log);
        *ret_components = TAKE_PTR(components);
        *ret_n_components = n_components;

        return 0;
}

#endif

#define MAX_REPORT_GENERATE_RETRIES 10

int tpm2_generate_report(
                Tpm2Context *c,
                const Tpm2ReportOptions *options,
                const Tpm2Handle *key,
                const TPM2B_DATA *external_data,
                Tpm2Report **ret) {

#if HAVE_OPENSSL
        int r;

        assert(c);
        assert(options);

        log_debug("Generating TPM report.");

        r = dlopen_tpm2(LOG_DEBUG);
        if (r < 0)
                return r;

        TPMI_ALG_HASH pcr_bank;
        r = tpm2_get_best_pcr_bank(c, options->pcr_mask, &pcr_bank);
        if (r < 0)
                return log_debug_errno(r, "Failed to select PCR bank");

        TPML_PCR_SELECTION pcrs;
        tpm2_tpml_pcr_selection_from_mask(options->pcr_mask, pcr_bank, &pcrs);

        NvPCRReportRequest *nv_pcrs = NULL;
        size_t n_nv_pcrs = 0;
        CLEANUP_ARRAY(nv_pcrs, n_nv_pcrs, nvpcr_report_request_array_free);

        nv_pcrs = new0(NvPCRReportRequest, strv_length(options->nv_pcrs));
        if (!nv_pcrs)
                return log_oom_debug();

        STRV_FOREACH(s, options->nv_pcrs) {
                const char *name = *s;

                if (!tpm2_nvpcr_name_is_valid(name))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Attempt to report NvPCR with invalid name '%s', refusing", name);

                uint32_t nv_index;
                uint64_t priority;
                r = tpm2_nvpcr_get_index(name, &nv_index, &priority);
                if (r < 0)
                        return log_debug_errno(r, "Attemt to report invalid NvPCR '%s'", name);

                _cleanup_(Esys_Freep) TPM2B_NV_PUBLIC *nv_public = NULL;
                _cleanup_(tpm2_handle_freep) Tpm2Handle *nv_handle = NULL;
                r = tpm2_nv_index_to_handle(c, nv_index, /* session= */ NULL, &nv_public, /* ret_name= */ NULL, &nv_handle);
                if (r < 0)
                        return log_debug_errno(r, "Failed to obtain handle and public area for NvPCR '%s'", name);

                _cleanup_free_ char *authenticated_data = NULL;
                r = make_nvpcr_report_authenticated_data(name, priority, &authenticated_data);
                if (r < 0)
                        return log_debug_errno(r, "Failed to make qualifying data for NvPCR '%s'", name);

                _cleanup_free_ char *name_dup = strdup(name);
                if (!name_dup)
                        return log_oom_debug();

                log_debug("Created NvPCR report request for '%s', index 0x%" PRIx32 ".", name, nv_index);

                nv_pcrs[n_nv_pcrs++] = (NvPCRReportRequest) {
                        .name = TAKE_PTR(name_dup),
                        .public = TAKE_PTR(nv_public),
                        .handle = TAKE_PTR(nv_handle),
                        .authenticated_data = TAKE_PTR(authenticated_data),
                };
        }

        _cleanup_free_ TPMT_PUBLIC *pubkey = NULL;
        if (key) {
                _cleanup_(Esys_Freep) TPM2B_PUBLIC *public = NULL;
                r = tpm2_read_public(c, /* session= */ NULL, key, &public, /* ret_name= */ NULL, /* ret_qname= */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read public area of signing key");

                /* Ensure the supplied object is a restricted signing key. Restricted signing keys have to
                 * specify a signing scheme in order to be valid, which means we don't have to select a
                 * scheme when calling the TPM attestation functions. If we permit a normal signing key here,
                 * we would need to select a signing scheme when calling the TPM attestation functions in
                 * the scenario where the key hasn't specified one - they all just pass a NULL scheme now,
                 * so they'll fail with an unrestricted key if it's not explicit about its signing scheme. */
                if ((public->publicArea.objectAttributes & (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT)) != (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Supplied object is not a restricted signing key");

                pubkey = new0(TPMT_PUBLIC, 1);
                if (!pubkey)
                        return log_oom_debug();
                memcpy(pubkey, &public->publicArea, sizeof(TPMT_PUBLIC));
        }

        if (external_data) {
                r = tpm2_max_data_size(c);
                if (r < 0)
                        return r;
                if (external_data->size > r)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "External data size larger than supported by the TPM");
        }

        _cleanup_(tpm2_report_freep) Tpm2Report *report = NULL;
        for (int i = MAX_REPORT_GENERATE_RETRIES;; i--) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *event_log = NULL;
                Tpm2ReportComponent *components = NULL;
                size_t n_components = 0;
                CLEANUP_ARRAY(components, n_components, tpm2_report_component_array_free);

                r = tpm2_generate_report_try(
                                c,
                                key,
                                &pcrs,
                                nv_pcrs, n_nv_pcrs,
                                external_data,
                                &event_log,
                                &components, &n_components);
                if (r == -EBUSY && i > 0) {
                        log_debug("Audit session lost exclusivity, retrying.");
                        continue;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to generate TPM report");

                report = new(Tpm2Report, 1);
                if (!report)
                        return log_oom_debug();

                *report = (Tpm2Report) {
                        .event_log = TAKE_PTR(event_log),
                        .public_key = TAKE_PTR(pubkey),
                        .components = TAKE_PTR(components),
                        .n_components = n_components,
                };
                break;
        }

        if (ret)
                *ret = TAKE_PTR(report);

        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "OpenSSL support is disabled.");
#endif
}
