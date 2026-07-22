/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "iovec-util.h"
#include "log.h"
#include "pcrextend-util.h"
#include "pkcs7-util.h"
#include "sha256.h"
#include "string-util.h"
#include "tpm2-pcr.h"
#include "user-record.h"

static int pcrextend_pcr_now(unsigned pcr, const char *word, const struct iovec *secret, const char *event) {

#if HAVE_TPM2
        int r;

        assert(word);

        if (!secret)
                secret = &iovec_empty;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.PCRExtend");
        if (r < 0)
                return r;

        /* Build the parameters explicitly so that, when they carry the secret we can mark the
         * variant sensitive: this keeps the secret out of the debug log and ensures its heap
         * buffer is erased rather than merely freed. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        r = sd_json_buildo(
                        &parameters,
                        SD_JSON_BUILD_PAIR_INTEGER("pcr", pcr),
                        SD_JSON_BUILD_PAIR_STRING("text", word),
                        SD_JSON_BUILD_PAIR_CONDITION(iovec_is_set(secret),
                                                     "secret",
                                                     SD_JSON_BUILD_BASE64(secret->iov_base, secret->iov_len)),
                        SD_JSON_BUILD_PAIR_STRING("eventType", event));
        if (r < 0)
                return log_debug_errno(r, "Failed to build io.systemd.PCRExtend.Extend() parameters: %m");

        if (iovec_is_set(secret))
                sd_json_variant_sensitive(parameters);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_call(vl, "io.systemd.PCRExtend.Extend", parameters, &reply, &error_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %m");
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                if (r != -EBADR)
                        return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %m");

                return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %s", error_id);
        }

        log_debug("Measurement of '%s' into PCR %u completed.", word, pcr);
        return 1;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support disabled, not measuring.");
#endif
}

static int pcrextend_nvpcr_now(const char *nvpcr, const char *word, const char *event) {
#if HAVE_TPM2
        int r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.PCRExtend");
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.PCRExtend.Extend",
                        /* ret_reply= */ NULL,
                        &error_id,
                        SD_JSON_BUILD_PAIR_STRING("nvpcr", nvpcr),
                        SD_JSON_BUILD_PAIR_STRING("text", word),
                        SD_JSON_BUILD_PAIR_STRING("eventType", event));
        if (r < 0)
                return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %m");
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply);
                if (r != -EBADR)
                        return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %m");

                return log_debug_errno(r, "Failed to issue io.systemd.PCRExtend.Extend() varlink call: %s", error_id);
        }

        log_debug("Measurement of '%s' into NvPCR '%s' completed.", word, nvpcr);
        return 1;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support disabled, not measuring.");
#endif
}

int pcrextend_machine_id_word(char **ret) {
        _cleanup_free_ char *word = NULL;
        sd_id128_t mid;
        int r;

        assert(ret);

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire machine ID: %m");

        word = strjoin("machine-id:", SD_ID128_TO_STRING(mid));
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

int pcrextend_product_id_word(char **ret) {
        _cleanup_free_ char *word = NULL;
        sd_id128_t pid;
        int r;

        assert(ret);

        r = id128_get_product(&pid);
        if (IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* No product UUID field, or an all-zero or all-0xFF UUID */
                word = strdup("product-id:missing");
        else if (r < 0)
                return log_error_errno(r, "Failed to acquire product ID: %m");
        else
                word = strjoin("product-id:", SD_ID128_TO_STRING(pid));
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

int pcrextend_login_word(UserRecord *ur, char **ret) {
        int r;

        assert(ur);
        assert(ret);

        /* Reduce the user record to the sections that make up its stable, host-specific identity, and turn
         * that into a word to measure into the 'login' NvPCR. We deliberately keep the 'regular',
         * 'perMachine' and 'binding' sections (the portable identity plus how it is realized on *this*
         * host), but drop 'privileged' (so password hash churn doesn't perturb the NvPCR), 'secret' and
         * 'status' (transient) and 'signature' (so the scheme is identical for signed and unsigned records).
         * Only 'regular' is required, the others are merely allowed, so plain NSS users reduce cleanly. */
        UserRecordLoadFlags mask =
                USER_RECORD_REQUIRE_REGULAR |
                USER_RECORD_ALLOW_PER_MACHINE |
                USER_RECORD_ALLOW_BINDING |
                USER_RECORD_STRIP_PRIVILEGED |
                USER_RECORD_STRIP_SECRET |
                USER_RECORD_STRIP_STATUS |
                USER_RECORD_STRIP_SIGNATURE |
                USER_RECORD_PERMISSIVE;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = user_group_record_mangle(ur->json, mask, &v, /* ret_mask= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to reduce user record of '%s': %m", ur->user_name);

        /* Normalize so the serialization is canonical (stable key order) regardless of how the record was
         * assembled by the various userdb backends. */
        r = sd_json_variant_normalize(&v);
        if (r < 0)
                return log_error_errno(r, "Failed to normalize user record of '%s': %m", ur->user_name);

        /* Format to compact, single-line JSON (no SD_JSON_FORMAT_NEWLINE), so the measured word stays on one
         * line and the colon-separated word structure is unambiguous. */
        _cleanup_free_ char *text = NULL;
        r = sd_json_variant_format(v, /* flags= */ 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format user record of '%s': %m", ur->user_name);

        _cleanup_free_ char *name_escaped = xescape(ur->user_name, ":"); /* Avoid ambiguity around ":" */
        if (!name_escaped)
                return log_oom();

        _cleanup_free_ char *word = strjoin("login:", name_escaped, ":", text);
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

int pcrextend_verity_word(
                const char *name,
                const struct iovec *root_hash,
                const struct iovec *root_hash_sig,
                char **ret) {

        int r;

        assert(name);
        assert(iovec_is_set(root_hash));
        assert(ret);

        _cleanup_free_ char *name_escaped = xescape(name, ":"); /* Avoid ambiguity around ":" */
        if (!name_escaped)
                return log_oom();

        _cleanup_free_ char *h = hexmem(root_hash->iov_base, root_hash->iov_len);
        if (!h)
                return log_oom();

        _cleanup_free_ char *sigs = NULL;
        if (iovec_is_set(root_hash_sig)) {
                size_t n_signers = 0;
                Signer *signers = NULL;

                /* Let's extract the X.509 issuer + serial number from the PKCS#7 signature and include that
                 * in the measurement record. This is useful since it allows us to have different signing
                 * keys for confext + sysext + other types of DDIs, and by means of this information we can
                 * discern which kind it was. Ideally, we'd measure the fingerprint of the X.509 certificate,
                 * but typically that's not available in a PKCS#7 signature. */

                CLEANUP_ARRAY(signers, n_signers, signer_free_many);

                r = pkcs7_extract_signers(root_hash_sig, &signers, &n_signers);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(i, signers, n_signers) {
                        _cleanup_free_ char *serial = hexmem(i->serial.iov_base, i->serial.iov_len);
                        if (!serial)
                                return log_oom();

                        _cleanup_free_ char *issuer = NULL;
                        if (base64mem(i->issuer.iov_base, i->issuer.iov_len, &issuer) < 0)
                                return log_oom();

                        if (strextendf_with_separator(&sigs, ",", "%s/%s", serial, issuer) < 0)
                                return log_oom();
                }
        }

        _cleanup_free_ char *word = strjoin("verity:", name_escaped, ":", h, ":", strempty(sigs));
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

int pcrextend_verity_now(
                const char *name,
                const struct iovec *root_hash,
                const struct iovec *root_hash_sig) {

        int r;

        _cleanup_free_ char *word = NULL;
        r = pcrextend_verity_word(
                        name,
                        root_hash,
                        root_hash_sig,
                        &word);
        if (r < 0)
                return r;

        return pcrextend_nvpcr_now("verity", word, "dm_verity");
}

#define IMDS_USERDATA_TRUNCATED_MAX 256U

int pcrextend_imds_userdata_word(const struct iovec *data, char **ret) {
        assert(iovec_is_set(data));
        assert(ret);

        /* We include both a hash of the complete user data, and a truncated version of the data in the word
         * we measure. The former protects the actual data, the latter is useful for debugging. */

        _cleanup_free_ char *hash = sha256_direct_hex(data->iov_base, data->iov_len);
        if (!hash)
                return log_oom();

        _cleanup_free_ char *data_encoded = NULL;
        if (base64mem_full(data->iov_base, MIN(data->iov_len, IMDS_USERDATA_TRUNCATED_MAX), /* line_break= */ SIZE_MAX, &data_encoded) < 0)
                return log_oom();

        _cleanup_free_ char *word = strjoin("imds-userdata:", hash, ":", data_encoded);
        if (!word)
                return log_oom();

        *ret = TAKE_PTR(word);
        return 0;
}

int pcrextend_imds_userdata_now(const struct iovec *data) {
        int r;

        _cleanup_free_ char *word = NULL;
        r = pcrextend_imds_userdata_word(data, &word);
        if (r < 0)
                return r;

        return pcrextend_pcr_now(TPM2_PCR_KERNEL_CONFIG, word, /* secret= */ NULL, "imds_userdata");
}
