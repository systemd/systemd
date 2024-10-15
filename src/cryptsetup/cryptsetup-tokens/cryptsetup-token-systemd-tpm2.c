/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "cryptsetup-token-util.h"
#include "hexdecoct.h"
#include "json-util.h"
#include "luks2-tpm2.h"
#include "memory-util.h"
#include "strv.h"
#include "tpm2-util.h"
#include "version.h"

#define TOKEN_NAME "systemd-tpm2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {

        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR " systemd-v" PROJECT_VERSION_FULL " (" GIT_VERSION ")";
}

static int log_debug_open_error(struct crypt_device *cd, int r) {
        if (r == -EAGAIN)
                return crypt_log_debug_errno(cd, r, "TPM2 device not found.");
        if (r == -ENXIO)
                return crypt_log_debug_errno(cd, r, "No matching TPM2 token data found.");

        return crypt_log_debug_errno(cd, r, TOKEN_NAME " open failed: %m.");
}

_public_ int cryptsetup_token_open_pin(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                const char *pin,
                size_t pin_size,
                char **ret_password, /* freed by cryptsetup_token_buffer_free */
                size_t *ret_password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        _cleanup_(erase_and_freep) char *base64_encoded = NULL, *pin_string = NULL;
        _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {};
        _cleanup_(iovec_done_erase) struct iovec decrypted_key = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        uint32_t hash_pcr_mask, pubkey_pcr_mask;
        systemd_tpm2_plugin_params params = {
                .search_pcr_mask = UINT32_MAX
        };
        uint16_t pcr_bank, primary_alg;
        ssize_t base64_encoded_size;
        TPM2Flags flags = 0;
        const char *json;
        int r;

        assert(token >= 0);
        assert(pin || pin_size == 0);
        assert(ret_password);
        assert(ret_password_len);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        assert(token == r);
        assert(json);

        r = crypt_normalize_pin(pin, pin_size, &pin_string);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Cannot normalize PIN: %m");

        if (usrptr)
                params = *(systemd_tpm2_plugin_params *)usrptr;

        r = sd_json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Failed to parse token JSON data: %m");

        struct iovec *blobs = NULL, *policy_hash = NULL;
        size_t n_blobs = 0, n_policy_hash = 0;
        CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);
        CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);

        r = tpm2_parse_luks2_json(
                        v,
                        /* ret_keyslot= */ NULL,
                        &hash_pcr_mask,
                        &pcr_bank,
                        &pubkey,
                        &pubkey_pcr_mask,
                        &primary_alg,
                        &blobs,
                        &n_blobs,
                        &policy_hash,
                        &n_policy_hash,
                        &salt,
                        &srk,
                        &pcrlock_nv,
                        &flags);
        if (r < 0)
                return log_debug_open_error(cd, r);

        if (params.search_pcr_mask != UINT32_MAX && hash_pcr_mask != params.search_pcr_mask)
                return crypt_log_debug_errno(cd, ENXIO, "PCR mask doesn't match expectation (%" PRIu32 " vs. %" PRIu32 ")", hash_pcr_mask, params.search_pcr_mask);

        r = acquire_luks2_key(
                        params.device,
                        hash_pcr_mask,
                        pcr_bank,
                        &pubkey,
                        pubkey_pcr_mask,
                        params.signature_path,
                        pin_string,
                        params.pcrlock_path,
                        primary_alg,
                        blobs,
                        n_blobs,
                        policy_hash,
                        n_policy_hash,
                        &salt,
                        &srk,
                        &pcrlock_nv,
                        flags,
                        &decrypted_key);
        if (r < 0)
                return log_debug_open_error(cd, r);

        /* Before using this key as passphrase we base64 encode it, for compat with homed */
        base64_encoded_size = base64mem(decrypted_key.iov_base, decrypted_key.iov_len, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_debug_open_error(cd, base64_encoded_size);

        /* free'd automatically by libcryptsetup */
        *ret_password = TAKE_PTR(base64_encoded);
        *ret_password_len = base64_encoded_size;

        return 0;
}

/*
 * This function is called from within following libcryptsetup calls
 * provided conditions further below are met:
 *
 * crypt_activate_by_token(), crypt_activate_by_token_type(type == 'systemd-tpm2'):
 *
 * - token is assigned to at least one luks2 keyslot eligible to activate LUKS2 device
 *   (alternatively: name is set to null, flags contains CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY
 *    and token is assigned to at least single keyslot).
 *
 * - if plugin defines validate function (see cryptsetup_token_validate below) it must have
 *   passed the check (aka return 0)
 */
_public_ int cryptsetup_token_open(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                char **ret_password, /* freed by cryptsetup_token_buffer_free */
                size_t *ret_password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        return cryptsetup_token_open_pin(cd, token, NULL, 0, ret_password, ret_password_len, usrptr);
}

/*
 * libcryptsetup callback for memory deallocation of 'password' parameter passed in
 * any crypt_token_open_* plugin function
 */
_public_ void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len) {
        erase_and_free(buffer);
}

/*
 * prints systemd-tpm2 token content in crypt_dump().
 * 'type' and 'keyslots' fields are printed by libcryptsetup
 */
_public_ void cryptsetup_token_dump(
                struct crypt_device *cd /* is always LUKS2 context */,
                const char *json /* validated 'systemd-tpm2' token if cryptsetup_token_validate is defined */) {

        _cleanup_free_ char *hash_pcrs_str = NULL, *pubkey_pcrs_str = NULL, *pubkey_str = NULL;
        _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        uint32_t hash_pcr_mask, pubkey_pcr_mask;
        uint16_t pcr_bank, primary_alg;
        TPM2Flags flags = 0;
        int r;

        assert(json);

        r = sd_json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " JSON object: %m");

        struct iovec *blobs = NULL, *policy_hash = NULL;
        size_t n_blobs = 0, n_policy_hash = 0;
        CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);
        CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);

        r = tpm2_parse_luks2_json(
                        v,
                        NULL,
                        &hash_pcr_mask,
                        &pcr_bank,
                        &pubkey,
                        &pubkey_pcr_mask,
                        &primary_alg,
                        &blobs,
                        &n_blobs,
                        &policy_hash,
                        &n_policy_hash,
                        &salt,
                        &srk,
                        &pcrlock_nv,
                        &flags);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " JSON fields: %m");

        hash_pcrs_str = tpm2_pcr_mask_to_string(hash_pcr_mask);
        if (!hash_pcrs_str)
                return (void) crypt_log_debug_errno(cd, ENOMEM, "Cannot format PCR hash mask: %m");

        pubkey_pcrs_str = tpm2_pcr_mask_to_string(pubkey_pcr_mask);
        if (!pubkey_pcrs_str)
                return (void) crypt_log_debug_errno(cd, ENOMEM, "Cannot format PCR hash mask: %m");

        r = crypt_dump_buffer_to_hex_string(pubkey.iov_base, pubkey.iov_len, &pubkey_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Cannot dump " TOKEN_NAME " content: %m");

        crypt_log(cd, "\ttpm2-hash-pcrs:   %s\n", strna(hash_pcrs_str));
        crypt_log(cd, "\ttpm2-pcr-bank:    %s\n", strna(tpm2_hash_alg_to_string(pcr_bank)));
        crypt_log(cd, "\ttpm2-pubkey:" CRYPT_DUMP_LINE_SEP "%s\n", pubkey_str);
        crypt_log(cd, "\ttpm2-pubkey-pcrs: %s\n", strna(pubkey_pcrs_str));
        crypt_log(cd, "\ttpm2-primary-alg: %s\n", strna(tpm2_asym_alg_to_string(primary_alg)));
        crypt_log(cd, "\ttpm2-pin:         %s\n", true_false(flags & TPM2_FLAGS_USE_PIN));
        crypt_log(cd, "\ttpm2-pcrlock:     %s\n", true_false(flags & TPM2_FLAGS_USE_PCRLOCK));
        crypt_log(cd, "\ttpm2-salt:        %s\n", true_false(iovec_is_set(&salt)));
        crypt_log(cd, "\ttpm2-srk:         %s\n", true_false(iovec_is_set(&srk)));
        crypt_log(cd, "\ttpm2-pcrlock-nv:  %s\n", true_false(iovec_is_set(&pcrlock_nv)));

        FOREACH_ARRAY(p, policy_hash, n_policy_hash) {
                _cleanup_free_ char *policy_hash_str = NULL;

                r = crypt_dump_buffer_to_hex_string(p->iov_base, p->iov_len, &policy_hash_str);
                if (r < 0)
                        return (void) crypt_log_debug_errno(cd, r, "Cannot dump " TOKEN_NAME " content: %m");

                crypt_log(cd, "\ttpm2-policy-hash:" CRYPT_DUMP_LINE_SEP "%s\n", policy_hash_str);
        }

        FOREACH_ARRAY(b, blobs, n_blobs) {
                _cleanup_free_ char *blob_str = NULL;

                r = crypt_dump_buffer_to_hex_string(b->iov_base, b->iov_len, &blob_str);
                if (r < 0)
                        return (void) crypt_log_debug_errno(cd, r, "Cannot dump " TOKEN_NAME " content: %m");

                crypt_log(cd, "\ttpm2-blob:        %s\n", blob_str);
        }
}

/*
 * Note:
 *   If plugin is available in library path, it's called in before following libcryptsetup calls:
 *
 *   crypt_token_json_set, crypt_dump, any crypt_activate_by_token_* flavour
 */
_public_ int cryptsetup_token_validate(
                struct crypt_device *cd, /* is always LUKS2 context */
                const char *json /* contains valid 'type' and 'keyslots' fields. 'type' is 'systemd-tpm2' */) {

        int r;
        sd_json_variant *w, *e;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert(json);

        r = sd_json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Could not parse " TOKEN_NAME " json object: %m");

        w = sd_json_variant_by_key(v, "tpm2-pcrs");
        if (!w || !sd_json_variant_is_array(w)) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-pcrs' field.");
                return 1;
        }

        JSON_VARIANT_ARRAY_FOREACH(e, w) {
                uint64_t u;

                if (!sd_json_variant_is_number(e)) {
                        crypt_log_debug(cd, "TPM2 PCR is not a number.");
                        return 1;
                }

                u = sd_json_variant_unsigned(e);
                if (!TPM2_PCR_INDEX_VALID(u)) {
                        crypt_log_debug(cd, "TPM2 PCR number out of range.");
                        return 1;
                }
        }

        /* The bank field is optional, since it was added in systemd 250 only. Before the bank was hardcoded
         * to SHA256. */
        w = sd_json_variant_by_key(v, "tpm2-pcr-bank");
        if (w) {
                /* The PCR bank field is optional */

                if (!sd_json_variant_is_string(w)) {
                        crypt_log_debug(cd, "TPM2 PCR bank is not a string.");
                        return 1;
                }

                if (tpm2_hash_alg_from_string(sd_json_variant_string(w)) < 0) {
                        crypt_log_debug(cd, "TPM2 PCR bank invalid or not supported: %s.", sd_json_variant_string(w));
                        return 1;
                }
        }

        /* The primary key algorithm field is optional, since it was also added in systemd 250 only. Before
         * the algorithm was hardcoded to ECC. */
        w = sd_json_variant_by_key(v, "tpm2-primary-alg");
        if (w) {
                /* The primary key algorithm is optional */

                if (!sd_json_variant_is_string(w)) {
                        crypt_log_debug(cd, "TPM2 primary key algorithm is not a string.");
                        return 1;
                }

                if (tpm2_asym_alg_from_string(sd_json_variant_string(w)) < 0) {
                        crypt_log_debug(cd, "TPM2 primary key algorithm invalid or not supported: %s", sd_json_variant_string(w));
                        return 1;
                }
        }

        w = sd_json_variant_by_key(v, "tpm2-blob");
        if (!w) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-blob' field.");
                return 1;
        }

        if (sd_json_variant_is_array(w)) {
                sd_json_variant *i;
                JSON_VARIANT_ARRAY_FOREACH(i, w) {
                        r = sd_json_variant_unbase64(i, /* ret= */ NULL, /* ret_size= */ NULL);
                        if (r < 0)
                                return crypt_log_debug_errno(cd, r, "Invalid base64 data in 'tpm2-blob' field: %m");
                }
        } else {
                r = sd_json_variant_unbase64(w, /* ret= */ NULL, /* ret_size= */ NULL);
                if (r < 0)
                        return crypt_log_debug_errno(cd, r, "Invalid base64 data in 'tpm2-blob' field: %m");
        }

        w = sd_json_variant_by_key(v, "tpm2-policy-hash");
        if (!w) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-policy-hash' field.");
                return 1;
        }

        if (sd_json_variant_is_array(w)) {
                sd_json_variant *i;
                JSON_VARIANT_ARRAY_FOREACH(i, w) {
                        r = sd_json_variant_unhex(i, /* ret= */ NULL, /* ret_size= */ NULL);
                        if (r < 0)
                                return crypt_log_debug_errno(cd, r, "Invalid hex data in 'tpm2-policy-hash' field: %m");
                }
        } else {
                r = sd_json_variant_unhex(w, /* ret= */ NULL, /* ret_size= */ NULL);
                if (r < 0)
                        return crypt_log_debug_errno(cd, r, "Invalid hex data in 'tpm2-policy-hash' field: %m");
        }

        w = sd_json_variant_by_key(v, "tpm2-pin");
        if (w) {
                if (!sd_json_variant_is_boolean(w)) {
                        crypt_log_debug(cd, "TPM2 PIN policy is not a boolean.");
                        return 1;
                }
        }

        return 0;
}
