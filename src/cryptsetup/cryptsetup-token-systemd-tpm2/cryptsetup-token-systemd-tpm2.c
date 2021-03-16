/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "tpm2-util.h"
#include "luks2-tpm2.h"

#define TOKEN_NAME "systemd-tpm2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define crypt_log_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)
#define crypt_log_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define crypt_log_std(cd, x...) crypt_logf(cd, CRYPT_LOG_NORMAL, x)

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {
        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

static int log_debug_open_error(struct crypt_device *cd, int r) {
        if (r == -EAGAIN)
                crypt_log_dbg(cd, "TPM2 device not found.");
        else if (r == -ENXIO)
                crypt_log_dbg(cd, "No matching TPM2 token data found.");
        else if (r == -ENOMEM)
                crypt_log_dbg(cd, "Not Enough memory.");
        else if (r == -EINVAL)
                crypt_log_dbg(cd, "Internal error unlocking device using system-tmp2 token.");

        return r;
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
 * - if plugin defines validate funtion (see cryptsetup_token_validate below) it must have
 *   passed the check (aka return 0)
 */
_public_ int cryptsetup_token_open(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        int r;
        const char *json;
        size_t blob_size, policy_hash_size, decrypted_key_size;
        uint32_t pcr_mask;
        tpm2_params params = {
                .search_pcr_mask = UINT32_MAX
        };
        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
        _cleanup_free_ char *base64_blob = NULL, *hex_policy_hash = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;

        assert(token >= 0);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        assert(token == r);
        assert(json);

        if (usrptr)
                params = *(tpm2_params *)usrptr;

        r = parse_luks2_tpm2_data(json, params.search_pcr_mask, &pcr_mask, &base64_blob, &hex_policy_hash);
        if (r < 0)
                return log_debug_open_error(cd, r);

        /* should not happen since cryptsetup_token_validate have passed */
        r = unbase64mem(base64_blob, SIZE_MAX, &blob, &blob_size);
        if (r < 0)
                return log_debug_open_error(cd, r);

        /* should not happen since cryptsetup_token_validate have passed */
        r = unhexmem(hex_policy_hash, SIZE_MAX, &policy_hash, &policy_hash_size);
        if (r < 0)
                return log_debug_open_error(cd, r);

        r = acquire_luks2_key(
                        pcr_mask,
                        params.device,
                        blob,
                        blob_size,
                        policy_hash,
                        policy_hash_size,
                        &decrypted_key,
                        &decrypted_key_size);
        if (r < 0)
                return log_debug_open_error(cd, r);

        /* Before using this key as passphrase we base64 encode it, for compat with homed */
        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (r < 0)
                return log_debug_open_error(cd, r);

        /* free'd automaticaly by libcryptsetup */
        *password_len = strlen(base64_encoded);
        *password = TAKE_PTR(base64_encoded);

        return 0;
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

        bool first;
        uint32_t i, pcr, pcr_mask;
        _cleanup_free_ char* base64_blob = NULL, *hex_policy_hash = NULL;

        if (parse_luks2_tpm2_data(json, UINT32_MAX, &pcr_mask, &base64_blob, &hex_policy_hash))
                return;

        crypt_log_std(cd, "\ttpm2-pcrs:  ");
        for (i = 0, first = true; i < TPM2_PCRS_MAX; i++) {
                pcr = pcr_mask & (UINT32_C(1) << i);
                if (pcr) {
                        crypt_log_std(cd, "%s%" PRIu32, first ? "" : ", ", pcr);
                        first = false;
                }
        }

        /* well, it's stored in plaintext json metadata anyway... */
        crypt_log_std(cd, "\n\ttmp2-blob:  %s\n", base64_blob);

        crypt_log_std(cd, "\ttmp2-policy-hash: %s\n", hex_policy_hash);
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
        JsonVariant *w, *e;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
        size_t blob_size = 0, policy_hash_size = 0;

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0) {
                crypt_log_dbg(cd, "Could not parse " TOKEN_NAME " json object%s.",
                              r == -ENOMEM ? " (not enough memory)" : "");
                return 1;
        }

        w = json_variant_by_key(v, "tpm2-pcrs");
        if (!w || !json_variant_is_array(w)) {
                crypt_log_dbg(cd, "TPM2 token data lacks 'tpm2-pcrs' field.");
                return 1;
        }

        JSON_VARIANT_ARRAY_FOREACH(e, w) {
                uintmax_t u;

                if (!json_variant_is_number(e)) {
                        crypt_log_dbg(cd, "TPM2 PCR is not a number.");
                        return 1;
                }

                u = json_variant_unsigned(e);
                if (u >= TPM2_PCRS_MAX) {
                        crypt_log_dbg(cd, "TPM2 PCR number out of range.");
                        return 1;
                }
        }

        w = json_variant_by_key(v, "tpm2-blob");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_dbg(cd, "TPM2 token data lacks 'tpm2-blob' field.");
                return 1;
        }

        if (unbase64mem(json_variant_string(w), SIZE_MAX, &blob, &blob_size) < 0) {
                crypt_log_dbg(cd, "Invalid base64 data in 'tpm2-blob' field.");
                return 1;
        }

        w = json_variant_by_key(v, "tpm2-policy-hash");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_dbg(cd, "TPM2 token data lacks 'tpm2-policy-hash' field.");
                return 1;
        }

        if (unhexmem(json_variant_string(w), SIZE_MAX, &policy_hash, &policy_hash_size) < 0) {
                crypt_log_dbg(cd, "Invalid base64 data in 'tpm2-policy-hash' field.");
                return 1;
        }

        return 0;
}
