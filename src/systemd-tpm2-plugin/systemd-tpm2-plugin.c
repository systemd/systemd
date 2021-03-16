/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-util.h"
#include "cryptsetup-token.h"
#include "hexdecoct.h"
#include "json.h"
#include "memory-util.h"
#include "tpm2-util.h"
#include "luks2-tpm2.h"

#define TOKEN_NAME "systemd-tpm2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define log_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)
#define log_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define log_std(cd, x...) crypt_logf(cd, CRYPT_LOG_NORMAL, x)

const char *cryptsetup_token_version(void) {
        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

int cryptsetup_token_open(struct crypt_device *cd, int token,
                char **password, size_t *password_len, void *usrptr) {

        int r;
        const char *json;
        size_t blob_size, policy_hash_size, decrypted_key_size;
        uint32_t pcr_mask, search_pcr_mask = UINT32_MAX;
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
                search_pcr_mask = *(uint32_t *)usrptr;

        r = parse_luks2_tpm2_data(json, search_pcr_mask, &pcr_mask, &base64_blob, &hex_policy_hash);
        if (r == -ENXIO)
                log_err(cd, "No valid TPM2 token data found.");
        if (r)
                return r;

        r = unbase64mem(base64_blob, SIZE_MAX, &blob, &blob_size);
        if (r < 0)
                return -EINVAL;

        r = unhexmem(hex_policy_hash, SIZE_MAX, &policy_hash, &policy_hash_size);
        if (r < 0)
                return -EINVAL;

        r = acquire_luks2_key(
                        pcr_mask,
                        blob,
                        blob_size,
                        policy_hash,
                        policy_hash_size,
                        &decrypted_key,
                        &decrypted_key_size);
        if (r) {
                log_err(cd, "Failed to acquire LUKS2 key from tpm.");
                return -EINVAL;
        }

        /* Before using this key as passphrase we base64 encode it, for compat with homed */

        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (r < 0) {
                log_err(cd, "Not enough memory.");
                return -ENOMEM;
        }

        /* free'd automaticaly by libcryptsetup */
        *password_len = strlen(base64_encoded);
        *password = TAKE_PTR(base64_encoded);

        return 0;
}

/* libcryptsetup callback for deallocation of memory passed in 'password' parameters */
void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len __attribute__((unused))) {
        erase_and_free(buffer);
}

/* prints systemd-tpm2 token content in crypt_dump() */
void cryptsetup_token_dump(struct crypt_device *cd, const char *json) {

        bool first;
        uint32_t i, pcr, pcr_mask;
        _cleanup_free_ char* base64_blob = NULL, *hex_policy_hash = NULL;

        if (parse_luks2_tpm2_data(json, UINT32_MAX, &pcr_mask, &base64_blob, &hex_policy_hash))
                return;

        log_std(cd, "\ttpm2-pcrs:  ");
        for (i = 0, first = true; i < TPM2_PCRS_MAX; i++) {
                pcr = pcr_mask & (UINT32_C(1) << i);
                if (pcr) {
                        log_std(cd, "%s%" PRIu32, first ? "" : ", ", pcr);
                        first = false;
                }
        }

        /* well, it's stored in plaintext json metadata anyway... */
        log_std(cd, "\n\ttmp2-blob:  %s\n", base64_blob);

        log_std(cd, "\ttmp2-policy-hash: %s\n", hex_policy_hash);
}

/*
 * validate LUKS2 token with file type:"systemd-tpm2" is
 * valid from owner perspective.
 *
 * It's called before every crypt_token_json_set(), crypt_dump() or crypt_activate_by_token*()
 * if the plugin is available in the system.
 */
int cryptsetup_token_validate(struct crypt_device *cd, const char *json) {

        JsonVariant *w, *e;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
        size_t blob_size = 0, policy_hash_size = 0;

        /*
         * libcryptsetup guarantees 'json' parameter contains
         * valid LUKS2 token (it has 'type' and 'keyslots' fields)
         * with 'type' field having "systemd-tpm2" string content.
         */

        if (json_parse(json, 0, &v, NULL, NULL) < 0) {
                /* this should not happen */
                log_err(cd, "Could not parse " TOKEN_NAME " json object.");
                return 1;
        }

        w = json_variant_by_key(v, "tpm2-pcrs");
        if (!w || !json_variant_is_array(w)) {
                log_dbg(cd, "TPM2 token data lacks 'tpm2-pcrs' field.");
                return 1;
        }

        JSON_VARIANT_ARRAY_FOREACH(e, w) {
                uintmax_t u;

                if (!json_variant_is_number(e)) {
                        log_dbg(cd, "TPM2 PCR is not a number.");
                        return 1;
                }

                u = json_variant_unsigned(e);
                if (u >= TPM2_PCRS_MAX) {
                        log_dbg(cd, "TPM2 PCR number out of range.");
                        return 1;
                }
        }

        w = json_variant_by_key(v, "tpm2-blob");
        if (!w || !json_variant_is_string(w)) {
                log_dbg(cd, "TPM2 token data lacks 'tpm2-blob' field.");
                return 1;
        }

        if (unbase64mem(json_variant_string(w), SIZE_MAX, &blob, &blob_size) < 0) {
                log_dbg(cd, "Invalid base64 data in 'tpm2-blob' field.");
                return 1;
        }

        w = json_variant_by_key(v, "tpm2-policy-hash");
        if (!w || !json_variant_is_string(w)) {
                log_dbg(cd, "TPM2 token data lacks 'tpm2-policy-hash' field.");
                return 1;
        }

        if (unhexmem(json_variant_string(w), SIZE_MAX, &policy_hash, &policy_hash_size) < 0) {
                log_dbg(cd, "Invalid base64 data in 'tpm2-policy-hash' field.");
                return 1;
        }

        if (cryptsetup_get_keyslot_from_token(v) < 0) {
                log_dbg(cd, "Failed to extract keyslot index from TPM2 JSON data.");
                return 1;
        }

        return 0;
}
