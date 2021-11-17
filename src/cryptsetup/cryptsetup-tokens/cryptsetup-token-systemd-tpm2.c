/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "cryptsetup-token-util.h"
#include "hexdecoct.h"
#include "luks2-tpm2.h"
#include "memory-util.h"
#include "tpm2-util.h"
#include "version.h"

#define TOKEN_NAME "systemd-tpm2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {

        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR " systemd-v" STRINGIFY(PROJECT_VERSION) " (" GIT_VERSION ")";
}

static int log_debug_open_error(struct crypt_device *cd, int r) {
        if (r == -EAGAIN) {
                crypt_log_debug(cd, "TPM2 device not found.");
                return r;
        } else if (r == -ENXIO) {
                crypt_log_debug(cd, "No matching TPM2 token data found.");
                return r;
        }

        return crypt_log_debug_errno(cd, r, TOKEN_NAME " open failed: %m.");
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
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        int r;
        const char *json;
        size_t blob_size, policy_hash_size, decrypted_key_size;
        uint32_t pcr_mask;
        uint16_t pcr_bank, primary_alg;
        systemd_tpm2_plugin_params params = {
                .search_pcr_mask = UINT32_MAX
        };
        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
        _cleanup_free_ char *base64_blob = NULL, *hex_policy_hash = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;

        assert(password);
        assert(password_len);
        assert(token >= 0);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        assert(token == r);
        assert(json);

        if (usrptr)
                params = *(systemd_tpm2_plugin_params *)usrptr;

        r = parse_luks2_tpm2_data(json, params.search_pcr_mask, &pcr_mask, &pcr_bank, &primary_alg, &base64_blob, &hex_policy_hash);
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
                        pcr_bank,
                        primary_alg,
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

        /* free'd automatically by libcryptsetup */
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

        int r;
        uint32_t pcr_mask;
        uint16_t pcr_bank, primary_alg;
        size_t decoded_blob_size;
        _cleanup_free_ char *base64_blob = NULL, *hex_policy_hash = NULL,
                            *pcrs_str = NULL, *blob_str = NULL, *policy_hash_str = NULL;
        _cleanup_free_ void *decoded_blob = NULL;

        assert(json);

        r = parse_luks2_tpm2_data(json, UINT32_MAX, &pcr_mask, &pcr_bank, &primary_alg, &base64_blob, &hex_policy_hash);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " metadata: %m.");

        for (uint32_t i = 0; i < TPM2_PCRS_MAX; i++) {
                if ((pcr_mask & (UINT32_C(1) << i)) &&
                    ((r = strextendf_with_separator(&pcrs_str, ", ", "%" PRIu32, i)) < 0))
                        return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");
        }

        r = unbase64mem(base64_blob, SIZE_MAX, &decoded_blob, &decoded_blob_size);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        r = crypt_dump_buffer_to_hex_string(decoded_blob, decoded_blob_size, &blob_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        r = crypt_dump_hex_string(hex_policy_hash, &policy_hash_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        crypt_log(cd, "\ttpm2-pcrs:  %s\n", strna(pcrs_str));
        crypt_log(cd, "\ttpm2-bank:  %s\n", strna(tpm2_pcr_bank_to_string(pcr_bank)));
        crypt_log(cd, "\ttpm2-primary-alg:  %s\n", strna(tpm2_primary_alg_to_string(primary_alg)));
        crypt_log(cd, "\ttpm2-blob:  %s\n", blob_str);
        crypt_log(cd, "\ttpm2-policy-hash:" CRYPT_DUMP_LINE_SEP "%s\n", policy_hash_str);
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

        assert(json);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Could not parse " TOKEN_NAME " json object: %m");

        w = json_variant_by_key(v, "tpm2-pcrs");
        if (!w || !json_variant_is_array(w)) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-pcrs' field.");
                return 1;
        }

        JSON_VARIANT_ARRAY_FOREACH(e, w) {
                uint64_t u;

                if (!json_variant_is_number(e)) {
                        crypt_log_debug(cd, "TPM2 PCR is not a number.");
                        return 1;
                }

                u = json_variant_unsigned(e);
                if (u >= TPM2_PCRS_MAX) {
                        crypt_log_debug(cd, "TPM2 PCR number out of range.");
                        return 1;
                }
        }

        /* The bank field is optional, since it was added in systemd 250 only. Before the bank was hardcoded
         * to SHA256. */
        w = json_variant_by_key(v, "tpm2-pcr-bank");
        if (w) {
                /* The PCR bank field is optional */

                if (!json_variant_is_string(w)) {
                        crypt_log_debug(cd, "TPM2 PCR bank is not a string.");
                        return 1;
                }

                if (tpm2_pcr_bank_from_string(json_variant_string(w)) < 0) {
                        crypt_log_debug(cd, "TPM2 PCR bank invalid or not supported: %s.", json_variant_string(w));
                        return 1;
                }
        }

        /* The primary key algorithm field is optional, since it was also added in systemd 250 only. Before
         * the algorithm was hardcoded to ECC. */
        w = json_variant_by_key(v, "tpm2-primary-alg");
        if (w) {
                /* The primary key algorithm is optional */

                if (!json_variant_is_string(w)) {
                        crypt_log_debug(cd, "TPM2 primary key algorithm is not a string.");
                        return 1;
                }

                if (tpm2_primary_alg_from_string(json_variant_string(w)) < 0) {
                        crypt_log_debug(cd, "TPM2 primary key algorithm invalid or not supported: %s", json_variant_string(w));
                        return 1;
                }
        }

        w = json_variant_by_key(v, "tpm2-blob");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-blob' field.");
                return 1;
        }

        r = unbase64mem(json_variant_string(w), SIZE_MAX, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Invalid base64 data in 'tpm2-blob' field: %m");

        w = json_variant_by_key(v, "tpm2-policy-hash");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "TPM2 token data lacks 'tpm2-policy-hash' field.");
                return 1;
        }

        r = unhexmem(json_variant_string(w), SIZE_MAX, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Invalid base64 data in 'tpm2-policy-hash' field: %m");

        return 0;
}
