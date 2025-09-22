/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <syslog.h>

#include "alloc-util.h"
#include "cryptsetup-token.h"
#include "cryptsetup-token-util.h"
#include "dlopen-note.h"
#include "hexdecoct.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "luks2-tpm2.h"
#include "memory-util.h"
#include "string-util.h"
#include "tpm2-util.h"
#include "version.h"

#define TOKEN_NAME "systemd-tpm2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

/* for libcryptsetup debug purpose */
_public_ const char* cryptsetup_token_version(void) {
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(required);
        TPM2_NOTE(suggested);

        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR " systemd-v" PROJECT_VERSION_FULL " (" GIT_VERSION ")";
}

static int log_debug_open_error(struct crypt_device *cd, int token, int r) {
        if (r == -EAGAIN)
                return crypt_log_debug_errno(cd, r, "TPM2 device not found.");
        if (r == -ENOSTR) {
                /* Remap to -EPERM so libcryptsetup's CRYPT_ANY_TOKEN loop keeps iterating. */
                (void) crypt_log_debug_errno(cd, r, "Token %d: no matching TPM2 token data found.", token);
                return -EPERM;
        }
        if (IN_SET(r, -EREMCHG, -EREMOTE, -EADDRNOTAVAIL)) {
                /* Remap as above. Note: For now without -EUCLEAN because currently the only error it
                 * reports won't be solved by moving to another token. */
                (void) crypt_log_debug_errno(cd, r, "Token %d: TPM policy does not match current system state, skipping.", token);
                return -EPERM;
        }

        return crypt_log_debug_errno(cd, r, "Token %d: open failed: %m.", token);
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
        _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {}, fido2_cid = {}, fido2_salt = {};
        _cleanup_free_ char *pubkey_policy_ref = NULL;
        _cleanup_(iovec_done_erase) struct iovec decrypted_key = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        uint32_t hash_pcr_mask, pubkey_pcr_mask;
        systemd_tpm2_plugin_params params = {
                .search_pcr_mask = UINT32_MAX
        };
        uint16_t pcr_bank, primary_alg;
        ssize_t base64_encoded_size;
        TPM2Flags flags = 0;
        Fido2EnrollFlags fido2_flags;
        _cleanup_free_ char *fido2_rp = NULL;
        const char *json;
        int r;

        assert(token >= 0);
        assert(pin || pin_size == 0);
        assert(ret_password);
        assert(ret_password_len);

        r = dlopen_cryptsetup(LOG_DEBUG);
        if (r < 0)
                return r;

        /* This must not fail at this moment (internal error) */
        r = sym_crypt_token_json_get(cd, token, &json);
        assert(token == r);
        assert(json);

        r = crypt_normalize_pin(pin, pin_size, &pin_string);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Cannot normalize PIN: %m");

        if (usrptr)
                params = *(systemd_tpm2_plugin_params *)usrptr;

        r = sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r == -ENOMEM)
                return r;
        if (r < 0) {
                /* Remap to -EPERM so libcryptsetup keeps iterating past a broken token. */
                (void) crypt_log_debug_errno(cd, r, "Token %d: failed to parse JSON data: %m", token);
                return -EPERM;
        }

        struct iovec *blobs = NULL, *policy_hash = NULL;
        size_t n_blobs = 0, n_policy_hash = 0;
        CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);
        CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);

        Argon2IdParameters argon2id_params = {};

        r = tpm2_parse_luks2_json(
                        v,
                        /* ret_keyslot= */ NULL,
                        &hash_pcr_mask,
                        &pcr_bank,
                        &pubkey,
                        &pubkey_policy_ref,
                        &pubkey_pcr_mask,
                        &primary_alg,
                        &blobs,
                        &n_blobs,
                        &policy_hash,
                        &n_policy_hash,
                        &salt,
                        &srk,
                        &pcrlock_nv,
                        &flags,
                        &argon2id_params,
                        &fido2_cid,
                        &fido2_salt,
                        &fido2_rp,
                        &fido2_flags);
        if (r < 0)
                return log_debug_open_error(cd, token, r);

        if (params.search_pcr_mask != UINT32_MAX && hash_pcr_mask != params.search_pcr_mask) {
                /* Remap to -EPERM so libcryptsetup keeps iterating to the next token. */
                crypt_log_debug(cd, "Token %d: PCR mask doesn't match expectation (%" PRIu32 " vs. %" PRIu32 ")", token, hash_pcr_mask, params.search_pcr_mask);
                return -EPERM;
        }

        r = acquire_luks2_key(
                        params.device,
                        hash_pcr_mask,
                        pcr_bank,
                        &pubkey,
                        pubkey_policy_ref,
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
                        /* argon2id_params= */ FLAGS_SET(flags, TPM2_FLAGS_USE_ARGON2ID) ? &argon2id_params : NULL,
                        params.fido2_device,
                        &fido2_cid,
                        &fido2_salt,
                        params.fido2_rp ?: fido2_rp,
                        fido2_flags,
                        &decrypted_key);
        if (r < 0)
                return log_debug_open_error(cd, token, r);

        /* Before using this key as passphrase we base64 encode it, for compat with homed */
        base64_encoded_size = base64mem(decrypted_key.iov_base, decrypted_key.iov_len, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_debug_open_error(cd, token, base64_encoded_size);

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

        _cleanup_free_ char *hash_pcrs_str = NULL, *pubkey_pcrs_str = NULL, *pubkey_str = NULL, *pubkey_policy_ref = NULL, *fido2_cid_str = NULL, *fido2_salt_str = NULL;
        _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {}, fido2_cid = {}, fido2_salt = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        uint32_t hash_pcr_mask, pubkey_pcr_mask;
        uint16_t pcr_bank, primary_alg;
        TPM2Flags flags = 0;
        Fido2EnrollFlags fido2_flags;
        _cleanup_free_ char *fido2_rp = NULL;
        int r;

        assert(json);

        if (dlopen_cryptsetup(LOG_DEBUG) < 0)
                return;

        r = sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " JSON object: %m");

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
                        &pubkey_policy_ref,
                        &pubkey_pcr_mask,
                        &primary_alg,
                        &blobs,
                        &n_blobs,
                        &policy_hash,
                        &n_policy_hash,
                        &salt,
                        &srk,
                        &pcrlock_nv,
                        &flags,
                        /* ret_argon2id_params= */ NULL,
                        &fido2_cid,
                        &fido2_salt,
                        &fido2_rp,
                        &fido2_flags);
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

        r = crypt_dump_buffer_to_hex_string(fido2_cid.iov_base, fido2_cid.iov_len, &fido2_cid_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Cannot dump " TOKEN_NAME " content: %m");

        r = crypt_dump_buffer_to_hex_string(fido2_salt.iov_base, fido2_salt.iov_len, &fido2_salt_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Cannot dump " TOKEN_NAME " content: %m");

        crypt_log(cd, "\ttpm2-hash-pcrs:           %s\n", strna(hash_pcrs_str));
        crypt_log(cd, "\ttpm2-pcr-bank:            %s\n", strna(tpm2_hash_alg_to_string(pcr_bank)));
        crypt_log(cd, "\ttpm2-pubkey:" CRYPT_DUMP_LINE_SEP "%s\n", pubkey_str);
        crypt_log(cd, "\ttpm2-pubkey-ref:          %s\n", pubkey_policy_ref);
        crypt_log(cd, "\ttpm2-pubkey-pcrs:         %s\n", strna(pubkey_pcrs_str));
        if (primary_alg != 0)
                crypt_log(cd, "\ttpm2-primary-alg:         %s\n", strna(tpm2_asym_alg_to_string(primary_alg)));
        crypt_log(cd, "\ttpm2-pin:                 %s\n", true_false(flags & TPM2_FLAGS_USE_PIN));
        crypt_log(cd, "\ttpm2-pcrlock:             %s\n", true_false(flags & TPM2_FLAGS_USE_PCRLOCK));
        crypt_log(cd, "\ttpm2-argon2id:            %s\n", true_false(flags & TPM2_FLAGS_USE_ARGON2ID));
        crypt_log(cd, "\ttpm2-fido2:               %s\n", true_false(flags & TPM2_FLAGS_USE_FIDO2));
        crypt_log(cd, "\ttpm2-salt:                %s\n", true_false(iovec_is_set(&salt)));
        crypt_log(cd, "\ttpm2-srk:                 %s\n", true_false(iovec_is_set(&srk)));
        crypt_log(cd, "\ttpm2-pcrlock-nv:          %s\n", true_false(iovec_is_set(&pcrlock_nv)));
        crypt_log(cd, "\tfido2-credential:" CRYPT_DUMP_LINE_SEP "%s\n", fido2_cid_str);
        crypt_log(cd, "\tfido2-salt:" CRYPT_DUMP_LINE_SEP "%s\n", fido2_salt_str);
        crypt_log(cd, "\tfido2-rp:" CRYPT_DUMP_LINE_SEP "%s\n", fido2_rp);
        crypt_log(cd, "\tfido2-clientPin-required: %s\n", true_false(fido2_flags & FIDO2ENROLL_PIN));
        crypt_log(cd, "\tfido2-up-required:        %s\n", true_false(fido2_flags & FIDO2ENROLL_UP));
        crypt_log(cd, "\tfido2-uv-required:        %s\n", true_false(fido2_flags & FIDO2ENROLL_UV));

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

                crypt_log(cd, "\ttpm2-blob:  %s\n", blob_str);
        }
}

static int validate_tpm2_pcrs(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        sd_json_variant *i;

        assert(variant);

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                uint64_t u;

                if (!sd_json_variant_is_number(i))
                        return json_log(i, flags, SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR is not a number.");

                u = sd_json_variant_unsigned(i);
                if (!TPM2_PCR_INDEX_VALID(u))
                        return json_log(i, flags, SYNTHETIC_ERRNO(EINVAL), "TPM2 PCR number out of range.");
        }

        return 0;
}

static int validate_tpm2_pcr_bank(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        assert(variant);

        if (tpm2_hash_alg_from_string(sd_json_variant_string(variant)) < 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "TPM2 PCR bank invalid or not supported: %s.", sd_json_variant_string(variant));

        return 0;
}

static int validate_tpm2_primary_alg(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        assert(variant);

        if (tpm2_asym_alg_from_string(sd_json_variant_string(variant)) < 0)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL),
                                "TPM2 primary key algorithm invalid or not supported: %s", sd_json_variant_string(variant));

        return 0;
}

static int validate_tpm2_blob(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int r;

        assert(variant);

        if (sd_json_variant_is_array(variant)) {
                sd_json_variant *i;
                JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                        r = sd_json_variant_unbase64(i, /* ret= */ NULL, /* ret_size= */ NULL);
                        if (r < 0)
                                return json_log(i, flags, r, "Invalid base64 data in 'tpm2-blob' field: %m");
                }
        } else {
                r = sd_json_variant_unbase64(variant, /* ret= */ NULL, /* ret_size= */ NULL);
                if (r < 0)
                        return json_log(variant, flags, r, "Invalid base64 data in 'tpm2-blob' field: %m");
        }

        return 0;
}

static int validate_tpm2_policy_hash(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int r;

        assert(variant);

        if (sd_json_variant_is_array(variant)) {
                sd_json_variant *i;
                JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                        r = sd_json_variant_unhex(i, /* ret= */ NULL, /* ret_size= */ NULL);
                        if (r < 0)
                                return json_log(i, flags, r, "Invalid hex data in 'tpm2-policy-hash' field: %m");
                }
        } else {
                r = sd_json_variant_unhex(variant, /* ret= */ NULL, /* ret_size= */ NULL);
                if (r < 0)
                        return json_log(variant, flags, r, "Invalid hex data in 'tpm2-policy-hash' field: %m");
        }

        return 0;
}

static int validate_unbase64(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        int r;

        assert(variant);

        r = sd_json_variant_unbase64(variant, /* ret= */ NULL, /* ret_size= */ NULL);
        if (r < 0)
                return json_log(variant, flags, r, "Invalid base64 data in '%s' field: %m", name);

        return 0;
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "tpm2-pcrs",                SD_JSON_VARIANT_ARRAY,         validate_tpm2_pcrs,        0, SD_JSON_MANDATORY },
                { "tpm2-pcr-bank",            SD_JSON_VARIANT_STRING,        validate_tpm2_pcr_bank,    0, 0                 },
                { "tpm2-primary-alg",         SD_JSON_VARIANT_STRING,        validate_tpm2_primary_alg, 0, 0                 },
                { "tpm2-blob",                _SD_JSON_VARIANT_TYPE_INVALID, validate_tpm2_blob,        0, SD_JSON_MANDATORY },
                { "tpm2-policy-hash",         _SD_JSON_VARIANT_TYPE_INVALID, validate_tpm2_policy_hash, 0, SD_JSON_MANDATORY },
                { "tpm2-pin",                 SD_JSON_VARIANT_BOOLEAN,       NULL,                      0, 0                 },
                { "tpm2-fido2",               SD_JSON_VARIANT_BOOLEAN,       NULL,                      0, 0                 },
                { "fido2-credential",         SD_JSON_VARIANT_STRING,        validate_unbase64,         0, 0                 },
                { "fido2-salt",               SD_JSON_VARIANT_STRING,        validate_unbase64,         0, 0                 },
                { "fido2-rp",                 SD_JSON_VARIANT_STRING,        NULL,                      0, 0                 },
                { "fido2-clientPin-required", SD_JSON_VARIANT_BOOLEAN,       NULL,                      0, 0                 },
                { "fido2-up-required",        SD_JSON_VARIANT_BOOLEAN,       NULL,                      0, 0                 },
                { "fido2-uv-required",        SD_JSON_VARIANT_BOOLEAN,       NULL,                      0, 0                 },
                {},
        };

        assert(json);

        r = dlopen_cryptsetup(LOG_DEBUG);
        if (r < 0)
                return r;

        r = sd_json_parse(json, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Could not parse " TOKEN_NAME " json object: %m");

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_LOG, NULL);
        if (r < 0)
                return 1; /* Dispatch handles logging, return 1 for validation failure */

        return 0;
}
