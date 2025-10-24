/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptenroll-tpm2.h"
#include "cryptsetup-tpm2.h"
#include "cryptsetup-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "hexdecoct.h"
#include "fido2-util.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "log.h"
#include "memory-util.h"
#include "random-util.h"
#include "sha256.h"
#include "strv.h"
#include "tpm2-util.h"

#if HAVE_TPM2
static int search_policy_hash(
                struct crypt_device *cd,
                const struct iovec policy_hash[],
                size_t n_policy_hash) {

        int r;

        assert(cd);

        /* Searches among the already enrolled TPM2 tokens for one that matches the exact set of policies specified */

        if (n_policy_hash == 0)
                return -ENOENT;

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                int keyslot;
                sd_json_variant *w;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-tpm2", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                keyslot = cryptsetup_get_keyslot_from_token(v);
                if (keyslot < 0) {
                        /* Handle parsing errors of the keyslots field gracefully, since it's not 'owned' by
                         * us, but by the LUKS2 spec */
                        log_warning_errno(keyslot, "Failed to determine keyslot of JSON token %i, skipping: %m", token);
                        continue;
                }

                w = sd_json_variant_by_key(v, "tpm2-policy-hash");
                if (!w)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "TPM2 token data lacks 'tpm2-policy-hash' field.");

                /* This is either an array of strings (for sharded enrollments), or a single string */
                if (sd_json_variant_is_array(w)) {

                        if (sd_json_variant_elements(w) == n_policy_hash) {
                                sd_json_variant *i;
                                bool match = true;
                                size_t j = 0;

                                JSON_VARIANT_ARRAY_FOREACH(i, w) {
                                        _cleanup_(iovec_done) struct iovec thash = {};

                                        r = sd_json_variant_unhex(i, &thash.iov_base, &thash.iov_len);
                                        if (r < 0)
                                                return log_error_errno(r, "Invalid hex data in 'tpm2-policy-hash' field item : %m");

                                        if (iovec_memcmp(policy_hash + j, &thash) != 0) {
                                                match = false;
                                                break;
                                        }

                                        j++;
                                }

                                if (match) /* Found entry with the exact same set of hashes */
                                        return keyslot;
                        }

                } else if (n_policy_hash == 1) {
                        _cleanup_(iovec_done) struct iovec thash = {};

                        r = sd_json_variant_unhex(w, &thash.iov_base, &thash.iov_len);
                        if (r < 0)
                                return log_error_errno(r, "Invalid hex data in 'tpm2-policy-hash' field: %m");

                        if (iovec_memcmp(policy_hash + 0, &thash) == 0)
                                return keyslot; /* Found entry with same hash. */
                }
        }

        return -ENOENT; /* Not found */
}

static int get_pin(char **ret_pin_str, TPM2Flags *ret_flags) {
        _cleanup_(erase_and_freep) char *pin_str = NULL;
        TPM2Flags flags = 0;
        int r;

        assert(ret_pin_str);
        assert(ret_flags);

        r = getenv_steal_erase("NEWPIN", &pin_str);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire PIN from environment: %m");
        if (r > 0)
                flags |= TPM2_FLAGS_USE_PIN;
        else {
                for (size_t i = 5;; i--) {
                        _cleanup_strv_free_erase_ char **pin = NULL, **pin2 = NULL;

                        if (i <= 0)
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(ENOKEY), "Too many attempts, giving up.");

                        AskPasswordRequest req = {
                                .tty_fd = -EBADF,
                                .message = "Please enter TPM2 PIN:",
                                .icon = "drive-harddisk",
                                .keyring = "tpm2-pin",
                                .credential = "cryptenroll.new-tpm2-pin",
                                .until = USEC_INFINITY,
                                .hup_fd = -EBADF,
                        };

                        pin = strv_free_erase(pin);
                        r = ask_password_auto(
                                        &req,
                                        /* flags= */ 0,
                                        &pin);
                        if (r < 0)
                                return log_error_errno(r, "Failed to ask for user pin: %m");
                        assert(strv_length(pin) == 1);

                        req.message = "Please enter TPM2 PIN (repeat):";

                        r = ask_password_auto(
                                        &req,
                                        /* flags= */ 0,
                                        &pin2);
                        if (r < 0)
                                return log_error_errno(r, "Failed to ask for user pin: %m");
                        assert(strv_length(pin) == 1);

                        if (strv_equal(pin, pin2)) {
                                pin_str = strdup(*pin);
                                if (!pin_str)
                                        return log_oom();
                                flags |= TPM2_FLAGS_USE_PIN;
                                break;
                        }

                        log_error("PINs didn't match, please try again!");
                }
        }

        *ret_flags |= flags;
        *ret_pin_str = TAKE_PTR(pin_str);

        return 0;
}

static int get_fido2_secret(
                struct crypt_device *cd,
                const char *device,
                Fido2EnrollFlags lock_with,
                int cred_alg,
                const char *salt_file,
                /*bool parameters_in_header, */
                struct iovec *ret_salt,
                struct iovec *ret_cid,
                char **ret_secret_str,
                Fido2EnrollFlags *ret_lock_with,
                TPM2Flags *ret_flags) {

        _cleanup_(iovec_done_erase) struct iovec salt = {};
        _cleanup_(erase_and_freep) void *cid = NULL;
        _cleanup_(erase_and_freep) void *secret = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        size_t cid_size, secret_size;
        ssize_t base64_encoded_size;
        const char *node, *un;
        TPM2Flags flags = 0;
        int r;

        assert(ret_salt);
        assert(ret_cid);
        assert(ret_secret_str);
        assert(ret_lock_with);
        assert(ret_flags);

        assert_se(cd);
        assert_se(device);

        assert_se(node = crypt_get_device_name(cd));

        un = strempty(crypt_get_uuid(cd));

        if (salt_file)
                r = fido2_read_salt_file(
                                salt_file,
                                /* offset= */ UINT64_MAX,
                                /* client= */ "cryptenroll",
                                /* node= */ un,
                                &salt);
        else
                r = fido2_generate_salt(&salt);
        if (r < 0)
                return r;

        r = fido2_generate_hmac_hash(
                        device,
                        /* rp_id= */ "io.systemd.cryptsetup",
                        /* rp_name= */ "Encrypted Volume",
                        /* user_id= */ un, strlen(un), /* We pass the user ID and name as the same: the disk's UUID if we have it */
                        /* user_name= */ un,
                        /* user_display_name= */ node,
                        /* user_icon= */ NULL,
                        /* askpw_icon= */ "drive-harddisk",
                        /* askpw_credential= */ "cryptenroll.fido2-pin",
                        lock_with,
                        cred_alg,
                        &salt,
                        &cid, &cid_size,
                        &secret, &secret_size,
                        NULL,
                        &lock_with);
        if (r < 0)
                return r;

        /* Before we use the secret, we base64 encode it, for compat with homed, and to make it easier to type in manually */
        base64_encoded_size = base64mem(secret, secret_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        /* if (/\*parameters_in_header*\/true) { */
        /*         r = sd_json_buildo(&v, */
        /*                         SD_JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-fido2")), */
        /*                         SD_JSON_BUILD_PAIR("keyslots", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING(keyslot_as_string))), */
        /*                         SD_JSON_BUILD_PAIR("fido2-credential", SD_JSON_BUILD_BASE64(cid, cid_size)), */
        /*                         SD_JSON_BUILD_PAIR("fido2-salt", JSON_BUILD_IOVEC_BASE64(&salt)), */
        /*                         SD_JSON_BUILD_PAIR("fido2-rp", JSON_BUILD_CONST_STRING("io.systemd.cryptsetup")), */
        /*                         SD_JSON_BUILD_PAIR("fido2-clientPin-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_PIN))), */
        /*                         SD_JSON_BUILD_PAIR("fido2-up-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UP))), */
        /*                         SD_JSON_BUILD_PAIR("fido2-uv-required", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UV)))); */
        /*         if (r < 0) */
        /*                 return log_error_errno(r, "Failed to prepare FIDO2 JSON token object: %m"); */

        /*         r = cryptsetup_add_token_json(cd, v); */
        /*         if (r < 0) */
        /*                 return log_error_errno(r, "Failed to add FIDO2 JSON token to LUKS2 header: %m"); */
        /* } else { */
        /*         _cleanup_free_ char *base64_encoded_cid = NULL, *link = NULL; */

        /*         r = base64mem(cid, cid_size, &base64_encoded_cid); */
        /*         if (r < 0) */
        /*                 return log_error_errno(r, "Failed to base64 encode FIDO2 credential ID: %m"); */

        /*         r = terminal_urlify_man("crypttab", "5", &link); */
        /*         if (r < 0) */
        /*                 return log_oom(); */

        /*         fflush(stdout); */
        /*         fprintf(stderr, */
        /*                 "A FIDO2 credential has been registered for this volume:\n\n" */
        /*                 "    %s%sfido2-cid=%s", */
        /*                 emoji_enabled() ? glyph(GLYPH_LOCK_AND_KEY) : "", */
        /*                 emoji_enabled() ? " " : "", */
        /*                 ansi_highlight()); */
        /*         fflush(stderr); */

        /*         fputs(base64_encoded_cid, stdout); */
        /*         fflush(stdout); */

        /*         fputs(ansi_normal(), stderr); */
        /*         fflush(stderr); */

        /*         fputc('\n', stdout); */
        /*         fflush(stdout); */

        /*         fprintf(stderr, */
        /*                 "\nPlease save this FIDO2 credential ID. It is required when unlocking the volume\n" */
        /*                 "using the associated FIDO2 keyslot which we just created. To configure automatic\n" */
        /*                 "unlocking using this FIDO2 token, add an appropriate entry to your /etc/crypttab\n" */
        /*                 "file, see %s for details.\n", link); */
        /*         fflush(stderr); */
        /* } */

        /* log_info("New FIDO2 token enrolled as key slot %i.", keyslot); */
        /* return keyslot; */

        flags |= TPM2_FLAGS_USE_FIDO2;

        *ret_salt = TAKE_STRUCT(salt);
        *ret_cid = IOVEC_MAKE(TAKE_PTR(cid), cid_size);
        *ret_secret_str = TAKE_PTR(base64_encoded);
        *ret_lock_with = lock_with;
        *ret_flags |= flags;

        return 0;
}
#endif

int load_volume_key_tpm2(
                struct crypt_device *cd,
                const char *cd_node,
                const char *device,
                void *ret_vk,
                size_t *ret_vks) {

#if HAVE_TPM2
        _cleanup_(iovec_done_erase) struct iovec decrypted_key = {};
        _cleanup_(erase_and_freep) char *passphrase = NULL;
        ssize_t passphrase_size;
        int r;

        assert_se(cd);
        assert_se(cd_node);
        assert_se(ret_vk);
        assert_se(ret_vks);

        bool found_some = false;
        int token = 0; /* first token to look at */

        for (;;) {
                _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {};
                struct iovec *blobs = NULL, *policy_hash = NULL;
                size_t n_blobs = 0, n_policy_hash = 0;
                uint32_t hash_pcr_mask, pubkey_pcr_mask;
                uint16_t pcr_bank, primary_alg;
                TPM2Flags tpm2_flags;
                int keyslot;

                CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);
                CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);

                r = find_tpm2_auto_data(
                                cd,
                                UINT32_MAX,
                                token,
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
                                &tpm2_flags,
                                &keyslot,
                                &token);
                if (r == -ENXIO)
                        return log_full_errno(LOG_NOTICE,
                                              SYNTHETIC_ERRNO(EAGAIN),
                                              found_some
                                              ? "No TPM2 metadata matching the current system state found in LUKS2 header."
                                              : "No TPM2 metadata enrolled in LUKS2 header.");
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        /* TPM2 support not compiled in? */
                        return log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "TPM2 support not available.");
                if (r < 0)
                        return r;

                found_some = true;

                r = acquire_tpm2_key(
                                cd_node,
                                device,
                                hash_pcr_mask,
                                pcr_bank,
                                &pubkey,
                                pubkey_pcr_mask,
                                /* signature_path= */ NULL,
                                /* pcrlock_path= */ NULL,
                                primary_alg,
                                /* key_file= */ NULL, /* key_file_size= */ 0, /* key_file_offset= */ 0, /* no key file */
                                blobs,
                                n_blobs,
                                policy_hash,
                                n_policy_hash,
                                &salt,
                                &srk,
                                &pcrlock_nv,
                                tpm2_flags,
                                /* until= */ 0,
                                "cryptenroll.tpm2-pin",
                                /* askpw_flags= */ 0,
                                &decrypted_key);
                if (IN_SET(r, -EACCES, -ENOLCK))
                        return log_notice_errno(SYNTHETIC_ERRNO(EAGAIN), "TPM2 PIN unlock failed");
                if (r != -EPERM)
                        break;

                token++; /* try a different token next time */
        }

        if (r < 0)
                return log_error_errno(r, "Unlocking via TPM2 device failed: %m");

        passphrase_size = base64mem(decrypted_key.iov_base, decrypted_key.iov_len, &passphrase);
        if (passphrase_size < 0)
                return log_oom();

        r = crypt_volume_key_get(
                        cd,
                        CRYPT_ANY_SLOT,
                        ret_vk,
                        ret_vks,
                        passphrase,
                        passphrase_size);
        if (r < 0)
                return log_error_errno(r, "Unlocking via TPM2 device failed: %m");

        return r;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 unlocking not supported.");
#endif
}

int enroll_tpm2(struct crypt_device *cd,
                const struct iovec *volume_key,
                const char *device,
                uint32_t seal_key_handle,
                const char *device_key,
                Tpm2PCRValue *hash_pcr_values,
                size_t n_hash_pcr_values,
                const char *pcr_pubkey_path,
                bool load_pcr_pubkey,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                bool use_pin,
                const char *pcrlock_path,
                bool use_fido2,
                const char *fido2_device,
                Fido2EnrollFlags fido2_lock_with,
                int fido2_cred_alg,
                const char *fido2_salt_file,
                /*bool fido2_parameters_in_header, */
                int *ret_slot_to_wipe) {

#if HAVE_TPM2
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *signature_json = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_(iovec_done) struct iovec srk = {}, pubkey = {};
        _cleanup_(iovec_done_erase) struct iovec secret = {};
        _cleanup_(iovec_done_erase) struct iovec fido2_salt = {};
        _cleanup_(iovec_done_erase) struct iovec fido2_cid = {};
        const char *node;
        _cleanup_(erase_and_freep) char *pin_str = NULL;
        _cleanup_(erase_and_freep) char *fido2_secret_str = NULL;
        _cleanup_(erase_and_freep) char *fido2_cid_str = NULL;
        ssize_t base64_encoded_size;
        int r, keyslot, slot_to_wipe = -1;
        TPM2Flags flags = 0;
        uint8_t binary_salt[SHA256_DIGEST_SIZE] = {};
        /*
         * erase the salt, we'd rather attempt to not have this in a coredump
         * as an attacker would have all the parameters but pin used to create
         * the session key. This problem goes away when we move to a trusted
         * primary key, aka the SRK.
         */
        CLEANUP_ERASE(binary_salt);

        assert(cd);
        assert(iovec_is_set(volume_key));
        assert(tpm2_pcr_values_valid(hash_pcr_values, n_hash_pcr_values));
        assert(TPM2_PCR_MASK_VALID(pubkey_pcr_mask));
        assert(ret_slot_to_wipe);

        assert_se(node = crypt_get_device_name(cd));

        if (use_pin) {
                r = get_pin(&pin_str, &flags);
                if (r < 0)
                        return r;

                r = crypto_random_bytes(binary_salt, sizeof(binary_salt));
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire random salt: %m");

                uint8_t salted_pin[SHA256_DIGEST_SIZE] = {};
                CLEANUP_ERASE(salted_pin);
                r = tpm2_util_pbkdf2_hmac_sha256(pin_str, strlen(pin_str), binary_salt, sizeof(binary_salt), salted_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to perform PBKDF2: %m");

                pin_str = erase_and_free(pin_str);
                /* re-stringify pin_str */
                base64_encoded_size = base64mem(salted_pin, sizeof(salted_pin), &pin_str);
                if (base64_encoded_size < 0)
                        return log_error_errno(base64_encoded_size, "Failed to base64 encode salted pin: %m");
        }

        if (use_fido2) {
                r = get_fido2_secret(cd, fido2_device, fido2_lock_with, fido2_cred_alg, fido2_salt_file, /*fido2_parameters_in_header, */&fido2_salt, &fido2_cid, &fido2_secret_str, &fido2_lock_with, &flags);
        }

        TPM2B_PUBLIC public = {};
        if (pcr_pubkey_path || load_pcr_pubkey) {
                r = tpm2_load_pcr_public_key(pcr_pubkey_path, &pubkey.iov_base, &pubkey.iov_len);
                if (r < 0) {
                        if (pcr_pubkey_path || signature_path || r != -ENOENT)
                                return log_error_errno(r, "Failed to read TPM PCR public key: %m");

                        log_debug_errno(r, "Failed to read TPM2 PCR public key, proceeding without: %m");
                        pubkey_pcr_mask = 0;
                } else {
                        r = tpm2_tpm2b_public_from_pem(pubkey.iov_base, pubkey.iov_len, &public);
                        if (r < 0)
                                return log_error_errno(r, "Could not convert public key to TPM2B_PUBLIC: %m");

                        if (signature_path) {
                                /* Also try to load the signature JSON object, to verify that our enrollment will work.
                                 * This is optional however, skip it if it's not explicitly provided. */

                                r = tpm2_load_pcr_signature(signature_path, &signature_json);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read TPM PCR signature: %m");
                        }
                }
        } else
                pubkey_pcr_mask = 0;

        bool any_pcr_value_specified = tpm2_pcr_values_has_any_values(hash_pcr_values, n_hash_pcr_values);

        _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy pcrlock_policy = {};
        if (pcrlock_path) {
                r = tpm2_pcrlock_policy_load(pcrlock_path, &pcrlock_policy);
                if (r < 0)
                        return r;
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Couldn't find pcrlock policy %s.", pcrlock_path);

                any_pcr_value_specified = true;
                flags |= TPM2_FLAGS_USE_PCRLOCK;
        }

        _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
        TPM2B_PUBLIC device_key_public = {};
        if (device_key) {
                r = tpm2_load_public_key_file(device_key, &device_key_public);
                if (r < 0)
                        return r;

                if (!tpm2_pcr_values_has_all_values(hash_pcr_values, n_hash_pcr_values))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Must provide all PCR values when using TPM2 device key.");
        } else {
                r = tpm2_context_new_or_warn(device, &tpm2_context);
                if (r < 0)
                        return r;

                if (!tpm2_pcr_values_has_all_values(hash_pcr_values, n_hash_pcr_values)) {
                        r = tpm2_pcr_read_missing_values(tpm2_context, hash_pcr_values, n_hash_pcr_values);
                        if (r < 0)
                                return log_error_errno(r, "Could not read pcr values: %m");
                }
        }

        uint16_t hash_pcr_bank = 0;
        uint32_t hash_pcr_mask = 0;

        if (n_hash_pcr_values > 0) {
                size_t hash_count;

                r = tpm2_pcr_values_hash_count(hash_pcr_values, n_hash_pcr_values, &hash_count);
                if (r < 0)
                        return log_error_errno(r, "Could not get hash count: %m");

                if (hash_count > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Multiple PCR banks selected.");

                /* If we use a literal PCR value policy, derive the bank to use from the algorithm specified on the hash values */
                hash_pcr_bank = hash_pcr_values[0].hash;
                r = tpm2_pcr_values_to_mask(hash_pcr_values, n_hash_pcr_values, hash_pcr_bank, &hash_pcr_mask);
                if (r < 0)
                        return log_error_errno(r, "Could not get hash mask: %m");

        } else if (pubkey_pcr_mask != 0 && !device_key) {

                /* If no literal PCR value policy is used, then let's determine the mask to use automatically
                 * from the measurements of the TPM. */
                r = tpm2_get_best_pcr_bank(
                                tpm2_context,
                                pubkey_pcr_mask,
                                &hash_pcr_bank);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine best PCR bank: %m");
        }

        /* Unfortunately TPM2 policy semantics make it very hard to combine PolicyAuthorize (which we need
         * for signed PCR policies) and PolicyAuthorizeNV (which we need for pcrlock policies). Hence, let's
         * use a "sharded" secret, and lock the first shard to the signed PCR policy, and the 2nd to the
         * pcrlock – if both are requested. */

        TPM2B_DIGEST policy_hash[2] = {
                TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE),
                TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE),
        };
        size_t n_policy_hash = 1;

        /* If both PCR public key unlock and pcrlock unlock is selected, then we create the one for PCR public key unlock first. */
        r = tpm2_calculate_sealing_policy(
                        hash_pcr_values,
                        n_hash_pcr_values,
                        iovec_is_set(&pubkey) ? &public : NULL,
                        use_pin,
                        use_fido2,
                        pcrlock_path && !iovec_is_set(&pubkey) ? &pcrlock_policy : NULL,
                        policy_hash + 0);
        if (r < 0)
                return r;

        if (pcrlock_path && iovec_is_set(&pubkey)) {
                r = tpm2_calculate_sealing_policy(
                                hash_pcr_values,
                                n_hash_pcr_values,
                                /* public= */ NULL, /* This one is off now */
                                use_pin,
                                use_fido2,
                                &pcrlock_policy,    /* And this one on instead. */
                                policy_hash + 1);
                if (r < 0)
                        return r;

                n_policy_hash ++;
        }

        struct iovec *blobs = NULL;
        size_t n_blobs = 0;
        CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);

        if (device_key) {
                if (n_policy_hash > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Combined signed PCR policies and pcrlock policies cannot be calculated offline, currently.");

                blobs = new0(struct iovec, 1);
                if (!blobs)
                        return log_oom();

                n_blobs = 1;

                r = tpm2_calculate_seal(
                                seal_key_handle,
                                &device_key_public,
                                /* attributes= */ NULL,
                                /* secret= */ NULL,
                                policy_hash + 0,
                                pin_str,
                                fido2_secret_str,
                                &secret,
                                blobs + 0,
                                &srk);
        } else
                r = tpm2_seal(tpm2_context,
                              seal_key_handle,
                              policy_hash,
                              n_policy_hash,
                              pin_str,
                              fido2_secret_str,
                              &secret,
                              &blobs,
                              &n_blobs,
                              /* ret_primary_alg= */ NULL,
                              &srk);
        if (r < 0)
                return log_error_errno(r, "Failed to seal to TPM2: %m");

        struct iovec policy_hash_as_iovec[2] = {
                IOVEC_MAKE(policy_hash[0].buffer, policy_hash[0].size),
                IOVEC_MAKE(policy_hash[1].buffer, policy_hash[1].size),
        };

        /* Let's see if we already have this specific PCR policy hash enrolled, if so, exit early. */
        r = search_policy_hash(cd, policy_hash_as_iovec, n_policy_hash);
        if (r == -ENOENT)
                log_debug_errno(r, "PCR policy hash not yet enrolled, enrolling now.");
        else if (r < 0)
                return r;
        else if (use_pin) {
                log_debug("This PCR set is already enrolled, re-enrolling anyway to update PIN.");
                slot_to_wipe = r;
        } else {
                log_info("This PCR set is already enrolled, executing no operation.");
                *ret_slot_to_wipe = -1;
                return r; /* return existing keyslot, so that wiping won't kill it */
        }

        /* If possible, verify the sealed data object. */
        if ((!iovec_is_set(&pubkey) || signature_json) && !any_pcr_value_specified && !device_key) {
                _cleanup_(iovec_done_erase) struct iovec secret2 = {};

                log_debug("Unsealing for verification...");
                r = tpm2_unseal(tpm2_context,
                                hash_pcr_mask,
                                hash_pcr_bank,
                                &pubkey,
                                pubkey_pcr_mask,
                                signature_json,
                                pin_str,
                                pcrlock_path ? &pcrlock_policy : NULL,
                                /* primary_alg= */ 0,
                                blobs,
                                n_blobs,
                                policy_hash_as_iovec,
                                n_policy_hash,
                                &srk,
                                &secret2);
                if (r < 0)
                        return log_error_errno(r, "Failed to unseal secret using TPM2: %m");

                if (iovec_memcmp(&secret, &secret2) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "TPM2 seal/unseal verification failed.");
        }

        /* let's base64 encode the key to use, for compat with homed (and it's easier to every type it in by keyboard, if that might end up being necessary. */
        base64_encoded_size = base64mem(secret.iov_base, secret.iov_len, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        base64_encoded,
                        base64_encoded_size);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new TPM2 key to %s: %m", node);

        r = tpm2_make_luks2_json(
                        keyslot,
                        hash_pcr_mask,
                        hash_pcr_bank,
                        &pubkey,
                        pubkey_pcr_mask,
                        /* primary_alg= */ 0,
                        blobs,
                        n_blobs,
                        policy_hash_as_iovec,
                        n_policy_hash,
                        use_pin ? &IOVEC_MAKE(binary_salt, sizeof(binary_salt)) : NULL,
                        &srk,
                        pcrlock_path ? &pcrlock_policy.nv_handle : NULL,
                        flags,
                        use_fido2 ? &fido2_cid : NULL,
                        use_fido2 ? &fido2_salt : NULL,
                        fido2_lock_with,
                        &v);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare TPM2 JSON token object: %m");

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0)
                return log_error_errno(r, "Failed to add TPM2 JSON token to LUKS2 header: %m");

        log_info("New TPM2 token enrolled as key slot %i.", keyslot);

        *ret_slot_to_wipe = slot_to_wipe;
        return keyslot;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 key enrollment not supported.");
#endif
}
