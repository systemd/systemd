/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptenroll-tpm2.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "memory-util.h"
#include "tpm2-util.h"

static int search_policy_hash(
                struct crypt_device *cd,
                const void *hash,
                size_t hash_size) {

        int r;

        assert(cd);
        assert(hash || hash_size == 0);

        if (hash_size == 0)
                return 0;

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token ++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                _cleanup_free_ void *thash = NULL;
                size_t thash_size = 0;
                int keyslot;
                JsonVariant *w;

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

                w = json_variant_by_key(v, "tpm2-policy-hash");
                if (!w || !json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "TPM2 token data lacks 'tpm2-policy-hash' field.");

                r = unhexmem(json_variant_string(w), SIZE_MAX, &thash, &thash_size);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid base64 data in 'tpm2-policy-hash' field.");

                if (memcmp_nn(hash, hash_size, thash, thash_size) == 0)
                        return keyslot; /* Found entry with same hash. */
        }

        return -ENOENT; /* Not found */
}

static int get_pin(char **ret_pin_str, TPM2Flags *ret_flags) {
        _cleanup_free_ char *pin_str = NULL;
        int r;
        TPM2Flags flags = 0;

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

                        pin = strv_free_erase(pin);
                        r = ask_password_auto(
                                        "Please enter TPM2 PIN:",
                                        "drive-harddisk",
                                        NULL,
                                        "tpm2-pin",
                                        "cryptenroll.tpm2-pin",
                                        USEC_INFINITY,
                                        0,
                                        &pin);
                        if (r < 0)
                                return log_error_errno(r, "Failed to ask for user pin: %m");
                        assert(strv_length(pin) == 1);

                        r = ask_password_auto(
                                        "Please enter TPM2 PIN (repeat):",
                                        "drive-harddisk",
                                        NULL,
                                        "tpm2-pin",
                                        "cryptenroll.tpm2-pin",
                                        USEC_INFINITY,
                                        0,
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

        *ret_flags = flags;
        *ret_pin_str = TAKE_PTR(pin_str);

        return 0;
}

int enroll_tpm2(struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size,
                const char *device,
                uint32_t pcr_mask,
                bool use_pin) {

        _cleanup_(erase_and_freep) void *secret = NULL, *secret2 = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        size_t secret_size, secret2_size, blob_size, hash_size;
        _cleanup_free_ void *blob = NULL, *hash = NULL;
        uint16_t pcr_bank, primary_alg;
        const char *node;
        _cleanup_(erase_and_freep) char *pin_str = NULL;
        int r, keyslot;
        TPM2Flags flags = 0;

        assert(cd);
        assert(volume_key);
        assert(volume_key_size > 0);
        assert(pcr_mask < (1U << TPM2_PCRS_MAX)); /* Support 24 PCR banks */

        assert_se(node = crypt_get_device_name(cd));

        if (use_pin) {
                r = get_pin(&pin_str, &flags);
                if (r < 0)
                        return r;
        }

        r = tpm2_seal(device, pcr_mask, pin_str, &secret, &secret_size, &blob, &blob_size, &hash, &hash_size, &pcr_bank, &primary_alg);
        if (r < 0)
                return r;

        /* Let's see if we already have this specific PCR policy hash enrolled, if so, exit early. */
        r = search_policy_hash(cd, hash, hash_size);
        if (r == -ENOENT)
                log_debug_errno(r, "PCR policy hash not yet enrolled, enrolling now.");
        else if (r < 0)
                return r;
        else {
                log_info("This PCR set is already enrolled, executing no operation.");
                return r; /* return existing keyslot, so that wiping won't kill it */
        }

        /* Quick verification that everything is in order, we are not in a hurry after all. */
        log_debug("Unsealing for verification...");
        r = tpm2_unseal(device, pcr_mask, pcr_bank, primary_alg, blob, blob_size, hash, hash_size, pin_str, &secret2, &secret2_size);
        if (r < 0)
                return r;

        if (memcmp_nn(secret, secret_size, secret2, secret2_size) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "TPM2 seal/unseal verification failed.");

        /* let's base64 encode the key to use, for compat with homed (and it's easier to every type it in by keyboard, if that might end up being necessary. */
        r = base64mem(secret, secret_size, &base64_encoded);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode secret key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        base64_encoded,
                        strlen(base64_encoded));
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new TPM2 key to %s: %m", node);

        r = tpm2_make_luks2_json(keyslot, pcr_mask, pcr_bank, primary_alg, blob, blob_size, hash, hash_size, flags, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare TPM2 JSON token object: %m");

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0)
                return log_error_errno(r, "Failed to add TPM2 JSON token to LUKS2 header: %m");

        log_info("New TPM2 token enrolled as key slot %i.", keyslot);
        return keyslot;
}
