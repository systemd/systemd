/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "log.h"
#include "luks2-tpm2.h"
#include "parse-util.h"
#include "random-util.h"
#include "sha256.h"
#include "strv.h"
#include "tpm2-util.h"

int acquire_luks2_key(
                const char *device,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pin,
                uint16_t primary_alg,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                const void *salt,
                size_t salt_size,
                TPM2Flags flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *signature_json = NULL;
        _cleanup_free_ char *auto_device = NULL;
        _cleanup_(erase_and_freep) char *b64_salted_pin = NULL;
        int r;

        assert(salt || salt_size == 0);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        if (!device) {
                r = tpm2_find_device_auto(LOG_DEBUG, &auto_device);
                if (r == -ENODEV)
                        return -EAGAIN; /* Tell the caller to wait for a TPM2 device to show up */
                if (r < 0)
                        return r;

                device = auto_device;
        }

        if ((flags & TPM2_FLAGS_USE_PIN) && !pin)
                return -ENOANO;

        /* If we're using a PIN, and the luks header has a salt, it better have a pin too */
        if ((flags & TPM2_FLAGS_USE_PIN) && salt_size > 0 && !pin)
                return -ENOANO;

        if (pin && salt_size > 0) {
                uint8_t salted_pin[SHA256_DIGEST_SIZE] = {};
                CLEANUP_ERASE(salted_pin);
                r = tpm2_util_pbkdf2_hmac_sha256(pin, strlen(pin), salt, salt_size, salted_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to perform PBKDF2: %m");

                r = base64mem(salted_pin, sizeof(salted_pin), &b64_salted_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 encode salted pin: %m");
                pin = b64_salted_pin;
        }

        if (pubkey_pcr_mask != 0) {
                r = tpm2_load_pcr_signature(signature_path, &signature_json);
                if (r < 0)
                        return r;
        }

        return tpm2_unseal(
                        device,
                        hash_pcr_mask,
                        pcr_bank,
                        pubkey, pubkey_size,
                        pubkey_pcr_mask,
                        signature_json,
                        pin,
                        primary_alg,
                        key_data, key_data_size,
                        policy_hash, policy_hash_size,
                        ret_decrypted_key, ret_decrypted_key_size);
}
