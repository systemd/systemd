/* SPDX-License-Identifier: LGPL-2.1-or-later */
// Question: Looks like OpenSSL is optional in cryptenroll, is their always a crypto
// library available for PBKDF??
#include <openssl/evp.h>

#include "alloc-util.h"
#include "ask-password-api.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "log.h"
#include "luks2-tpm2.h"
#include "parse-util.h"
#include "random-util.h"
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
                const char *salt,
                size_t salt_size,
                TPM2Flags flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *signature_json = NULL;
        _cleanup_free_ char *auto_device = NULL;
        _cleanup_(erase_and_freep) char *b64_salted_pin = NULL;
        int r;

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

        if ((flags & TPM2_FLAGS_USE_SALT) && !(pin && salt))
                return -ENOANO;

        char salted_pin[32] = {};
        r = PKCS5_PBKDF2_HMAC(pin, strlen(pin), salt, salt_size, 1000, EVP_sha256(), salted_pin, EVP_sha256());
        if (r != 0)
                return 1;

        r = base64mem(salted_pin, sizeof(salted_pin), &b64_salted_pin);
        // TODO: what's the proper erase function for clearing salted_pin memory
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode salted pin: %m");


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
                        b64_salted_pin,
                        primary_alg,
                        key_data, key_data_size,
                        policy_hash, policy_hash_size,
                        ret_decrypted_key, ret_decrypted_key_size);
}
