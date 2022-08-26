/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "ask-password-api.h"
#include "cryptsetup-tpm2.h"
#include "env-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "json.h"
#include "parse-util.h"
#include "random-util.h"
#include "tpm2-util.h"

static int get_pin(usec_t until, AskPasswordFlags ask_password_flags, bool headless, char **ret_pin_str) {
        _cleanup_free_ char *pin_str = NULL;
        _cleanup_strv_free_erase_ char **pin = NULL;
        int r;

        assert(ret_pin_str);

        r = getenv_steal_erase("PIN", &pin_str);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire PIN from environment: %m");
        if (!r) {
                if (headless)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(ENOPKG),
                                        "PIN querying disabled via 'headless' option. "
                                        "Use the '$PIN' environment variable.");

                pin = strv_free_erase(pin);
                r = ask_password_auto(
                                "Please enter TPM2 PIN:",
                                "drive-harddisk",
                                NULL,
                                "tpm2-pin",
                                "cryptsetup.tpm2-pin",
                                until,
                                ask_password_flags,
                                &pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user pin: %m");
                assert(strv_length(pin) == 1);

                pin_str = strdup(pin[0]);
                if (!pin_str)
                        return log_oom();
        }

        *ret_pin_str = TAKE_PTR(pin_str);

        return r;
}

int acquire_tpm2_key(
                const char *volume_name,
                const char *device,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const void *pubkey,
                size_t pubkey_size,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                uint16_t primary_alg,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                TPM2Flags flags,
                usec_t until,
                bool headless,
                AskPasswordFlags ask_password_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *signature_json = NULL;
        _cleanup_free_ void *loaded_blob = NULL;
        _cleanup_free_ char *auto_device = NULL;
        size_t blob_size;
        const void *blob;
        int r;

        if (!device) {
                r = tpm2_find_device_auto(LOG_DEBUG, &auto_device);
                if (r == -ENODEV)
                        return -EAGAIN; /* Tell the caller to wait for a TPM2 device to show up */
                if (r < 0)
                        return r;

                device = auto_device;
        }

        if (key_data) {
                blob = key_data;
                blob_size = key_data_size;
        } else {
                _cleanup_free_ char *bindname = NULL;

                /* If we read the salt via AF_UNIX, make this client recognizable */
                if (asprintf(&bindname, "@%" PRIx64"/cryptsetup-tpm2/%s", random_u64(), volume_name) < 0)
                        return log_oom();

                r = read_full_file_full(
                                AT_FDCWD, key_file,
                                key_file_offset == 0 ? UINT64_MAX : key_file_offset,
                                key_file_size == 0 ? SIZE_MAX : key_file_size,
                                READ_FULL_FILE_CONNECT_SOCKET,
                                bindname,
                                (char**) &loaded_blob, &blob_size);
                if (r < 0)
                        return r;

                blob = loaded_blob;
        }

        if (pubkey_pcr_mask != 0) {
                r = tpm2_load_pcr_signature(signature_path, &signature_json);
                if (r < 0)
                        return r;
        }

        if (!(flags & TPM2_FLAGS_USE_PIN))
                return tpm2_unseal(
                                device,
                                hash_pcr_mask,
                                pcr_bank,
                                pubkey, pubkey_size,
                                pubkey_pcr_mask,
                                signature_json,
                                /* pin= */ NULL,
                                primary_alg,
                                blob,
                                blob_size,
                                policy_hash,
                                policy_hash_size,
                                ret_decrypted_key,
                                ret_decrypted_key_size);

        for (int i = 5;; i--) {
                _cleanup_(erase_and_freep) char *pin_str = NULL;

                if (i <= 0)
                        return -EACCES;

                r = get_pin(until, ask_password_flags, headless, &pin_str);
                if (r < 0)
                        return r;

                r = tpm2_unseal(device,
                                hash_pcr_mask,
                                pcr_bank,
                                pubkey, pubkey_size,
                                pubkey_pcr_mask,
                                signature_json,
                                pin_str,
                                primary_alg,
                                blob,
                                blob_size,
                                policy_hash,
                                policy_hash_size,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                /* We get this error in case there is an authentication policy mismatch. This should
                 * not happen, but this avoids confusing behavior, just in case. */
                if (IN_SET(r, -EPERM, -ENOLCK))
                        return r;
                if (r < 0)
                        continue;

                return r;
        }
}

int find_tpm2_auto_data(
                struct crypt_device *cd,
                uint32_t search_pcr_mask,
                int start_token,
                uint32_t *ret_hash_pcr_mask,
                uint16_t *ret_pcr_bank,
                void **ret_pubkey,
                size_t *ret_pubkey_size,
                uint32_t *ret_pubkey_pcr_mask,
                uint16_t *ret_primary_alg,
                void **ret_blob,
                size_t *ret_blob_size,
                void **ret_policy_hash,
                size_t *ret_policy_hash_size,
                TPM2Flags *ret_flags,
                int *ret_keyslot,
                int *ret_token) {

        int r, token;

        assert(cd);

        for (token = start_token; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_free_ void *blob = NULL, *policy_hash = NULL, *pubkey = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                size_t blob_size, policy_hash_size, pubkey_size;
                uint32_t hash_pcr_mask, pubkey_pcr_mask;
                uint16_t pcr_bank, primary_alg;
                TPM2Flags flags;
                int keyslot;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-tpm2", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                r = tpm2_parse_luks2_json(
                                v,
                                &keyslot,
                                &hash_pcr_mask,
                                &pcr_bank,
                                &pubkey, &pubkey_size,
                                &pubkey_pcr_mask,
                                &primary_alg,
                                &blob, &blob_size,
                                &policy_hash, &policy_hash_size,
                                &flags);
                if (r == -EUCLEAN) /* Gracefully handle issues in JSON fields not owned by us */
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to parse TPM2 JSON data: %m");

                if (search_pcr_mask == UINT32_MAX ||
                    search_pcr_mask == hash_pcr_mask) {

                        if (start_token <= 0)
                                log_info("Automatically discovered security TPM2 token unlocks volume.");

                        *ret_hash_pcr_mask = hash_pcr_mask;
                        *ret_pcr_bank = pcr_bank;
                        *ret_pubkey = TAKE_PTR(pubkey);
                        *ret_pubkey_size = pubkey_size;
                        *ret_pubkey_pcr_mask = pubkey_pcr_mask;
                        *ret_primary_alg = primary_alg;
                        *ret_blob = TAKE_PTR(blob);
                        *ret_blob_size = blob_size;
                        *ret_policy_hash = TAKE_PTR(policy_hash);
                        *ret_policy_hash_size = policy_hash_size;
                        *ret_keyslot = keyslot;
                        *ret_token = token;
                        *ret_flags = flags;
                        return 0;
                }

                /* PCR mask doesn't match what is configured, ignore this entry, let's see next */
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "No valid TPM2 token data found.");
}
