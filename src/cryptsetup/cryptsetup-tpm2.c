/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-tpm2.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "json.h"
#include "parse-util.h"
#include "random-util.h"
#include "tpm2-util.h"

int acquire_tpm2_key(
                const char *volume_name,
                const char *device,
                uint32_t pcr_mask,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const void *key_data,
                size_t key_data_size,
                const void *policy_hash,
                size_t policy_hash_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

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

        return tpm2_unseal(device, pcr_mask, blob, blob_size, policy_hash, policy_hash_size, ret_decrypted_key, ret_decrypted_key_size);
}

int find_tpm2_auto_data(
                struct crypt_device *cd,
                uint32_t search_pcr_mask,
                int start_token,
                uint32_t *ret_pcr_mask,
                void **ret_blob,
                size_t *ret_blob_size,
                void **ret_policy_hash,
                size_t *ret_policy_hash_size,
                int *ret_keyslot,
                int *ret_token) {

        _cleanup_free_ void *blob = NULL, *policy_hash = NULL;
        size_t blob_size = 0, policy_hash_size = 0;
        int r, keyslot = -1, token = -1;
        uint32_t pcr_mask = 0;

        assert(cd);

        for (token = start_token; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                JsonVariant *w, *e;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-tpm2", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                w = json_variant_by_key(v, "tpm2-pcrs");
                if (!w || !json_variant_is_array(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "TPM2 token data lacks 'tpm2-pcrs' field.");

                assert(pcr_mask == 0);
                JSON_VARIANT_ARRAY_FOREACH(e, w) {
                        uintmax_t u;

                        if (!json_variant_is_number(e))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "TPM2 PCR is not a number.");

                        u = json_variant_unsigned(e);
                        if (u >= TPM2_PCRS_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "TPM2 PCR number out of range.");

                        pcr_mask |= UINT32_C(1) << u;
                }

                if (search_pcr_mask != UINT32_MAX &&
                    search_pcr_mask != pcr_mask) /* PCR mask doesn't match what is configured, ignore this entry */
                        continue;

                assert(!blob);
                w = json_variant_by_key(v, "tpm2-blob");
                if (!w || !json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "TPM2 token data lacks 'tpm2-blob' field.");

                r = unbase64mem(json_variant_string(w), SIZE_MAX, &blob, &blob_size);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid base64 data in 'tpm2-blob' field.");

                assert(!policy_hash);
                w = json_variant_by_key(v, "tpm2-policy-hash");
                if (!w || !json_variant_is_string(w))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "TPM2 token data lacks 'tpm2-policy-hash' field.");

                r = unhexmem(json_variant_string(w), SIZE_MAX, &policy_hash, &policy_hash_size);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid base64 data in 'tpm2-policy-hash' field.");

                assert(keyslot < 0);
                keyslot = cryptsetup_get_keyslot_from_token(v);
                if (keyslot < 0)
                        return log_error_errno(keyslot, "Failed to extract keyslot index from TPM2 JSON data: %m");

                break;
        }

        if (!blob)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "No valid TPM2 token data found.");

        if (start_token <= 0)
                log_info("Automatically discovered security TPM2 token unlocks volume.");

        *ret_pcr_mask = pcr_mask;
        *ret_blob = TAKE_PTR(blob);
        *ret_blob_size = blob_size;
        *ret_policy_hash = TAKE_PTR(policy_hash);
        *ret_policy_hash_size = policy_hash_size;
        *ret_keyslot = keyslot;
        *ret_token = token;

        return 0;
}
