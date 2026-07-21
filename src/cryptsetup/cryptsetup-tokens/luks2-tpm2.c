/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "crypto-util.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "libfido2-util.h"
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
                const struct iovec *pubkey,
                const char *pubkey_policy_ref,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pin,
                const char *pcrlock_path,
                uint16_t primary_alg,
                const struct iovec blobs[],
                size_t n_blobs,
                const struct iovec policy_hash[],
                size_t n_policy_hash,
                const struct iovec *salt,
                const struct iovec *srk,
                const struct iovec *pcrlock_nv,
                TPM2Flags flags,
                const Argon2IdParameters *argon2id_params,
                const char *fido2_device,
                const struct iovec *fido2_cid,
                const struct iovec *fido2_salt,
                const char *fido2_rp,
                Fido2EnrollFlags fido2_flags,
                struct iovec *ret_decrypted_key) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signature_json = NULL;
        _cleanup_free_ char *auto_device = NULL;
        _cleanup_(erase_and_freep) char *b64_pin = NULL;
        _cleanup_(iovec_done_erase) struct iovec key1 = {};
        bool argon2id = FLAGS_SET(flags, TPM2_FLAGS_USE_ARGON2ID);
        _cleanup_(erase_and_freep) char *b64_fido2_secret = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
#if HAVE_LIBFIDO2
        _cleanup_(erase_and_freep) void *fido2_secret = NULL;
        size_t fido2_secret_size;
        ssize_t b64_fido2_secret_size;
#endif
        int r;

        assert(iovec_is_valid(salt));
        assert(ret_decrypted_key);

        if (!device) {
                r = tpm2_find_device_auto(&auto_device);
                if (r == -ENODEV)
                        return -EAGAIN; /* Tell the caller to wait for a TPM2 device to show up */
                if (r < 0)
                        return log_error_errno(r, "Could not find TPM2 device: %m");

                device = auto_device;
        }

        if ((flags & TPM2_FLAGS_USE_FIDO2) && !fido2_device) {
                r = fido2_find_device_auto(&auto_device);
                if (r < 0)
                        return log_error_errno(r, "Could not find FIDO2 device: %m");

                fido2_device = auto_device;
        }

        if ((flags & TPM2_FLAGS_USE_PIN) && !pin)
                return -ENOANO;

        if ((flags & TPM2_FLAGS_USE_FIDO2) && (fido2_flags & FIDO2ENROLL_PIN) && !pin)
                return -ENOANO;

        /* One limitation is that we only have one PIN for the TPM2 and the FIDO2 if both are required */
        if ((flags & TPM2_FLAGS_USE_FIDO2) && (fido2_flags & FIDO2ENROLL_PIN) && pin) {
                pins = strv_new(pin);
                if (!pins)
                        return log_oom();
        }

        if (argon2id) {
                if (isempty(pin))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Argon2id PIN requires a non-empty PIN.");
                if (!iovec_is_set(salt))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argon2id PIN requires salt in LUKS2 token.");

                r = tpm2_argon2id_derive_split(pin, salt, argon2id_params, &key1, &b64_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to perform Argon2id: %m");

                pin = b64_pin;
        } else if (pin && iovec_is_set(salt)) {
                uint8_t salted_pin[SHA256_DIGEST_SIZE] = {};
                CLEANUP_ERASE(salted_pin);
                r = tpm2_util_pbkdf2_hmac_sha256(pin, strlen(pin), salt->iov_base, salt->iov_len, salted_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to perform PBKDF2: %m");

                r = base64mem(salted_pin, sizeof(salted_pin), &b64_pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to base64 encode salted pin: %m");
                pin = b64_pin;
        }

#if HAVE_LIBFIDO2
        if (flags & TPM2_FLAGS_USE_FIDO2) {
                r = fido2_use_hmac_hash(
                        fido2_device,
                        fido2_rp ?: "io.systemd.cryptsetup",
                        fido2_salt->iov_base, fido2_salt->iov_len,
                        fido2_cid->iov_base, fido2_cid->iov_len,
                        pins,
                        fido2_flags,
                        &fido2_secret,
                        &fido2_secret_size);
                if (r == -ENOLCK)
                        r = -ENOANO;
                if (r < 0)
                        return r;

                b64_fido2_secret_size = base64mem(fido2_secret, fido2_secret_size, &b64_fido2_secret);
                if (b64_fido2_secret_size < 0)
                        return log_error_errno((int)b64_fido2_secret_size, "Failed to base64 encode key: %m");
        }
#endif

        if (pubkey_pcr_mask != 0) {
                r = tpm2_load_pcr_signature(signature_path, &signature_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to load PCR signature: %m");
        }

        _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy pcrlock_policy = {};
        if (FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK)) {
                r = tpm2_pcrlock_policy_load(pcrlock_path, &pcrlock_policy);
                if (r < 0)
                        return r;
                if (r == 0) {
                        r = tpm2_pcrlock_policy_from_credentials(srk, pcrlock_nv, &pcrlock_policy);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Couldn't find pcrlock policy for volume.");
                }
        }

        _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
        r = tpm2_context_new_or_warn(device, &tpm2_context);
        if (r < 0)
                return r;

        _cleanup_(iovec_done_erase) struct iovec unsealed = {};
        r = tpm2_unseal(tpm2_context,
                        hash_pcr_mask,
                        pcr_bank,
                        pubkey,
                        pubkey_policy_ref,
                        pubkey_pcr_mask,
                        signature_json,
                        pin,
                        b64_fido2_secret,
                        FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK) ? &pcrlock_policy : NULL,
                        primary_alg,
                        blobs,
                        n_blobs,
                        policy_hash,
                        n_policy_hash,
                        srk,
                        argon2id ? &unsealed : ret_decrypted_key);
        if (r == -EREMOTE)
                return log_warning_errno(r, "TPM key integrity check failed. Key enrolled in superblock most likely does not belong to this TPM.");
        if (r == -EADDRNOTAVAIL)
                return log_warning_errno(r, "NV index referenced by token is missing, unwritten, or unusable, it could be for another system.");
        if (r == -EILSEQ)
                /* cryptsetup docs say we should return ENOANO on bad PIN */
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Bad %s.", argon2id ? "password" : "PIN");
        if (r == -ENOLCK)
                return log_error_errno(r, "TPM is in dictionary attack lock-out mode.");
        if (ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r)) {
                log_warning_errno(r, "TPM policy does not match current system state. Either system has been tampered with or policy out-of-date: %m");
                /* Normalize to -EPERM so callers don't confuse it with -ENOANO's "needs PIN" meaning. */
                return -EPERM;
        }
        if (r == -ENOSTR)
                return log_warning_errno(r, "No signature for current PCR policy in TPM2 signature JSON, token does not apply to current boot state: %m");
        if (r < 0)
                return log_error_errno(r, "Failed to unseal secret using TPM2: %m");

        if (argon2id) {
                _cleanup_(iovec_done_erase) struct iovec volume_key = {};
                r = tpm2_argon2id_hkdf(&key1, &unsealed, &volume_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive volume key via HKDF: %m");

                *ret_decrypted_key = TAKE_STRUCT(volume_key);
        }

        return 0;
}
