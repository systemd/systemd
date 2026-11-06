/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "crypto-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "hexdecoct.h"
#include "libfido2-util.h"
#include "log.h"
#include "luks2-tpm2.h"
#include "parse-util.h"
#include "random-util.h"
#include "sha256.h"
#include "strv.h"
#include "tpm2-util.h"

static int unlock_with_fido2(
                const char *fido2_device,
                const struct iovec *fido2_cid,
                const char *fido2_rp,
                const struct iovec *fido2_public_key,
                const char *fido2_public_key_algorithm,
                const struct iovec *fido2_public_key_tag,
                Fido2EnrollFlags fido2_flags,
                char **pins,
                const struct iovec *unsealed,
                struct iovec *ret_secret) {

#if HAVE_LIBFIDO2
        _cleanup_(iovec_done_erase) struct iovec fido2_salt = {};
        _cleanup_(erase_and_freep) void *secret = NULL;
        size_t secret_size;
        int r;

        assert(fido2_cid);
        assert(unsealed);
        assert(ret_secret);

        /* For TPM2+FIDO2 tokens the unsealed secret is not the passphrase. Instead, the passphrase is the
         * FIDO2 token's hmac-secret for a salt derived from the unsealed secret, see
         * tpm2_fido2_derive_salt(). */

        /* Only hand the salt to a FIDO2 token after making sure that the public key we are going to verify
         * the token with belongs to this enrollment. */
        r = tpm2_fido2_verify_public_key_tag(unsealed, fido2_public_key_algorithm, fido2_public_key, fido2_public_key_tag);
        if (r == -EBADMSG) {
                log_error_errno(r, "The FIDO2 public key in the TPM2+FIDO2 token does not match the sealed secret, "
                                "the LUKS2 header was tampered with or is corrupted.");
                return -EPERM;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to verify FIDO2 public key: %m");

        r = tpm2_fido2_derive_salt(unsealed, &fido2_salt);
        if (r < 0)
                return log_error_errno(r, "Failed to derive FIDO2 salt: %m");

        r = fido2_use_hmac_hash(
                        fido2_device,
                        fido2_rp ?: "io.systemd.cryptsetup",
                        fido2_salt.iov_base, fido2_salt.iov_len,
                        fido2_cid->iov_base, fido2_cid->iov_len,
                        fido2_public_key,
                        fido2_public_key_algorithm,
                        pins,
                        fido2_flags,
                        &secret,
                        &secret_size);
        if (r == -ENOLCK) /* libcryptsetup returns -ENOANO also on wrong PIN */
                return -ENOANO;
        if (IN_SET(r, -EAGAIN, -EBADSLT))
                /* None of the plugged-in FIDO2 tokens holds the credential (-EAGAIN), or the configured one
                 * does not (-EBADSLT): treat it like a missing token, see acquire_luks2_key(). */
                return -ENOMEDIUM;
        if (r == -ENOSTR)
                /* The user didn't touch the token in time. The token module turns -ENOSTR into "no matching
                 * TPM2 token data" and moves on to the next token, hence remap it. */
                return -ETIMEDOUT;
        if (r == -EKEYREJECTED) {
                /* A device claimed to have the credential but couldn't prove it. The salt was not handed
                 * out. Let libcryptsetup move on to the next token. */
                log_error_errno(r, "No FIDO2 token proved possession of the enrolled credential, refusing to unlock with this token.");
                return -EPERM;
        }
        if (r < 0)
                return r;

        *ret_secret = IOVEC_MAKE(TAKE_PTR(secret), secret_size);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "FIDO2 support not available, skipping TPM2+FIDO2 token.");
#endif
}

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
                const char *fido2_rp,
                const struct iovec *fido2_public_key,
                const char *fido2_public_key_algorithm,
                const struct iovec *fido2_public_key_tag,
                Fido2EnrollFlags fido2_flags,
                struct iovec *ret_decrypted_key) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signature_json = NULL;
        _cleanup_free_ char *auto_device = NULL;
        _cleanup_(erase_and_freep) char *b64_pin = NULL;
        _cleanup_(iovec_done_erase) struct iovec key1 = {};
        _cleanup_strv_free_erase_ char **pins = NULL;
        bool argon2id = FLAGS_SET(flags, TPM2_FLAGS_USE_ARGON2ID);
        bool fido2 = FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2);
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

        if (fido2) {
                /* Check that a FIDO2 token is plugged in at all, before asking for any PIN. -ENOMEDIUM tells
                 * the caller to wait for one to show up. An unconfigured device is left unset, so that the
                 * token holding the credential is looked for among all plugged-in ones. */
                r = fido2_have_device(fido2_device);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        /* No FIDO2 support (libfido2 is an optional dependency). Report the token like one
                         * that doesn't match, so that libcryptsetup moves on to the next one. */
                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                               "FIDO2 support not available, skipping TPM2+FIDO2 token.");
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEDIUM;
        }

        if ((flags & TPM2_FLAGS_USE_PIN) && !pin)
                return -ENOANO;

        if (fido2 && FLAGS_SET(fido2_flags, FIDO2ENROLL_PIN)) {
                if (!pin)
                        return -ENOANO;

                /* libcryptsetup only passes a single PIN, hence if both the TPM2 and the FIDO2 token
                 * require one, it is the same, see enroll_tpm2(). */
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
                        FLAGS_SET(flags, TPM2_FLAGS_USE_PIN) ? pin : NULL, /* Might be the FIDO2 PIN only */
                        FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK) ? &pcrlock_policy : NULL,
                        primary_alg,
                        blobs,
                        n_blobs,
                        policy_hash,
                        n_policy_hash,
                        srk,
                        argon2id || fido2 ? &unsealed : ret_decrypted_key);
        if (r == -EREMOTE)
                return log_warning_errno(r, "TPM key integrity check failed. Key enrolled in superblock most likely does not belong to this TPM.");
        if (r == -EADDRNOTAVAIL)
                return log_warning_errno(r, "NV index referenced by token is missing, unwritten, or unusable, it could be for another system.");
        if (r == -EILSEQ)
                /* cryptsetup docs say we should return ENOANO on bad PIN */
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Bad %s.", argon2id ? "password" : "PIN");
        if (r == -ENOLCK)
                return log_error_errno(r, "TPM is in dictionary attack lock-out mode.");
        if (r == -EUCLEAN)
                return log_error_errno(r, "PCR values kept changing while unsealing the TPM2 secret, giving up. Something on this system extends a PCR continuously.");
        if (ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r)) {
                log_warning_errno(r, "TPM policy does not match current system state. Either system has been tampered with or policy out-of-date: %m");
                /* Normalize to -EPERM so callers don't confuse it with -ENOANO's "needs PIN" meaning. */
                return -EPERM;
        }
        if (r == -ENOSTR)
                return log_warning_errno(r, "No signature for current PCR policy in TPM2 signature JSON, token does not apply to current boot state: %m");
        if (r < 0)
                return log_error_errno(r, "Failed to unseal secret using TPM2: %m");

        if (fido2) {
                _cleanup_(iovec_done_erase) struct iovec secret = {};

                r = unlock_with_fido2(
                                fido2_device,
                                fido2_cid,
                                fido2_rp,
                                fido2_public_key,
                                fido2_public_key_algorithm,
                                fido2_public_key_tag,
                                fido2_flags,
                                pins,
                                &unsealed,
                                &secret);
                if (r < 0)
                        return r;

                if (!argon2id) {
                        *ret_decrypted_key = TAKE_STRUCT(secret);
                        return 0;
                }

                /* The Argon2id step below applies to the FIDO2 secret instead. */
                iovec_done_erase(&unsealed);
                unsealed = TAKE_STRUCT(secret);
        }

        if (argon2id) {
                _cleanup_(iovec_done_erase) struct iovec volume_key = {};
                r = tpm2_argon2id_hkdf(&key1, &unsealed, &volume_key);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive volume key via HKDF: %m");

                *ret_decrypted_key = TAKE_STRUCT(volume_key);
        }

        return 0;
}
