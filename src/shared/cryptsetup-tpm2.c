/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "crypto-util.h"
#include "cryptsetup-fido2.h"
#include "cryptsetup-tpm2.h"
#include "cryptsetup-util.h"
#include "env-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "libfido2-util.h"
#include "log.h"
#include "random-util.h"
#include "strv.h"
#include "tpm2-util.h"

#if HAVE_LIBCRYPTSETUP && HAVE_TPM2
static int get_pin(
                usec_t until,
                const char *askpw_message,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                char **envpin,
                char **ret_pin_str) {
        _cleanup_(erase_and_freep) char *pin_str = NULL;
        _cleanup_strv_free_erase_ char **pin = NULL;
        int r;

        assert(askpw_message);
        assert(envpin);
        assert(ret_pin_str);

        /* $PIN is a single-use resource, and the caller may already have claimed it on our behalf, to keep
         * the FIDO2 code from swallowing it. Consume that first, and only look at the environment if it
         * didn't. */
        pin_str = TAKE_PTR(*envpin);
        if (!pin_str) {
                r = getenv_steal_erase("PIN", &pin_str);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire PIN from environment: %m");
        }

        if (!pin_str) {
                if (FLAGS_SET(askpw_flags, ASK_PASSWORD_HEADLESS))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(ENOPKG),
                                        "PIN querying disabled via 'headless' option. "
                                        "Use the '$PIN' environment variable.");

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = askpw_message,
                        .icon = "drive-harddisk",
                        .keyring = "tpm2-pin",
                        .credential = askpw_credential,
                        .until = until,
                        .hup_fd = -EBADF,
                };

                pin = strv_free_erase(pin);
                r = ask_password_auto(&req, askpw_flags, &pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user pin: %m");
                assert(strv_length(pin) == 1);

                pin_str = strdup(pin[0]);
                if (!pin_str)
                        return log_oom();
        }

        *ret_pin_str = TAKE_PTR(pin_str);

        return 0;
}

static int acquire_fido2_secret(
                const char *volume_name,
                const char *friendly_name,
                const char *fido2_device,
                const struct iovec *fido2_cid,
                const struct iovec *fido2_salt,
                const char *fido2_rp,
                Fido2EnrollFlags fido2_flags,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                const char *pin,
                char **ret_fido2_secret_str) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        size_t decrypted_key_size;
        ssize_t base64_encoded_size;
        int r;

        assert(ret_fido2_secret_str);

        r = acquire_fido2_key(
                        volume_name,
                        friendly_name,
                        fido2_device,
                        fido2_rp,
                        fido2_cid->iov_base, fido2_cid->iov_len,
                        /* key_file= */ NULL,
                        /* key_file_size= */ 0,
                        /* key_file_offset= */ 0,
                        fido2_salt,
                        until,
                        fido2_flags,
                        "cryptsetup.fido2-pin",
                        askpw_flags,
                        pin,
                        &decrypted_key,
                        &decrypted_key_size);
        if (IN_SET(r, -EAGAIN, -EBADSLT))
                /* None of the plugged-in FIDO2 tokens holds the credential of this slot (-EAGAIN), or the
                 * configured one does not (-EBADSLT). Use -ENOMEDIUM for both, to distinguish them from the
                 * "no TPM2 chip" -EAGAIN: callers then try the other slots, and wait for the token to show
                 * up if none of them works. */
                return -ENOMEDIUM;
        if (r < 0)
                return r;

        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_oom();

        *ret_fido2_secret_str = TAKE_PTR(base64_encoded);

        return 0;
}
#endif

int acquire_tpm2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                uint32_t hash_pcr_mask,
                uint16_t pcr_bank,
                const struct iovec *pubkey,
                const char *pubkey_policy_ref,
                uint32_t pubkey_pcr_mask,
                const char *signature_path,
                const char *pcrlock_path,
                uint16_t primary_alg,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec blobs[],
                size_t n_blobs,
                const struct iovec policy_hash[],
                size_t n_policy_hash,
                const struct iovec *salt,
                const struct iovec *srk,
                const struct iovec *pcrlock_nv,
                TPM2Flags flags,
                const char *fido2_device,
                const struct iovec *fido2_cid,
                const struct iovec *fido2_salt,
                const char *fido2_rp,
                Fido2EnrollFlags fido2_flags,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                const Argon2IdParameters *argon2id_params,
                struct iovec *ret_decrypted_key) {

#if HAVE_LIBCRYPTSETUP && HAVE_TPM2
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signature_json = NULL;
        _cleanup_(iovec_done) struct iovec loaded_blob = {};
        _cleanup_free_ char *tpm2_auto_device = NULL;
        _cleanup_(erase_and_freep) char *fido2_secret_str = NULL, *envpin = NULL;
        int r;

        assert(iovec_is_valid(salt));

        if (!device) {
                r = tpm2_find_device_auto(&tpm2_auto_device);
                if (r == -ENODEV)
                        return -EAGAIN; /* Tell the caller to wait for a TPM2 device to show up */
                if (r < 0)
                        return log_error_errno(r, "Could not find TPM2 device: %m");

                device = tpm2_auto_device;
        }

        if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2)) {
                /* Check that a FIDO2 token is plugged in at all, before asking for any PIN. -ENOMEDIUM tells
                 * the caller to wait for one to show up. An unconfigured device is left unset, so that the
                 * token holding the credential is looked for among all plugged-in ones. */
                r = fido2_have_device(fido2_device);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOMEDIUM;
        }

        if (n_blobs == 0) {
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
                                (char**) &loaded_blob.iov_base, &loaded_blob.iov_len);
                if (r < 0)
                        return r;

                blobs = &loaded_blob;
                n_blobs = 1;
        }

        if (pubkey_pcr_mask != 0) {
                r = tpm2_load_pcr_signature(signature_path, &signature_json);
                if (r < 0)
                        return log_error_errno(r, "Failed to load pcr signature: %m");
        }

        _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy pcrlock_policy = {};

        if (FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK)) {
                r = tpm2_pcrlock_policy_load(pcrlock_path, &pcrlock_policy);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Not found? Then search among passed credentials */
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

        /* Recover the hmac-secret early, unless a PIN is required, to avoid multiple tapping. */
        if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2) &&
            !(FLAGS_SET(flags, TPM2_FLAGS_USE_PIN) && FLAGS_SET(fido2_flags, FIDO2ENROLL_PIN))) {

                /* acquire_fido2_key() consumes $PIN when no PIN is handed to it. If the TPM2 wants a PIN
                 * but the FIDO2 token does not, that $PIN belongs to the TPM2, so claim it here before the
                 * FIDO2 code can erase it, and pass it on to get_pin() below. */
                if (FLAGS_SET(flags, TPM2_FLAGS_USE_PIN)) {
                        r = getenv_steal_erase("PIN", &envpin);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire PIN from environment: %m");
                }

                r = acquire_fido2_secret(
                                volume_name,
                                friendly_name,
                                fido2_device,
                                fido2_cid,
                                fido2_salt,
                                fido2_rp,
                                fido2_flags,
                                until,
                                askpw_credential,
                                askpw_flags,
                                /* pin= */ NULL,
                                &fido2_secret_str);
                if (r < 0)
                        return r;
        }

        if (!(flags & TPM2_FLAGS_USE_PIN)) {
                r = tpm2_unseal(tpm2_context,
                                hash_pcr_mask,
                                pcr_bank,
                                pubkey,
                                pubkey_policy_ref,
                                pubkey_pcr_mask,
                                signature_json,
                                /* pin= */ NULL,
                                fido2_secret_str,
                                FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK) ? &pcrlock_policy : NULL,
                                primary_alg,
                                blobs,
                                n_blobs,
                                policy_hash,
                                n_policy_hash,
                                srk,
                                ret_decrypted_key);
                if (r == -EREMOTE)
                        return log_warning_errno(r, "TPM key integrity check failed. Key enrolled in superblock most likely does not belong to this TPM.");
                if (r == -EADDRNOTAVAIL)
                        return log_warning_errno(r, "NV index referenced by token is missing, unwritten, or unusable, it could be for another system.");
                if (r == -EUCLEAN)
                        return log_error_errno(r, "PCR values kept changing while unsealing the TPM2 secret, giving up. Something on this system extends a PCR continuously.");
                if (ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r)) {
                        log_warning_errno(r, "TPM policy does not match current system state. Either system has been tampered with or policy out-of-date: %m");
                        /* Normalize to -EPERM so callers don't confuse it with -ENOANO's "needs PIN" meaning. */
                        return -EPERM;
                }
                if (r == -ENOSTR)
                        return log_warning_errno(r, "No signature for current PCR policy in TPM2 signature JSON, token does not apply to current boot state: %m");
                if (r == -EILSEQ) {
                        /* A wrong FIDO2 token would have failed the pre-flight earlier, so the token here is
                         * correct and its hmac-secret matches; an authValue mismatch therefore means the
                         * enrollment metadata is inconsistent or out of date (or the header was tampered
                         * with). Without a FIDO2 token in the picture there's nothing token specific to
                         * report. */
                        if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2))
                                return log_error_errno(r, "TPM2 authorization failed although the FIDO2 token was accepted; "
                                                       "the enrollment metadata is inconsistent or out of date "
                                                       "(or the LUKS2 header was tampered with).");

                        return log_error_errno(r, "TPM2 authorization failed; the enrollment metadata is inconsistent "
                                               "or out of date (or the LUKS2 header was tampered with).");
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to unseal secret using TPM2: %m");

                return r;
        }

        bool argon2id = FLAGS_SET(flags, TPM2_FLAGS_USE_ARGON2ID);

        for (int i = 5;; i--) {
                _cleanup_(erase_and_freep) char *input_str = NULL, *b64_key2 = NULL;
                _cleanup_(iovec_done_erase) struct iovec key1 = {};
                const char *pin_used;

                if (i <= 0)
                        return -EACCES;

                r = get_pin(until,
                            FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2) && FLAGS_SET(fido2_flags, FIDO2ENROLL_PIN) ?
                                    "Please enter FIDO2 token PIN:" : "Please enter TPM2 PIN:",
                            askpw_credential, askpw_flags, &envpin, &input_str);
                if (r < 0)
                        return r;

                askpw_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;

                if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2) && FLAGS_SET(fido2_flags, FIDO2ENROLL_PIN)) {
                        fido2_secret_str = erase_and_free(fido2_secret_str);

                        r = acquire_fido2_secret(
                                        volume_name,
                                        friendly_name,
                                        fido2_device,
                                        fido2_cid,
                                        fido2_salt,
                                        fido2_rp,
                                        fido2_flags,
                                        until,
                                        askpw_credential,
                                        askpw_flags,
                                        input_str,
                                        &fido2_secret_str);
                        if (IN_SET(r, -ENOANO, -ENOLCK)) {
                                log_warning("FIDO2 token PIN incorrect, please try again.");
                                continue;
                        }
                        if (r < 0)
                                return r;
                }

                if (argon2id) {
                        if (isempty(input_str))
                                return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Argon2id PIN requires a non-empty PIN.");
                        if (!iovec_is_set(salt))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argon2id PIN requires salt in LUKS2 token.");

                        r = tpm2_argon2id_derive_split(input_str, salt, argon2id_params, &key1, &b64_key2);
                        if (r < 0)
                                return log_error_errno(r, "Failed to perform Argon2id: %m");

                        pin_used = b64_key2;
                } else {
                        if (iovec_is_set(salt)) {
                                uint8_t salted_pin[SHA256_DIGEST_SIZE] = {};
                                CLEANUP_ERASE(salted_pin);

                                r = tpm2_util_pbkdf2_hmac_sha256(input_str, strlen(input_str), salt->iov_base, salt->iov_len, salted_pin);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to perform PBKDF2: %m");

                                r = base64mem(salted_pin, sizeof(salted_pin), &b64_key2);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to base64 encode salted pin: %m");

                                pin_used = b64_key2;
                        } else
                                /* else: no salting needed, backwards compat with non-salted pins */
                                pin_used = input_str;
                }

                _cleanup_(iovec_done_erase) struct iovec unsealed = {};
                r = tpm2_unseal(tpm2_context,
                                hash_pcr_mask,
                                pcr_bank,
                                pubkey,
                                pubkey_policy_ref,
                                pubkey_pcr_mask,
                                signature_json,
                                pin_used,
                                fido2_secret_str,
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
                if (r == -EUCLEAN)
                        return log_error_errno(r, "PCR values kept changing while unsealing the TPM2 secret, giving up. Something on this system extends a PCR continuously.");
                if (ERRNO_IS_NEG_TPM2_UNSEAL_BAD_PCR(r)) {
                        log_warning_errno(r, "TPM policy does not match current system state. Either system has been tampered with or policy out-of-date: %m");
                        /* Normalize to -EPERM so callers don't confuse it with -ENOANO's "needs PIN" meaning. */
                        return -EPERM;
                }
                if (r == -ENOSTR)
                        return log_warning_errno(r, "No signature for current PCR policy in TPM2 signature JSON, token does not apply to current boot state: %m");
                if (r == -ENOLCK)
                        return log_error_errno(r, "TPM is in dictionary attack lock-out mode.");
                if (r == -EILSEQ) {
                        /* The FIDO2 token accepted the client PIN and returned the correct hmac-secret (a
                         * wrong token or PIN would have failed earlier, as the cid was checked), so when
                         * that PIN is also the TPM2 PIN there is nothing left for the user to fix: the
                         * policy metadata is inconsistent or out of date, or the header was tampered
                         * with. Otherwise it's the separate TPM2 PIN that is wrong, which is retryable.  A
                         * similar check is in luks2-tpm2.c. */
                        if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2) && FLAGS_SET(fido2_flags, FIDO2ENROLL_PIN))
                                return log_error_errno(r, "TPM2 authorization failed although the FIDO2 token and PIN were accepted; "
                                                       "the enrollment metadata is inconsistent or out of date "
                                                       "(or the LUKS2 header was tampered with).");
                        log_warning_errno(r, "Bad %s.", argon2id ? "password" : "PIN");
                        continue;
                }
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
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support not available.");
#endif
}

int find_tpm2_auto_data(
                struct crypt_device *cd,
                uint32_t search_pcr_mask,
                int start_token,
                int log_level,
                uint32_t *ret_hash_pcr_mask,
                uint16_t *ret_pcr_bank,
                struct iovec *ret_pubkey,
                char **ret_pubkey_policy_ref,
                uint32_t *ret_pubkey_pcr_mask,
                uint16_t *ret_primary_alg,
                struct iovec **ret_blobs,
                size_t *ret_n_blobs,
                struct iovec **ret_policy_hash,
                size_t *ret_n_policy_hash,
                struct iovec *ret_salt,
                struct iovec *ret_srk,
                struct iovec *ret_pcrlock_nv,
                TPM2Flags *ret_flags,
                struct iovec *ret_fido2_cid,
                struct iovec *ret_fido2_salt,
                char **ret_fido2_rp,
                Fido2EnrollFlags *ret_fido2_flags,
                int *ret_keyslot,
                int *ret_token,
                Argon2IdParameters *ret_argon2id_params) {

#if HAVE_LIBCRYPTSETUP && HAVE_TPM2
        int r, token;

        assert(cd);
        assert(ret_hash_pcr_mask);
        assert(ret_pcrlock_nv);
        assert(ret_pubkey);
        assert(ret_pubkey_policy_ref);
        assert(ret_pubkey_pcr_mask);
        assert(ret_primary_alg);
        assert(ret_blobs);
        assert(ret_n_blobs);
        assert(ret_policy_hash);
        assert(ret_n_policy_hash);
        assert(ret_salt);
        assert(ret_srk);
        assert(ret_pcrlock_nv);
        assert(ret_flags);
        assert(ret_fido2_cid);
        assert(ret_fido2_salt);
        assert(ret_fido2_rp);
        assert(ret_fido2_flags);
        assert(ret_keyslot);
        assert(ret_token);

        for (token = start_token; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {}, fido2_cid = {}, fido2_salt = {};
                _cleanup_free_ char *pubkey_policy_ref = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                struct iovec *blobs = NULL, *policy_hash = NULL;
                size_t n_blobs = 0, n_policy_hash = 0;
                uint32_t hash_pcr_mask, pubkey_pcr_mask;
                uint16_t pcr_bank, primary_alg;
                Argon2IdParameters ap = {};
                TPM2Flags flags;
                Fido2EnrollFlags fido2_flags;
                _cleanup_free_ char *fido2_rp = NULL;
                int keyslot;

                CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);
                CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);

                r = cryptsetup_get_token_as_json(cd, token, "systemd-tpm2", &v);
                if (ERRNO_IS_NEG_CRYPTSETUP_TOKEN_SKIP(r))
                        continue;
                if (r < 0)
                        return log_full_errno(log_level, r, "Failed to read JSON token data off disk: %m");

                r = tpm2_parse_luks2_json(
                                v,
                                &keyslot,
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
                                &ap,
                                &fido2_cid,
                                &fido2_salt,
                                &fido2_rp,
                                &fido2_flags);
                if (r == -EUCLEAN) /* Gracefully handle issues in JSON fields not owned by us */
                        continue;
                if (r < 0)
                        return log_full_errno(log_level, r, "Failed to parse TPM2 JSON data: %m");

                if (search_pcr_mask == UINT32_MAX ||
                    search_pcr_mask == hash_pcr_mask) {

                        if (start_token <= 0)
                                /* Syslog priorities count the other way round: the higher the number, the
                                 * less severe. Hence MAX() keeps this at LOG_INFO for callers passing
                                 * LOG_ERR, and lowers it to LOG_DEBUG for callers requesting quiet operation. */
                                log_full(MAX(log_level, LOG_INFO), "Automatically discovered security TPM2 token unlocks volume.");

                        *ret_hash_pcr_mask = hash_pcr_mask;
                        *ret_pcr_bank = pcr_bank;
                        *ret_pubkey = TAKE_STRUCT(pubkey);
                        *ret_pubkey_policy_ref = TAKE_PTR(pubkey_policy_ref);
                        *ret_pubkey_pcr_mask = pubkey_pcr_mask;
                        *ret_primary_alg = primary_alg;
                        *ret_blobs = TAKE_PTR(blobs);
                        *ret_n_blobs = n_blobs;
                        *ret_policy_hash = TAKE_PTR(policy_hash);
                        *ret_n_policy_hash = n_policy_hash;
                        *ret_salt = TAKE_STRUCT(salt);
                        *ret_keyslot = keyslot;
                        *ret_token = token;
                        *ret_srk = TAKE_STRUCT(srk);
                        *ret_pcrlock_nv = TAKE_STRUCT(pcrlock_nv);
                        *ret_flags = flags;
                        if (ret_argon2id_params)
                                *ret_argon2id_params = ap;
                        *ret_fido2_cid = TAKE_STRUCT(fido2_cid);
                        *ret_fido2_salt = TAKE_STRUCT(fido2_salt);
                        *ret_fido2_rp = TAKE_PTR(fido2_rp);
                        *ret_fido2_flags = fido2_flags;
                        return 0;
                }

                /* PCR mask doesn't match what is configured, ignore this entry, let's see next */
        }

        return log_full_errno(log_level, SYNTHETIC_ERRNO(ENXIO), "No valid TPM2 token data found.");
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 support not available.");
#endif
}

int cryptsetup_tpm2_unlock_auto(
                struct crypt_device *cd,
                int *ret_keyslot,
                char **ret_passphrase) {

#if HAVE_LIBCRYPTSETUP && HAVE_TPM2
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *signature_json = NULL;
        _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
        bool found_some = false, signature_load_failed = false;
        int r;

        assert(cd);
        assert(ret_keyslot);
        assert(ret_passphrase);

        /* Non-interactive counterpart to acquire_tpm2_key(), for use from library code. Walks all
         * "systemd-tpm2" tokens in the LUKS2 header and returns the first one that unseals against the
         * local TPM2 (auto-detected), as the base64-encoded keyslot passphrase (which is how
         * systemd-cryptenroll and systemd-repart enroll the sealed secret) plus the keyslot it belongs to.
         * PIN-protected and FIDO2-bound tokens are skipped, we never prompt. Logs at debug level only,
         * except that the pcrlock policy helpers log on their own for pcrlock-bound tokens. Returns -ENXIO
         * if no token could be used. */

        for (int token = 0;; token++) {
                _cleanup_(iovec_done) struct iovec pubkey = {}, salt = {}, srk = {}, pcrlock_nv = {}, fido2_cid = {}, fido2_salt = {};
                _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy pcrlock_policy = {};
                _cleanup_(iovec_done_erase) struct iovec secret = {};
                _cleanup_(erase_and_freep) char *b64 = NULL;
                _cleanup_free_ char *pubkey_policy_ref = NULL, *fido2_rp = NULL;
                struct iovec *blobs = NULL, *policy_hash = NULL;
                size_t n_blobs = 0, n_policy_hash = 0;
                uint32_t hash_pcr_mask, pubkey_pcr_mask;
                uint16_t pcr_bank, primary_alg;
                Fido2EnrollFlags fido2_flags;
                TPM2Flags flags;
                int keyslot;

                CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);
                CLEANUP_ARRAY(policy_hash, n_policy_hash, iovec_array_free);

                r = find_tpm2_auto_data(
                                cd,
                                /* search_pcr_mask= */ UINT32_MAX,
                                token,
                                LOG_DEBUG,
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
                                &fido2_cid,
                                &fido2_salt,
                                &fido2_rp,
                                &fido2_flags,
                                &keyslot,
                                &token,
                                /* ret_argon2id_params= */ NULL);
                if (r == -ENXIO) /* No (more) TPM2 tokens in the header */
                        break;
                if (r < 0)
                        return r;

                if (flags & (TPM2_FLAGS_USE_PIN|TPM2_FLAGS_USE_ARGON2ID)) {
                        log_debug("TPM2 token %i requires a PIN (or Argon2id), skipping.", token);
                        continue;
                }

                if (FLAGS_SET(flags, TPM2_FLAGS_USE_FIDO2)) {
                        log_debug("TPM2 token %i requires a FIDO2 token, skipping.", token);
                        continue;
                }

                found_some = true;

                if (pubkey_pcr_mask != 0) {
                        /* The signature file is the same for all tokens, hence load it only once, and don't
                         * retry if that failed. */
                        if (!signature_json && !signature_load_failed) {
                                r = tpm2_load_pcr_signature(/* path= */ NULL, &signature_json);
                                if (r == -ENOMEM)
                                        return r;
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to load PCR signature, cannot use TPM2 tokens bound to a public key: %m");
                                        signature_load_failed = true;
                                }
                        }
                        if (!signature_json)
                                continue;
                }

                if (FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK)) {
                        r = tpm2_pcrlock_policy_load(/* path= */ NULL, &pcrlock_policy);
                        if (r == 0) /* Not found? Then search among passed credentials */
                                r = tpm2_pcrlock_policy_from_credentials(&srk, &pcrlock_nv, &pcrlock_policy);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                log_debug_errno(r, "Failed to load pcrlock policy for TPM2 token %i, skipping: %m", token);
                        else if (r == 0)
                                log_debug("No pcrlock policy found for TPM2 token %i, skipping.", token);
                        if (r <= 0)
                                continue;
                }

                /* Only talk to the TPM2 once we know there's a token we could actually use */
                if (!tpm2_context) {
                        _cleanup_free_ char *device = NULL;

                        r = tpm2_find_device_auto(&device);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to find TPM2 device: %m");

                        r = tpm2_context_new(device, &tpm2_context);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to create TPM2 context: %m");
                }

                r = tpm2_unseal(tpm2_context,
                                hash_pcr_mask,
                                pcr_bank,
                                &pubkey,
                                pubkey_policy_ref,
                                pubkey_pcr_mask,
                                signature_json,
                                /* pin= */ NULL,
                                /* fido2_secret= */ NULL,
                                FLAGS_SET(flags, TPM2_FLAGS_USE_PCRLOCK) ? &pcrlock_policy : NULL,
                                primary_alg,
                                blobs,
                                n_blobs,
                                policy_hash,
                                n_policy_hash,
                                &srk,
                                &secret);
                if (ERRNO_IS_NEG_TPM2_TOKEN_MISMATCH(r)) {
                        log_debug_errno(r, "TPM2 token %i does not match current system state, skipping: %m", token);
                        continue;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to unseal secret using TPM2: %m");

                /* The sealed secret is enrolled base64-encoded as keyslot passphrase, for compat with homed */
                if (base64mem(secret.iov_base, secret.iov_len, &b64) < 0)
                        return -ENOMEM;

                *ret_keyslot = keyslot;
                *ret_passphrase = TAKE_PTR(b64);
                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                               found_some ? "No TPM2 token matching the current system state found in LUKS2 header."
                                          : "No TPM2 token usable without user interaction enrolled in LUKS2 header.");
#else
        return -EOPNOTSUPP;
#endif
}
