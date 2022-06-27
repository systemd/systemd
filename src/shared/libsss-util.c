/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libsss-util.h"

#if HAVE_LIBSSS
#include "alloc-util.h"
#include "ask-password-api.h"
#include "dlfcn-util.h"
#include "format-table.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "json.h"
#include "locale-util.h"
#include "log.h"
#include "memory-util.h"
#include "parse-util.h"
#include "random-util.h"
#include "strv.h"


static void *libsss_dl = NULL;

int (*sym_sss_generate)(sss_share *, unsigned short, unsigned short, sss_secret *, boolean) = NULL;
int (*sym_sss_regenerate)(sss_share *, unsigned short, unsigned short, sss_secret *) = NULL;
int (*sym_sss_combine)(const sss_share *, unsigned short, sss_secret *) = NULL;

int dlopen_libsss(void) {
        return dlopen_many_sym_or_warn(&libsss_dl, "libsss.so", LOG_DEBUG,
                        DLSYM_ARG(sss_generate),
                        DLSYM_ARG(sss_regenerate),
                        DLSYM_ARG(sss_combine));
}

/* NBO@TODO
 * Count n_mandatory and n_shared_shares in this function inplace of the parse_one_option function
 */
int factor_init(Factor *factor, EnrollType type) {

    int err = 0;

    factor->token = -1;
    factor->enroll_type = type;
    factor->combination_type = MANDATORY;

    switch (factor->enroll_type) {
        case ENROLL_MANDATORY:
            break ;
        case ENROLL_PASSWORD:
            break ;
        case ENROLL_RECOVERY:
            break ;
        case ENROLL_PKCS11:
            factor->pkcs11.token_uri = NULL;
            factor->pkcs11.token_uri_auto = false;
            //STATIC_DESTRUCTOR_REGISTER(factor->pkcs11.token_uri, freep);
            break ;

        case ENROLL_FIDO2:
            factor->fido2.device = NULL;
            factor->fido2.device_auto = false;
            factor->fido2.cid = NULL;
            factor->fido2.cid_size = 0;
            factor->fido2.rp_id = NULL;
            factor->fido2.lock_with = FIDO2ENROLL_PIN | FIDO2ENROLL_UP;
#if HAVE_LIBFIDO2
            factor->fido2.cred_alg = COSE_ES256;
#else
            factor->fido2.cred_alg = 0
#endif
            //STATIC_DESTRUCTOR_REGISTER(factor->fido2.device, freep);
            //STATIC_DESTRUCTOR_REGISTER(factor->fido2.cid, freep);
            //STATIC_DESTRUCTOR_REGISTER(factor->fido2.rp_id, freep);
            break ;

        case ENROLL_TPM2:
            factor->tpm2.device = NULL;
            factor->tpm2.device_auto = false;
            factor->tpm2.pcr_mask = UINT32_MAX;
            factor->tpm2.use_pin = false;
            //STATIC_DESTRUCTOR_REGISTER(factor->tpm2.device, freep);
            break ;

        default:
            factor->enroll_type = _ENROLL_TYPE_INVALID;
            err = 1;
    }
    return err;
}

/*
 * n_factors = Total number of factors
 * n_shares = Number of CombinationType shares to fetch from the factor array
 */
sss_share *factors_to_shares(const Factor *const factors, size_t n_factors, CombinationType combination_type, size_t n_shares) {
        sss_share *ret_shares = NULL;

        if (n_shares > n_factors)
            return NULL;
        ret_shares = malloc(sizeof(sss_share) * n_shares);
        if (!ret_shares) {
            return NULL;
        }
        for (size_t i = 0, j = 0; i < n_factors; i++) {
            if (factors[i].share && factors[i].combination_type == combination_type) {
                memcpy(ret_shares + j, factors[i].share, sizeof(sss_share));
                j++;
            }
        }
        return ret_shares;
}

// TODO@NBO change name to is_token_already_assigned
int is_factor_already_assigned(const Factor *const factor_list, uint16_t factor_number, int token) {
    for (int i = 0; i < factor_number; i++) {
        if (factor_list[i].token == token) {
            return 1;
        }
    }
    return 0;
}

/* This checks if the user asked a valid sss combination.
 * A valid sss combination must follow these rules:
 *      - The number of shared factors must be superior to one.
 *      - The definition of a quorum is mandatory.
 *      - The quorum must be positive and strictly inferior to the number of shared factors.
 */
int sss_valid_combination_check(const int n_shared, const int quorum) {
        if (n_shared && !quorum) {
                return log_error_errno(
                        SYNTHETIC_ERRNO(EINVAL),
                        "Can't share without quorum.");
        }
        if (n_shared == 1) {
                return log_error_errno(
                        SYNTHETIC_ERRNO(EINVAL),
                        "Will not share only one factor.");
        }
        if (quorum && n_shared && quorum >= n_shared) {
                return log_error_errno(
                        SYNTHETIC_ERRNO(EINVAL),
                        "Quorum must be strictly inferior to the number of shared factors.");
        }
        return 0;
}

/* NBO@TODO
 * The function alter the n_factor argument, should mention it in the function name.
 * Maybe change the name to something more explicit and comprehensive
 */
void try_validate_factor(bool *is_factor, uint16_t *n_factor) {
        if (*is_factor == true) {
                *is_factor = false;
                (*n_factor)++;
        }
}

int factor_compare(const void *a, const void *b) {
        const Factor *left = a;
        const Factor *right = b;

        if (right->combination_type > left->combination_type) {
                return left->combination_type - right->combination_type;
        }
        return right->enroll_type - left->enroll_type;
}

/* The goal of this function is to decrypt @encrypted_share using the symetric @key and return the clear share through
 * @ret_share.
 *
 * @key                 : The symetric key used to decrypt the @encrypted_share, the key is first derived using scrypt.
 * @key_size            : The symetric key size.
 * @encrypted_share     : Encrypted data representation of the Share.
 * @factor              : Factor used to check integrity and return de decrypted share.
 * */
int decrypt_share(const void *const key, const size_t key_size, const unsigned char *const encrypted_share, Factor *factor) {
    _cleanup_(erase_and_freep) void *derived_key = NULL;
    gcry_cipher_hd_t    hd;
    gcry_error_t        err;

    assert(factor->share);
    assert(encrypted_share);
    assert_se(key_size > 0);
    assert(key);

    initialize_libgcrypt(false);
     /* Use scrypt from the libgcrypt to derive the @key */
    derived_key = malloc0(DERIVATION_KEY_SIZE);
    err = gcry_kdf_derive(key, key_size, GCRY_KDF_SCRYPT, /*subalgo = CPU/memory cost parameter N*/16384, /* salt */factor->salt, /* saltlen */ SALT_LEN, /* parallelization parameter p*/1, DERIVATION_KEY_SIZE, derived_key);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to derive key: %m");

    /* Configure and create @hd cipher handle */
    err = gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, GCRY_CIPHER_SECURE);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to create the cipher handle: %m");

    /* Set the previously @derived_key to the @hd cipher handle.*/
    err = gcry_cipher_setkey(hd, derived_key, DERIVATION_KEY_SIZE);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to set encryption key: %m");


    err = gcry_cipher_setiv(hd, factor->nonce, sizeof(unsigned char) * NONCE_LEN);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to gcry_cipher_setiv: %m");

    /* Decrypt the @encrypted_share using libgcrypt AES256 cipher keywrap mode and store it in @ret_share */
    err = gcry_cipher_decrypt(hd, factor->share, sizeof(sss_share), (unsigned char *)encrypted_share, sizeof(sss_share));;
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to encrypt the share: %m");

    err = gcry_cipher_checktag(hd, factor->tag, sizeof(unsigned char) * TAG_LEN);
    if (gcry_err_code(err) == GPG_ERR_CHECKSUM)
        return -EAGAIN;

    return 0;
}

int fetch_sss_json_data(Factor *factor, JsonVariant *v, unsigned char **ret_encrypted_share) {
     JsonVariant *w;
     size_t nonce_size = 0;
     size_t tag_size = 0;
     size_t sss_salt_size = 0;
     size_t encrypted_share_size = 0;
     int r;
     _cleanup_free_ void *encrypted_share = NULL;

     w = json_variant_by_key(v, "sss-combination-type");
     if (!w || !json_variant_is_string(w))
         return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                 "Failed to extract 'sss-combination-type' field from FIDO2 JSON data: %m");

     // If token is not same combination type, don't even try to assign the share
     if (!(factor->combination_type == streq(json_variant_string(w), "shared") ? SHARED : MANDATORY))
             return -EAGAIN;

     w = json_variant_by_key(v, "sss-share");
     if (!w || !json_variant_is_string(w))
         return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                 "Failed to extract 'sss-share' field from FIDO2 JSON data: %m");

     r = unbase64mem(json_variant_string(w), SIZE_MAX, &encrypted_share, &encrypted_share_size);
     if (r < 0)
             return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                    "Invalid base64 data in 'sss-share' field.");

     w = json_variant_by_key(v, "sss-nonce");
     if (!w || !json_variant_is_string(w))
         return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                 "Failed to extract 'sss-nonce' field from FIDO2 JSON data: %m");

     r = unbase64mem(json_variant_string(w), SIZE_MAX, (void**)&(factor->nonce), &nonce_size);
     if (r < 0)
             return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                    "Invalid base64 data in 'sss-nonce' field.");

     w = json_variant_by_key(v, "sss-tag");
     if (!w || !json_variant_is_string(w))
         return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                 "Failed to extract 'sss-tag' field from FIDO2 JSON data: %m");

     r = unbase64mem(json_variant_string(w), SIZE_MAX, (void**)&(factor->tag), &tag_size);
     if (r < 0)
             return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                    "Invalid base64 data in 'sss-tag' field.");

     w = json_variant_by_key(v, "sss-salt");
     if (!w || !json_variant_is_string(w))
         return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                 "Failed to extract 'sss-salt' field from FIDO2 JSON data: %m");

     r = unbase64mem(json_variant_string(w), SIZE_MAX, (void**)&(factor->salt), &sss_salt_size);
     if (r < 0)
             return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                    "Invalid base64 data in 'sss-salt' field.");

     if (encrypted_share)
        *ret_encrypted_share = TAKE_PTR(encrypted_share);
     return r;
}

int find_sss_auto_data(
                Factor *factor,
                struct crypt_device *cd,
                unsigned char **ret_encrypted_share,
                int *ret_keyslot) {
        int r;

        assert(cd);
        assert(ret_keyslot);

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token ++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                int ks;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-sss", &v);
                if (IN_SET(r, -ENOENT, -EINVAL, -EMEDIUMTYPE))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                ks = cryptsetup_get_keyslot_from_token(v);
                if (ks < 0) {
                        /* Handle parsing errors of the keyslots field gracefully, since it's not 'owned' by
                         * us, but by the LUKS2 spec */
                        log_warning_errno(ks, "Failed to extract keyslot index from SSS JSON data token %i, skipping: %m", token);
                        continue;
                }

                if (*ret_keyslot >= 0 && *ret_keyslot != ks) {
                        continue ;
                }
                *ret_keyslot = ks;
                r = fetch_sss_json_data(factor, v, ret_encrypted_share);
                if (r == -EAGAIN)
                        continue;
                if (r < 0)
                        return r;
        }

        log_info("Automatically discovered security SSS token unlocks volume.");
        return 0;
}

int encrypt_share(const void *const key, const size_t key_size, Factor *const factor, unsigned char *ret_encrypted_share) {
    _cleanup_(erase_and_freep) void *derived_key = NULL;

    assert(key);
    assert_se(key_size > 0);
    assert(factor->share);
    assert(ret_encrypted_share);

    gcry_cipher_hd_t    hd;
    gcry_error_t        err;
    int r;

    initialize_libgcrypt(false);
    factor->salt = malloc(sizeof(unsigned char) * SALT_LEN);
    if (!factor->salt)
            return log_oom();
    r = crypto_random_bytes(factor->salt, sizeof(unsigned char) * SALT_LEN);
    if (r < 0)
            return log_error_errno(r, "Failed to generate random salt: %m");

    factor->nonce = malloc(sizeof(unsigned char) * NONCE_LEN);
    if (!factor->nonce)
            return log_oom();
    r = crypto_random_bytes(factor->nonce, sizeof(unsigned char) * NONCE_LEN);
    if (r < 0)
            return log_error_errno(r, "Failed to generate random nonce: %m");

    factor->tag = malloc(sizeof(unsigned char) * TAG_LEN);
    if (!factor->tag)
            return log_oom();

     /* Use scrypt from the libgcrypt to derive the @key. */
    derived_key = malloc0(DERIVATION_KEY_SIZE);
    if (!derived_key)
        return log_oom();
     err = gcry_kdf_derive(key, key_size, GCRY_KDF_SCRYPT, /*subalgo = CPU/memory cost parameter N*/16384, /* salt */factor->salt, /* saltlen */ SALT_LEN, /* parallelization parameter p*/1, DERIVATION_KEY_SIZE, derived_key);
     if (gcry_err_code(err))
         return log_error_errno(err, "Failed to derive key: %m");

    /* Configure and create @hd cipher handle */
    err = gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, GCRY_CIPHER_SECURE);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to create the cipher handle: %m");

    /* Set the previously @derived_key to the @hd cipher handle.*/
    err = gcry_cipher_setkey(hd, derived_key, DERIVATION_KEY_SIZE);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to set encryption key: %m");

    err = gcry_cipher_setiv(hd, factor->nonce, sizeof(unsigned char) * NONCE_LEN);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to gcry_cipher_setiv: %m");

    /* Encrypt the @share using libgcrypt AES256 cipher keywrap mode.*/
    err = gcry_cipher_encrypt(hd, ret_encrypted_share, sizeof(sss_share), (unsigned char *)(factor->share), sizeof(sss_share));
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to encrypt the share: %m");

    err = gcry_cipher_gettag(hd, factor->tag, sizeof(unsigned char) * TAG_LEN);
    if (gcry_err_code(err))
        return log_error_errno(err, "Failed to gcry_cipher_gettag: %m");


    gcry_cipher_close(hd);
    return 0;
}

int enroll_mandatory(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size,
                Factor *factor, int keyslot) {

        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_(erase_and_freep) unsigned char *encrypted_share = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;

        int r;

        assert_se(cd);
        assert_se(volume_key);
        assert_se(volume_key_size > 0);

        if (factor->share) {
                encrypted_share = malloc0(sizeof(sss_share));
                if (!encrypted_share)
                    return log_oom();

                encrypt_share(factor->share->raw_share.share, SSS_SECRET_SIZE, factor, encrypted_share);
                if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                    return log_oom();

                r = json_build(&v,
                               JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("type", JSON_BUILD_STRING("systemd-sss")),
                                               JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string))),
                                               JSON_BUILD_PAIR("sss-share", JSON_BUILD_BASE64(encrypted_share, sizeof(sss_share))),
                                               JSON_BUILD_PAIR("sss-nonce", JSON_BUILD_BASE64(factor->nonce, NONCE_LEN)),
                                               JSON_BUILD_PAIR("sss-tag", JSON_BUILD_BASE64(factor->tag, TAG_LEN)),
                                               JSON_BUILD_PAIR("sss-salt", JSON_BUILD_BASE64(factor->salt, SALT_LEN)),
                                               JSON_BUILD_PAIR("sss-combination-type", JSON_BUILD_STRING(factor->combination_type == MANDATORY ? "mandatory" : "shared"))));
        }
        if (r < 0)
                return log_error_errno(r, "Failed to prepare sss JSON token object: %m");

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0)
                return log_error_errno(r, "Failed to add sss JSON token to LUKS2 header: %m");

        log_info("New sss token enrolled as key slot %i.", keyslot);
        return keyslot;
}

int get_random(unsigned char *buf, uint16_t len) {
    return crypto_random_bytes(buf, len);
}

#endif
