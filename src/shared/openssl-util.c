/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "openssl-util.h"
#include "alloc-util.h"
#include "hexdecoct.h"
#include "random-util.h"

#if HAVE_OPENSSL
int openssl_hash(const EVP_MD *alg,
                 const void *msg,
                 size_t msg_len,
                 uint8_t *ret_hash,
                 size_t *ret_hash_len) {

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = NULL;
        unsigned len;
        int r;

        ctx = EVP_MD_CTX_new();
        if (!ctx)
                /* This function just calls OPENSSL_zalloc, so failure
                 * here is almost certainly a failed allocation. */
                return -ENOMEM;

        /* The documentation claims EVP_DigestInit behaves just like
         * EVP_DigestInit_ex if passed NULL, except it also calls
         * EVP_MD_CTX_reset, which deinitializes the context. */
        r = EVP_DigestInit_ex(ctx, alg, NULL);
        if (r == 0)
                return -EIO;

        r = EVP_DigestUpdate(ctx, msg, msg_len);
        if (r == 0)
                return -EIO;

        r = EVP_DigestFinal_ex(ctx, ret_hash, &len);
        if (r == 0)
                return -EIO;

        if (ret_hash_len)
                *ret_hash_len = len;

        return 0;
}

static int rsa_encrypt_bytes(
                EVP_PKEY *pkey,
                const void *decrypted_key,
                size_t decrypted_key_size,
                void **ret_encrypt_key,
                size_t *ret_encrypt_key_size) {

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        _cleanup_free_ void *b = NULL;
        size_t l;

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate public key context");

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize public key context");

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to configure PKCS#1 padding");

        if (EVP_PKEY_encrypt(ctx, NULL, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine encrypted key size");

        b = malloc(l);
        if (!b)
                return -ENOMEM;

        if (EVP_PKEY_encrypt(ctx, b, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine encrypted key size");

        *ret_encrypt_key = TAKE_PTR(b);
        *ret_encrypt_key_size = l;

        return 0;
}

static int rsa_pkey_to_suitable_key_size(
                EVP_PKEY *pkey,
                size_t *ret_suitable_key_size) {

        size_t suitable_key_size;
        int bits;

        assert_se(pkey);
        assert_se(ret_suitable_key_size);

        /* Analyzes the specified public key and that it is RSA. If so, will return a suitable size for a
         * disk encryption key to encrypt with RSA for use in PKCS#11 security token schemes. */

        if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "X.509 certificate does not refer to RSA key.");

        bits = EVP_PKEY_bits(pkey);
        log_debug("Bits in RSA key: %i", bits);

        /* We use PKCS#1 padding for the RSA cleartext, hence let's leave some extra space for it, hence only
         * generate a random key half the size of the RSA length */
        suitable_key_size = bits / 8 / 2;

        if (suitable_key_size < 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Uh, RSA key size too short?");

        *ret_suitable_key_size = suitable_key_size;
        return 0;
}

static int pkey_generate_ec_key(int nid, EVP_PKEY **ret_ppkey) {

        assert(ret_ppkey);

        int r = 0;
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *pctx = NULL;
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *kctx = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *params = NULL;

        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate pkey context");

        r = EVP_PKEY_paramgen_init((pctx));
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialze pkey parameters context");

        r = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set pkey context ec curve nid");

        r = EVP_PKEY_paramgen(pctx, &params);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate pkey parameters");

        kctx = EVP_PKEY_CTX_new(params, NULL);
        if (!kctx)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate pkey context");

        r = EVP_PKEY_keygen_init(kctx);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize pkey keygen context");

        *ret_ppkey = NULL;

        r = EVP_PKEY_keygen(kctx, ret_ppkey);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate pkey");

        return 0;
}

static int pkey_ecdh_derive_shared_secret(
                EVP_PKEY *pkey,
                EVP_PKEY *peer_key,
                uint8_t *ret_shared_secret,
                size_t *ret_shared_secret_len) {

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = NULL;
        int r = 0;
        size_t secret_len = 0;

        assert(pkey);
        assert(peer_key);
        assert(ret_shared_secret_len);

        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate pkey context");

        r = EVP_PKEY_derive_init(ctx);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize pkey derive context");

        r = EVP_PKEY_derive_set_peer(ctx, peer_key);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to set peer key for derivation");

        r = EVP_PKEY_derive(ctx, NULL, &secret_len);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to get derived key size");

        if (!ret_shared_secret) {
                *ret_shared_secret_len = secret_len;
                return 0;
        }

        r = EVP_PKEY_derive(ctx, ret_shared_secret, ret_shared_secret_len);
        if (r != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to derive shared secret");

        return 0;
}

#  if PREFER_OPENSSL
int string_hashsum(
                const char *s,
                size_t len,
                const EVP_MD *md_algorithm,
                char **ret) {

        uint8_t hash[EVP_MAX_MD_SIZE];
        size_t hash_size;
        char *enc;
        int r;

        hash_size = EVP_MD_size(md_algorithm);
        assert(hash_size > 0);

        r = openssl_hash(md_algorithm, s, len, hash, NULL);
        if (r < 0)
                return r;

        enc = hexmem(hash, hash_size);
        if (!enc)
                return -ENOMEM;

        *ret = enc;
        return 0;

}
#  endif

static int pkey_generate_volume_key_ec(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_savedata,
                size_t *ret_savedata_size) {

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_new = NULL;
        int nid;
        int r;

        EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        if (!ec_key)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "PKEY doesn't have EC_KEY associated");

        if (EC_KEY_check_key(ec_key) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "EC_KEY associated with PKEY is not valid");

        nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
        r = pkey_generate_ec_key(nid, &pkey_new);
        if (r < 0)
                return log_error_errno(r, "Failed to generate ec key: %m");

        r = pkey_ecdh_derive_shared_secret(pkey_new, pkey, NULL, ret_decrypted_key_size);
        if (r < 0 || *ret_decrypted_key_size == 0)
                return log_error_errno(r, "Failed to determine derived shared secret size: %m");

        *ret_decrypted_key = malloc(*ret_decrypted_key_size);
        if (!*ret_decrypted_key)
                return log_oom();

        r = pkey_ecdh_derive_shared_secret(pkey_new, pkey, *ret_decrypted_key, ret_decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to derive shared secret: %m");

        *ret_savedata_size = i2d_PUBKEY(pkey_new, NULL);
        if (*ret_savedata_size == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine encoded public key size");

        *ret_savedata = malloc(*ret_savedata_size);
        if (!*ret_savedata)
                return log_oom();

        /* i2d_PUBKEY function has a side effect that makes *pp point to end of the allocated buffer */
        uint8_t *buffer = *ret_savedata;
        *ret_savedata_size = i2d_PUBKEY(pkey_new, &buffer);
        if (*ret_savedata_size == 0)
                return  log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get encoded public key");

        return 0;

}

static int pkey_generate_volume_key_rsa(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_savedata,
                size_t *ret_savedata_size) {

        assert(pkey);
        assert_se(ret_decrypted_key);
        assert_se(ret_savedata);
        assert_se(ret_savedata_size);

        int r = rsa_pkey_to_suitable_key_size(pkey, ret_decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to determine RSA public key size.");

        log_debug("Generating %zu bytes random key.", *ret_decrypted_key_size);

        *ret_decrypted_key = malloc(*ret_decrypted_key_size);
        if (!*ret_decrypted_key)
                        return log_oom();

        r = genuine_random_bytes(*ret_decrypted_key, *ret_decrypted_key_size, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random key: %m");

        r = rsa_encrypt_bytes(pkey, *ret_decrypted_key, *ret_decrypted_key_size, ret_savedata, ret_savedata_size);
        if (r < 0)
                return log_error_errno(r, "Failed to encrypt key: %m");

        return 0;

}

int X509_certificate_generate_volume_key(
                X509 *cert,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_savedata,
                size_t *ret_savedata_size) {

        assert_se(cert);
        assert_se(ret_decrypted_key);
        assert_se(ret_savedata);
        assert_se(ret_savedata_size);

        _cleanup_free_ void *decrypted_key = NULL;
        size_t decrypted_key_size = 0;
        _cleanup_free_ void *savedata = NULL;
        size_t savedata_size = 0;
        int r = 0;

        EVP_PKEY *pkey = X509_get0_pubkey(cert);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract public key from X.509 certificate.");


        int type = EVP_PKEY_base_id(pkey);
        if (type == EVP_PKEY_RSA)
                r = pkey_generate_volume_key_rsa(pkey, &decrypted_key, &decrypted_key_size, &savedata, &savedata_size);
        else if (type == EVP_PKEY_EC)
                r = pkey_generate_volume_key_ec(pkey, &decrypted_key, &decrypted_key_size, &savedata, &savedata_size);
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsuported public key type: %s", OBJ_nid2sn(type));

        if (r < 0)
                return r;

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_savedata = TAKE_PTR(savedata);
        *ret_savedata_size = savedata_size;
        return 0;
}
#endif
