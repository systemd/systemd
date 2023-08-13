/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "openssl-util.h"
#include "random-util.h"

#if HAVE_OPENSSL
/* For each error in the the Openssl thread error queue, log the provided message and the Openssl error
 * string. If there are no errors in the Openssl thread queue, this logs the message with "No openssl
 * errors." This logs at level debug. Returns -EIO (or -ENOMEM). */
#define log_openssl_errors(fmt, ...) _log_openssl_errors(UNIQ, fmt, ##__VA_ARGS__)
#define _log_openssl_errors(u, fmt, ...)                                \
        ({                                                              \
                size_t UNIQ_T(MAX, u) = 512 /* arbitrary, but openssl doc states it must be >= 256 */; \
                _cleanup_free_ char *UNIQ_T(BUF, u) = malloc(UNIQ_T(MAX, u)); \
                !UNIQ_T(BUF, u)                                         \
                        ? log_oom_debug()                               \
                        : __log_openssl_errors(u, UNIQ_T(BUF, u), UNIQ_T(MAX, u), fmt, ##__VA_ARGS__) \
                        ?: log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": No openssl errors.", ##__VA_ARGS__); \
        })
#define __log_openssl_errors(u, buf, max, fmt, ...)                     \
        ({                                                              \
                int UNIQ_T(R, u) = 0;                                   \
                for (;;) {                                              \
                        unsigned long UNIQ_T(E, u) = ERR_get_error();   \
                        if (UNIQ_T(E, u) == 0)                          \
                                break;                                  \
                        ERR_error_string_n(UNIQ_T(E, u), buf, max);     \
                        UNIQ_T(R, u) = log_debug_errno(SYNTHETIC_ERRNO(EIO), fmt ": %s", ##__VA_ARGS__, buf); \
                }                                                       \
                UNIQ_T(R, u);                                           \
        })

int openssl_pkey_from_pem(const void *pem, size_t pem_size, EVP_PKEY **ret) {
        assert(pem);
        assert(ret);

        _cleanup_fclose_ FILE *f = NULL;
        f = fmemopen((void*) pem, pem_size, "r");
        if (!f)
                return log_oom_debug();

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
        if (!pkey)
                return log_openssl_errors("Failed to parse PEM");

        *ret = TAKE_PTR(pkey);

        return 0;
}

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

int rsa_encrypt_bytes(
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
                return log_openssl_errors("Failed to allocate public key context");

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize public key context");

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return log_openssl_errors("Failed to configure PKCS#1 padding");

        if (EVP_PKEY_encrypt(ctx, NULL, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        b = malloc(l);
        if (!b)
                return -ENOMEM;

        if (EVP_PKEY_encrypt(ctx, b, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_openssl_errors("Failed to determine encrypted key size");

        *ret_encrypt_key = TAKE_PTR(b);
        *ret_encrypt_key_size = l;

        return 0;
}

int rsa_pkey_to_suitable_key_size(
                EVP_PKEY *pkey,
                size_t *ret_suitable_key_size) {

        size_t suitable_key_size;
        int bits;

        assert(pkey);
        assert(ret_suitable_key_size);

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

/* Generate RSA public key from provided "n" and "e" values. Note that if "e" is a number (e.g. uint32_t), it
 * must be provided here big-endian, e.g. wrap it with htobe32(). */
int rsa_pkey_from_n_e(const void *n, size_t n_size, const void *e, size_t e_size, EVP_PKEY **ret) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;

        assert(n);
        assert(e);
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        _cleanup_(BN_freep) BIGNUM *bn_n = BN_bin2bn(n, n_size, NULL);
        if (!bn_n)
                return log_openssl_errors("Failed to create BIGNUM for RSA n");

        _cleanup_(BN_freep) BIGNUM *bn_e = BN_bin2bn(e, e_size, NULL);
        if (!bn_e)
                return log_openssl_errors("Failed to create BIGNUM for RSA e");

#if OPENSSL_VERSION_MAJOR >= 3
        if (EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n))
                return log_openssl_errors("Failed to set RSA OSSL_PKEY_PARAM_RSA_N");

        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e))
                return log_openssl_errors("Failed to set RSA OSSL_PKEY_PARAM_RSA_E");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build RSA OSSL_PARAM");

        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create RSA EVP_PKEY");
#else
        _cleanup_(RSA_freep) RSA *rsa_key = RSA_new();
        if (!rsa_key)
                return log_openssl_errors("Failed to create new RSA");

        if (!RSA_set0_key(rsa_key, bn_n, bn_e, NULL))
                return log_openssl_errors("Failed to set RSA n/e");
        /* rsa_key owns these now, don't free */
        TAKE_PTR(bn_n);
        TAKE_PTR(bn_e);

        pkey = EVP_PKEY_new();
        if (!pkey)
                return log_openssl_errors("Failed to create new EVP_PKEY");

        if (!EVP_PKEY_assign_RSA(pkey, rsa_key))
                return log_openssl_errors("Failed to assign RSA key");
        /* pkey owns this now, don't free */
        TAKE_PTR(rsa_key);
#endif

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Get the "n" and "e" values from the pkey. The values are returned in "bin" format, i.e. BN_bn2bin(). */
int rsa_pkey_to_n_e(
                const EVP_PKEY *pkey,
                void **ret_n,
                size_t *ret_n_size,
                void **ret_e,
                size_t *ret_e_size) {

        assert(pkey);
        assert(ret_n);
        assert(ret_n_size);
        assert(ret_e);
        assert(ret_e_size);

#if OPENSSL_VERSION_MAJOR >= 3
        _cleanup_(BN_freep) BIGNUM *bn_n = NULL;
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n))
                return log_openssl_errors("Failed to get RSA n");

        _cleanup_(BN_freep) BIGNUM *bn_e = NULL;
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e))
                return log_openssl_errors("Failed to get RSA e");
#else
        const RSA *rsa = EVP_PKEY_get0_RSA((EVP_PKEY*) pkey);
        if (!rsa)
                return log_openssl_errors("Failed to get RSA key from public key");

        const BIGNUM *bn_n = RSA_get0_n(rsa);
        if (!bn_n)
                return log_openssl_errors("Failed to get RSA n");

        const BIGNUM *bn_e = RSA_get0_e(rsa);
        if (!bn_e)
                return log_openssl_errors("Failed to get RSA e");
#endif

        size_t n_size = BN_num_bytes(bn_n), e_size = BN_num_bytes(bn_e);
        _cleanup_free_ void *n = malloc(n_size), *e = malloc(e_size);
        if (!n || !e)
                return log_oom_debug();

        assert(BN_bn2bin(bn_n, n) == (int) n_size);
        assert(BN_bn2bin(bn_e, e) == (int) e_size);

        *ret_n = TAKE_PTR(n);
        *ret_n_size = n_size;
        *ret_e = TAKE_PTR(e);
        *ret_e_size = e_size;

        return 0;
}

/* Generate a new RSA key with the specified number of bits. */
int rsa_pkey_new(size_t bits, EVP_PKEY **ret) {
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (EVP_PKEY_keygen_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int) bits) <= 0)
                return log_openssl_errors("Failed to set RSA bits to %zu", bits);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_openssl_errors("Failed to generate ECC key");

        *ret = TAKE_PTR(pkey);

        return 0;
}

/* Generate ECC public key from provided curve ID and x/y points. */
int ecc_pkey_from_curve_x_y(
                int curve_id,
                const void *x,
                size_t x_size,
                const void *y,
                size_t y_size,
                EVP_PKEY **ret) {

        assert(x);
        assert(y);
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        _cleanup_(BN_freep) BIGNUM *bn_x = BN_bin2bn(x, x_size, NULL);
        if (!bn_x)
                return log_openssl_errors("Failed to create BIGNUM x");

        _cleanup_(BN_freep) BIGNUM *bn_y = BN_bin2bn(y, y_size, NULL);
        if (!bn_y)
                return log_openssl_errors("Failed to create BIGNUM y");

        _cleanup_(EC_GROUP_freep) EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_id);
        if (!group)
                return log_openssl_errors("ECC curve id %d not supported", curve_id);

        _cleanup_(EC_POINT_freep) EC_POINT *point = EC_POINT_new(group);
        if (!point)
                return log_openssl_errors("Failed to create new EC_POINT");

        if (!EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL))
                return log_openssl_errors("Failed to set ECC coordinates");

#if OPENSSL_VERSION_MAJOR >= 3
        if (EVP_PKEY_fromdata_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        _cleanup_(OSSL_PARAM_BLD_freep) OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!bld)
                return log_openssl_errors("Failed to create new OSSL_PARAM_BLD");

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, (char*) OSSL_EC_curve_nid2name(curve_id), 0))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_GROUP_NAME");

        _cleanup_(OPENSSL_freep) void *pbuf = NULL;
        size_t pbuf_len = 0;
        pbuf_len = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char**) &pbuf, NULL);
        if (pbuf_len == 0)
                return log_openssl_errors("Failed to convert ECC point to buffer");

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pbuf, pbuf_len))
                return log_openssl_errors("Failed to add ECC OSSL_PKEY_PARAM_PUB_KEY");

        _cleanup_(OSSL_PARAM_freep) OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        if (!params)
                return log_openssl_errors("Failed to build ECC OSSL_PARAM");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
                return log_openssl_errors("Failed to create ECC EVP_PKEY");
#else
        _cleanup_(EC_KEY_freep) EC_KEY *eckey = EC_KEY_new();
        if (!eckey)
                return log_openssl_errors("Failed to create new EC_KEY");

        if (!EC_KEY_set_group(eckey, group))
                return log_openssl_errors("Failed to set ECC group");

        if (!EC_KEY_set_public_key(eckey, point))
                return log_openssl_errors("Failed to set ECC point");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = EVP_PKEY_new();
        if (!pkey)
                return log_openssl_errors("Failed to create new EVP_PKEY");

        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
                return log_openssl_errors("Failed to assign ECC key");
        /* pkey owns this now, don't free */
        TAKE_PTR(eckey);
#endif

    *ret = TAKE_PTR(pkey);

    return 0;
}

int ecc_pkey_to_curve_x_y(
                const EVP_PKEY *pkey,
                int *ret_curve_id,
                void **ret_x,
                size_t *ret_x_size,
                void **ret_y,
                size_t *ret_y_size) {

        _cleanup_(BN_freep) BIGNUM *bn_x = NULL, *bn_y = NULL;
        int curve_id;

        assert(pkey);

#if OPENSSL_VERSION_MAJOR >= 3
        size_t name_size;
        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &name_size))
                return log_openssl_errors("Failed to get ECC group name size");

        _cleanup_free_ char *name = new(char, name_size + 1);
        if (!name)
                return log_oom_debug();

        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, name, name_size + 1, NULL))
                return log_openssl_errors("Failed to get ECC group name");

        curve_id = OBJ_sn2nid(name);
        if (curve_id == NID_undef)
                return log_openssl_errors("Failed to get ECC curve id");

        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x))
                return log_openssl_errors("Failed to get ECC point x");

        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y))
                return log_openssl_errors("Failed to get ECC point y");
#else
        const EC_KEY *eckey = EVP_PKEY_get0_EC_KEY((EVP_PKEY*) pkey);
        if (!eckey)
                return log_openssl_errors("Failed to get EC_KEY");

        const EC_GROUP *group = EC_KEY_get0_group(eckey);
        if (!group)
                return log_openssl_errors("Failed to get EC_GROUP");

        curve_id = EC_GROUP_get_curve_name(group);
        if (curve_id == NID_undef)
                return log_openssl_errors("Failed to get ECC curve id");

        const EC_POINT *point = EC_KEY_get0_public_key(eckey);
        if (!point)
                return log_openssl_errors("Failed to get EC_POINT");

        bn_x = BN_new();
        bn_y = BN_new();
        if (!bn_x || !bn_y)
                return log_openssl_errors("Failed to create new BIGNUM");

        if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, NULL))
                return log_openssl_errors("Failed to get ECC x/y.");
#endif

        size_t x_size = BN_num_bytes(bn_x), y_size = BN_num_bytes(bn_y);
        _cleanup_free_ void *x = malloc(x_size), *y = malloc(y_size);
        if (!x || !y)
                return log_oom_debug();

        assert(BN_bn2bin(bn_x, x) == (int) x_size);
        assert(BN_bn2bin(bn_y, y) == (int) y_size);

        if (ret_curve_id)
                *ret_curve_id = curve_id;
        if (ret_x)
                *ret_x = TAKE_PTR(x);
        if (ret_x_size)
                *ret_x_size = x_size;
        if (ret_y)
                *ret_y = TAKE_PTR(y);
        if (ret_y_size)
                *ret_y_size = y_size;

        return 0;
}

/* Generate a new ECC key for the specified ECC curve id. */
int ecc_pkey_new(int curve_id, EVP_PKEY **ret) {
        assert(ret);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!ctx)
                return log_openssl_errors("Failed to create new EVP_PKEY_CTX");

        if (EVP_PKEY_keygen_init(ctx) <= 0)
                return log_openssl_errors("Failed to initialize EVP_PKEY_CTX");

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_id) <= 0)
                return log_openssl_errors("Failed to set ECC curve %d", curve_id);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
                return log_openssl_errors("Failed to generate ECC key");

        *ret = TAKE_PTR(pkey);

        return 0;
}

int pubkey_fingerprint(EVP_PKEY *pk, const EVP_MD *md, void **ret, size_t *ret_size) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX* m = NULL;
        _cleanup_free_ void *d = NULL, *h = NULL;
        int sz, lsz, msz;
        unsigned umsz;
        unsigned char *dd;

        /* Calculates a message digest of the DER encoded public key */

        assert(pk);
        assert(md);
        assert(ret);
        assert(ret_size);

        sz = i2d_PublicKey(pk, NULL);
        if (sz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        dd = d = malloc(sz);
        if (!d)
                return log_oom_debug();

        lsz = i2d_PublicKey(pk, &dd);
        if (lsz < 0)
                return log_openssl_errors("Unable to convert public key to DER format");

        m = EVP_MD_CTX_new();
        if (!m)
                return log_openssl_errors("Failed to create new EVP_MD_CTX");

        if (EVP_DigestInit_ex(m, md, NULL) != 1)
                return log_openssl_errors("Failed to initialize %s context", EVP_MD_name(md));

        if (EVP_DigestUpdate(m, d, lsz) != 1)
                return log_openssl_errors("Failed to run %s context", EVP_MD_name(md));

        msz = EVP_MD_size(md);
        assert(msz > 0);

        h = malloc(msz);
        if (!h)
                return log_oom_debug();

        umsz = msz;
        if (EVP_DigestFinal_ex(m, h, &umsz) != 1)
                return log_openssl_errors("Failed to finalize hash context");

        assert(umsz == (unsigned) msz);

        *ret = TAKE_PTR(h);
        *ret_size = msz;

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

static int rsa_pkey_generate_volume_key(
                EVP_PKEY *pkey,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_free_ void *saved_key = NULL;
        size_t decrypted_key_size, saved_key_size;
        int r;

        r = rsa_pkey_to_suitable_key_size(pkey, &decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to determine RSA public key size.");

        log_debug("Generating %zu bytes random key.", decrypted_key_size);

        decrypted_key = malloc(decrypted_key_size);
        if (!decrypted_key)
                return log_oom();

        r = crypto_random_bytes(decrypted_key, decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random key: %m");

        r = rsa_encrypt_bytes(pkey, decrypted_key, decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to encrypt random key: %m");

        *ret_decrypted_key = TAKE_PTR(decrypted_key);
        *ret_decrypted_key_size = decrypted_key_size;
        *ret_saved_key = TAKE_PTR(saved_key);
        *ret_saved_key_size = saved_key_size;
        return 0;
}

int x509_generate_volume_key(
                X509 *cert,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size,
                void **ret_saved_key,
                size_t *ret_saved_key_size) {

        assert(cert);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);
        assert(ret_saved_key);
        assert(ret_saved_key_size);

        EVP_PKEY *pkey = X509_get0_pubkey(cert);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract public key from X.509 certificate.");

        int type = EVP_PKEY_get_base_id(pkey);
        switch (type) {

        case EVP_PKEY_RSA:
                return rsa_pkey_generate_volume_key(pkey, ret_decrypted_key, ret_decrypted_key_size, ret_saved_key, ret_saved_key_size);

        case NID_undef:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine a type of public key");

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported public key type: %s", OBJ_nid2sn(type));
        }
}
#endif

int x509_fingerprint(X509 *cert, uint8_t buffer[static SHA256_DIGEST_SIZE]) {
#if HAVE_OPENSSL
        _cleanup_free_ uint8_t *der = NULL;
        int dersz;

        assert(cert);

        dersz = i2d_X509(cert, &der);
        if (dersz < 0)
                return log_openssl_errors("Unable to convert PEM certificate to DER format");

        sha256_direct(der, dersz, buffer);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "openssl is not supported, cannot calculate X509 fingerprint: %m");
#endif
}
