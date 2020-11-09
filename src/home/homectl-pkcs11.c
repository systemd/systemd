/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "homectl-pkcs11.h"
#include "libcrypt-util.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "pkcs11-util.h"
#include "random-util.h"
#include "strv.h"

struct pkcs11_callback_data {
        char *pin_used;
        X509 *cert;
};

#if HAVE_P11KIT
static void pkcs11_callback_data_release(struct pkcs11_callback_data *data) {
        erase_and_free(data->pin_used);
        X509_free(data->cert);
}

static int pkcs11_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(erase_and_freep) char *pin_used = NULL;
        struct pkcs11_callback_data *data = userdata;
        CK_OBJECT_HANDLE object;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);
        assert(data);

        /* Called for every token matching our URI */

        r = pkcs11_token_login(m, session, slot_id, token_info, "home directory operation", "user-home", "pkcs11-pin", UINT64_MAX, &pin_used);
        if (r < 0)
                return r;

        r = pkcs11_token_find_x509_certificate(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_read_x509_certificate(m, session, object, &data->cert);
        if (r < 0)
                return r;

        /* Let's read some random data off the token and write it to the kernel pool before we generate our
         * random key from it. This way we can claim the quality of the RNG is at least as good as the
         * kernel's and the token's pool */
        (void) pkcs11_token_acquire_rng(m, session);

        data->pin_used = TAKE_PTR(pin_used);
        return 1;
}
#endif

static int acquire_pkcs11_certificate(
                const char *uri,
                X509 **ret_cert,
                char **ret_pin_used) {

#if HAVE_P11KIT
        _cleanup_(pkcs11_callback_data_release) struct pkcs11_callback_data data = {};
        int r;

        r = pkcs11_find_token(uri, pkcs11_callback, &data);
        if (r == -EAGAIN) /* pkcs11_find_token() doesn't log about this error, but all others */
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Specified PKCS#11 token with URI '%s' not found.",
                                       uri);
        if (r < 0)
                return r;

        *ret_cert = TAKE_PTR(data.cert);
        *ret_pin_used = TAKE_PTR(data.pin_used);

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}

static int encrypt_bytes(
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
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to allocate public key context");

        if (EVP_PKEY_encrypt_init(ctx) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to initialize public key context");

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to configure PKCS#1 padding");

        if (EVP_PKEY_encrypt(ctx, NULL, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine encrypted key size");

        b = malloc(l);
        if (!b)
                return log_oom();

        if (EVP_PKEY_encrypt(ctx, b, &l, decrypted_key, decrypted_key_size) <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine encrypted key size");

        *ret_encrypt_key = TAKE_PTR(b);
        *ret_encrypt_key_size = l;

        return 0;
}

static int add_pkcs11_encrypted_key(
                JsonVariant **v,
                const char *uri,
                const void *encrypted_key, size_t encrypted_key_size,
                const void *decrypted_key, size_t decrypted_key_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *l = NULL, *w = NULL, *e = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL, *hashed = NULL;
        int r;

        assert(v);
        assert(uri);
        assert(encrypted_key);
        assert(encrypted_key_size > 0);
        assert(decrypted_key);
        assert(decrypted_key_size > 0);

        /* Before using UNIX hashing on the supplied key we base64 encode it, since crypt_r() and friends
         * expect a NUL terminated string, and we use a binary key */
        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode secret key: %m");

        r = hash_password(base64_encoded, &hashed);
        if (r < 0)
                return log_error_errno(errno_or_else(EINVAL), "Failed to UNIX hash secret key: %m");

        r = json_build(&e, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("uri", JSON_BUILD_STRING(uri)),
                                       JSON_BUILD_PAIR("data", JSON_BUILD_BASE64(encrypted_key, encrypted_key_size)),
                                       JSON_BUILD_PAIR("hashedPassword", JSON_BUILD_STRING(hashed))));
        if (r < 0)
                return log_error_errno(r, "Failed to build encrypted JSON key object: %m");

        w = json_variant_ref(json_variant_by_key(*v, "privileged"));
        l = json_variant_ref(json_variant_by_key(w, "pkcs11EncryptedKey"));

        r = json_variant_append_array(&l, e);
        if (r < 0)
                return log_error_errno(r, "Failed append PKCS#11 encrypted key: %m");

        r = json_variant_set_field(&w, "pkcs11EncryptedKey", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set PKCS#11 encrypted key: %m");

        r = json_variant_set_field(v, "privileged", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update privileged field: %m");

        return 0;
}

static int add_pkcs11_token_uri(JsonVariant **v, const char *uri) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(v);
        assert(uri);

        w = json_variant_ref(json_variant_by_key(*v, "pkcs11TokenUri"));
        if (w) {
                r = json_variant_strv(w, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PKCS#11 token list: %m");

                if (strv_contains(l, uri))
                        return 0;
        }

        r = strv_extend(&l, uri);
        if (r < 0)
                return log_oom();

        w = json_variant_unref(w);
        r = json_variant_new_array_strv(&w, l);
        if (r < 0)
                return log_error_errno(r, "Failed to create PKCS#11 token URI JSON: %m");

        r = json_variant_set_field(v, "pkcs11TokenUri", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update PKCS#11 token URI list: %m");

        return 0;
}

int identity_add_token_pin(JsonVariant **v, const char *pin) {
        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL, *l = NULL;
        _cleanup_(strv_free_erasep) char **pins = NULL;
        int r;

        assert(v);

        if (isempty(pin))
                return 0;

        w = json_variant_ref(json_variant_by_key(*v, "secret"));
        l = json_variant_ref(json_variant_by_key(w, "tokenPin"));

        r = json_variant_strv(l, &pins);
        if (r < 0)
                return log_error_errno(r, "Failed to convert PIN array: %m");

        if (strv_find(pins, pin))
                return 0;

        r = strv_extend(&pins, pin);
        if (r < 0)
                return log_oom();

        strv_uniq(pins);

        l = json_variant_unref(l);

        r = json_variant_new_array_strv(&l, pins);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate new PIN array JSON: %m");

        json_variant_sensitive(l);

        r = json_variant_set_field(&w, "tokenPin", l);
        if (r < 0)
                return log_error_errno(r, "Failed to update PIN field: %m");

        r = json_variant_set_field(v, "secret", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update secret object: %m");

        return 1;
}

int identity_add_pkcs11_key_data(JsonVariant **v, const char *uri) {
        _cleanup_(erase_and_freep) void *decrypted_key = NULL, *encrypted_key = NULL;
        _cleanup_(erase_and_freep) char *pin = NULL;
        size_t decrypted_key_size, encrypted_key_size;
        _cleanup_(X509_freep) X509 *cert = NULL;
        EVP_PKEY *pkey;
        RSA *rsa;
        int bits;
        int r;

        assert(v);

        r = acquire_pkcs11_certificate(uri, &cert, &pin);
        if (r < 0)
                return r;

        pkey = X509_get0_pubkey(cert);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract public key from X.509 certificate.");

        if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "X.509 certificate does not refer to RSA key.");

        rsa = EVP_PKEY_get0_RSA(pkey);
        if (!rsa)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to acquire RSA public key from X.509 certificate.");

        bits = RSA_bits(rsa);
        log_debug("Bits in RSA key: %i", bits);

        /* We use PKCS#1 padding for the RSA cleartext, hence let's leave some extra space for it, hence only
         * generate a random key half the size of the RSA length */
        decrypted_key_size = bits / 8 / 2;

        if (decrypted_key_size < 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Uh, RSA key size too short?");

        log_debug("Generating %zu bytes random key.", decrypted_key_size);

        decrypted_key = malloc(decrypted_key_size);
        if (!decrypted_key)
                return log_oom();

        r = genuine_random_bytes(decrypted_key, decrypted_key_size, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random key: %m");

        r = encrypt_bytes(pkey, decrypted_key, decrypted_key_size, &encrypted_key, &encrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to encrypt key: %m");

        /* Add the token URI to the public part of the record. */
        r = add_pkcs11_token_uri(v, uri);
        if (r < 0)
                return r;

        /* Include the encrypted version of the random key we just generated in the privileged part of the record */
        r = add_pkcs11_encrypted_key(
                        v,
                        uri,
                        encrypted_key, encrypted_key_size,
                        decrypted_key, decrypted_key_size);
        if (r < 0)
                return r;

        /* If we acquired the PIN also include it in the secret section of the record, so that systemd-homed
         * can use it if it needs to, given that it likely needs to decrypt the key again to pass to LUKS or
         * fscrypt. */
        r = identity_add_token_pin(v, pin);
        if (r < 0)
                return r;

        return 0;
}

#if HAVE_P11KIT
static int list_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_free_ char *token_uri_string = NULL, *token_label = NULL, *token_manufacturer_id = NULL, *token_model = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        Table *t = userdata;
        int uri_result, r;

        assert(slot_info);
        assert(token_info);

        /* We only care about hardware devices here with a token inserted. Let's filter everything else
         * out. (Note that the user can explicitly specify non-hardware tokens if they like, but during
         * enumeration we'll filter those, since software tokens are typically the system certificate store
         * and such, and it's typically not what people want to bind their home directories to.) */
        if (!FLAGS_SET(token_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
                return -EAGAIN;

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        token_manufacturer_id = pkcs11_token_manufacturer_id(token_info);
        if (!token_manufacturer_id)
                return log_oom();

        token_model = pkcs11_token_model(token_info);
        if (!token_model)
                return log_oom();

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));

        r = table_add_many(
                        t,
                        TABLE_STRING, token_uri_string,
                        TABLE_STRING, token_label,
                        TABLE_STRING, token_manufacturer_id,
                        TABLE_STRING, token_model);
        if (r < 0)
                return table_log_add_error(r);

        return -EAGAIN; /* keep scanning */
}
#endif

int list_pkcs11_tokens(void) {
#if HAVE_P11KIT
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("uri", "label", "manufacturer", "model");
        if (!t)
                return log_oom();

        r = pkcs11_find_token(NULL, list_callback, t);
        if (r < 0 && r != -EAGAIN)
                return r;

        if (table_get_rows(t) <= 1) {
                log_info("No suitable PKCS#11 tokens found.");
                return 0;
        }

        r = table_print(t, stdout);
        if (r < 0)
                return log_error_errno(r, "Failed to show device table: %m");

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}

#if HAVE_P11KIT
static int auto_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        char **t = userdata;
        int uri_result;

        assert(slot_info);
        assert(token_info);

        if (!FLAGS_SET(token_info->flags, CKF_HW_SLOT|CKF_TOKEN_PRESENT))
                return -EAGAIN;

        if (*t)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "More than one suitable PKCS#11 token found.");

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return log_oom();

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, t);
        if (uri_result != P11_KIT_URI_OK)
                return log_warning_errno(SYNTHETIC_ERRNO(EAGAIN), "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));

        return 0;
}
#endif

int find_pkcs11_token_auto(char **ret) {
#if HAVE_P11KIT
        int r;

        r = pkcs11_find_token(NULL, auto_callback, ret);
        if (r == -EAGAIN)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "No suitable PKCS#11 tokens found.");
        if (r < 0)
                return r;

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}
