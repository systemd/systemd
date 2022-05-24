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

        if (strv_contains(pins, pin))
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

static int acquire_pkcs11_certificate(
                const char *uri,
                const char *askpw_friendly_name,
                const char *askpw_icon_name,
                X509 **ret_cert,
                char **ret_pin_used) {
#if HAVE_P11KIT
        return pkcs11_acquire_certificate(uri, askpw_friendly_name, askpw_icon_name, ret_cert, ret_pin_used);
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PKCS#11 tokens not supported on this build.");
#endif
}

int identity_add_pkcs11_key_data(JsonVariant **v, const char *uri) {
        _cleanup_(erase_and_freep) void *decrypted_key = NULL, *encrypted_key = NULL;
        _cleanup_(erase_and_freep) char *pin = NULL;
        size_t decrypted_key_size, encrypted_key_size;
        _cleanup_(X509_freep) X509 *cert = NULL;
        EVP_PKEY *pkey;
        int r;

        assert(v);

        r = acquire_pkcs11_certificate(uri, "home directory operation", "user-home", &cert, &pin);
        if (r < 0)
                return r;

        pkey = X509_get0_pubkey(cert);
        if (!pkey)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to extract public key from X.509 certificate.");

        r = rsa_pkey_to_suitable_key_size(pkey, &decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to extract RSA key size from X509 certificate.");

        log_debug("Generating %zu bytes random key.", decrypted_key_size);

        decrypted_key = malloc(decrypted_key_size);
        if (!decrypted_key)
                return log_oom();

        r = crypto_random_bytes(decrypted_key, decrypted_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random key: %m");

        r = rsa_encrypt_bytes(pkey, decrypted_key, decrypted_key_size, &encrypted_key, &encrypted_key_size);
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
