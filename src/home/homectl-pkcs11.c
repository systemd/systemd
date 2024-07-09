/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "homectl-pkcs11.h"
#include "libcrypt-util.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "pkcs11-util.h"
#include "strv.h"

int identity_add_token_pin(sd_json_variant **v, const char *pin) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL, *l = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
        int r;

        assert(v);

        if (isempty(pin))
                return 0;

        w = sd_json_variant_ref(sd_json_variant_by_key(*v, "secret"));
        l = sd_json_variant_ref(sd_json_variant_by_key(w, "tokenPin"));

        r = sd_json_variant_strv(l, &pins);
        if (r < 0)
                return log_error_errno(r, "Failed to convert PIN array: %m");

        if (strv_contains(pins, pin))
                return 0;

        r = strv_extend(&pins, pin);
        if (r < 0)
                return log_oom();

        strv_uniq(pins);

        l = sd_json_variant_unref(l);

        r = sd_json_variant_new_array_strv(&l, pins);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate new PIN array JSON: %m");

        sd_json_variant_sensitive(l);

        r = sd_json_variant_set_field(&w, "tokenPin", l);
        if (r < 0)
                return log_error_errno(r, "Failed to update PIN field: %m");

        r = sd_json_variant_set_field(v, "secret", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update secret object: %m");

        return 1;
}

#if HAVE_P11KIT

static int add_pkcs11_token_uri(sd_json_variant **v, const char *uri) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(v);
        assert(uri);

        w = sd_json_variant_ref(sd_json_variant_by_key(*v, "pkcs11TokenUri"));
        if (w) {
                r = sd_json_variant_strv(w, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PKCS#11 token list: %m");

                if (strv_contains(l, uri))
                        return 0;
        }

        r = strv_extend(&l, uri);
        if (r < 0)
                return log_oom();

        w = sd_json_variant_unref(w);
        r = sd_json_variant_new_array_strv(&w, l);
        if (r < 0)
                return log_error_errno(r, "Failed to create PKCS#11 token URI JSON: %m");

        r = sd_json_variant_set_field(v, "pkcs11TokenUri", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update PKCS#11 token URI list: %m");

        return 0;
}

static int add_pkcs11_encrypted_key(
                sd_json_variant **v,
                const char *uri,
                const void *encrypted_key, size_t encrypted_key_size,
                const void *decrypted_key, size_t decrypted_key_size) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL, *w = NULL, *e = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL, *hashed = NULL;
        ssize_t base64_encoded_size;
        int r;

        assert(v);
        assert(uri);
        assert(encrypted_key);
        assert(encrypted_key_size > 0);
        assert(decrypted_key);
        assert(decrypted_key_size > 0);

        /* Before using UNIX hashing on the supplied key we base64 encode it, since crypt_r() and friends
         * expect a NUL terminated string, and we use a binary key */
        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = hash_password(base64_encoded, &hashed);
        if (r < 0)
                return log_error_errno(errno_or_else(EINVAL), "Failed to UNIX hash secret key: %m");

        r = sd_json_buildo(&e,
                           SD_JSON_BUILD_PAIR("uri", SD_JSON_BUILD_STRING(uri)),
                           SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_BASE64(encrypted_key, encrypted_key_size)),
                           SD_JSON_BUILD_PAIR("hashedPassword", SD_JSON_BUILD_STRING(hashed)));
        if (r < 0)
                return log_error_errno(r, "Failed to build encrypted JSON key object: %m");

        w = sd_json_variant_ref(sd_json_variant_by_key(*v, "privileged"));
        l = sd_json_variant_ref(sd_json_variant_by_key(w, "pkcs11EncryptedKey"));

        r = sd_json_variant_append_array(&l, e);
        if (r < 0)
                return log_error_errno(r, "Failed append PKCS#11 encrypted key: %m");

        r = sd_json_variant_set_field(&w, "pkcs11EncryptedKey", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set PKCS#11 encrypted key: %m");

        r = sd_json_variant_set_field(v, "privileged", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update privileged field: %m");

        return 0;
}

int identity_add_pkcs11_key_data(sd_json_variant **v, const char *uri) {
        _cleanup_(erase_and_freep) void *decrypted_key = NULL, *saved_key = NULL;
        _cleanup_(erase_and_freep) char *pin = NULL;
        size_t decrypted_key_size, saved_key_size;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        int r;

        assert(v);

        r = pkcs11_acquire_public_key(
                        uri,
                        "home directory operation",
                        "user-home",
                        "home.token-pin",
                        /* askpw_flags= */ 0,
                        &pkey,
                        &pin);
        if (r < 0)
                return r;

        r = pkey_generate_volume_keys(pkey, &decrypted_key, &decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume keys: %m");

        /* Add the token URI to the public part of the record. */
        r = add_pkcs11_token_uri(v, uri);
        if (r < 0)
                return r;

        /* Include the encrypted version of the random key we just generated in the privileged part of the record */
        r = add_pkcs11_encrypted_key(
                        v,
                        uri,
                        saved_key, saved_key_size,
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

#endif
