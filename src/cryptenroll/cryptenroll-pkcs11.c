/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-pkcs11.h"
#include "hexdecoct.h"
#include "json.h"
#include "memory-util.h"
#include "openssl-util.h"
#include "pkcs11-util.h"

int enroll_pkcs11(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size,
                const char *uri) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        size_t decrypted_key_size, saved_key_size;
        _cleanup_free_ void *saved_key = NULL;
        _cleanup_(X509_freep) X509 *cert = NULL;
        ssize_t base64_encoded_size;
        const char *node;
        int keyslot, r;

        assert_se(cd);
        assert_se(volume_key);
        assert_se(volume_key_size > 0);
        assert_se(uri);

        assert_se(node = crypt_get_device_name(cd));

        r = pkcs11_acquire_certificate(uri, "volume enrollment operation", "drive-harddisk", &cert, NULL);
        if (r < 0)
                return r;

        r = x509_generate_volume_keys(cert, &decrypted_key, &decrypted_key_size, &saved_key, &saved_key_size);
        if (r < 0)
                return log_error_errno(r, "Failed to generate volume keys: %m");

        /* Let's base64 encode the key to use, for compat with homed (and it's easier to type it in by
         * keyboard, if that might ever end up being necessary.) */
        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        base64_encoded,
                        base64_encoded_size);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new PKCS#11 key to %s: %m", node);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0)
                return log_oom();

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-pkcs11")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string))),
                                       JSON_BUILD_PAIR("pkcs11-uri", JSON_BUILD_STRING(uri)),
                                       JSON_BUILD_PAIR("pkcs11-key", JSON_BUILD_BASE64(saved_key, saved_key_size))));
        if (r < 0)
                return log_error_errno(r, "Failed to prepare PKCS#11 JSON token object: %m");

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0)
                return log_error_errno(r, "Failed to add PKCS#11 JSON token to LUKS2 header: %m");

        log_info("New PKCS#11 token enrolled as key slot %i.", keyslot);
        return keyslot;
}
