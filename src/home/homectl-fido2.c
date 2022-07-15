/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBFIDO2
#include <fido.h>
#endif

#include "ask-password-api.h"
#include "errno-util.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "homectl-fido2.h"
#include "homectl-pkcs11.h"
#include "libcrypt-util.h"
#include "libfido2-util.h"
#include "locale-util.h"
#include "memory-util.h"
#include "random-util.h"
#include "strv.h"

#if HAVE_LIBFIDO2
static int add_fido2_credential_id(
                JsonVariant **v,
                const void *cid,
                size_t cid_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *w = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *escaped = NULL;
        int r;

        assert(v);
        assert(cid);

        r = base64mem(cid, cid_size, &escaped);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode FIDO2 credential ID: %m");

        w = json_variant_ref(json_variant_by_key(*v, "fido2HmacCredential"));
        if (w) {
                r = json_variant_strv(w, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse FIDO2 credential ID list: %m");

                if (strv_contains(l, escaped))
                        return 0;
        }

        r = strv_extend(&l, escaped);
        if (r < 0)
                return log_oom();

        w = json_variant_unref(w);
        r = json_variant_new_array_strv(&w, l);
        if (r < 0)
                return log_error_errno(r, "Failed to create FIDO2 credential ID JSON: %m");

        r = json_variant_set_field(v, "fido2HmacCredential", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update FIDO2 credential ID: %m");

        return 0;
}

static int add_fido2_salt(
                JsonVariant **v,
                const void *cid,
                size_t cid_size,
                const void *fido2_salt,
                size_t fido2_salt_size,
                const void *secret,
                size_t secret_size,
                Fido2EnrollFlags lock_with) {

        _cleanup_(json_variant_unrefp) JsonVariant *l = NULL, *w = NULL, *e = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL, *hashed = NULL;
        int r;

        /* Before using UNIX hashing on the supplied key we base64 encode it, since crypt_r() and friends
         * expect a NUL terminated string, and we use a binary key */
        r = base64mem(secret, secret_size, &base64_encoded);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode secret key: %m");

        r = hash_password(base64_encoded, &hashed);
        if (r < 0)
                return log_error_errno(errno_or_else(EINVAL), "Failed to UNIX hash secret key: %m");

        r = json_build(&e, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("credential", JSON_BUILD_BASE64(cid, cid_size)),
                                       JSON_BUILD_PAIR("salt", JSON_BUILD_BASE64(fido2_salt, fido2_salt_size)),
                                       JSON_BUILD_PAIR("hashedPassword", JSON_BUILD_STRING(hashed)),
                                       JSON_BUILD_PAIR("up", JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UP))),
                                       JSON_BUILD_PAIR("uv", JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UV))),
                                       JSON_BUILD_PAIR("clientPin", JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_PIN)))));

        if (r < 0)
                return log_error_errno(r, "Failed to build FIDO2 salt JSON key object: %m");

        w = json_variant_ref(json_variant_by_key(*v, "privileged"));
        l = json_variant_ref(json_variant_by_key(w, "fido2HmacSalt"));

        r = json_variant_append_array(&l, e);
        if (r < 0)
                return log_error_errno(r, "Failed append FIDO2 salt: %m");

        r = json_variant_set_field(&w, "fido2HmacSalt", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set FDO2 salt: %m");

        r = json_variant_set_field(v, "privileged", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update privileged field: %m");

        return 0;
}
#endif

int identity_add_fido2_parameters(
                JsonVariant **v,
                const char *device,
                Fido2EnrollFlags lock_with,
                int cred_alg) {

#if HAVE_LIBFIDO2
        JsonVariant *un, *realm, *rn;
        _cleanup_(erase_and_freep) void *secret = NULL, *salt = NULL;
        _cleanup_(erase_and_freep) char *used_pin = NULL;
        size_t cid_size, salt_size, secret_size;
        _cleanup_free_ void *cid = NULL;
        const char *fido_un;
        int r;

        assert(v);
        assert(device);

        un = json_variant_by_key(*v, "userName");
        if (!un)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "userName field of user record is missing");
        if (!json_variant_is_string(un))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "userName field of user record is not a string");

        realm = json_variant_by_key(*v, "realm");
        if (realm) {
                if (!json_variant_is_string(realm))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "realm field of user record is not a string");

                fido_un = strjoina(json_variant_string(un), json_variant_string(realm));
        } else
                fido_un = json_variant_string(un);

        rn = json_variant_by_key(*v, "realName");
        if (rn && !json_variant_is_string(rn))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "realName field of user record is not a string");

        r = fido2_generate_hmac_hash(
                        device,
                        /* rp_id= */ "io.systemd.home",
                        /* rp_name= */ "Home Directory",
                        /* user_id= */ fido_un, strlen(fido_un), /* We pass the user ID and name as the same */
                        /* user_name= */ fido_un,
                        /* user_display_name= */ rn ? json_variant_string(rn) : NULL,
                        /* user_icon_name= */ NULL,
                        /* askpw_icon_name= */ "user-home",
                        lock_with,
                        cred_alg,
                        &cid, &cid_size,
                        &salt, &salt_size,
                        &secret, &secret_size,
                        &used_pin,
                        &lock_with);
        if (r < 0)
                return r;

        r = add_fido2_credential_id(
                        v,
                        cid,
                        cid_size);
        if (r < 0)
                return r;

        r = add_fido2_salt(
                        v,
                        cid,
                        cid_size,
                        salt,
                        salt_size,
                        secret,
                        secret_size,
                        lock_with);
        if (r < 0)
                return r;

        /* If we acquired the PIN also include it in the secret section of the record, so that systemd-homed
         * can use it if it needs to, given that it likely needs to decrypt the key again to pass to LUKS or
         * fscrypt. */
        r = identity_add_token_pin(v, used_pin);
        if (r < 0)
                return r;

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 tokens not supported on this build.");
#endif
}
