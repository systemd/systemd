/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBFIDO2
#include <fido.h>
#endif

#include "ask-password-api.h"
#include "errno-util.h"
#include "fido2-util.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "homectl-fido2.h"
#include "homectl-pkcs11.h"
#include "iovec-util.h"
#include "json-util.h"
#include "libcrypt-util.h"
#include "libfido2-util.h"
#include "locale-util.h"
#include "memory-util.h"
#include "random-util.h"
#include "strv.h"

#if HAVE_LIBFIDO2
static int add_fido2_credential_id(
                sd_json_variant **v,
                const void *cid,
                size_t cid_size) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *escaped = NULL;
        ssize_t escaped_size;
        int r;

        assert(v);
        assert(cid);

        escaped_size = base64mem(cid, cid_size, &escaped);
        if (escaped_size < 0)
                return log_error_errno(escaped_size, "Failed to base64 encode FIDO2 credential ID: %m");

        w = sd_json_variant_ref(sd_json_variant_by_key(*v, "fido2HmacCredential"));
        if (w) {
                r = sd_json_variant_strv(w, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse FIDO2 credential ID list: %m");

                if (strv_contains(l, escaped))
                        return 0;
        }

        r = strv_extend(&l, escaped);
        if (r < 0)
                return log_oom();

        w = sd_json_variant_unref(w);
        r = sd_json_variant_new_array_strv(&w, l);
        if (r < 0)
                return log_error_errno(r, "Failed to create FIDO2 credential ID JSON: %m");

        r = sd_json_variant_set_field(v, "fido2HmacCredential", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update FIDO2 credential ID: %m");

        return 0;
}

static int add_fido2_salt(
                sd_json_variant **v,
                const void *cid,
                size_t cid_size,
                const struct iovec *salt,
                const void *secret,
                size_t secret_size,
                Fido2EnrollFlags lock_with) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL, *w = NULL, *e = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL, *hashed = NULL;
        ssize_t base64_encoded_size;
        int r;

        assert(v);
        assert(cid);
        assert(iovec_is_set(salt));
        assert(secret);

        /* Before using UNIX hashing on the supplied key we base64 encode it, since crypt_r() and friends
         * expect a NUL terminated string, and we use a binary key */
        base64_encoded_size = base64mem(secret, secret_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return log_error_errno(base64_encoded_size, "Failed to base64 encode secret key: %m");

        r = hash_password(base64_encoded, &hashed);
        if (r < 0)
                return log_error_errno(errno_or_else(EINVAL), "Failed to UNIX hash secret key: %m");

        r = sd_json_buildo(&e,
                           SD_JSON_BUILD_PAIR("credential", SD_JSON_BUILD_BASE64(cid, cid_size)),
                           SD_JSON_BUILD_PAIR("salt", JSON_BUILD_IOVEC_BASE64(salt)),
                           SD_JSON_BUILD_PAIR("hashedPassword", SD_JSON_BUILD_STRING(hashed)),
                           SD_JSON_BUILD_PAIR("up", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UP))),
                           SD_JSON_BUILD_PAIR("uv", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_UV))),
                           SD_JSON_BUILD_PAIR("clientPin", SD_JSON_BUILD_BOOLEAN(FLAGS_SET(lock_with, FIDO2ENROLL_PIN))));

        if (r < 0)
                return log_error_errno(r, "Failed to build FIDO2 salt JSON key object: %m");

        w = sd_json_variant_ref(sd_json_variant_by_key(*v, "privileged"));
        l = sd_json_variant_ref(sd_json_variant_by_key(w, "fido2HmacSalt"));

        r = sd_json_variant_append_array(&l, e);
        if (r < 0)
                return log_error_errno(r, "Failed to append FIDO2 salt: %m");

        r = sd_json_variant_set_field(&w, "fido2HmacSalt", l);
        if (r < 0)
                return log_error_errno(r, "Failed to set FIDO2 salt: %m");

        r = sd_json_variant_set_field(v, "privileged", w);
        if (r < 0)
                return log_error_errno(r, "Failed to update privileged field: %m");

        return 0;
}
#endif

int identity_add_fido2_parameters(
                sd_json_variant **v,
                const char *device,
                Fido2EnrollFlags lock_with,
                int cred_alg) {

#if HAVE_LIBFIDO2
        sd_json_variant *un, *realm, *rn;
        _cleanup_(iovec_done) struct iovec salt = {};
        _cleanup_(erase_and_freep) void *secret = NULL;
        _cleanup_(erase_and_freep) char *used_pin = NULL;
        size_t cid_size, secret_size;
        _cleanup_free_ void *cid = NULL;
        const char *fido_un;
        int r;

        assert(v);
        assert(device);

        un = sd_json_variant_by_key(*v, "userName");
        if (!un)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "userName field of user record is missing");
        if (!sd_json_variant_is_string(un))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "userName field of user record is not a string");

        realm = sd_json_variant_by_key(*v, "realm");
        if (realm) {
                if (!sd_json_variant_is_string(realm))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "realm field of user record is not a string");

                fido_un = strjoina(sd_json_variant_string(un), sd_json_variant_string(realm));
        } else
                fido_un = sd_json_variant_string(un);

        rn = sd_json_variant_by_key(*v, "realName");
        if (rn && !sd_json_variant_is_string(rn))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "realName field of user record is not a string");

        r = fido2_generate_salt(&salt);
        if (r < 0)
               return r;

        r = fido2_generate_hmac_hash(
                        device,
                        /* rp_id= */ "io.systemd.home",
                        /* rp_name= */ "Home Directory",
                        /* user_id= */ fido_un, strlen(fido_un), /* We pass the user ID and name as the same */
                        /* user_name= */ fido_un,
                        /* user_display_name= */ rn ? sd_json_variant_string(rn) : NULL,
                        /* user_icon_name= */ NULL,
                        /* askpw_icon_name= */ "user-home",
                        /* askpw_credential= */ "home.token-pin",
                        lock_with,
                        cred_alg,
                        &salt,
                        &cid, &cid_size,
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
                        &salt,
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
