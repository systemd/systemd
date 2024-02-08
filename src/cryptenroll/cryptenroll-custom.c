/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright © 2024 GNOME Foundation Inc
 *      Original Author: Adrian Vovk
 */

#include "bus-polkit.h"
#include "cryptenroll-custom.h"
#include "cryptenroll-wipe.h"
#include "cryptenroll.h"

int enroll_slot_and_token(
                struct crypt_device *cd,
                void *volume_key,
                size_t volume_key_size,
                const char *passphrase,
                size_t passphrase_size,
                JsonVariant *token) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        const char *node = NULL;
        int r, q, keyslot;

        assert(cd);
        assert(volume_key);
        assert(passphrase);
        assert(token);

        assert_se(node = crypt_get_device_name(cd));

        v = json_variant_ref(token);

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        passphrase,
                        passphrase_size);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new key to %s: %m", node);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0) {
                log_oom();
                goto rollback;
        }

        r = json_variant_set_fieldb(&v, "keyslots",
                                    JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string)));
        if (r < 0) {
                log_error_errno(r, "Failed to insert keyslot into JSON token object: %m");
                goto rollback;
        }

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0) {
                log_error_errno(r, "Failed to add JSON token to LUKS2 header: %m");
                goto rollback;
        }

        return 0;

rollback:
        q = crypt_keyslot_destroy(cd, keyslot);
        if (q < 0)
                log_warning_errno(q, "Unable to remove key slot we just added again, can't rollback, sorry: %m");
        return r;
}

int enroll_slot_and_tokenb(struct crypt_device *cd,
                           void *volume_key,
                           size_t volume_key_size,
                           const char *passphrase,
                           size_t passphrase_size,
                           ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *token = NULL;
        va_list ap;
        int r;

        assert(cd);
        assert(volume_key);
        assert(passphrase);

        va_start(ap, passphrase_size);
        r = json_buildv(&token, ap);
        va_end(ap);

        if (r < 0)
                return log_error_errno(r, "Failed to build JSON token: %m");

        return enroll_slot_and_token(cd, volume_key, volume_key_size,
                                     passphrase, passphrase_size, token);
}

int vl_method_enroll_custom(Varlink *link,
                            JsonVariant *params,
                            VarlinkMethodFlags flags,
                            void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                VARLINK_DISPATCH_UNLOCK_FIELDS,
                VARLINK_DISPATCH_WIPE_FIELDS,
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        _cleanup_(erase_and_freep) void *vk = NULL;
        size_t vks;
        int r;

        r = varlink_dispatch(link, params, dispatch_table, NULL);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.cryptenroll.enroll-custom",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        polkit_registry);
        if (r <= 0)
                return r;

        r = vl_luks_setup(link, params, &cd, &vk, &vks);
        if (r != 0)
                return r;

        return varlink_errorb(
                        link,
                        VARLINK_ERROR_METHOD_NOT_IMPLEMENTED,
                        JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", "io.systemd.CryptEnroll.EnrollCustom")));
}
