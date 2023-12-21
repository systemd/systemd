/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-empty.h"
#include "json.h"

int enroll_empty(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        const char *node;
        int keyslot, r, q;
        char keyslot_str[DECIMAL_STR_MAX(keyslot)];

        assert_se(cd);
        assert_se(volume_key);
        assert_se(volume_key_size > 0);

        assert_se(node = crypt_get_device_name(cd));

        /* No need to robustly protect against brute-force attacks... */
        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        /* passphrase= */ "",
                        /* passphrase_size= */ 0);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add empty key to %s: %m", node);
        xsprintf(keyslot_str, "%i", keyslot);

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-empty")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_str)))));
        if (r < 0) {
                log_error_errno(r, "Failed to prepare systemd-empty JSON token object: %m");
                goto rollback;
        }

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0) {
                log_error_errno(r, "Failed to add systemd-empty JSON token to LUKS2 header: %m");
                goto rollback;
        }

        log_info("Empty key enrolled as key slot %i.", keyslot);
        return keyslot;

rollback:
        q = crypt_keyslot_destroy(cd, keyslot);
        if (q < 0)
                log_error_errno(q, "Unable to remove key slot we just added, can't rollback, sorry: %m");

        return r;
}
