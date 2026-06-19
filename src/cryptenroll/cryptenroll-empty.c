/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-empty.h"
#include "cryptsetup-util.h"
#include "iovec-util.h"
#include "log.h"

int enroll_empty(
                struct crypt_device *cd,
                const struct iovec *volume_key) {

        int keyslot, r, q;
        const char *node;

        assert_se(cd);
        assert_se(iovec_is_set(volume_key));

        assert_se(node = sym_crypt_get_device_name(cd));

        /* No need to robustly protect against brute-force attacks... */
        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = sym_crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key->iov_base,
                        volume_key->iov_len,
                        /* passphrase= */ "",
                        /* passphrase_size= */ 0);
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add empty key to %s: %m", node);

        r = cryptsetup_add_token_empty(cd, keyslot);
        if (r < 0) {
                log_error_errno(r, "Failed to add empty JSON token to LUKS2 header: %m");
                goto rollback;
        }

        log_warning("New empty key enrolled as key slot %i. Warning: This disables confidentiality protections!", keyslot);
        return keyslot;

rollback:
        q = sym_crypt_keyslot_destroy(cd, keyslot);
        if (q < 0)
                log_debug_errno(q, "Unable to remove key slot we just added again, can't rollback, sorry: %m");

        return r;
}
