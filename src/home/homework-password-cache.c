/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "homework-password-cache.h"

void password_cache_free(PasswordCache *cache) {
        if (!cache)
                return;

        cache->pkcs11_passwords = strv_free_erase(cache->pkcs11_passwords);
        cache->fido2_passwords = strv_free_erase(cache->fido2_passwords);
}
