/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "strv.h"
#include "user-record.h"

typedef struct PasswordCache {
        /* Passwords acquired from the kernel keyring */
        char **keyring_passwords;

        /* Decoding passwords from security tokens is expensive and typically requires user interaction,
         * hence cache any we already figured out. */
        char **pkcs11_passwords;
        char **fido2_passwords;
} PasswordCache;

void password_cache_free(PasswordCache *cache);

static inline bool password_cache_contains(const PasswordCache *cache, const char *p) {
        if (!cache)
                return false;

        return strv_contains(cache->pkcs11_passwords, p) ||
                strv_contains(cache->fido2_passwords, p) ||
                strv_contains(cache->keyring_passwords, p);
}

void password_cache_load_keyring(UserRecord *h, PasswordCache *cache);
