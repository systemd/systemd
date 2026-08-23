/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework-forward.h"
#include "strv.h"

typedef struct PasswordCache {
        /* The volume key from the kernel keyring */
        void *volume_key;
        size_t volume_key_size;

        /* Decoding passwords from security tokens is expensive and typically requires user interaction,
         * hence cache any we already figured out. */
        char **pkcs11_passwords;
        char **fido2_passwords;
} PasswordCache;

void password_cache_free(PasswordCache *cache);

static inline bool password_cache_contains(const PasswordCache *cache, const char *p) {
        if (!cache)
                return false;

        /* Used to decide whether or not to set a minimal PBKDF, under the assumption that if
         * the cache contains a password then the password came from a hardware token of some kind
         * and is thus naturally high-entropy. */

        return strv_contains(cache->pkcs11_passwords, p) ||
                strv_contains(cache->fido2_passwords, p);
}

void password_cache_load_keyring(UserRecord *h, PasswordCache *cache);
