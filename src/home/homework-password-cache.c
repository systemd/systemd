/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "homework-password-cache.h"
#include "keyring-util.h"
#include "missing_syscall.h"
#include "user-record.h"

void password_cache_free(PasswordCache *cache) {
        if (!cache)
                return;

        cache->pkcs11_passwords = strv_free_erase(cache->pkcs11_passwords);
        cache->fido2_passwords = strv_free_erase(cache->fido2_passwords);
        cache->keyring_passwords = strv_free_erase(cache->keyring_passwords);
}

int password_cache_load_keyring(UserRecord *h, PasswordCache *cache) {
        _cleanup_(erase_and_freep) void *p = NULL;
        _cleanup_free_ char *name = NULL;
        char **strv;
        key_serial_t serial;
        size_t sz;
        int r;

        assert(h);
        assert(cache);

        /* Loads the password we need to for automatic resizing from the kernel keyring */

        name = strjoin("homework-user-", h->user_name);
        if (!name)
                return log_oom();

        serial = request_key("user", name, NULL, 0);
        if (serial == -1)
                return log_debug_errno(errno, "Failed to request key '%s': %m", name);

        r = keyring_read(serial, &p, &sz);
        if (r < 0)
                return log_debug_errno(r, "Failed to read keyring key '%s': %m", name);

        if (memchr(p, 0, sz))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Cached password contains embedded NUL byte. Rejecting.");

        strv = new(char*, 2);
        if (!strv)
                return log_oom();

        strv[0] = TAKE_PTR(p); /* Note that keyring_read() will NUL terminate implicitly, hence we don't have
                                * to NUL terminate manually here: it's a valid string. */
        strv[1] = NULL;

        strv_free_erase(cache->keyring_passwords);
        cache->keyring_passwords = strv;

        log_debug("Successfully acquired home key from kernel keyring.");
        return 0;
}
