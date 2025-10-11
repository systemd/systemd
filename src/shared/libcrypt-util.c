/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <crypt.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "libcrypt-util.h"
#include "log.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"

int make_salt(char **ret) {
        const char *e;
        char *salt;

        /* If we have crypt_gensalt_ra() we default to the "preferred method" (i.e. usually yescrypt).
         * crypt_gensalt_ra() is usually provided by libxcrypt. */

        e = secure_getenv("SYSTEMD_CRYPT_PREFIX");
        if (!e)
                e = crypt_preferred_method();

        log_debug("Generating salt for hash prefix: %s", e);

        salt = crypt_gensalt_ra(e, 0, NULL, 0);
        if (!salt)
                return -errno;

        *ret = salt;
        return 0;
}

int hash_password_full(const char *password, void **cd_data, int *cd_size, char **ret) {
        _cleanup_free_ char *salt = NULL;
        _cleanup_(erase_and_freep) void *_cd_data = NULL;
        const char *p;
        int r, _cd_size = 0;

        assert(!!cd_data == !!cd_size);

        r = make_salt(&salt);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate salt: %m");

        errno = 0;
        p = crypt_ra(password, salt, cd_data ?: &_cd_data, cd_size ?: &_cd_size);
        if (!p)
                return log_debug_errno(errno_or_else(SYNTHETIC_ERRNO(EINVAL)), "crypt_ra() failed: %m");

        return strdup_to(ret, p);
}

bool looks_like_hashed_password(const char *s) {
        /* Returns false if the specified string is certainly not a hashed UNIX password. crypt(5) lists
         * various hashing methods. We only reject (return false) strings which are documented to have
         * different meanings.
         *
         * In particular, we allow locked passwords, i.e. strings starting with "!", including just "!",
         * i.e. the locked empty password. See also fc58c0c7bf7e4f525b916e3e5be0de2307fef04e.
         */
        if (!s)
                return false;

        s += strspn(s, "!"); /* Skip (possibly duplicated) locking prefix */

        return !STR_IN_SET(s, "x", "*");
}

int test_password_one(const char *hashed_password, const char *password) {
        _cleanup_(erase_and_freep) void *cd_data = NULL;
        int cd_size = 0;
        const char *k;

        errno = 0;
        k = crypt_ra(password, hashed_password, &cd_data, &cd_size);
        if (!k) {
                if (errno == ENOMEM)
                        return -ENOMEM;
                /* Unknown or unavailable hashing method or string too short */
                return 0;
        }

        return streq(k, hashed_password);
}

int test_password_many(char **hashed_password, const char *password) {
        int r;

        STRV_FOREACH(hpw, hashed_password) {
                r = test_password_one(*hpw, password);
                if (r < 0)
                        return r;
                if (r > 0)
                        return true;
        }

        return false;
}
