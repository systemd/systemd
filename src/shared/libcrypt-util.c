/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_CRYPT_H
/* libxcrypt is a replacement for glibc's libcrypt, and libcrypt might be
 * removed from glibc at some point. As part of the removal, defines for
 * crypt(3) are dropped from unistd.h, and we must include crypt.h instead.
 *
 * Newer versions of glibc (v2.0+) already ship crypt.h with a definition
 * of crypt(3) as well, so we simply include it if it is present.  MariaDB,
 * MySQL, PostgreSQL, Perl and some other wide-spread packages do it the
 * same way since ages without any problems.
 */
#  include <crypt.h>
#else
#  include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "libcrypt-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_stdlib.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"

int make_salt(char **ret) {

#if HAVE_CRYPT_GENSALT_RA
        const char *e;
        char *salt;

        /* If we have crypt_gensalt_ra() we default to the "preferred method" (i.e. usually yescrypt).
         * crypt_gensalt_ra() is usually provided by libxcrypt. */

        e = secure_getenv("SYSTEMD_CRYPT_PREFIX");
        if (!e)
#if HAVE_CRYPT_PREFERRED_METHOD
                e = crypt_preferred_method();
#else
                e = "$6$";
#endif

        log_debug("Generating salt for hash prefix: %s", e);

        salt = crypt_gensalt_ra(e, 0, NULL, 0);
        if (!salt)
                return -errno;

        *ret = salt;
        return 0;
#else
        /* If crypt_gensalt_ra() is not available, we use SHA512 and generate the salt on our own. */

        static const char table[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
                "./";

        uint8_t raw[16];
        char *salt, *j;
        size_t i;
        int r;

        /* This is a bit like crypt_gensalt_ra(), but doesn't require libcrypt, and doesn't do anything but
         * SHA512, i.e. is legacy-free and minimizes our deps. */

        assert_cc(sizeof(table) == 64U + 1U);

        log_debug("Generating fallback salt for hash prefix: $6$");

        /* Insist on the best randomness by setting RANDOM_BLOCK, this is about keeping passwords secret after all. */
        r = crypto_random_bytes(raw, sizeof(raw));
        if (r < 0)
                return r;

        salt = new(char, 3+sizeof(raw)+1+1);
        if (!salt)
                return -ENOMEM;

        /* We only bother with SHA512 hashed passwords, the rest is legacy, and we don't do legacy. */
        j = stpcpy(salt, "$6$");
        for (i = 0; i < sizeof(raw); i++)
                j[i] = table[raw[i] & 63];
        j[i++] = '$';
        j[i] = 0;

        *ret = salt;
        return 0;
#endif
}

#if HAVE_CRYPT_RA
#  define CRYPT_RA_NAME "crypt_ra"
#else
#  define CRYPT_RA_NAME "crypt_r"

/* Provide a poor man's fallback that uses a fixed size buffer. */

static char* systemd_crypt_ra(const char *phrase, const char *setting, void **data, int *size) {
        assert(data);
        assert(size);

        /* We allocate the buffer because crypt(3) says: struct crypt_data may be quite large (32kB in this
         * implementation of libcrypt; over 128kB in some other implementations). This is large enough that
         * it may be unwise to allocate it on the stack. */

        if (!*data) {
                *data = new0(struct crypt_data, 1);
                if (!*data) {
                        errno = ENOMEM;
                        return NULL;
                }

                *size = (int) (sizeof(struct crypt_data));
        }

        char *t = crypt_r(phrase, setting, *data);
        if (!t)
                return NULL;

        /* crypt_r may return a pointer to an invalid hashed password on error. Our callers expect NULL on
         * error, so let's just return that. */
        if (t[0] == '*')
                return NULL;

        return t;
}

#define crypt_ra systemd_crypt_ra

#endif

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
                return log_debug_errno(errno_or_else(SYNTHETIC_ERRNO(EINVAL)),
                                       CRYPT_RA_NAME "() failed: %m");

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
