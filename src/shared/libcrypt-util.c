/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBCRYPT
#  include <crypt.h>
#endif

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "errno-util.h"
#include "libcrypt-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_LIBCRYPT
static void *libcrypt_dl = NULL;

static DLSYM_PROTOTYPE(crypt_gensalt_ra) = NULL;
static DLSYM_PROTOTYPE(crypt_preferred_method) = NULL;
static DLSYM_PROTOTYPE(crypt_ra) = NULL;

int dlopen_libcrypt(void) {
#ifdef __GLIBC__
        static int cached = 0;
        int r;

        if (libcrypt_dl)
                return 0; /* Already loaded */

        if (cached < 0)
                return cached; /* Already tried, and failed. */

        /* Several distributions like Debian/Ubuntu and OpenSUSE provide libxcrypt as libcrypt.so.1,
         * while others like Fedora/CentOS and Arch provide it as libcrypt.so.2. */
        ELF_NOTE_DLOPEN("crypt",
                        "Support for hashing passwords",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libcrypt.so.2", "libcrypt.so.1");

        _cleanup_(dlclosep) void *dl = NULL;
        r = dlopen_safe("libcrypt.so.2", &dl, /* reterr_dlerror= */ NULL);
        if (r < 0) {
                const char *dle = NULL;
                r = dlopen_safe("libcrypt.so.1", &dl, &dle);
                if (r < 0) {
                        log_debug_errno(r, "libcrypt.so.2/libcrypt.so.1 is not available: %s", dle ?: STRERROR(r));
                        return (cached = -EOPNOTSUPP); /* turn into recognizable error */
                }
                log_debug("Loaded 'libcrypt.so.1' via dlopen()");
        } else
                log_debug("Loaded 'libcrypt.so.2' via dlopen()");

        r = dlsym_many_or_warn(
                        dl, LOG_DEBUG,
                        DLSYM_ARG(crypt_gensalt_ra),
                        DLSYM_ARG(crypt_preferred_method),
                        DLSYM_ARG(crypt_ra));
        if (r < 0)
                return (cached = r);

        libcrypt_dl = TAKE_PTR(dl);
#else
        libcrypt_dl = NULL;
        sym_crypt_gensalt_ra = missing_crypt_gensalt_ra;
        sym_crypt_preferred_method = missing_crypt_preferred_method;
        sym_crypt_ra = missing_crypt_ra;
#endif
        return 0;
}

int make_salt(char **ret) {
        const char *e;
        char *salt;
        int r;

        assert(ret);

        r = dlopen_libcrypt();
        if (r < 0)
                return r;

        e = secure_getenv("SYSTEMD_CRYPT_PREFIX");
        if (!e)
                e = sym_crypt_preferred_method();

        log_debug("Generating salt for hash prefix: %s", e);

        salt = sym_crypt_gensalt_ra(e, 0, NULL, 0);
        if (!salt)
                return -errno;

        *ret = salt;
        return 0;
}

int hash_password(const char *password, char **ret) {
        _cleanup_free_ char *salt = NULL;
        _cleanup_(erase_and_freep) void *cd_data = NULL;
        const char *p;
        int r, cd_size = 0;

        assert(password);
        assert(ret);

        r = make_salt(&salt);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate salt: %m");

        errno = 0;
        p = sym_crypt_ra(password, salt, &cd_data, &cd_size);
        if (!p)
                return log_debug_errno(errno_or_else(SYNTHETIC_ERRNO(EINVAL)), "crypt_ra() failed: %m");

        return strdup_to(ret, p);
}

int test_password_one(const char *hashed_password, const char *password) {
        _cleanup_(erase_and_freep) void *cd_data = NULL;
        int r, cd_size = 0;
        const char *k;

        assert(hashed_password);
        assert(password);

        r = dlopen_libcrypt();
        if (r < 0)
                return r;

        errno = 0;
        k = sym_crypt_ra(password, hashed_password, &cd_data, &cd_size);
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

        assert(password);

        STRV_FOREACH(hpw, hashed_password) {
                r = test_password_one(*hpw, password);
                if (r < 0)
                        return r;
                if (r > 0)
                        return true;
        }

        return false;
}
#endif

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
