/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "errno-util.h"
#include "log.h"

void* safe_dlclose(void *dl) {
        if (!dl)
                return NULL;

        assert_se(dlclose(dl) == 0);
        return NULL;
}

static int dlsym_many_or_warnv(void *dl, int log_level, va_list ap) {
        void (**fn)(void);

        /* Tries to resolve a bunch of function symbols, and logs an error about if it cannot resolve one of
         * them. Note that this function possibly modifies the supplied function pointers if the whole
         * operation fails. */

        while ((fn = va_arg(ap, typeof(fn)))) {
                void (*tfn)(void);
                const char *symbol;

                symbol = va_arg(ap, typeof(symbol));

                tfn = (typeof(tfn)) dlsym(dl, symbol);
                if (!tfn)
                        return log_full_errno(log_level,
                                              SYNTHETIC_ERRNO(ELIBBAD),
                                              "Can't find symbol %s: %s", symbol, dlerror());
                *fn = tfn;
        }

        return 0;
}

int dlsym_many_or_warn_sentinel(void *dl, int log_level, ...) {
        va_list ap;
        int r;

        va_start(ap, log_level);
        r = dlsym_many_or_warnv(dl, log_level, ap);
        va_end(ap);

        return r;
}

int dlopen_many_sym_or_warn_sentinel(void **dlp, const char *filename, int log_level, ...) {
        int r;

        if (*dlp)
                return 0; /* Already loaded */

        _cleanup_(dlclosep) void *dl = NULL;
        const char *dle = NULL;
        r = dlopen_safe(filename, &dl, &dle);
        if (r < 0) {
                log_debug_errno(r, "Shared library '%s' is not available: %s", filename, dle ?: STRERROR(r));
                return -EOPNOTSUPP; /* Turn into recognizable error */
        }

        log_debug("Loaded shared library '%s' via dlopen().", filename);

        va_list ap;
        va_start(ap, log_level);
        r = dlsym_many_or_warnv(dl, log_level, ap);
        va_end(ap);

        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to. After all this
         * was traditionally a regular shared library dependency which lives forever too. */
        *dlp = TAKE_PTR(dl);
        return 1;
}

static bool dlopen_blocked = false;

void block_dlopen(void) {
        dlopen_blocked = true;
}

int dlopen_safe(const char *filename, void **ret, const char **reterr_dlerror) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        assert(filename);

        /* A wrapper around dlopen(), that takes dlopen_blocked into account, and tries to normalize the
         * error reporting a bit. */

        int flags = RTLD_NOW|RTLD_NODELETE; /* Always set RTLD_NOW + RTLD_NODELETE, for security reasons */

        /* If dlopen() is blocked we'll still try it, but set RTLD_NOLOAD, so that it will still work if
         * already loaded (for example because the binary linked to things regularly), but fail if not. */
        if (dlopen_blocked)
                flags |= RTLD_NOLOAD;

        errno = 0;
        dl = dlopen(filename, flags);
        if (!dl) {
                if (dlopen_blocked) {
                        (void) dlerror(); /* consume error, so that no later call will return it */

                        if (reterr_dlerror)
                                *reterr_dlerror = NULL;

                        return log_debug_errno(SYNTHETIC_ERRNO(EPERM), "Refusing loading of '%s', as loading further dlopen() modules has been blocked.", filename);
                }

                r = errno_or_else(ENOPKG);

                if (reterr_dlerror)
                        *reterr_dlerror = dlerror();
                else
                        (void) dlerror(); /* consume error, so that no later call will return it */

                return r;
        }

        if (ret)
                *ret = TAKE_PTR(dl);

        return 0;
}
