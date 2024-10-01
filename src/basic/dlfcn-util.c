/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"

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
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (*dlp)
                return 0; /* Already loaded */

        dl = dlopen(filename, RTLD_NOW|RTLD_NODELETE);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "%s is not installed: %s", filename, dlerror());

        log_debug("Loaded '%s' via dlopen()", filename);

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
