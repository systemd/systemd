/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"

int dlsym_many_and_warn(void *dl, int level, ...) {
        va_list ap;
        int r;

        /* Tries to resolve a bunch of function symbols, and logs errors about the ones it cannot
         * resolve. Note that this function possibly modifies the supplied function pointers if the whole
         * operation fails */

        va_start(ap, level);

        for (;;) {
                void (**fn)(void);
                void (*tfn)(void);
                const char *symbol;

                fn = va_arg(ap, typeof(fn));
                if (!fn)
                        break;

                symbol = va_arg(ap, typeof(symbol));

                tfn = (typeof(tfn)) dlsym(dl, symbol);
                if (!tfn) {
                        r = log_full_errno(level,
                                           SYNTHETIC_ERRNO(ELIBBAD),
                                           "Can't find symbol %s: %s", symbol, dlerror());
                        va_end(ap);
                        return r;
                }

                *fn = tfn;
        }

        va_end(ap);
        return 0;
}
