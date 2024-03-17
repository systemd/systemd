/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBIDN2
#  include <idn2.h>
#elif HAVE_LIBIDN
#  include <idna.h>
#  include <stringprep.h>
#endif

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "idn-util.h"

#if HAVE_LIBIDN || HAVE_LIBIDN2
static void* idn_dl = NULL;
#endif

#if HAVE_LIBIDN2
DLSYM_FUNCTION(idn2_lookup_u8);
const char *(*sym_idn2_strerror)(int rc) _const_ = NULL;
DLSYM_FUNCTION(idn2_to_unicode_8z8z);

int dlopen_idn(void) {
        return dlopen_many_sym_or_warn(
                        &idn_dl, "libidn2.so.0", LOG_DEBUG,
                        DLSYM_ARG(idn2_lookup_u8),
                        DLSYM_ARG(idn2_strerror),
                        DLSYM_ARG(idn2_to_unicode_8z8z));
}
#endif

#if HAVE_LIBIDN
DLSYM_FUNCTION(idna_to_ascii_4i);
DLSYM_FUNCTION(idna_to_unicode_44i);
DLSYM_FUNCTION(stringprep_ucs4_to_utf8);
DLSYM_FUNCTION(stringprep_utf8_to_ucs4);

int dlopen_idn(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (idn_dl)
                return 0; /* Already loaded */

        dl = dlopen("libidn.so.12", RTLD_LAZY);
        if (!dl) {
                /* libidn broke ABI in 1.34, but not in a way we care about (a new field got added to an
                 * open-coded struct we do not use), hence support both versions. */
                dl = dlopen("libidn.so.11", RTLD_LAZY);
                if (!dl)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "libidn support is not installed: %s", dlerror());
        }

        r = dlsym_many_or_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(idna_to_ascii_4i),
                        DLSYM_ARG(idna_to_unicode_44i),
                        DLSYM_ARG(stringprep_ucs4_to_utf8),
                        DLSYM_ARG(stringprep_utf8_to_ucs4));
        if (r < 0)
                return r;

        idn_dl = TAKE_PTR(dl);

        return 1;
}
#endif
