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
DLSYM_PROTOTYPE(idn2_lookup_u8) = NULL;
const char *(*sym_idn2_strerror)(int rc) _const_ = NULL;
DLSYM_PROTOTYPE(idn2_to_unicode_8z8z) = NULL;

int dlopen_idn(void) {
        ELF_NOTE_DLOPEN("idn",
                        "Support for internationalized domain names",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libidn2.so.0");

        return dlopen_many_sym_or_warn(
                        &idn_dl, "libidn2.so.0", LOG_DEBUG,
                        DLSYM_ARG(idn2_lookup_u8),
                        DLSYM_ARG(idn2_strerror),
                        DLSYM_ARG(idn2_to_unicode_8z8z));
}
#endif

#if HAVE_LIBIDN
DLSYM_PROTOTYPE(idna_to_ascii_4i) = NULL;
DLSYM_PROTOTYPE(idna_to_unicode_44i) = NULL;
DLSYM_PROTOTYPE(stringprep_ucs4_to_utf8) = NULL;
DLSYM_PROTOTYPE(stringprep_utf8_to_ucs4) = NULL;

int dlopen_idn(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        ELF_NOTE_DLOPEN("idn",
                        "Support for internationalized domain names",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libidn.so.12", "libidn.so.11");

        if (idn_dl)
                return 0; /* Already loaded */

        dl = dlopen("libidn.so.12", RTLD_NOW|RTLD_NODELETE);
        if (!dl) {
                /* libidn broke ABI in 1.34, but not in a way we care about (a new field got added to an
                 * open-coded struct we do not use), hence support both versions. */
                dl = dlopen("libidn.so.11", RTLD_NOW|RTLD_NODELETE);
                if (!dl)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "libidn support is not installed: %s", dlerror());
                log_debug("Loaded 'libidn.so.11' via dlopen()");
        } else
                log_debug("Loaded 'libidn.so.12' via dlopen()");

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
