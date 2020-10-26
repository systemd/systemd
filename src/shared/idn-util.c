/* SPDX-License-Identifier: LGPL-2.1+ */

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
wrap_type_idn2_lookup_u8 sym_idn2_lookup_u8;
wrap_type_idn2_strerror sym_idn2_strerror;
wrap_type_idn2_to_unicode_8z8z sym_idn2_to_unicode_8z8z;

int dlopen_idn(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (idn_dl)
                return 0; /* Already loaded */

        dl = dlopen("libidn2-wrapper.so", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libidn2 support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        &sym_idn2_lookup_u8,       "wrap_idn2_lookup_u8",
                        &sym_idn2_strerror,        "wrap_idn2_strerror",
                        &sym_idn2_to_unicode_8z8z, "wrap_idn2_to_unicode_8z8z",
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        idn_dl = TAKE_PTR(dl);

        return 1;
}
#endif

#if HAVE_LIBIDN
wrap_type_idna_to_ascii_4i sym_idna_to_ascii_4i;
wrap_type_idna_to_unicode_44i sym_idna_to_unicode_44i;
wrap_type_stringprep_ucs4_to_utf8 sym_stringprep_ucs4_to_utf8;
wrap_type_stringprep_utf8_to_ucs4 sym_stringprep_utf8_to_ucs4;

int dlopen_idn(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (idn_dl)
                return 0; /* Already loaded */

        dl = dlopen("libidn-wrapper.so", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libidn support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        &sym_idna_to_ascii_4i,        "wrap_idna_to_ascii_4i",
                        &sym_idna_to_unicode_44i,     "wrap_idna_to_unicode_44i",
                        &sym_stringprep_ucs4_to_utf8, "wrap_stringprep_ucs4_to_utf8",
                        &sym_stringprep_utf8_to_ucs4, "wrap_stringprep_utf8_to_ucs4",
                        NULL);
        if (r < 0)
                return r;

        idn_dl = TAKE_PTR(dl);

        return 1;
}
#endif
