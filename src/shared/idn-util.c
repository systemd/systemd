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
int (*sym_idn2_lookup_u8)(const uint8_t* src, uint8_t** lookupname, int flags) = NULL;
const char *(*sym_idn2_strerror)(int rc) = NULL;
int (*sym_idn2_to_unicode_8z8z)(const char * input, char ** output, int flags) = NULL;

int dlopen_idn(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (idn_dl)
                return 0; /* Already loaded */

        dl = dlopen("libidn2.so.0", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libidn2 support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(idn2_lookup_u8),
                        DLSYM_ARG(idn2_strerror),
                        DLSYM_ARG(idn2_to_unicode_8z8z),
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
int (*sym_idna_to_ascii_4i)(const uint32_t * in, size_t inlen, char *out, int flags);
int (*sym_idna_to_unicode_44i)(const uint32_t * in, size_t inlen,uint32_t * out, size_t * outlen, int flags);
char* (*sym_stringprep_ucs4_to_utf8)(const uint32_t * str, ssize_t len, size_t * items_read, size_t * items_written);
uint32_t* (*sym_stringprep_utf8_to_ucs4)(const char *str, ssize_t len, size_t *items_written);

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

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(idna_to_ascii_4i),
                        DLSYM_ARG(idna_to_unicode_44i),
                        DLSYM_ARG(stringprep_ucs4_to_utf8),
                        DLSYM_ARG(stringprep_utf8_to_ucs4),
                        NULL);
        if (r < 0)
                return r;

        idn_dl = TAKE_PTR(dl);

        return 1;
}
#endif
