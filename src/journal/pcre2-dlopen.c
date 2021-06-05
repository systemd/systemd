/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "pcre2-dlopen.h"

#if HAVE_PCRE2
static void *pcre2_dl = NULL;

pcre2_match_data* (*sym_pcre2_match_data_create)(uint32_t, pcre2_general_context *);
void (*sym_pcre2_match_data_free)(pcre2_match_data *);
void (*sym_pcre2_code_free)(pcre2_code *);
pcre2_code* (*sym_pcre2_compile)(PCRE2_SPTR, PCRE2_SIZE, uint32_t, int *, PCRE2_SIZE *, pcre2_compile_context *);
int (*sym_pcre2_get_error_message)(int, PCRE2_UCHAR *, PCRE2_SIZE);
int (*sym_pcre2_match)(const pcre2_code *, PCRE2_SPTR, PCRE2_SIZE, PCRE2_SIZE, uint32_t, pcre2_match_data *, pcre2_match_context *);
PCRE2_SIZE* (*sym_pcre2_get_ovector_pointer)(pcre2_match_data *);

int dlopen_pcre2(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (pcre2_dl)
                return 0; /* Already loaded */

        dl = dlopen("libpcre2-8.so.0", RTLD_LAZY);
        if (!dl)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "PCRE2 support is not installed: %s", dlerror());

        /* So here's something weird: PCRE2 actually renames the symbols exported by the library via C
         * macros, so that the exported symbols carry a suffix "_8" but when used from C the suffix is
         * gone. In the argument list below we ignore this mangling. Surprisingly (at least to me), we
         * actually get away with that. That's because DLSYM_ARG() useses STRINGIFY() to generate a string
         * version of the symbol name, and that resolves the macro mapping implicitly already, so that the
         * string actually contains the "_8" suffix already due to that and we don't have to append it
         * manually anymore. C is weird. 🤯 */

        r = dlsym_many_and_warn(
                        dl,
                        LOG_ERR,
                        DLSYM_ARG(pcre2_match_data_create),
                        DLSYM_ARG(pcre2_match_data_free),
                        DLSYM_ARG(pcre2_code_free),
                        DLSYM_ARG(pcre2_compile),
                        DLSYM_ARG(pcre2_get_error_message),
                        DLSYM_ARG(pcre2_match),
                        DLSYM_ARG(pcre2_get_ovector_pointer),
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        pcre2_dl = TAKE_PTR(dl);

        return 1;
}

#else

int dlopen_pcre2(void) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "PCRE2 support is not compiled in.");
}
#endif
