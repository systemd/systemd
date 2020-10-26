/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "pcre2-dlopen.h"
#include "pcre2-wrapper.h"

#if HAVE_PCRE2
static void *pcre2_dl = NULL;

wrap_type_pcre2_match_data_create_8 sym_pcre2_match_data_create;
wrap_type_pcre2_match_data_free_8 sym_pcre2_match_data_free;
wrap_type_pcre2_code_free_8 sym_pcre2_code_free;
wrap_type_pcre2_compile_8 sym_pcre2_compile;
wrap_type_pcre2_get_error_message_8 sym_pcre2_get_error_message;
wrap_type_pcre2_match_8 sym_pcre2_match;
wrap_type_pcre2_get_ovector_pointer_8 sym_pcre2_get_ovector_pointer;

int dlopen_pcre2(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (pcre2_dl)
                return 0; /* Already loaded */

        dl = dlopen("libpcre2-wrapper.so", RTLD_LAZY);
        if (!dl)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "PCRE2 support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_ERR,
                        &sym_pcre2_match_data_create,   "wrap_pcre2_match_data_create_8",
                        &sym_pcre2_match_data_free,     "wrap_pcre2_match_data_free_8",
                        &sym_pcre2_code_free,           "wrap_pcre2_code_free_8",
                        &sym_pcre2_compile,             "wrap_pcre2_compile_8",
                        &sym_pcre2_get_error_message,   "wrap_pcre2_get_error_message_8",
                        &sym_pcre2_match,               "wrap_pcre2_match_8",
                        &sym_pcre2_get_ovector_pointer, "wrap_pcre2_get_ovector_pointer_8",
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
