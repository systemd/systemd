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

        r = dlsym_many_and_warn(
                        dl,
                        LOG_ERR,
                        &sym_pcre2_match_data_create, "pcre2_match_data_create_8",
                        &sym_pcre2_match_data_free, "pcre2_match_data_free_8",
                        &sym_pcre2_code_free, "pcre2_code_free_8",
                        &sym_pcre2_compile, "pcre2_compile_8",
                        &sym_pcre2_get_error_message, "pcre2_get_error_message_8",
                        &sym_pcre2_match, "pcre2_match_8",
                        &sym_pcre2_get_ovector_pointer, "pcre2_get_ovector_pointer_8",
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
