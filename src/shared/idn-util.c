/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "idn-util.h"
#include "log.h"                /* IWYU pragma: keep */

static void* idn_dl = NULL;

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
