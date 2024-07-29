/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_LIBIDN2
#  include <idn2.h>
#elif HAVE_LIBIDN
#  include <idna.h>
#  include <stringprep.h>
#endif

#include <inttypes.h>

#if HAVE_LIBIDN2 || HAVE_LIBIDN
#include "dlfcn-util.h"

int dlopen_idn(void);
#else
static inline int dlopen_idn(void) {
        return -EOPNOTSUPP;
}
#endif

#if HAVE_LIBIDN2
extern DLSYM_PROTOTYPE(idn2_lookup_u8);
extern const char *(*sym_idn2_strerror)(int rc) _const_;
extern DLSYM_PROTOTYPE(idn2_to_unicode_8z8z);
#endif

#if HAVE_LIBIDN
extern DLSYM_PROTOTYPE(idna_to_ascii_4i);
extern DLSYM_PROTOTYPE(idna_to_unicode_44i);
extern DLSYM_PROTOTYPE(stringprep_ucs4_to_utf8);
extern DLSYM_PROTOTYPE(stringprep_utf8_to_ucs4);
#endif
