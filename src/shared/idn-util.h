/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBIDN2
#include <idn2.h>

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(idn2_lookup_u8);
extern DLSYM_PROTOTYPE(idn2_strerror);
extern DLSYM_PROTOTYPE(idn2_to_unicode_8z8z);

int dlopen_idn(void);
#else
static inline int dlopen_idn(void) {
        return -EOPNOTSUPP;
}
#endif
