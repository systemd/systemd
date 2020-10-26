/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

#if HAVE_LIBIDN2
#  include <idn2.h>
#  include "idn2-wrapper.h"
#elif HAVE_LIBIDN
#  include <idna.h>
#  include <stringprep.h>
#  include "idn-wrapper.h"
#endif

#if HAVE_LIBIDN2 || HAVE_LIBIDN
int dlopen_idn(void);
#else
static inline int dlopen_idn(void) {
        return -EOPNOTSUPP;
}
#endif

#if HAVE_LIBIDN2
extern wrap_type_idn2_lookup_u8 sym_idn2_lookup_u8;
extern wrap_type_idn2_strerror sym_idn2_strerror;
extern wrap_type_idn2_to_unicode_8z8z sym_idn2_to_unicode_8z8z;
#endif

#if HAVE_LIBIDN
extern wrap_type_idna_to_ascii_4i sym_idna_to_ascii_4i;
extern wrap_type_idna_to_unicode_44i sym_idna_to_unicode_44i;
extern wrap_type_stringprep_ucs4_to_utf8 sym_stringprep_ucs4_to_utf8;
extern wrap_type_stringprep_utf8_to_ucs4 sym_stringprep_utf8_to_ucs4;
#endif
