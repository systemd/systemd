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
int dlopen_idn(void);
#else
static inline int dlopen_idn(void) {
        return -EOPNOTSUPP;
}
#endif

#if HAVE_LIBIDN2
extern int (*sym_idn2_lookup_u8)(const uint8_t* src, uint8_t** lookupname, int flags);
extern const char *(*sym_idn2_strerror)(int rc);
extern int (*sym_idn2_to_unicode_8z8z)(const char * input, char ** output, int flags);
#endif

#if HAVE_LIBIDN
extern int (*sym_idna_to_ascii_4i)(const uint32_t * in, size_t inlen, char *out, int flags);
extern int (*sym_idna_to_unicode_44i)(const uint32_t * in, size_t inlen,uint32_t * out, size_t * outlen, int flags);
extern char* (*sym_stringprep_ucs4_to_utf8)(const uint32_t * str, ssize_t len, size_t * items_read, size_t * items_written);
extern uint32_t* (*sym_stringprep_utf8_to_ucs4)(const char *str, ssize_t len, size_t *items_written);
#endif
