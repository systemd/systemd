/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#if HAVE_GCRYPT
#include <gcrypt.h>

#include "macro.h"

void initialize_libgcrypt(bool secmem);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(gcry_md_hd_t, gcry_md_close, NULL);
#endif

#if !PREFER_OPENSSL
#  if HAVE_GCRYPT
int string_hashsum(const char *s, size_t len, int md_algorithm, char **out);
#  endif

static inline int string_hashsum_sha224(const char *s, size_t len, char **out) {
#  if HAVE_GCRYPT
        return string_hashsum(s, len, GCRY_MD_SHA224, out);
#  else
        return -EOPNOTSUPP;
#  endif
}

static inline int string_hashsum_sha256(const char *s, size_t len, char **out) {
#  if HAVE_GCRYPT
        return string_hashsum(s, len, GCRY_MD_SHA256, out);
#  else
        return -EOPNOTSUPP;
#  endif
}
#endif
