/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

#if HAVE_GCRYPT
#include <gcrypt.h>

#include "macro.h"

void initialize_libgcrypt(bool secmem);

DEFINE_TRIVIAL_CLEANUP_FUNC(gcry_md_hd_t, gcry_md_close);
#endif
