/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "../libc-shim.h"

DEFINE_LIBC_PURE_SHIM(strtol, long,
                      const char *, nptr,
                      char **, endptr,
                      int, base)

DEFINE_LIBC_PURE_SHIM(strtoul, unsigned long,
                      const char *, nptr,
                      char **, endptr,
                      int, base)

DEFINE_LIBC_PURE_SHIM(strtoll, long long,
                      const char *, nptr,
                      char **, endptr,
                      int, base)

DEFINE_LIBC_PURE_SHIM(strtoull, unsigned long long,
                      const char *, nptr,
                      char **, endptr,
                      int, base)
