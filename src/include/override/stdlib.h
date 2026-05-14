/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <stdlib.h>     /* IWYU pragma: export */

/* Route the strtol-family integer parsers through dlsym shims so we don't pin a particular libc
 * symbol version at link time. glibc 2.38 redirects these to __isoc23_* (binary "0b" prefix
 * support), bumping us to GLIBC_2.38; the older non-C23 symbols still exist and behave the same
 * for everything else, which is all we need. Skipped on musl, which has no such redirect. */

#ifdef __GLIBC__
long strtol_shim(const char *nptr, char **endptr, int base);
unsigned long strtoul_shim(const char *nptr, char **endptr, int base);
long long strtoll_shim(const char *nptr, char **endptr, int base);
unsigned long long strtoull_shim(const char *nptr, char **endptr, int base);
#define strtol strtol_shim
#define strtoul strtoul_shim
#define strtoll strtoll_shim
#define strtoull strtoull_shim
#endif
